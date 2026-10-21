<!-- markdownlint-disable MD033 MD041 -->
<div align="center">

# php2shell

**Remote, HTTP-only RCE on PHP 8.4.26 + Apache prefork + mod_php — ASLR bypassed, no `session_start()`, no file written on the target.**

[![PHP](https://img.shields.io/badge/PHP-8.3%20%7C%208.4%20%7C%208.5-777BB4?logo=php&logoColor=white)](https://hub.docker.com/_/php)
[![Apache](https://img.shields.io/badge/Apache-2.4%20prefork-D22128?logo=apache&logoColor=white)](https://httpd.apache.org/)
[![Platform](https://img.shields.io/badge/platform-linux%2Famd64-informational)](#requirements)
[![Status](https://img.shields.io/badge/8.4%20%26%208.5-RCE%20verified-success)](#reproduction-status)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

English&nbsp;|&nbsp;[中文](README.zh-CN.md)

</div>

---

A single **`exploit.py`** turns a dangling pointer left behind by `session.upload_progress` into full
command execution on an unmodified `php:8.4.26-apache` container. Every byte of attack traffic is an
ordinary `multipart/form-data` POST; the target web root is literally `<?php echo "OK\n"; ?>`. The
chain leaks the Zend MM chunk base and the `libphp.so` base over two `Set-Cookie` out-of-bounds reads,
then forges a `HashTable` whose destructor is `zif_system`:

```console
$ python3 exploit.py -u http://127.0.0.1:8088/index.php
[+] chunk base  = 0x7f3f73600000
[+] libphp base = 0x7f3f752a5000
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> [!WARNING]
> **Authorized research only.** This is a reproduction of public vulnerability research, intended for
> use against the self-contained Docker lab in this repository or systems you are explicitly
> authorized to test. Running it against machines you do not own or operate is illegal. You are
> responsible for your own use.

## Table of contents

- [Highlights](#highlights)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Reproduction status](#reproduction-status)
- [How it works](#how-it-works)
- [Offsets &amp; profiles](#offsets--profiles)
- [Running arbitrary commands](#running-arbitrary-commands)
- [Command-line options](#command-line-options)
- [Target configuration](#target-configuration)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)
- [Limitations](#limitations)
- [Credits](#credits)
- [License](#license)

## Highlights

- **One command, full chain.** `exploit.py` performs worker rotation, the two-stage leak,
  `zif_system` execution and proof retrieval, with per-stage retries.
- **Pure HTTP.** No `session_start()` on the target page, no PHP written on the target side, no local
  signals — only `multipart/form-data` POSTs.
- **ASLR bypassed.** Two `Set-Cookie` out-of-bounds reads recover the chunk and `libphp` bases at
  runtime; the terminal stage calls `zif_system` inside `libphp` and never touches libc.
- **No target build.** The environment is the official `php:8.4.26-apache` image plus a handful of
  config mounts — there is no `docker build`.
- **Multi-version.** The same chain gets reliable RCE on the official **8.4** and **8.5** images; the
  only version-sensitive value is a single chunk-relative offset, picked automatically on localhost.
- **Self-calibrating offsets.** Against a localhost container the libphp symbol offsets are read
  straight from `libphp.so` (and refreshed on every run, so switching images can't leave them stale),
  so an image refresh needs no manual edit.

## Requirements

| Tool | Version |
| --- | --- |
| Docker Engine / Desktop | any recent release |
| Docker Compose | v2 (`docker compose`) |
| Python | 3.9+ (standard library only) |
| Host architecture | `linux/amd64` (the image is amd64; the offsets are x86-64) |

## Quick start

The block below goes from zero to RCE. Copy and run it as-is.

```bash
git clone https://github.com/3em0/php2shell.git
cd php2shell

# 1) Pull the official image (PHP 8.4.26 / Debian 12 / Apache prefork)
docker compose -f docker/docker-compose.yml pull

# 2) Start the target: single worker, display_errors=On, memory_limit=8M
docker compose -f docker/docker-compose.yml up -d

# 3) Wait for Apache and confirm a normal page
for i in $(seq 1 20); do
  curl -fsS http://127.0.0.1:8088/index.php >/dev/null 2>&1 && break
  sleep 0.5
done
curl -s http://127.0.0.1:8088/index.php   # -> OK

# 4) One command completes the whole exploit; the first run reads libphp offsets automatically
python3 exploit.py -u http://127.0.0.1:8088/index.php
# PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The default command is `id>/out/p1` (10 bytes). The container's `/out` is bind-mounted to the
repository's `./out`, so the proof lands directly on the host. On the first run `exploit.py` invokes
[`docker/offsets.py`](docker/offsets.py), which parses `zif_system` / `zval_ptr_dtor` out of the
container's `libphp.so` and caches them in `out/offsets.env`.

## Reproduction status

Measured live on the official PHP `-apache` images (all Debian 12 bookworm), `linux/amd64`, using
the shipped `docker/` lab with `PHP_IMAGE` pointed at each version:

| PHP version | Profile | libphp offsets | Stage 1–2 leaks | Stage 3 RCE |
| --- | --- | --- | --- | --- |
| **8.4.26** | `bookworm` (default) | auto `0x465370` / `0x65eb60` | reliable | ✅ **3 / 3** one-shot |
| **8.5.11** | `bookworm` (default) | auto `0x5996e0` / `0x7b47a0` | reliable | ✅ **6 / 6** one-shot |
| **8.3.35** | `bookworm83` (auto on localhost) | auto `0x3ac080` / `0x49ec50` | reliable (10 / 10) | ⚠️ occasional — see [limitations](#limitations) |

The libphp symbol offsets are read from each image at runtime, so only the chunk-relative `htdata`
offset is version-specific: `0x690d8` for 8.4/8.5, `0x6a0d8` for 8.3. Point the lab at another version
with:

```bash
PHP_IMAGE=php:8.5-apache docker compose -f docker/docker-compose.yml up -d --force-recreate
python3 exploit.py -u http://127.0.0.1:8088/index.php   # same command, offsets auto-adjust
```

## How it works

The vulnerable surface is session initialization triggered by `session.upload_progress` *before*
`RINIT`, combined with a dangling pointer that survives across requests after an out-of-memory
bailout. The entire attack is ordinary multipart HTTP.

| Stage | Action | Result |
| --- | --- | --- |
| 0 | **Worker rotation** — a 3 MB live field + 12 MB OOM field, then a session-initializing request; the child aborts and prefork forks a fresh worker that inherits the same mappings. | Clean, predictable heap |
| 1 | **Heap leak** — 1001 fields trip `max_input_vars` (with `display_errors=On` → `headers_sent=1`); the final 12 MB field OOMs inside `php_session_initialize()`, leaving `PS(http_session_vars)` dangling; `php_url_encode()` over-reads Zend MM chunk pointers into `Set-Cookie`. | Zend MM **chunk base** |
| 2 | **libphp leak** — a 56-byte HashTable page makes `ZSTR_LEN(PS(id))` read `nTableSize`, exposing `pDestructor = ZVAL_PTR_DTOR`. | **libphp base** |
| 3 | **Command execution** — a fake `reference` is pinned over `PS(http_session_vars)`; its fake `HashTable` has `pDestructor = zif_system`. | **RCE** |

The stage-3 destructor chain:

```text
php_session_track_init()
  zval_ptr_dtor(PS(http_session_vars))
    zend_reference_destroy(R0)
      zval_ptr_dtor(&ref->val)          # IS_ARRAY_EX
        zend_array_destroy(fake HT)
          zend_hash_destroy(fake HT)
            pDestructor(&bucket->val)   # zif_system
```

Why it works, in short:

- **No `session_start()` needed** — A/B session init happens in the multipart callbacks before
  `RINIT` (`FILE_START → php_session_rfc1867_update`; `END → php_session_rfc1867_cleanup`), independent
  of script content.
- **Why the pointer dangles** — the OOM bailout inside `php_session_initialize()` never clears
  `PS(http_session_vars)` / `PS(id)`; the next request's `php_session_track_init()` calls
  `zval_ptr_dtor` on it.
- **Why reoccupation works** — multipart field values are allocated as `zend_string`s during parsing;
  the 56 B / 55 B / 167 B sizes line up exactly to cover the stale reference and carry the fake
  HashTable.
- **Why ASLR falls** — the two out-of-bounds reads leak both bases; workers are swapped via pure-HTTP
  abort/fork while the address space is unchanged; the terminal stage avoids libc.

Full mechanism, gdb evidence and request calibration live in [`docs/`](#documentation).

## Offsets &amp; profiles

All version-specific values are collected in a single typed `Profile` table in
[`exploit.py`](exploit.py). `zif_offset` / `dtor_offset` are `libphp.so` symbol offsets and
`htdata_offset` is a Zend MM chunk-relative offset — all relative to a module/chunk base, so **none of
them depend on ASLR**. The `stage*` fields groom the heap and differ per build.

| Profile | Target build | `zif_system` | `ZVAL_PTR_DTOR` | `htdata` | stage1 / stage2 |
| --- | --- | --- | --- | --- | --- |
| **`bookworm`** (default) | official `php:8.4`/`8.5-apache` (Debian 12) | `0x465370` | `0x65eb60` | `0x690d8` | `n=841`, `t=406`, `v=16` |
| `bookworm83` | official `php:8.3-apache` (Debian 12) | `0x3ac080` | `0x49ec50` | `0x6a0d8` | `n=841`, `t=406`, `v=16` |
| `lab` | self-built (Apache 2.4.68, minimal PHP) | `0x43a870` | `0x613c50` | `0x6e0d8` | `n=892`, `t=443`, `v=1` |

Offset resolution precedence (highest first):

1. **CLI** — `--zif-offset` / `--dtor-offset` / `--htdata-offset`.
2. **Offsets file** — `out/offsets.env`, written by `docker/offsets.py` for a localhost container
   (libphp offsets only; refreshed on every localhost run so it can never go stale).
3. **Profile defaults** — the measured values in the table above.

Two conveniences make multi-version use zero-config:

- **Version-aware `htdata`.** On a localhost container the exploit reads the PHP minor version and,
  on the default profile, automatically uses the `bookworm83` `htdata` for 8.3 — so the same command
  fits 8.3 / 8.4 / 8.5 with no flags.
- **Own libphp defaults per profile.** Each profile carries its own correct libphp defaults, so it
  also works against a **remote** target of that build out of the box, even when `docker/offsets.py`
  cannot run (it only reaches a localhost container).

Switch profile with `--profile bookworm83` / `--profile lab`; disable auto-derivation with
`--offsets-file '' --no-auto-offsets`.

## Running arbitrary commands

The command is embedded in a live 167-byte `zend_string`, so the hard limit is **14 bytes**. For
anything longer, drop a script into the mounted directory and trigger it with a short shell command
(`sh</out/c` is 8 bytes):

```bash
printf 'id; uname -a > /out/p1\n' > out/c
python3 exploit.py -u http://127.0.0.1:8088/index.php -c 'sh</out/c'
```

## Command-line options

| Option | Default | Description |
| --- | --- | --- |
| `-u`, `--url` | *(required)* | Target PHP page, e.g. `http://127.0.0.1:8088/index.php` |
| `-c`, `--cmd` | `id>/out/p1` | Command to execute (max 14 bytes) |
| `--profile` | `bookworm` | Build profile: `bookworm` (8.4/8.5), `bookworm83` (8.3), or `lab` |
| `--proof-file` | `out/p1` | Local file read back after exploitation (`''` disables) |
| `--fetch` | *(off)* | `GET` this path afterwards (for commands writing to the web root) |
| `--zif-offset` / `--dtor-offset` / `--htdata-offset` | *(profile)* | Override individual offsets |
| `--offsets-file` | `out/offsets.env` | Offsets file to load (`''` disables) |
| `--docker-container` | `php2shell-target` | Container used to auto-derive offsets on localhost |
| `--no-auto-offsets` | *(off)* | Never run `docker/offsets.py` automatically |
| `--no-pre-rotate` | *(off)* | Skip the initial worker rotation |
| `--retries` | `3` | Attempts per leak stage (stage 3 uses `retries + 2`) |
| `-q`, `--quiet` | *(off)* | Suppress progress output |

## Target configuration

The shipped lab mirrors the settings the chain depends on
([`docker/php.ini`](docker/php.ini), [`docker/apache.conf`](docker/apache.conf)):

| Component | Value |
| --- | --- |
| PHP | 8.4.26 (NTS, mod_php) |
| Base OS | Debian 12 (bookworm) |
| Apache MPM | prefork, **single worker** |
| `display_errors` | `On` |
| `memory_limit` | `8M` |
| `max_input_vars` | `1000` |
| `session.use_cookies` / `use_strict_mode` | `1` / `0` |
| `session.upload_progress.enabled` | `On` |

## Repository layout

```text
php2shell/
├── exploit.py              # one-click exploit (worker rotation → leak → RCE)
├── docker/
│   ├── docker-compose.yml  # official php:8.4.26-apache, single-worker prefork
│   ├── apache.conf         # prefork: StartServers=MaxRequestWorkers=1
│   ├── php.ini             # display_errors=On, memory_limit=8M, upload_progress
│   ├── offsets.py          # parse zif_system / zval_ptr_dtor from libphp.so
│   └── www/index.php       # the entire target: <?php echo "OK\n"; ?>
├── out/                    # proof files and out/offsets.env land here
└── docs/                   # mechanism write-ups and gdb evidence
```

## Documentation

| Document | Topic |
| --- | --- |
| [docs/HTTP_HEAP_LEAK.md](docs/HTTP_HEAP_LEAK.md) | Stage-1 heap leak, request calibration |
| [docs/ASLR_PURE_HTTP.md](docs/ASLR_PURE_HTTP.md) | libphp leak and the full ASLR-bypass chain |
| [docs/DISPLAY_ERRORS_OFF.md](docs/DISPLAY_ERRORS_OFF.md) | Leak path that does not rely on `display_errors` |
| [docs/NOTES.md](docs/NOTES.md) | Root cause and php-src source locations |
| [docs/NOASLR_REPORT.md](docs/NOASLR_REPORT.md) | Earlier `arData` UAF RCE (mechanism reference) |

## Limitations

- The current RCE requires `display_errors=1`, `memory_limit=8M`, `max_input_vars=1000`,
  `session.use_cookies=1`, `session.use_strict_mode=0` and single-worker prefork.
- **PHP 8.3 is experimental.** On `php:8.3-apache` the ASLR leaks (stages 1–2) are fully reliable, but
  stage-3 code execution only lands occasionally with the 8.4-tuned grooming — 8.3 needs its own
  stage-3 calibration. Reliable RCE is currently verified on **8.4** and **8.5**.
- A pure-HTTP heap leak works with `display_errors=0`; the complete RCE for that configuration is not
  included here (see [docs/DISPLAY_ERRORS_OFF.md](docs/DISPLAY_ERRORS_OFF.md)).
- The offsets are x86-64; a different architecture or a rebuilt `libphp.so` shifts them (use
  `docker/offsets.py` or the `--*-offset` flags).

## Credits

Original vulnerability research and proof of concept by
[**@9bie**](https://github.com/9bie/php2shell-bypass-aslr-exp). This repository reproduces that work
in a self-contained Docker lab, restructures the per-profile offsets into one typed table, extends the
chain to PHP **8.5** (and the 8.3 leak path) with runtime offset auto-derivation and version-aware
`htdata` selection, and fixes the `out/` permission handling so the official-image flow calibrates
cleanly from a cold start.

## License

Released under the [MIT License](LICENSE). Provided for authorized security research and education
only.
