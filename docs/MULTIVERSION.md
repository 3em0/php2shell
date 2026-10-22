# Multi-version notes (PHP 8.1 – 8.5)

This chain was reproduced and tested against the official `php:*-apache` Docker
images on `linux/amd64`. All of the images below are currently **Debian 13
(trixie)** — the tags were rebuilt on the new Debian stable, so the original
"Debian 12 (bookworm)" description no longer matches what `docker pull` returns
(verified via `/etc/debian_version = 13.7`).

## Support matrix

| PHP | Image | Base | `zif_system` | `ZVAL_PTR_DTOR` | `htdata` | Result |
| --- | --- | --- | --- | --- | --- | --- |
| 8.5.11 | `php:8.5-apache` | Debian 13.7 | `0x5996e0` | `0x7b47a0` | `0x690d8` | ✅ RCE (6/6) |
| 8.4.26 | `php:8.4.26-apache` | Debian 13.7 | `0x465370` | `0x65eb60` | `0x690d8` | ✅ RCE (3/3) |
| 8.3.35 | `php:8.3-apache` | Debian 13.7 | `0x3ac080` | `0x49ec50` | `0x6a0d8` | ✅ RCE (8/8) |
| 8.2.35 | `php:8.2-apache` | Debian 13.7 | `0x3a1da0` | `0x491910` | — | ❌ stage 1 never leaks |
| 8.1.34 | `php:8.1-apache` | Debian 13.2 | `0x36f470` | `0x457150` | — | ❌ stage 1 never leaks |

- `zif_system` / `ZVAL_PTR_DTOR` are read from each image's `libphp.so` at
  runtime by `docker/offsets.py`, so they never need manual editing.
- `htdata` (the chunk-relative offset of the live 167-byte carrier) is the only
  version-specific constant for the working versions: `0x690d8` on 8.4/8.5,
  `0x6a0d8` on 8.3. On a localhost container the exploit picks it from the
  detected PHP minor version automatically.
- Heap grooming (`stage1_n=841`, `stage2_t=406`, `stage2_v=16`, the stage-3
  pads and carrier) is identical across 8.3/8.4/8.5.

Reproduce the table with [`../scripts/matrix.sh`](../scripts/matrix.sh).

## Why 8.3 is reliable (and 8.5 came for free)

8.4.26 and 8.5.11 use exactly the same requests and grooming; only the libphp
symbol offsets differ, and those are auto-derived. 8.3.35 uses the same grooming
too — its carrier just lands one page higher (`htdata` differs by `0x1000`).

One real bug was found and fixed along the way: stage 3's "keep `PS(id)` valid so
B's init leaves `send_cookie=0`" guard (which stops a `Set-Cookie` header from
being allocated at `R0+16` and clobbering `val.type`) was originally gated on the
profile name being exactly `bookworm`. When the 8.3 path became its own profile,
that guard was dropped and 8.3 stage-3 only landed occasionally. The guard
belongs to the carrier technique, so it is now gated on `stage3_carrier`; 8.3
went from ~0/8 to 8/8.

## Why 8.1 / 8.2 do not work

On `php:8.1-apache` and `php:8.2-apache` the stage-1 `Set-Cookie` over-read never
engages: request `B` returns a clean 32-byte session id, so the chain recovers no
chunk base and stops before stage 2.

Investigation (all on `php:8.2-apache`, 8.2.35):

1. **Instrumented stage 1.** Captured the `B` response directly: `Set-Cookie`
   is present but the decoded cookie is a clean **32-byte** session id with zero
   heap pointers — i.e. `PS(id)` was a normally-allocated fresh id at
   `php_session_send_cookie()` time, not the dangling/forged string.
2. **Forged-field size sweep.** Swept the forged `zend_string` field across
   55–167 bytes (multiple Zend MM bins). The cookie stayed 32 bytes for every
   size — so it is not a simple bin/size mismatch in the reoccupation.
3. **OOM-field size sweep.** Swept the OOM field across 9–32 MB. The cookie
   stayed 32 bytes for every size — so it is not a matter of where the
   allocation that bails out sits.
4. **Source diff.** `php_session_send_cookie` (the
   `php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)))` over-read vehicle),
   `php_session_reset_id` and `php_session_initialize` are **textually identical**
   between the `PHP-8.2` and `PHP-8.3` branches. The over-read vehicle therefore
   exists in 8.2's code as well.

**Conclusion.** The boundary at 8.3 is not a change in the session cookie/init
logic. The chain depends on A's OOM bailout leaving `PS(id)` dangling across the
request; on the 8.2 build that dangling state is not produced (B always creates a
fresh id), which points to a build / allocator / OOM-timing difference rather than
anything reachable by HTTP-level grooming. Pinning the exact instruction-level
cause would require a gdb trace of the OOM path, but the official images ship a
stripped `libphp.so` and the session functions are `static` (no symbols to break
on), so that is left as future work. 8.1/8.2 would need a different stage-1
primitive, if one exists on those builds.
