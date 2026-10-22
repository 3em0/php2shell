<!-- markdownlint-disable MD033 MD041 -->
<div align="center">

# php2shell

**纯远程、仅用 HTTP 对 PHP 8.4.26 + Apache prefork + mod_php 的 RCE —— 绕过 ASLR、目标页面无 `session_start()`、不在目标侧写任何 PHP。**

[![PHP](https://img.shields.io/badge/PHP-8.3%20%7C%208.4%20%7C%208.5-777BB4?logo=php&logoColor=white)](https://hub.docker.com/_/php)
[![Apache](https://img.shields.io/badge/Apache-2.4%20prefork-D22128?logo=apache&logoColor=white)](https://httpd.apache.org/)
[![Platform](https://img.shields.io/badge/platform-linux%2Famd64-informational)](#环境要求)
[![Status](https://img.shields.io/badge/8.3%20%7C%208.4%20%7C%208.5-RCE%20verified-success)](#复现结果)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[English](README.md)&nbsp;|&nbsp;中文

</div>

---

一个 **`exploit.py`** 把 `session.upload_progress` 留下的悬空指针变成在未经修改的 `php:8.4.26-apache`
容器上的命令执行。所有攻击流量都是普通的 `multipart/form-data` POST，目标 web 根目录只有
`<?php echo "OK\n"; ?>`。利用链通过两次 `Set-Cookie` 越界读分别泄漏 Zend MM chunk 基址和 `libphp.so`
基址，然后伪造一个析构器为 `zif_system` 的 `HashTable`：

```console
$ python3 exploit.py -u http://127.0.0.1:8088/index.php
[+] chunk base  = 0x7f3f73600000
[+] libphp base = 0x7f3f752a5000
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> [!WARNING]
> **仅限授权研究。** 本项目复现的是已公开的漏洞研究，仅用于本仓库自带的 Docker 靶场，或你已获明确授权
> 的系统。对非自有/未授权系统运行属于违法行为，后果自负。

## 目录

- [特性](#特性)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [复现结果](#复现结果)
- [原理](#原理)
- [偏移与 profile](#偏移与-profile)
- [执行任意命令](#执行任意命令)
- [命令行参数](#命令行参数)
- [目标配置](#目标配置)
- [仓库结构](#仓库结构)
- [文档](#文档)
- [边界与限制](#边界与限制)
- [致谢](#致谢)
- [许可证](#许可证)

## 特性

- **一条命令跑完整链。** `exploit.py` 自动完成 worker 轮换、两阶段泄漏、`zif_system` 执行和 proof 读取，
  每个阶段内置重试。
- **纯 HTTP。** 目标页面无需 `session_start()`、无需在目标侧写 PHP、无需本地信号，攻击流量只有
  `multipart/form-data` POST。
- **绕过 ASLR。** 两次 `Set-Cookie` 越界读在运行时恢复 chunk 和 `libphp` 基址；终端阶段调用 `libphp`
  内的 `zif_system`，完全不依赖 libc。
- **无需编译目标。** 环境就是官方 `php:8.4.26-apache` 镜像加若干配置挂载，没有 `docker build`。
- **多版本。** 同一条链在官方 **8.3**、**8.4** 和 **8.5** 镜像上都能稳定拿到 RCE；唯一与版本相关的只是一个
  chunk 相对偏移，本机运行时会自动选好。
- **偏移自标定。** 对本机容器会直接从 `libphp.so` 读取符号偏移，并在每次运行时刷新（换镜像也不会残留旧值），
  更换或升级镜像后无需手改。

## 环境要求

| 工具 | 版本 |
| --- | --- |
| Docker Engine / Desktop | 任意较新版本 |
| Docker Compose | v2（`docker compose`） |
| Python | 3.9+（仅标准库） |
| 主机架构 | `linux/amd64`（镜像为 amd64，偏移为 x86-64） |

## 快速开始

下面整段命令从零到 RCE，可直接复制执行：

```bash
git clone https://github.com/3em0/php2shell.git
cd php2shell

# 1) 拉官方镜像（PHP 8.4.26 / Debian 13 / Apache prefork）
docker compose -f docker/docker-compose.yml pull

# 2) 起目标：单 worker、display_errors=On、memory_limit=8M
docker compose -f docker/docker-compose.yml up -d

# 3) 等 Apache 就绪并确认普通页面
for i in $(seq 1 20); do
  curl -fsS http://127.0.0.1:8088/index.php >/dev/null 2>&1 && break
  sleep 0.5
done
curl -s http://127.0.0.1:8088/index.php   # -> OK

# 4) 一条命令完成整个利用；首次运行会自动读取 libphp 偏移
python3 exploit.py -u http://127.0.0.1:8088/index.php
# PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

默认命令是 `id>/out/p1`（10 字节）。容器里的 `/out` 挂载到仓库的 `./out`，proof 直接落在本机。首次运行
会自动调用 [`docker/offsets.py`](docker/offsets.py)，从容器内 `libphp.so` 解析 `zif_system` /
`zval_ptr_dtor` 并缓存到 `out/offsets.env`。

## 复现结果

在官方 PHP `-apache` 镜像（均为 Debian 13 trixie）、`linux/amd64` 上,用本仓库 `docker/` 靶场把
`PHP_IMAGE` 指向各版本实测：

| PHP 版本 | Profile | libphp 偏移 | 阶段 1–2 泄漏 | 阶段 3 RCE |
| --- | --- | --- | --- | --- |
| **8.3.35** | `official83`（本机自动选） | 自动 `0x3ac080` / `0x49ec50` | 稳定 | ✅ **8 / 8** 一键 |
| **8.4.26** | `official`（默认） | 自动 `0x465370` / `0x65eb60` | 稳定 | ✅ **3 / 3** 一键 |
| **8.5.11** | `official`（默认） | 自动 `0x5996e0` / `0x7b47a0` | 稳定 | ✅ **6 / 6** 一键 |

libphp 符号偏移在运行时从各镜像读取,因此只有 chunk 相对的 `htdata` 偏移与版本有关：8.4/8.5 为 `0x690d8`,
8.3 为 `0x6a0d8`。把靶场指向其他版本：

```bash
PHP_IMAGE=php:8.5-apache docker compose -f docker/docker-compose.yml up -d --force-recreate
python3 exploit.py -u http://127.0.0.1:8088/index.php   # 命令不变,偏移自动调整
```

用 [`scripts/matrix.sh`](scripts/matrix.sh) 可一键复测整张表（每次 trial 都重建容器,所以得到的是真实的冷启动
一键成功率）：

```bash
./scripts/matrix.sh -n 3            # 默认支持的镜像
./scripts/matrix.sh -n 8 php:8.5-apache
```

## 原理

漏洞面是 `session.upload_progress` 在 `RINIT` 之前触发的 session 初始化，加上 OOM bailout 后跨请求残留的
悬空指针。整条链都是普通 multipart HTTP：

| 阶段 | 动作 | 结果 |
| --- | --- | --- |
| 0 | **worker 轮换** —— 3MB 存活字段 + 12MB OOM 字段，紧跟一个初始化 session 的请求；child 以 SIGABRT 退出，prefork fork 出的新 worker 继承相同映射。 | 干净可预测的堆 |
| 1 | **堆泄漏** —— 1001 个字段触发 `max_input_vars` 警告（`display_errors=On` → `headers_sent=1`）；最后的 12MB 字段在 `php_session_initialize()` 内 OOM，`PS(http_session_vars)` 悬空；`php_url_encode()` 越界读把 Zend MM chunk 指针写进 `Set-Cookie`。 | Zend MM **chunk 基址** |
| 2 | **libphp 泄漏** —— 56 字节 HashTable 页让 `ZSTR_LEN(PS(id))` 读到 `nTableSize`，数据区暴露 `pDestructor = ZVAL_PTR_DTOR`。 | **libphp 基址** |
| 3 | **命令执行** —— 把伪造 `reference` 固定到 `PS(http_session_vars)`，其 fake `HashTable` 的 `pDestructor = zif_system`。 | **RCE** |

阶段 3 的析构触发链：

```text
php_session_track_init()
  zval_ptr_dtor(PS(http_session_vars))
    zend_reference_destroy(R0)
      zval_ptr_dtor(&ref->val)          # IS_ARRAY_EX
        zend_array_destroy(fake HT)
          zend_hash_destroy(fake HT)
            pDestructor(&bucket->val)   # zif_system
```

关键点：

- **为什么不需要 `session_start()`** —— A/B 的 session 初始化发生在 `RINIT` 前的 multipart 回调里
  （`FILE_START → php_session_rfc1867_update`；`END → php_session_rfc1867_cleanup`），与脚本内容无关。
- **指针为什么悬空** —— A 在 `php_session_initialize()` 内 OOM bailout，没有清空
  `PS(http_session_vars)` / `PS(id)`；下一请求的 `php_session_track_init()` 对其执行 `zval_ptr_dtor`。
- **为什么能重占** —— multipart 字段值在解析阶段被分配成 `zend_string`；56B / 55B / 167B 这些尺寸正好
  覆盖旧 reference、承载 fake HashTable。
- **为什么能过 ASLR** —— 两次越界读分别给出两个基址；阶段之间用纯 HTTP abort/fork 换 worker，地址空间
  不变；终端阶段不依赖 libc。

完整机制、gdb 证据与请求校准见 [`docs/`](#文档)。

## 偏移与 profile

所有版本相关的值都集中在 [`exploit.py`](exploit.py) 的一张带类型的 `Profile` 表里。`zif_offset` /
`dtor_offset` 是 `libphp.so` 符号偏移，`htdata_offset` 是 Zend MM chunk 相对偏移 —— 全部相对于
模块/chunk 基址，因此**都与 ASLR 无关**。`stage*` 字段负责堆标定，随构建不同而不同。

| Profile | 目标构建 | `zif_system` | `ZVAL_PTR_DTOR` | `htdata` | stage1 / stage2 |
| --- | --- | --- | --- | --- | --- |
| **`official`**（默认） | 官方 `php:8.4`/`8.5-apache`（Debian 13） | `0x465370` | `0x65eb60` | `0x690d8` | `n=841`、`t=406`、`v=16` |
| `official83` | 官方 `php:8.3-apache`（Debian 13） | `0x3ac080` | `0x49ec50` | `0x6a0d8` | `n=841`、`t=406`、`v=16` |
| `lab` | 自编译（Apache 2.4.68，最小 PHP） | `0x43a870` | `0x613c50` | `0x6e0d8` | `n=892`、`t=443`、`v=1` |

偏移取值优先级（从高到低）：

1. **命令行** —— `--zif-offset` / `--dtor-offset` / `--htdata-offset`。
2. **偏移文件** —— `out/offsets.env`，对本机容器由 `docker/offsets.py` 写入（仅 libphp 偏移；每次本机运行都刷新，不会残留旧值）。
3. **profile 默认值** —— 上表实测值。

两个便利设计让多版本使用零配置：

- **htdata 随版本自动。** 对本机容器,exp 会读取 PHP 小版本号,在默认 profile 下对 8.3 自动采用 `official83`
  的 `htdata` —— 因此同一条命令适配 8.3 / 8.4 / 8.5,无需加任何参数。
- **每个 profile 自带 libphp 默认值。** 因此对相应构建的**远程**目标也能开箱即用,即便 `docker/offsets.py`
  无法运行（它只能访问本机容器）。

用 `--profile official83` / `--profile lab` 切换 profile；用 `--offsets-file '' --no-auto-offsets`
关闭自动读取。

## 执行任意命令

命令被嵌入一个存活的 167 字节 `zend_string`，因此硬上限是 **14 字节**。要跑更长的命令，把脚本写进挂载目录，
再用一个短的 shell 触发（`sh</out/c` 是 8 字节）：

```bash
printf 'id; uname -a > /out/p1\n' > out/c
python3 exploit.py -u http://127.0.0.1:8088/index.php -c 'sh</out/c'
```

## 命令行参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-u`, `--url` | *(必填)* | 目标 PHP 页面，如 `http://127.0.0.1:8088/index.php` |
| `-c`, `--cmd` | `id>/out/p1` | 要执行的命令（最多 14 字节） |
| `--profile` | `official` | 构建 profile：`official`（8.4/8.5）、`official83`（8.3）或 `lab` |
| `--proof-file` | `out/p1` | 利用后回读的本机文件（`''` 关闭） |
| `--fetch` | *(关闭)* | 利用后 `GET` 此路径（用于写入 web 根目录的命令） |
| `--zif-offset` / `--dtor-offset` / `--htdata-offset` | *(profile)* | 覆盖单个偏移 |
| `--offsets-file` | `out/offsets.env` | 加载的偏移文件（`''` 关闭） |
| `--docker-container` | `php2shell-target` | 本机自动读取偏移所用的容器名 |
| `--no-auto-offsets` | *(关闭)* | 不自动运行 `docker/offsets.py` |
| `--no-pre-rotate` | *(关闭)* | 跳过初始 worker 轮换 |
| `--retries` | `3` | 每个泄漏阶段的尝试次数（阶段 3 用 `retries + 2`） |
| `-q`, `--quiet` | *(关闭)* | 关闭进度输出 |

## 目标配置

靶场配置与利用链所依赖的设置一致（[`docker/php.ini`](docker/php.ini)、
[`docker/apache.conf`](docker/apache.conf)）：

| 组件 | 取值 |
| --- | --- |
| PHP | 8.4.26（NTS，mod_php） |
| 基础系统 | Debian 13 (trixie) |
| Apache MPM | prefork，**单 worker** |
| `display_errors` | `On` |
| `memory_limit` | `8M` |
| `max_input_vars` | `1000` |
| `session.use_cookies` / `use_strict_mode` | `1` / `0` |
| `session.upload_progress.enabled` | `On` |

## 仓库结构

```text
php2shell/
├── exploit.py              # 一键利用（worker 轮换 → 泄漏 → RCE）
├── docker/
│   ├── docker-compose.yml  # 官方 php:8.4.26-apache，单 worker prefork
│   ├── apache.conf         # prefork：StartServers=MaxRequestWorkers=1
│   ├── php.ini             # display_errors=On、memory_limit=8M、upload_progress
│   ├── offsets.py          # 从 libphp.so 解析 zif_system / zval_ptr_dtor
│   └── www/index.php       # 整个目标：<?php echo "OK\n"; ?>
├── out/                    # proof 文件和 out/offsets.env 落在这里
├── scripts/matrix.sh       # 跨 PHP 版本跑 exp 并报告可靠性
└── docs/                   # 机制分析与 gdb 证据
```

## 文档

| 文档 | 主题 |
| --- | --- |
| [docs/HTTP_HEAP_LEAK.md](docs/HTTP_HEAP_LEAK.md) | 阶段 1 堆泄漏、请求校准 |
| [docs/ASLR_PURE_HTTP.md](docs/ASLR_PURE_HTTP.md) | libphp 泄漏与完整 ASLR 绕过链 |
| [docs/DISPLAY_ERRORS_OFF.md](docs/DISPLAY_ERRORS_OFF.md) | 不依赖 `display_errors` 的泄漏路径 |
| [docs/NOTES.md](docs/NOTES.md) | 根因与 php-src 源码位置 |
| [docs/NOASLR_REPORT.md](docs/NOASLR_REPORT.md) | 早期 `arData` UAF RCE（机制参考） |

## 边界与限制

- 当前 RCE 要求 `display_errors=1`、`memory_limit=8M`、`max_input_vars=1000`、
  `session.use_cookies=1`、`session.use_strict_mode=0`、单 worker prefork。
- 稳定 RCE 已在 PHP **8.3 / 8.4 / 8.5**（官方 `-apache` 镜像，`linux/amd64`）上验证。同一小版本的其他点版本
  预期同样可用（libphp 偏移自动读取），但未逐一测试。
- **PHP 8.1 / 8.2 不受此链影响。** 在 `php:8.1-apache`、`php:8.2-apache` 上,阶段 1 的 `Set-Cookie` 越界读
  始终不触发 —— 无论伪造 `zend_string` 字段取多大（已扫 55–167 B）,`B` 都只返回一个干净的 32 字节会话 id,
  因此拿不到任何泄漏,在阶段 2 之前就停止。该原语在 PHP **8.3 – 8.5**（已实测）上有效,分界点在 8.3;8.1/8.2
  需要另一套阶段 1 原语（若这些版本上存在的话）。
- `display_errors=0` 下纯 HTTP 堆泄漏可行，但该配置的完整 RCE 未包含在此
  （见 [docs/DISPLAY_ERRORS_OFF.md](docs/DISPLAY_ERRORS_OFF.md)）。
- 偏移为 x86-64；不同架构或重新编译的 `libphp.so` 会使其漂移（用 `docker/offsets.py` 或 `--*-offset`）。

## 致谢

原始漏洞研究与 PoC 由 [**@9bie**](https://github.com/9bie/php2shell-bypass-aslr-exp) 完成。本仓库在自带
Docker 靶场中复现该工作，把各 profile 的偏移重构进一张带类型的表，将利用链扩展到 PHP **8.3 / 8.4 / 8.5**
的稳定 RCE，加入运行时偏移自动读取与随版本自动选择 `htdata`，并修复了 `out/` 的权限处理，使官方镜像流程可以从
冷启动干净地自标定。

## 许可证

基于 [MIT 许可证](LICENSE) 发布，仅供授权的安全研究与教育用途。
