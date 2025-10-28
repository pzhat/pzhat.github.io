---
title: WebSec.fr level 1 CTF challenge
categories: [pentesting, Web-Exploitation, CTF]
tags: [CTF, Web]
---

# WebSec.fr level 1 CTF challenge

### Overview

![image](https://hackmd.io/_uploads/Sk1nSnX3xg.png)

Giao diện chức năng của level này ta có thể thấy nó là một web app có chức năng hiển thị username bằng cách nhập vào userID nên bước đầu ta có thể nghi ngờ nó dính Sql Injection.

### Phân tích source code

```php 
<?php
session_start ();

ini_set('display_errors', 'on');
ini_set('error_reporting', E_ALL);

include 'anti_csrf.php';

init_token ();

class LevelOne {
    public function doQuery($injection) {
        $pdo = new SQLite3('database.db', SQLITE3_OPEN_READONLY);
        
        $query = 'SELECT id,username FROM users WHERE id=' . $injection . ' LIMIT 1';
        $getUsers = $pdo->query($query);
        $users = $getUsers->fetchArray(SQLITE3_ASSOC);

        if ($users) {
            return $users;
        }

        return false;
    }
}

if (isset ($_POST['submit']) && isset ($_POST['user_id'])) {
    check_and_refresh_token();

    $lo = new LevelOne ();
    $userDetails = $lo->doQuery ($_POST['user_id']);
}
?>
```

Challenge cung cấp cho ta đoạn source code của của web app với logic được xử lý bằng php và ta có thể thấy rằng trường userID được query bằng SQLITE3.

- session_start(): Khởi tạo phiên làm việc cho người dùng.

- ini_set('display_errors', 'on'): Hiển thị lỗi PHP (hữu ích khi debug, nhưng không nên bật trong môi trường production).

- include 'anti_csrf.php': Bao gồm file chống CSRF (Cross-Site Request Forgery).

- init_token(): Khởi tạo token CSRF.

Ta để ý ở câu Sql Query:

```sql 
$query = 'SELECT id,username FROM users WHERE id=' . $injection . ' LIMIT 1';
```

Có thể thấy rằng biến `$injection` được truyền thẳng vào mà không có một bước kiểm tra hay filter nào và nó được đưa thẳng vào query từ đó mở ra khả năng Sql Injection.

### Khai thác và POC

Ta sẽ tiến hành thử inject payload `1 UNION SELECT null, sqlite_version(); -- -` xem liệu có trả về giá trị không.

![image](https://hackmd.io/_uploads/B15bFn7hgx.png)

Ở đây ta có thể thấy nhờ query `UNION` nó đã hợp 2 bảng lại vè đưa id về null còn kết quả của câu lệnh `sqlite_version();` đã được đưa vào giá trị thứ 2 và nó trả về kết quả.

Ở đây ta để ý dòng `LIMIT 1` nó sẽ khiến sql chỉ trả về dòng đầu tiên ở đây nếu nhập id bằng 1 thì nó sẽ chỉ trả dòng đầu tiên sau khi truy vấn `id =1`.

`1222 UNION SELECT username,password FROM users LIMIT 2,1 -- -` ta sẽ thử inject payload này ở đây mình sử dụng `LIMIT 2,1` với mục đích cho nó hiển thị 3 dòng và dùng id là 1222 là một id không tồn tại để nó trả về đầy đủ LIMIT 2,1 trong phần UNION SELECT sẽ ghi đè lên LIMIT 1 của truy vấn gốc, vì SQLite xử lý UNION như một tập hợp kết quả, và LIMIT áp dụng cho toàn bộ tập hợp đó.

![image](https://hackmd.io/_uploads/Sypq22m2gx.png)

Thành công lấy ra được flag.



