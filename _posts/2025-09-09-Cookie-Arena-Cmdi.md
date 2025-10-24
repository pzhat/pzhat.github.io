---
title: "Cookie Arena Challenges WU (@Phatmh)"
categories: [pentesting, Web-Exploitation, CTF]
tags: [CTF, Web]
---

# Cookie Arena Web Challenges WriteUp by (@Phatmh)

### NSLookup (Level 1)
Đây là một Website có chức năng là nslookup sử dụng hàm shell_exec của php để thực thi. Ta tiến hành truy cập để xem giao diện của web app.  
![image](https://hackmd.io/_uploads/SJGVV2iSgg.png)  
Ở đây ta thấy nó khá là basic khi chỉ có duy nhất một nơi có chức năng nslookup và bên cạnh là source code cho sẵn của chall, ta sẽ tiến hành phân tích source code được cấp sẵn.  
![image](https://hackmd.io/_uploads/H1wz8niHel.png)

Ở ngay đầu tiên ta gặp khởi tạo và include file design và tạo object `($design)` có tên là NSLookup Tool. Đến với những dòng tiếp theo là những thứ cần phải phân tích vì đây là đoạn logic code. Tại đây nó sẽ lấy tham số **domain** thông qua biến toàn cục là `($_GET)` sau đó sẽ in ra kết quả `($result)` sau khi mà đã thực hiện xong đoạn nslookup sử dụng hàm shell_exec. Ở đây có thể thấy rõ ràng cái sink nó sẽ nằm ở ngay đoạn chúng ta truyền vào domain hay ở đây là Untrusted Data, khi ta truyền Untrusted Data thì ở đây hàm `shell_exec` sẽ thực hiện lệnh nslookup với giá trị ta truyền vào. Từ đây ta có thể đưa ra giả thuyết rằng ứng dụng này hoàn toàn có thể bị khai thác command injection vì có thể thấy rằng không có một biện pháp validate nào được sử dụng ở đây.  
![image](https://hackmd.io/_uploads/HJYweTjreg.png)

Tiến hành sử dụng chức năng của web app ở đây ta sẽ thử lookup đến google để xem kết quả nó trả về sẽ thế nào.  
![image](https://hackmd.io/_uploads/SJdcgaiHee.png)  
Ở đây nó cho ra kết quả của là dns của 8.8.8.8 là google.com. Bây giờ ta sẽ tận dụng lỗ hổng trong logic code bằng cách sử dụng dấu `;` để thực hiện nối dài câu lệnh rồi thêm một lệnh nào đó ở đây tôi dùng `ls` để xem nó trả về kết quả gì.  
![image](https://hackmd.io/_uploads/HJaGWpsSge.png)  
Và ta đã thành công tận dụng lỗi command injection bằng cách sử dụng dấu `;` để nối chuỗi.  
![image](https://hackmd.io/_uploads/rk8IWasHex.png)  
Thành công đọc được flag bằng lệnh `cat /*.txt`.

---

### NSLookup (Level 2)
Ở lv2 thì cấu trúc nó vẫn sẽ giống như lv1 trên nhưng bây giờ cấu trúc logic code đã khác đi một chút.  
![image](https://hackmd.io/_uploads/HJini0nBlg.png)

Bây giờ giá trị domain đã được kẹp bên trong `''` để chắc chắn giá trị domain là một chuỗi và điều này cũng đã chặn đi các cách tấn công cmdi thông thường, vậy liệu ta có tận dụng được cái dấu `''` để nối dài chuỗi cmd để thực hiện RCE không. Câu trả lời là có, ta sẽ sử dụng thêm dấu `''` để thực hiện break và nối dài nó ra.  
![image](https://hackmd.io/_uploads/Hkrth03Heg.png)

Tấn công kiểu payload thông thường không còn áp dụng được.  
Tiến hành sử dụng payload khác ở đây tôi sử dụng `8.8.8.8';ls;#` để thử tấn công vì dấu `'` sẽ đóng đi phần domain sau đó dùng `;` để nối dài cmd và dùng `#` để loại bỏ phần sau.  
![image](https://hackmd.io/_uploads/SJZmRC2Bgl.png)  
Và có vẻ như nó đã work vì nó đã hiển thị các thư mục bằng lệnh `ls`. Bây giờ chỉ việc `cat` flag.  
![image](https://hackmd.io/_uploads/By2FAR2Sle.png)  
Thành công `cat` ra được flag.

---

### NSLookup (Level 3)
![image](https://hackmd.io/_uploads/B17u2JpHle.png)

Ở lv cuối của challenge này có vẻ như bây giờ nó đã khác đi không còn hiện sẵn source và chỉ cho ta cái hint là: Tất cả các lệnh đọc file 'cat', 'head', 'tail', 'less', 'strings', 'nl', "ls", "*", "curl", "wget" đều bị chặn và không tồn tại trên hệ thống. Bây giờ ta sẽ tiến hành view source để xem bên trong nó xử lý logic kiểu gì.  
![image](https://hackmd.io/_uploads/HJ0zTJTHgx.png)

Có vẻ như nó đã dùng regex để kiểm tra định dạng của domain khiến cho ta không thể dùng các cách nối dài chuỗi thông thường. Regex này chỉ cho phép domain chuẩn, không có ký tự đặc biệt như `;`, `|`, `&`, `'`, `"`... nhưng ta vẫn sẽ test thử xem nó có thực sự hoạt động không.  
![image](https://hackmd.io/_uploads/Hk7j6kTBlx.png)

Ở đây tôi tiến hành nối dài payload bằng lệnh shell là `whoami` để tránh dính filter nhưng có vẻ nối dài chuỗi cũng dính luôn phần validate. Nhưng sau khi tìm hiểu kĩ thì có vẻ phần JS dùng để validate nó chỉ hoạt động ở phía client side (browser) — vậy liệu có cách nào để tấn công theo hướng khác không? Câu trả lời là có: dùng các công cụ như `curl` hoặc **Burp**. Ở đây tôi sẽ thử dùng Burp tiến hành test thử.  
![image](https://hackmd.io/_uploads/BkyN01pBgg.png)

Và có lẽ suy nghĩ đã đúng vì nó đã trả về giá trị `www` khi thực hiện lệnh `whoami`. Vậy là trừ những lệnh đã được validate ra thì ta có thể thực hiện các lệnh khác chung chức năng. Nhưng làm sao để xác định hệ điều hành và loại shell mà server đang dùng? Ở đây tôi thử inject:
`domain='; echo $0; #`

để kiểm tra nó sẽ trả về cái gì.  
![image](https://hackmd.io/_uploads/ryOq_r6rll.png)

Ở đây nó trả về cho ta một dòng chữ `sh`, vậy là đã chắc cú là ta sẽ sử dụng `sh` để khai thác lỗi cmdi này. Ta tiến hành tấn công.  
![image](https://hackmd.io/_uploads/Sk1rKB6Hxl.png)

Ở đây tôi tiến hành sử dụng lệnh `echo *` để có thể đọc được thư mục thay vì dùng `ls` nhưng có vẻ dấu `*` cũng vẫn dính filter và khá khó để bypass. Sau đó tôi nhớ ra: server sử dụng Linux và Linux hỗ trợ cả base64 encode/decode, vậy nên tôi thử dùng base64 để encode và dùng `sh` để thực thi. Ở đây tôi sẽ sử dụng Linux trên máy để xem nó có thực sự hoạt động với base64 và `sh` không.  
![image](https://hackmd.io/_uploads/BkUNQU6Sle.png)

Ở đây tôi dùng lệnh `ls -al` để list ra các thư mục nhưng vì nó nằm trong `""` nên nó mặc định sẽ là một chuỗi; sau đó tôi đưa nó về base64 bằng `base64`—tôi có chuỗi `bHMgLWFsCg==`. Tiếp theo thử decode bằng `base64 -d` và đã decode thành công về `ls -al`; sau đó dùng pipeline để gán thêm `sh` để chạy được dòng shell đã thêm vào và đã thành công list ra được các thư mục có bên trong.  
![image](https://hackmd.io/_uploads/rkglNUpBeg.png)

Cả hai lệnh `echo "bHMgLWFsCg==" | base64 -d | sh` và `echo "ls -al" | base64 | base64 -d | sh` đều work nên tôi sẽ sử dụng cách này trong việc khai thác.  
![image](https://hackmd.io/_uploads/HyzS9BpBgl.png)

Ở đây payload của tôi là:
`';echo ZWNobyAq | base64 -d | sh ; #`
Phần dấu `'` để kết thúc chuỗi, sau đó nối dài bằng `;`, tiếp theo `echo` phần base64 nhưng chuỗi base64 đó chứa shell đã đưa vào là `echo *`; `base64 -d` giải mã về câu shell; cuối cùng `sh` sẽ thực thi nó (vì `sh` hỗ trợ thực thi chuỗi lệnh). Kết quả trả về là `index.php`. Từ đây ta có hướng đi mới là sử dụng base64 rồi inject các câu lệnh khác.  
![image](https://hackmd.io/_uploads/B1-corpBgx.png)

Ta tiến hành đọc các file chứa chữ `/flag`.  
![image](https://hackmd.io/_uploads/S13Tsrarxx.png)

Thành công tìm được 2 files — một file flag có tên giống như yêu cầu của bài, có vẻ đây là nơi cất chứa flag.  
![image](https://hackmd.io/_uploads/r1PN2H6rxg.png)

Tiến hành encode chuỗi shell (ở đây dùng `more see ` kết hợp với tên flag đã tìm ra trước đó) và inject.  
![image](https://hackmd.io/_uploads/B1Bw2HaSlx.png)

Thành công cat được flag đã được giấu.

