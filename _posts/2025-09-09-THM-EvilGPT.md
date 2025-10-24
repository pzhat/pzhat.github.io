---
title: Tryhackme EvilGPT challenge WriteUp by @phatmh
categories: [pentesting, RedTeam]
tags: [RedTeam, Pentest]
---

# Tryhackme EvilGPT challenge WriteUp by @phatmh

![image](https://hackmd.io/_uploads/SJs0f-gLgl.png)
![image](https://hackmd.io/_uploads/BJbzEWeIle.png)
Dùng netcat để tiến hành kết nối với chall và tiến hành LLM Inject để có thể moi được flag từ con AI.
![image](https://hackmd.io/_uploads/By7uHZgLxl.png)
Sau khi test thử thì đây không phải con AI bình thường như tôi nghĩ mà nó là một con AI thực thi các câu lệnh OS vậy bây giờ tiến hành thử moi ra các thứ có trong server.
![image](https://hackmd.io/_uploads/SkQHvWeUxg.png)
Tiến hành đọc thử source code của con AI xem nó có những cái gì.
### Tóm tắt chức năng
Tập tin Python evilai.py là một server Telnet đơn giản. Khi người dùng kết nối, nó:

Nhận yêu cầu từ người dùng bằng ngôn ngữ tự nhiên.

Dùng AI model (ollama) để chuyển đổi yêu cầu đó thành lệnh Linux.

Hỏi người dùng có muốn thực thi không.

Nếu đồng ý, thực thi lệnh bằng subprocess.run() và gửi kết quả về.

### Phân tích chức năng chính
AICommandExecutorServer class

__init__(): Khởi tạo server trên host, port, và chỉ định mô hình Ollama.

sanitize_input(): Làm sạch lệnh khỏi các ký tự nguy hiểm, tuy nhiên còn khá sơ sài và dễ bypass.

generate_command():

Gửi user_request (ngôn ngữ tự nhiên) đến mô hình ollama để lấy lệnh shell.

Chỉ yêu cầu mô hình trả về lệnh, không giải thích.

execute_command(): Thực thi lệnh đã sinh ra với:

subprocess.run(cmd_parts, capture_output=True, timeout=30)

Trả lại stdout, stderr, returncode

handle_client():

Gửi prompt → nhận input → gửi lệnh sinh ra → hỏi xác nhận → thực thi → gửi kết quả.

start_server(): Lắng nghe và tạo thread xử lý mỗi client.

Sau khi check thì có vẻ như ta hoàn toàn có thể bypass được con AI này vì nó cũng không có santilize một chút nào ở câu lệnh nên tôi sẽ thử hỏi thông tin về root folder.
![image](https://hackmd.io/_uploads/rkGg9-x8ee.png)
Sau khi truyền vào tôi tìm thấy một file có lẽ là file flag nằm ở thư mục root.
![image](https://hackmd.io/_uploads/rJ0G9ZlUel.png)
Bây giờ tiến hành hỏi nó làm sao để nó show flag ra cho mình đọc được.
![image](https://hackmd.io/_uploads/HJtjcWeLxx.png)
Sau một lúc hỏi thì đã hỏi ra được và thành công lấy được flag.
