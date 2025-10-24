---
title: TryHackme Pickle Rick Challenge WriteUp by Phatmh.
categories: [pentesting, RedTeam]
tags: [RedTeam, Pentest]
---

# TryHackme Pickle Rick Challenge WriteUp by Phatmh.
![image](https://hackmd.io/_uploads/HyFRp7ONel.png)
[link challenge]:https://tryhackme.com/room/picklerick
![image](https://hackmd.io/_uploads/SJcZC7_4ll.png)
Tiến hành dùng Openvpn kết nối với ***Tryhackme.***
![image](https://hackmd.io/_uploads/BkYLRXOEex.png)
Tiến hành kiểm tra mình đã cùng mạng mới máy bên Tryhackme hay chưa.![image](https://hackmd.io/_uploads/rk9dCQ_Nlx.png)
Câu hỏi và Ip của challenge nãy đã test và kết nối thành công.

### Bước 1: Recon

![image](https://hackmd.io/_uploads/SkoGJEuVlg.png)
Sử dụng Nmap để tiến hành kiểm tra xem có port nào đang được mở ra, ở đây phát hiện ra được bên máy đang mở port 22/tcp và port 88/tcp ở đây tôi nghĩ là server nạn nhân đang chạy ***SSH và HTTP***.

Tương tự tôi thực hiện scan UDP nhưng no response vậy nên có thể cho rằng là UDP không có port nào có thể khai thác hiện tại.

Cuối cùng là tiến hành ***Scan Services.***
![image](https://hackmd.io/_uploads/S1AvzVuNge.png)

![image](https://hackmd.io/_uploads/HkDIQ4uElg.png)
Kết quả cho ra Services của 2 cổng trên.

### Bước 2: Tiến hành tấn công xâm nhập
![image](https://hackmd.io/_uploads/Sk2J44ONlg.png)
Thử SSH đến admin nhưng có vẻ dù bấm loạn xạ như nào vẫn không thể kết nối SSH được đến.
Nếu SSH không đến bằng tài khoản admin default thì phải đọc về lỗi có sẵn của service OpenSSH mà server đang chạy nhưng khoan đã thử vào đó mình sẽ thử sang port 80 là HTTP để xem có gì trong đó.

![image](https://hackmd.io/_uploads/rklfHEuEgl.png)
Truy cập theo địa chỉ thì ra một Web bây giờ tiến hành thử ***View Page Source*** coi có đào thêm được gì không.
![image](https://hackmd.io/_uploads/S1oLB4uVll.png)
Có vẻ đi theo đường Port 80 sẽ hiệu quả vì khi View Source ta đã tìm thấy được UserName mà challenge giấu nằm ở đây.

Vậy liệu ngoài trong Source thì nó sẽ giấu một cái gì đó chẳng hạn như Password ở đâu, để tìm ra nó ta sẽ thử tiến hành Recon trang web này cụ thể là Scan Directory bằng công cụ ***GoBuster***.

![image](https://hackmd.io/_uploads/HJOeRVuNlg.png)
Sử dụng wordlist bé vì dùng wordlist lớn khá mất thời gian kết quả trả về cho chúng ta response 200 ở 3 directories.

![image](https://hackmd.io/_uploads/HkzDAN_Vxe.png)
Truy cập vào robots.txt nó trả về 1 dòng (Wubbalubbadubdub) có thể đây là mật khẩu vậy nên ta sẽ thử với tên đăng nhập mà đã tìm được từ trước.

![image](https://hackmd.io/_uploads/SklACEuVgx.png)
Truy cập vào login.php và tiến hành nhập.

![image](https://hackmd.io/_uploads/rJgg1rONge.png)
Truy cập trái phép thành công tài khoản.

Tiến hành xài tunnels để kết nối và viết shell bash vì khi thực thi các lệnh cat có vẻ bị chặn ở website.

![image](https://hackmd.io/_uploads/rJT_MrO4ex.png)
![image](https://hackmd.io/_uploads/ryqlNHO4gl.png)
Dùng python chạy shell nối tunnel với nhau.
![image](https://hackmd.io/_uploads/ryE-NSd4el.png)
Kết nối thành công với bên server.
![image](https://hackmd.io/_uploads/HJB7Nr_Ell.png)
Thành công tìm đáp án câu 1 từ đây ta hoàn toàn có thể tiếp tục tìm nốt đáp án cho câu sau.
Cảm ơn vì đã đọc.

