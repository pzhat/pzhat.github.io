---
title: Web Cache Deception Demo Lab
categories: [pentesting, Web-Exploitation]
tags: [Web]
---

# Web Cache Deception Demo Lab

### Tổng quan Web Cache Deception 

*Lỗ hổng "web cache deception" (đánh lừa bộ nhớ đệm web) là một dạng lỗ hổng bảo mật web, cho phép kẻ tấn công lừa hệ thống cache (bộ nhớ đệm web) lưu trữ và phục vụ lại những nội dung nhạy cảm hoặc riêng tư cho các bên không được ủy quyền. Đây là một hình thức khai thác sự khác biệt trong cách các server cache và server gốc xử lý các request—đặc biệt là về quy tắc lưu cache cho các tài nguyên động (như trang tài khoản người dùng, trang admin, v.v.).*

**Cách hoạt động của Web Cache Deception:**

- Hệ thống cache thường chỉ lưu trữ các tài nguyên tĩnh (file .css, .js, hình ảnh, v.v.) nhằm tăng tốc độ truy cập và giảm tải cho server.
- Với web cache deception, kẻ tấn công có thể gửi request với các phần mở rộng tên file (vd: /profile.js) hoặc thêm tham số giả mạo tới các URL vốn dĩ là nội dung động (ví dụ trang profile người dùng) có thể nói đây là fall back routing.
- Nếu ứng dụng web hoặc cache server xử lý sai, nó sẽ trả về nội dung động (ví dụ thông tin tài khoản) nhưng lưu nhầm vào cache. Những người dùng khác khi truy cập tới URL đó sẽ thấy được nội dung nhạy cảm đã bị cache, dù không có quyền truy cập.

### Source code

[Github](https://github.com/pzhat/WebCacheDeception)

### Phân tích và POC

![image](https://hackmd.io/_uploads/HkQdbVHpex.png)

Ở đây chỉ là demo cho lỗ hổng deception nên ta chỉ làm một cái func đăng nhập đơn giản sau đó dùng file static là `/account.css` để lấy được thông tin của user qua đó.

Đầu tiên ta sẽ đăng nhập với user là alice trước.

![image](https://hackmd.io/_uploads/H1W5QNrTxl.png)

Sau khi đăng nhập thì ta có session token của user vừa đăng nhập ở đây là alice `6324a18d`.

Tới bước này thì có thể thấy user alice đã được đăng nhập, bước tiếp theo nếu là trong thực tế thì attacker sẽ làm sao để cho user bấm vào đường dẫn để dẫn đến static file nhằm đánh lừa web cache.

![image](https://hackmd.io/_uploads/S1meSEBaxx.png)

Với session của alice ta tiến hành truy cập `/account.css` ở đây ta có thể thấy rằng trường `X-Cache-Status` trả về giá trị là `MISS`.

Với trường cache như vậy thì bước đầu ta đã thành công trong việc đánh lừa web cache server bây giờ ta sẽ thử với trình duyệt khác không có session thử truy cập đến `/account.css` xem nó sẽ có gì.

![image](https://hackmd.io/_uploads/SkZDkSBaex.png)

Ta sẽ tạo một tab mới và để chắc chắn thì mình sẽ xoá session đi cho chắc.

![image](https://hackmd.io/_uploads/B1EjyBSagl.png)

![image](https://hackmd.io/_uploads/H1VhJHrpgg.png)

Truy cập vào `/account.css` ở đây ta có thể thấy rằng web cache deception đã thành công vì ở đây ta đã lấy ra được CSRF token của user alice ra sau khi user đó truy cập đến file static thì phần config lỗi của web cache đã lưu lại session của alice và từ đó tạo cơ hội cho attacker truy cập lại vào đó và lấy cắp thông tin user.

```config 
location ~* \.(?:css|js|png|jpg|gif|ico)$ {
      proxy_pass http://app:8080;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-For $remote_addr;

      add_header Cache-Control "public, max-age=600" always;
      add_header X-Cache-Status $upstream_cache_status always;
      add_header X-Cache-Key $scheme$host$request_uri always;

      proxy_cache mycache;
      proxy_cache_key $scheme$host$request_uri;
      proxy_cache_valid 200 10m;

      proxy_no_cache off;
      proxy_cache_bypass 0;
```

Đoạn config gây ra lỗi nó nằm ở đây ở đây nginx được config để cache tất cả các đuôi tĩnh và điều đó dẫn đến khi người dùng truy cập đến file có đuôi tĩnh thì nó gây hiểu lầm cho server từ đó gây nên web cache deception.

```config 
 location ^~ /assets/ {
      try_files $uri =404;
      add_header Cache-Control "public, max-age=31536000, immutable";
    }

    # Không cache đường dẫn khác
    location / {
      proxy_pass http://app:8080;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-For $remote_addr;
    }
```

Ở đây là cách fix đúng ta sẽ chỉ cache cho mỗi allow list và không cache các đường dẫn khác ngoài nó bên cạnh đó không cache những file tĩnh không tồn tại nếu người dùng trỏ đến thì nên trả hẳn về 403 401 luôn để tránh lỗ hổng này.

