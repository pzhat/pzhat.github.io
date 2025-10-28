---
title: Java Servlet Path Traversal vulnerability
categories: [pentesting, Web-Exploitation]
tags: [Web]
---

# Java Servlet Path Traversal vulnerability

### Source Code:

[[Github Link](https://github.com/pzhat/Path_Traversal_Lab)]

### Overview

![image](https://hackmd.io/_uploads/SJl8JTtolx.png)

Đây là chức năng hiển thị hình ảnh của các file đã nằm trong folder `images`.

![image](https://hackmd.io/_uploads/rkGKkaYjle.png)

Ở đây ta test file `skibidi.jpg` và request nó sẽ hiển thị lên cho ta.

![image](https://hackmd.io/_uploads/ByPi1pKjgg.png)

Đây là nơi chứa các file có thể hiển thị.

Vì là build trên môi trường windows localhost qua apache tôi sẽ tạo một thư mục `/protected` có chứa file bí mật.

![image](https://hackmd.io/_uploads/S1ellTYsll.png)

### Tiến hành khai thác và POC

#### Level 1:

```java 
private void handleLevel1(String fileName, HttpServletResponse response) throws IOException {
        String fullPath = "images/" + fileName;
        InputStream in = fileModel.getFileStreamUnsafe(fullPath);

        if (in == null) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            response.getWriter().println("File not found: " + fullPath);
            return;
        }

        System.out.println("[Level 1] Requesting file: " + fullPath);
        response.setContentType(fileModel.getMimeType(fileName));

        try (OutputStream out = response.getOutputStream()) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }
```

Ở level đầu tiên sẽ không có lớp phòng thủ nào mà chỉ có chức năng hiển hị hình ảnh cơ bản lấy hình ảnh từ thư mục `/images` và đọc nó để hiển thị lên cho user.

Ở đây cách khai thác sẽ khá là đơn giản khi ta sẽ chỉ cần sử dụng relative path để có thể đưa vị trí của mình ra thư mục cha của thư mục `/images` là thư mục `webapps` sau đó trỏ đến vị trí folder bí mật là `protected`.

![image](https://hackmd.io/_uploads/SybReptiee.png)

Thành công back ra thư mục cha sau đó trỏ đến `/protected/passwd.txt`.

#### Level 2:

```java 
private void handleLevel2(String fileName, HttpServletResponse response) throws IOException {
        if (fileName.contains("..")) {
            response.getWriter().println("Hack Detected");
            return;
        }

        if (fileName.startsWith("/")) {
            fileName = fileName.substring(1);
        }
        viewFile(fileName, response);
    }
```

Đến với code logic của level 2 ta có thể thấy rằng nó đã có một lớp filter là dấu `..` nếu trong user input tồn tại dấu `..` thì ta sẽ được trả về hack detected vậy ta sẽ thử xem payload cũ xem nó trả về cái gì cho ta.

![image](https://hackmd.io/_uploads/ByYg7Eqjlg.png)

Vậy ngoài relative path ta sử dụng để thoát từ thư mục đang đứng ra thư mục cha ta còn có cách nào khác không?. Ở đây ngoài absolute path còn có một cái gọi là absolute path đó là bạn sẽ điền đúng đường dẫn và đầy đủ và đường dẫn đó sẽ được xử lý nếu webapp không được config đúng cách.

![image](https://hackmd.io/_uploads/B1ZqXVcsxe.png)

Ở đây mình gọi thẳng đến với `/protected/passwd.txt` và thành công lấy ra được thư mục bí mật giấu trong đó.

#### Level 3:

```java 
private void handleLevel3(String fileName, HttpServletResponse response) throws IOException {
        if (fileName.contains("..") || fileName.contains("/protected/")) {
            response.getWriter().println("Hack Detected");
            return;
        }

        String decodedFileName = URLDecoder.decode(fileName, "UTF-8");

        viewFile(decodedFileName, response);
    }
```

Ở level này có thể thấy logic handle đã được gán thêm 2 lớp filter đó là nó sẽ check `..` cùng với `/protected/` nếu trong user input tồn tại 2 cái này thì sẽ bị trả về `Hack Detected` vậy nên payload cơ bản ở level 1 và level 2 sẽ không còn khả thi nữa.

Ở đây ta thấy ở dòng `String decodedFileName = URLDecoder.decode(fileName, "UTF-8");` có sử dụng url decode mà trong khi đó servlet container sẽ tự decode 1 lần nếu như có sử dụng url encode vậy ở đây ta có thể lợi dụng cách này để có thể khai thác bằng cách sử dụng payload với double url encode để khi qua lớp filter nó sẽ không check được gì sau đó server sẽ decode 2 lần và ta sẽ truy cập được vào.

![image](https://hackmd.io/_uploads/r18EhVcjge.png)

Thành công khai thác path traversal bằng cách sử dụng double url encode `%252fprotected%252fpasswd.txt`.



