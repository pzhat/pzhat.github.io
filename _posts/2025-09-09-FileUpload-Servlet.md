---
title: Java Servlet FileUpload Vulnerability
categories: [pentesting, Web-Exploitation]
tags: [Web]
---

# Java Servlet FileUpload Vulnerability by @Phatmh

### Lỗ hổng File Upload

Bản chất của File Upload: File Upload đối với tôi nó đơn giản chỉ là lợi
dụng Unsafe Method để truyền một Untrusted Data vào nhằm thay đổi hành
vi của hệ thống trong trường hợp này là Web App, với FileUpload những gì
User Upload lên sẽ chính là Untrusted Data và với Feature Upload File
như này sẽ thế nào nếu nó không được Validate một cách cẩn thận ta sẽ
đến với DEMO bằng Java Servlet.

### Web App Overview

Đây là một Web App được dựng với mục đích như một môi trường test các
case phổ biến về lỗ hổng FileUpload. Feature chính của nó bao gồm:

<ol>
  <li>Upload File</li>
  <li>View File</li>
  <li>Delete File</li>
</ol>

![image](https://hackmd.io/_uploads/rJPNUzWwxx.png) 

Hình ảnh overview
của trang web. Và ở đây mình code theo từng level, mỗi level tương ứng
với mỗi cơ chế validate khác nhau và ở đây ta sẽ phải tìm các Bypass và
đi đên RCE. 

![image](https://hackmd.io/_uploads/rJQiLfbPll.png)

### Đi vào phân tích code

![image](https://hackmd.io/_uploads/BJVQ5Mbvxg.png) 

Ở đây mình dùng
`@WebServlet` để ánh xạ path của web chứa chức năng file upload đến
index.jsp vì ở đây mình làm trang web chứa nhiều lỗ hổng nên việc chia
ra từng alias là một ứng dụng rất cần thiết. Rồi đến với đoạn code đầu
tiên của class thì ta có đoạn `getUploadPath` đoạn này để define thư mục
mà mình sẽ Upload File lên cụ thể ở đây các file sẽ nằm ở `/upload`.

![image](https://hackmd.io/_uploads/SyKPiG-Ple.png) 

Đoạn code doGet()
trong Servlet này dùng để xử lý các request HTTP GET gửi tới endpoint
hello-file-upload. Đây là phần quan trọng của chức năng quản lý file
upload, bao gồm cả việc tạo thư mục upload nếu chưa có và xoá file nếu
có yêu cầu.

    response.setContentType("text/html");
    PrintWriter out = response.getWriter();

-   Dòng này thiết lập định dạng của response là text/html, tức là nội
    dung trả về là HTML.
-   PrintWriter out cho phép bạn ghi dữ liệu HTML vào response để hiển
    thị trên trình duyệt.

```java
    if (!uploadDir.exists()) uploadDir.mkdir();

-   Kiểm tra nếu thư mục upload chưa tồn tại thì tạo thư mục mới.

```java
    String deleteFile = request.getParameter("delete");

-   Lấy giá trị của query parameter delete từ URL.
```

```java
    if (deleteFile != null) {
        File fileToDelete = new File(uploadPath, deleteFile);
        if (fileToDelete.exists()) {
            fileToDelete.delete();
            response.sendRedirect("hello-file-upload");
            return;
        } else {
            out.println("<p style='color:red;'>File not found.</p>");
        }
    }

-   Xoá file nếu tồn tại.
-   ![image](https://hackmd.io/_uploads/ryCj6z-Pex.png) Đoạn HTML để
    render ra được các chức năng.

![image](https://hackmd.io/_uploads/Sk6gAMbPxl.png) Hiển thị tất cả file
trong thư mục upload dưới dạng danh sách HTML. Mỗi file có 2 tùy chọn: -
View: mở file trong tab mới. - Delete: gửi request để xóa file.

    File[] files = uploadDir.listFiles();

-   Lấy toàn bộ file trong thư mục upload (đã được tạo và gán ở phần
    trước).
```

```java
    if (files != null && files.length > 0) {
        out.println("<ul>");
        for (File f : files) {
            String fname = f.getName();

-   Nếu thư mục không rỗng, duyệt từng file để in ra dưới dạng danh sách
    `(<ul> và <li>)`

```

```java
    out.println("<li>" + fname +
        " [<a href='" + request.getContextPath() + "/upload/" + fname + "' target='_blank'>View</a>] " +
        "[<a href='?delete=" + fname + "' onclick='return confirm(\"Delete " + fname + "?\")'>Delete</a>]</li>");

-   Tạo link View và Delete.

```

```java
    } else {
        out.println("No uploaded files.");
    }

-   Nếu thư mục rỗng (không có file), in ra thông báo "No uploaded
    files."

![image](https://hackmd.io/_uploads/S1zhNmbDel.png)

    String uploadPath = getUploadPath(request);
    File uploadDir = new File(uploadPath);
    if (!uploadDir.exists()) uploadDir.mkdir();

-   Tạo thư mục upload nếu chưa có
-   getUploadPath(request) trả về đường dẫn thư mục upload trên server.
-   File uploadDir = new File(uploadPath) tạo đối tượng File để thao
    tác.
-   mkdir() tạo thư mục nếu chưa tồn tại.
```

```java
    String selectedCase = request.getParameter("case");

-   Lấy giá trị của tham số case trong form upload.

```

```java
    Part filePart = request.getPart("file");

-   filePart là đối tượng chứa toàn bộ dữ liệu file được upload.
-   request.getPart("file") dựa vào tên input trong HTML form:
```

```java
    String filename = filePart.getSubmittedFileName();

-   Lấy tên file gốc.

```

```java
    InputStream fileContent = filePart.getInputStream();
```
-   Lấy nội dung của File.

### Đi vào phân tích các case lỗi

#### Case1 : FileUpload Without Validation

![image](https://hackmd.io/_uploads/HkoT87bPgg.png) 

Với case đầu tiên
thì nó chỉ đơn giản là một chức năng Upload File nhưng không hề có một
lớp phòng thủ nào vì thế attacker sẽ có thể dễ dàng thực hiện Upload một
file thực thi nguy hiểm để RCE được WebApp.
![image](https://hackmd.io/_uploads/SJKdvQWPxg.png) 
Chọn Lv1 là no
filter. 

![image](https://hackmd.io/_uploads/SkSqvXbwgx.png) 

Thử Upload
lên một file `.txt` 

![image](https://hackmd.io/_uploads/HJX2vQ-Peg.png)

Test thử chức năng view file, có thể thấy rằng các file được upload lên
sẽ nằm ở thư mục`/upload`. Với case này thì rõ ràng là nó không hề có
một lớp filter nào vậy nên việc Upload Shell sẽ khá là đơn giản.

![image](https://hackmd.io/_uploads/BJoI_7bPll.png) 

Viết một File
shell.jsp với nội dung như trên.

![image](https://hackmd.io/_uploads/SJX9_Q-Dgx.png) 

Tiến hành Upload
shell.jsp lên và nó sẽ nằm ở thư mục `/upload`.

`http://localhost:1337/vulnerability_web_war_exploded/upload/shell.jsp?cmd=whoami`

Tiến hành truyền câu lệnh vào query `?cmd` ở đây tôi dùng `whoami` và đã
thành công thực thi câu lệnh RCE

![image](https://hackmd.io/_uploads/HyWQKmWPlx.png)

#### Case 2 : First Dot Split

![image](https://hackmd.io/_uploads/SkOOKQWPge.png)

    String[] parts = filename.split("\\.");

Tách tên file bằng dấu ".". Ví dụ: - "webshell.jsp" → \["webshell",
"jsp"\] - "webshell.jsp.jpg" → \["webshell", "jsp", "jpg"\] -
split("\\.") dùng \\. vì . là ký tự đặc biệt trong regex.

    String ext2 = parts.length > 1 ? parts[1].toLowerCase() : "";

-   Lấy phần mở rộng thứ 2, tức là index 1 Và lỗi đã xảy ra ở đây, lớp
    filter này chỉ có thể hoạt động trong trường hợp file mình upload
    lên chỉ có 1 dấu `.` trong trường hợp này ta hoàn toàn có thể dễ
    dàng Bypass bằng cách lợi dụng hành vi chỉ nhận dấu chấm đầu tiên
    bằng cách tạo 1 file có tên `shell.jpg.jsp` thì ở đây sau dấu chấm
    đầu tiên nó sẽ nhận định đây là file jpg nên sẽ đi qua lớp filter dễ
    dàng. ![image](https://hackmd.io/_uploads/SJFRAXbwgg.png) Chọn case
    2 và Upload thử file shell.jsp và đã bị dính filter.
    ![image](https://hackmd.io/_uploads/S17My4WPlx.png) Thay đổi tên
    file bằng cách thêm 1 extension là `.jpg` phía trước là file đã
    thành `shell.jpg.jsp` và response trả về là 302 chứng tỏ file đã
    được upload thành công.
    ![image](https://hackmd.io/_uploads/HyeDkNZDgg.png) File shell thực
    thi đã xuất hiện trong /upload.
    ![image](https://hackmd.io/_uploads/ry0q1NWweg.png) Thành công RCE
    với câu lệnh whoami trả về kết quả như trên.

#### Case 3 : Last Dot Check

![image](https://hackmd.io/_uploads/BkYGlEZDll.png) 

Chọn case 3, lúc này
file shell trước đã được xóa để tránh nhầm lẫn.

![image](https://hackmd.io/_uploads/SJerxVZDxx.png)

    String ext3 = filename.substring(filename.lastIndexOf('.') + 1).toLowerCase();

-   lastIndexOf('.'): tìm vị trí dấu chấm cuối cùng trong tên file.
-   substring(...): lấy tất cả ký tự sau dấu chấm đó → chính là đuôi
    file thực tế.
-   toLowerCase(): chuẩn hóa chữ thường để không bị bypass bởi JSP. Tại
    đây có thể thấy rằng lớp filter đã khá là cứng rồi vì nó sẽ check ở
    dấu chấm cuối cùng cho nên nếu ta test theo các case trước sẽ không
    còn tác dụng nữa. Vậy mindset ở đây là liệu ngoài jsp ra thì mặc
    định nó còn thực thi file nào khác nữa không? Sau một lúc tìm hiểu
    thì ta có thể Bypass được bằng file `jspx` vì lớp filter chỉ bắt mỗi
    `jsp`. 
    
    ![image](https://hackmd.io/_uploads/Bkt7NEWvxl.png) 
    
    Thành
    công đi qua lớp filter này bằng cách lợi dụng sự bất cẩn của dev ghi
    chặn nhưng không hết các đuôi file có thể thực thi. Ở đây sau khi
    tìm hiểu thì tomcat sẽ hiểu định dạng `jspx` là jsp xml vậy nên ta
    cần sửa lại một chút trong file shell.jspx

    ![image](https://hackmd.io/_uploads/B1jdH4-wle.png)

    ![image](https://hackmd.io/_uploads/SJLsSNWvgl.png) 
    
    Thành công RCE
    được. 
    
    ![image](https://hackmd.io/_uploads/HyzvmLEWDll.png)

#### Case 4 : JSP Block Only

![image](https://hackmd.io/_uploads/BJA6L4Wwee.png) 

Đến với case này thì
nó vẫn là kiểm tra chỉ cần có tồn tại jsp ở cuối filename là sẽ dính
filter nhưng mà cũng như ở case 3 ta có thể tìm kiếm file khác ngoài jsp
có thể thực thi như `jspx` đã được test ở bên trên. Tính ra case 3 ở đây
khá giống case 4 nhưng nếu như nó chặn hẳn jsp và jspx thì vẫn sẽ có
cách Bypass nhưng với điều kiện là tùy vào config của Web App, với tùy
trường hợp config ta có thể sử dụng. Nhưng ở đây có một case dễ khả thi
là sử dụng dấu `.` lợi dụng config up một file `shell.jsp.` lên, dựa
theo tìm hiểu về config của tomcat thì nó vẫn sẽ nhận là file jsp nếu
không được config cẩn thận thì có thể lợi dụng nó.

![image](https://hackmd.io/_uploads/rkWvcEZwll.png) 

Test thử
`shell.jsp.` và thành công upload lên.

![image](https://hackmd.io/_uploads/BklFcVWwgx.png) 

Trong danh sách đã
hiển thị các thư mục được upload và có file shell nằm trong đó.

![image](https://hackmd.io/_uploads/BklhqNbvgl.png) 

Thành công lợi dụng
config để upload RCE.

#### Case 5 : Content-Type Filter

![image](https://hackmd.io/_uploads/H1MBiVZDxg.png) 

Ở đây server chỉ
kiểm tra Content-Type trong phần header của file upload, chứ không kiểm
tra extension hoặc nội dung thực tế của file vậy nên có thể Bypass dễ
dàng bằng cách khiến nó hiểu rằng File thực thi là một File hoặc bất kì
file nào mà nó allow.

![image](https://hackmd.io/_uploads/HkmCiNbwlg.png) 

Mod lại content type
thành `image/png` 

![image](https://hackmd.io/_uploads/HkCx34Zwgx.png)

Thành công bypass qua lớp filter bằng cách lừa đây là một file image.

![image](https://hackmd.io/_uploads/B1u72V-Pgg.png) 

File shell.jsp đã có
giờ ta chỉ cần RCE như các case trên.

#### Case 6 : Magic Bytes Check

![image](https://hackmd.io/_uploads/HJy4T4bDgl.png) 

- 89504E47 là magic
bytes chuẩn của file PNG (`\x`{=tex}89PNG) - Đoạn code này sẽ check 4
bytes đầu để kiểm tra file được đưa lên có phải là file PNG không nếu
không thì sẽ bị chặn. Nhưng ở đây cho dù check được vào trong magic byte
nhưng vẫn chưa đủ để validate hết vì ta hoàn toàn có thể trick được hệ
thống bằng cách bỏ thêm đoạn `\x89PNG` vào trước các dòng payload để khi
nó đọc sẽ nhận định đây chính là file PNG vì nó chỉ nhận 4 bytes đầu.

![image](https://hackmd.io/_uploads/SyYEyrZwgl.png) 

Tạo một file
shell.jsp bằng linux.

![image](https://hackmd.io/_uploads/SyAu1rbPgg.png) 

Tạo một file
fake.jsp đưa magic byte vào đó để nó sẽ nhận là image sau đó ghép với
file shell.jsp bây giờ nội dung shell.jsp sẽ được đưa vào fake.jsp mà
magic byte của fake.jsp được giữ nguyên.

![image](https://hackmd.io/_uploads/S1lbgS-vxl.png) 

Kiểm tra lại nội
dung fake.jsp. 

![image](https://hackmd.io/_uploads/ByJwlSbwxg.png) 

Tiến
hành upload và upload thành công.

![image](https://hackmd.io/_uploads/B1RuxHZveg.png)

![image](https://hackmd.io/_uploads/SkkoxSbDge.png) 

Thành công RCE.

#### Case 7 : Path Traversal + FileUpload To RCE

![image](https://hackmd.io/_uploads/r1YKWB-Dle.png) 

Ở case này thì cũng
không có filter vì ở đây mình muốn mô phỏng tình huống là tại thư mục
upload nó sẽ được config là không cho phép run bất kì file thực thi nào,
vậy nếu rơi vào trường hợp đó thì có cách Path Traversal là có thể lợi
dụng được vì ta có thể thử với thư mục khác liệu thư mục đó có thực thi
được các file thực thi hay không.

![image](https://hackmd.io/_uploads/S1c7GHbvxe.png) 

Tiến hành upload thử
`../shell.jsp` và có thể thấy file đã được upload lên nhưng liệu nó có
đi ra khỏi thư mục /upload không.

![image](https://hackmd.io/_uploads/By7PfBZwlg.png) 

Check ở bên trong
cấu trúc thư mục thì có thể thấy rằng file shell.jsp đã thoát ra khỏi
thư mục upload. 

![image](https://hackmd.io/_uploads/S1xcMBZDel.png) 

 Kiểm
tra trong này thì nó kêu chưa có thư mục được upload và củng cố được
rằng file shell đã được upload ra ngoài thư mục cha. Bây giờ chỉ cần
truy cập đến và tiến hành RCE thôi.

#### Cơm thêm

Có vẻ như lỗi FileUpload ta còn có thể khai thác thêm một lỗi nữa là
Store XSS vì ở các Level có lớp filter check extension có vẻ như nó
không hề chặn file `.html`. Trình duyệt thực thi được script trong file
.html sau khi upload là vì server không cài đặt Content-Disposition:
attachment, và MIME type của file là text/html, nên trình duyệt xử lý
file như một trang web. Đầu tiên tạo một file xss.html với nội dung:

``` html
<script>
    alert(1);
</script>
```

Tiến hành Upload thử file lên.
![image](https://hackmd.io/_uploads/rkw4jWzPel.png)

![image](https://hackmd.io/_uploads/ry8Bibfvge.png) 

Thành công Upload
File `xss.html` lên bây giờ nếu ta là user bình thường bấm thử view thì
nó sẽ trả về như thế nào.

![image](https://hackmd.io/_uploads/BymFs-GDgg.png) 

Có thể thấy xss đã
được thực thi tại trường hợp này thì file đã được lưu và nếu user click
vào xem nó sẽ thực thi XSS và nó là store XSS, ở đây web này tôi không
khởi tạo session id nên không thể DEMO được XSS để lấy cắp cookie bằng
fetch và Webhook được.
