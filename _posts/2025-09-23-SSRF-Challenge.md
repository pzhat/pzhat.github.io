---
title: Java Code Server Side Request Forgery

---

# Java Code Server Side Request Forgery

### Source Code

[Github] https://github.com/pzhat/SSRF_vuln_demo 

### Overview 

![image](https://hackmd.io/_uploads/Sya3cd13gl.png)

Đây là lab mô phỏng lại lỗi SSRF với chức năng chính là fetch url cùng với đó là fetch file và preview lên.

### Tổng quan về lỗ hổng SSRF

SSRF (Server-Side Request Forgery) là một lỗ hổng bảo mật cho phép kẻ tấn công buộc server của một ứng dụng web phải gửi một yêu cầu mạng (request) đến một địa chỉ tùy ý do kẻ tấn công cung cấp.

Trong đoạn mã này, cốt lõi của vấn đề nằm ở chỗ:

- Ứng dụng nhận một tham số url từ người dùng.

- Ứng dụng sử dụng tham số url này để tạo một đối tượng java.net.URL.

- Server sau đó thực hiện một kết nối mạng đến URL đó mà không có bất kỳ sự kiểm tra hay ràng buộc nào.

=> Điều này cực kỳ nguy hiểm vì server thường có những đặc quyền mà người dùng bên ngoài không có, chẳng hạn như quyền truy cập vào mạng nội bộ (internal network), các dịch vụ trên localhost, hoặc các tài nguyên trên chính server.

![image](https://hackmd.io/_uploads/Hy6ypuyhxg.png)

![image](https://hackmd.io/_uploads/B1LcTdJ2xe.png)

### Phân tích chi tiết từng endpoint

1.Endpoint /ssrf/preview

Đây là endpoint nguy hiểm nhất vì nó có nhiều tính năng và cung cấp nhiều thông tin phản hồi cho attacker.

Cách hoạt động:
Nhận urlParam.

Trường hợp đặc biệt: Nếu URL có giao thức là `file (file://...)`, nó sẽ đọc nội dung của file đó trên hệ thống tập tin của server và hiển thị ra cho người dùng. Đây thực chất là một lỗ hổng `Local File Inclusion (LFI)`.

Đối với các giao thức khác (như http, https), nó thực hiện một yêu cầu HttpURLConnection, lấy nội dung phản hồi, và hiển thị nó dưới dạng ảnh (nếu là image/*) hoặc dạng văn bản.

```java
private void previewHandler(String urlParam, HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        resp.setContentType("text/html;charset=UTF-8");
        PrintWriter out = resp.getWriter();

        // Header HTML + CSS inline
        out.println("<!doctype html><html><head><meta charset='utf-8'>");
        out.println("<style>body{font-family:Segoe UI,Arial,sans-serif;"
                + "background:#fff;color:#000;padding:12px;font-size:14px}"
                + "h1{color:#007bff;font-size:20px;margin:0 0 12px 0}"
                + "pre{white-space:pre-wrap;word-break:break-word;"
                + "color:#000;background:#f8f8f8;padding:10px;border-radius:6px;"
                + "border:1px solid #ccc;font-size:13px;}"
                + "</style></head><body>");

        out.println("<h1>Preview Service</h1>");
        out.println("<form method='get' action='" + req.getContextPath()
                + "/ssrf/preview'><input name='url' value='" + escapeHtml(urlParam)
                + "' style='width:70%;padding:6px;font-size:14px'><button>Fetch</button></form>");

        if (urlParam == null || urlParam.isEmpty()) {
            out.println("<p style='color:gray'>No URL provided.</p></body></html>");
            return;
        }

        out.println("<p style='color:gray'>Requested URL: " + escapeHtml(urlParam) + "</p>");

        try {
            URL u = new URL(urlParam);

            if ("file".equalsIgnoreCase(u.getProtocol())) {
                // đọc file local
                File f = new File(u.getPath());
                if (!f.exists()) throw new FileNotFoundException(u.getPath());
                byte[] data = java.nio.file.Files.readAllBytes(f.toPath());
                String text = new String(data, StandardCharsets.UTF_8);
                out.println("<pre>" + escapeHtml(text) + "</pre>");
            } else {
                HttpURLConnection conn = (HttpURLConnection) u.openConnection();
                conn.setConnectTimeout(CONNECT_TIMEOUT);
                conn.setReadTimeout(READ_TIMEOUT);
                conn.setInstanceFollowRedirects(true);
                conn.setRequestProperty("User-Agent", "SSRF-Lab/1.0");

                int code = conn.getResponseCode();
                out.println("<p style='color:gray'>HTTP response code: " + code + "</p>");

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try (InputStream is = conn.getInputStream()) {
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
                }

                byte[] content = baos.toByteArray();
                String contentType = conn.getContentType();
                if (contentType != null && contentType.startsWith("image/")) {
                    String b64 = Base64.getEncoder().encodeToString(content);
                    out.println("<img src='data:" + escapeHtml(contentType)
                            + ";base64," + b64
                            + "' style='max-width:100%;border:1px solid #ccc;border-radius:4px'/>");
                } else {
                    // hiển thị source code dạng text
                    String text = new String(content, StandardCharsets.UTF_8);
                    out.println("<pre>" + escapeHtml(text) + "</pre>");
                }
            }
        } catch (Exception ex) {
            out.println("<pre style='color:red'>Fetch error: "
                    + escapeHtml(ex.toString()) + "</pre>");
        }

        out.println("</body></html>");
    }
```

2.Endpoint /ssrf/openStream
Cách hoạt động:
Nhận urlParam.

Sử dụng u.openStream() để mở một luồng đọc trực tiếp từ URL.

Stream nội dung này về cho người dùng dưới dạng một file tải về (Content-Disposition: attachment).

```java 
private void openStreamHandler(String urlParam, HttpServletResponse resp) {
        if (urlParam == null) {
            resp.setStatus(400);
            try { resp.getWriter().println("Missing url"); } catch (IOException ignored) {}
            return;
        }
        InputStream is = null;
        OutputStream os = null;
        try {
            URL u = new URL(urlParam);
            String name = new File(u.getPath()).getName();
            if (name == null || name.isEmpty()) name = "download.bin";
            resp.setHeader("Content-Disposition", "attachment; filename=\"" + name + "\"");
            is = u.openStream();
            os = resp.getOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = is.read(buf)) != -1) os.write(buf, 0, n);
            os.flush();
        } catch (Exception e) {
            resp.setStatus(500);
            try { resp.getWriter().println("Error: " + e.toString()); } catch (IOException ignored) {}
        } finally {
            try { if (is != null) is.close(); } catch (IOException ignored) {}
        }
    }
```

3.Endpoint /ssrf/httpurlconn
Cách hoạt động:
Nhận urlParam.

Sử dụng HttpURLConnection để thực hiện yêu cầu GET đến URL.

Trả về nội dung phản hồi dưới dạng text/plain.

```java 
private void httpUrlConnHandler(String urlParam, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/plain;charset=UTF-8");
        if (urlParam == null) {
            resp.getWriter().println("Missing url");
            return;
        }
        try {
            URL u = new URL(urlParam);
            HttpURLConnection conn = (HttpURLConnection) u.openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT);
            conn.setReadTimeout(READ_TIMEOUT);
            conn.setInstanceFollowRedirects(true);
            try (InputStream is = conn.getInputStream();
                 BufferedReader br = new BufferedReader(
                         new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                PrintWriter out = resp.getWriter();
                while ((line = br.readLine()) != null) out.println(line);
            }
        } catch (Exception e) {
            resp.getWriter().println("Error: " + e.toString());
        }
    }

```

### POC và hướng khai thác

Đối với các chức năng như fetch URL hoặc fetch file thì thường dễ dính SSRF và với func kiểu này hướng khai thác sẽ là fetch ngược lại về mạng nội bộ của máy chủ.

Ở đây bình thường sẽ cố fetch vào `127.0.0.1` hay còn gọi là ip loopback để đưa ngược về máy host hay là server.

Với trường hợp này ta sẽ ví dụ là mình không biết liệu ip loopback sẽ được chạy ở port nào thì cách đầu tiên nghĩ đến sẽ là bruteforce vào port và xem request trả về.

Sau khi brute sẽ có thông tin port ở đây mình host bằng python 1 cái local port 8000 với file `secret.txt` bên trong

![image](https://hackmd.io/_uploads/ByYNXYk3ex.png)

Sau khi fetch đến mạng nội bộ với port 8000 thì ta có thông tin bên trong là có 1 file `Secret.txt` bây giờ chỉ cần thử truy cập bằng cách fetch luôn tên file vào trong đường link trỏ đến mạng loopback nội bộ.

![image](https://hackmd.io/_uploads/SJhBNKy3xl.png)

![image](https://hackmd.io/_uploads/BJ1CdKynel.png)


Thành công lôi ra được thông tin của file bí mật.

Tiếp đến là đến với chức năng fetch file bằng cách gọi protocol là `file` để trỏ đến file content trong server nếu server có chức năng này.

Ở đây bình thường nếu host trên linux thì payload sẽ là `file:///etc/passwd với
file://\/\/etc/passwd` nó sẽ trỏ đến file quan trọng là `/etc/passwd` trong linux còn đây mình host bằng windows nên sẽ thử trỏ đến file `Secret.txt` đã được chuẩn bị sẵn.

![image](https://hackmd.io/_uploads/Sk5sHtyhle.png)

Thành công trỏ đến được file bí mật với `file` protocol và đọc được file.