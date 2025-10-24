---
title: Server Side Request Forgery (Java)
categories: [pentesting, Web-Exploitation]
tags: [Web]
---

# Server Side Request Forgery (Java) 

### Source Code

Github: https://github.com/pzhat/SSRF_vuln_demo

### What is SSRF

Giới thiệu về Server-Side Request Forgery :

 Chúng ta có xu hướng lơ là, mất cảnh giác khi đang trong vùng an toàn

 → Developer nghĩ rằng hacker sẽ không truy cập được các ứng dụng nội bộ do đó việc bị hack gần như là không thể
 
→ Pentester cũng không đủ thời gian để security test hết tất cả dịch vụ nội bộ

→ Khả năng tìm ra lỗi trên các dịch vụ nội bộ sẽ rất cao nếu ”lẻn” vào được bên trong

Và chủng lỗi SSRF này đáp ứng chúng ta cách để lẻn vào dịch vụ nội bộ đó.

Đối với các tính năng xử lý URL (như fetch image / video, preview link, …) thì loại lỗi thường gặp là Server-Side Request Forgery.

### Overview Lab

Luồng xử lý tổng quát: 

- doGet() lấy path và param url + level.

Với mỗi endpoint:

- /ssrf/preview — gọi previewHandler(url, req, resp, level); preview hiển thị form và chạy FilterManager.check(...) trước khi fetch. Nếu pass → thực hiện chính xác phần fetch nguyên bản bạn muốn (dùng new URL(urlParam) + url.openStream() đọc dòng rồi out.println(content) — không escape).

- /ssrf/openStream và /ssrf/httpurlconn — đều gọi FilterManager.check(...) trước rồi thực hiện fetch/downloading theo hành vi gốc của bạn (openStream / HttpURLConnection).

- FilterManager là một bộ kiểm tra theo switch(level) gọi các lớp con Level2..Level5 (inner static classes). Mặc định DEFAULT_LEVEL = 1 → tức không filter nếu không truyền level.

![image](https://hackmd.io/_uploads/B16CcBxhxe.png)

Đây là một lab ssrf với chức năng chính là fetch url cùng với file nói chung nó còn xử lý cả protocols.

![image](https://hackmd.io/_uploads/rklMsHxhlx.png)

Ta thử fetch url của một trang web nó sẽ nhảy ra hết giao diện của trang đó cho ta thấy được.

![image](https://hackmd.io/_uploads/SyL10Bx2ex.png)

Thử với protocol là file và đọc được trong máy.

Ở đây tôi sẽ chia Lab thành 4 levels khác nhau với mỗi level là một lớp filter với độ khó tăng dần lên.

### Phân tích và khai thác từng level

```java
   URL url = new URL(urlParam);

            // Open a connection and read the content
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(url.openStream())
            );
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            reader.close();
            // Output the content to the response
            out.println(content.toString());
```

Đây là logic xử lý url chính của bài.

#### Level 1:

Đến với level 1 thì sẽ không có 1 lớp filter nào cả nó mặc định sẽ chỉ có các chức năng như trên.

Vậy ở đây ta sẽ lợi dụng chức năng fetch này như thế nào. Bản chất SSRF nó là lợi dụng để có thể tấn công vào nội bộ nên ta sẽ thử tấn công vào `ip loopback` là `127.0.0.1`.

![image](https://hackmd.io/_uploads/Syd5HAgnex.png)

Có vẻ trong trường hợp này có vẻ port 8080 không mở nên ta sẽ thử brute force port xem kết quả trả về ra sao.

![image](https://hackmd.io/_uploads/H1H1hJbhge.png)

Sau khi tiến hành brute ta thấy có 2 port đáng nghi là `8081` và `8000`.

![image](https://hackmd.io/_uploads/ryKEnyW2el.png)

Kiểm tra port 8081 thì ta có thể thấy trang burp hiện lên vậy đây là proxy của burp không phải thứ ta đang tìm kiếm.

![image](https://hackmd.io/_uploads/HyUPnkWngl.png)

Tới với port 8000 thì ta có thể thấy ở đây có vẻ là nơi cất giấu thư mục bí mật nằm trong loopback hay là trong mạng nội bộ.

![image](https://hackmd.io/_uploads/HyVih1Z3xe.png)

Thành công đọc được file bí mật nằm trong nội bộ.

Ngoài ra thì nếu ta bằng cách nào biết được cấu trúc thư mục trong máy nội bộ thì hoàn toàn ta có thể sử dụng protocol như `file` để đọc thẳng luôn.

![image](https://hackmd.io/_uploads/BygXa1-2el.png)

Thành công với protocol `file`.

#### Level 2:

```java 
 private static class Level2 {
        static boolean check(String scheme, String lowerUrl, HttpServletResponse resp) throws IOException {
            if ("file".equals(scheme) || "gopher".equals(scheme) || "jar".equals(scheme) || "ftp".equals(scheme)) {
                resp.sendError(400, "Protocol not allowed (level2)");
                return false;
            }
            if (lowerUrl.contains("127.0.0.1") || lowerUrl.contains("localhost") || lowerUrl.contains("0.0.0.0")) {
                resp.sendError(403, "Access to loopback blocked (naive) (level2)");
                return false;
            }
            return true;
        }
    }
```

Ở đây có thể thấy đã có lớp filter nó sẽ chặn lại các từ như `file`, `gopher`, `jar`, `ftp`, `127.0.0.1`, `localhost`, `0.0.0.0` điều này khiến cho cách ở level đầu có vẻ không còn hoạt động nữa.

![image](https://hackmd.io/_uploads/HJKEQlb2lx.png)

Có thể thấy khi mình payload dạng `http://127.0.0.1:8000/Secret.txt` trong đó có chứa `127.0.0.1` nằm trong black list nên đã dính 403 Forbidden. 

Vậy liệu có cách nào để có thể bypass qua được lớp filter này không? Ở đây ta để ý rằng nó sẽ chặn một chuỗi cụ thể là `127.0.0.1` nhưng ở đây ta hoàn toàn có thể rút ngắn ip lại thành `127.0.1` để có thể bypass bây giờ ta sẽ test thử.

![image](https://hackmd.io/_uploads/SySh9Xb2ge.png)

![image](https://hackmd.io/_uploads/SyvpcQZhxl.png)

Thành công đọc được file bí mật qua IPv4 loopback. Ngoài ra ta hoàn toàn có thể sử dụng IPv6 loopback để bypass qua lớp filter này.

![image](https://hackmd.io/_uploads/H1L4sQb3lg.png)

![image](https://hackmd.io/_uploads/rkVHjQZhxe.png)

Thành công sử dụng IPv6 để bypass.

#### Level 3:

```java 
  private static class Level3 {
        static boolean check(String host, HttpServletResponse resp) throws IOException {
            if (host == null) return true; // cannot check
            String h = host.toLowerCase();
            if ("127.0.0.1".equals(h) || "localhost".equals(h) || "127.0.1".equals(h) || "[::1]".equals(h)) {
                resp.sendError(403, "Access to loopback denied (level3)");
                return false;
            }
            return true;
        }
    }
```

Ở đây bị đã bị filter thêm `127.0.1` và IPv6 cũng đã bị filter.

![image](https://hackmd.io/_uploads/BkfMBNbhge.png)


Nhưng với lớp filter này thì bypass vẫn khá là dễ vì loopback IPv4 còn có dạng rút ngắn hơn đó là `127.1` nên ta có thể sử dụng nó xem thử kết quả trả về như thế nào.

![image](https://hackmd.io/_uploads/HJn1HN-neg.png)

![image](https://hackmd.io/_uploads/ByIeHVW2ge.png)

Ngoài ra nếu như trong trường hợp `127.1` cũng ăn filter thì ta còn có 1 cách nữa đó là sử dụng encode chẳng hạn như viết `127.0.0.1` dưới dạng thập phân là `2130706433` nếu nó có parse thì ta sẽ thành công bypass được.

![image](https://hackmd.io/_uploads/S18CWLbnge.png)

![image](https://hackmd.io/_uploads/ryrJzIWhex.png)

Thành công sử dụng số thập phân để bypass.

#### Level 4:

```java 
private static class Level4 {
        static boolean check(String host, HttpServletResponse resp) throws IOException {
            String toResolve = host;
            if (toResolve == null) {
                resp.sendError(400, "Host missing for resolution (level4)");
                return false;
            }
            try {
                InetAddress[] addrs = InetAddress.getAllByName(toResolve);
                for (InetAddress a : addrs) {
                    if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isSiteLocalAddress()) {
                        resp.sendError(403, "Access to internal network denied (resolved: " + a.getHostAddress() + ") (level4)");
                        return false;
                    }
                }
            } catch (UnknownHostException uhe) {
                resp.sendError(400, "Host resolution failed (level4)");
                return false;
            } catch (Exception e) {
                resp.sendError(400, "Host resolution error (level4)");
                return false;
            }
            return true;
        }
    }
```

Bây giờ đến với level 4 thì mọi payload ta sử dụng từ 3 levels trước đã không còn có thể hoạt động được nữa.

Nếu địa chỉ là:

- isAnyLocalAddress() → ví dụ: 0.0.0.0

- isLoopbackAddress() → ví dụ: 127.0.0.1, ::1

- isSiteLocalAddress() → ví dụ: 192.168.x.x, 10.x.x.x, 172.16.x.x đến 172.31.x.x

Thì sẽ bị chặn với mã lỗi 403 (Forbidden), vì đây là các địa chỉ nội bộ.

Ngoài ra nó còn phân giải tên miền nên kiểu payload encode cũng không còn có hiệu lực lên nữa.

Sau một lúc tìm hiểu thì ta có một kịch bản tấn công khả thi cao là `Open Redirect` ta sẽ trỏ `127.0.0.1` vào bằng proxy sau đó thì đưa nó ra mạng bên ngoài bằng tunnels và tiến hành fetch link do tunnel tạo ra là nằm ngoài mạng nội bộ nên khả năng bypass được rất cao.

```python 
# redirect.py
from http.server import BaseHTTPRequestHandler, HTTPServer

class R(BaseHTTPRequestHandler):
    def do_GET(self):
        # target nội bộ của server mục tiêu (ví dụ Tomcat chạy trên cùng máy với SSRF)
        target = "http://127.0.0.1:8000/Secret.txt"
        self.send_response(302)
        self.send_header('Location', target)
        self.end_headers()

if __name__ == '__main__':
    HTTPServer(('0.0.0.0', 9001), R).serve_forever()
```

Tiến hành redirect `http://127.0.0.1:8000/Secret.txt` vào `localhost 9001`.

![image](https://hackmd.io/_uploads/BJzWaUZnlx.png)

![image](https://hackmd.io/_uploads/r1TNpU-hex.png)

Sau đó tôi sử dụng pinggy để tunnel từ `localhost:9001` ra bên ngoài vì nếu mình dùng local thì sẽ dính mạng nội bộ.

![image](https://hackmd.io/_uploads/ryaSTUb2gg.png)

Tiến hành fetch và đã thành công khai thác được file Secret.txt trong mạng nội bộ.

#### Level 5:

```java 
  private static class Level5 {
        static boolean check(String host, HttpServletResponse resp) throws IOException {
            String[] allow = {
                    "example.com",
                    "static.example.net"
            };
            // chỉnh theo lab nếu cần
            if (host == null) {
                resp.sendError(403, "Host missing (level5)");
                return false;
            }
            for (String a : allow) {
                if (a.equalsIgnoreCase(host)) return true;
            }
            resp.sendError(403, "Host not in allowlist (level5)");
            return false;
        }
    }

```

Có thể thấy ở đây nó tạo một `whitelist` chỉ cho phép các domain giới hạn như là `example.com` và `static.example.net` và đoạn : 

```java 
for (String a : allow) {
    if (a.equalsIgnoreCase(host)) return true;
}
```

Chỉ khi chuỗi host khớp chính xác với một trong các tên miền được cho phép, thì mới được truy cập. Không có phân giải DNS, không có kiểm tra IP — chỉ là so sánh chuỗi.

Well với kiểu whitelist như này thì ý tưởng tấn công vẫn sẽ là kịch bản trỏ tới loopback và đưa ra tunnel hoặc ra domain mà mình sở hữu nhưng nằm trong whitelist ở trong trường hợp này thì mình sẽ làm theo hướng tunnel vì không có domain :v.

![image](https://hackmd.io/_uploads/HJQ4-dZnle.png)

Ta chạy python cho nó trỏ tới file trong mạng nội bộ bằng ip loopback.

![image](https://hackmd.io/_uploads/BJ4IbdWngg.png)

Đưa ra tunnel nhưng có vẻ như là ở đây nó không cho đổi tên nếu muốn dùng thì phải trả tiền nên mình sẽ mod một chút vào source.

```java 
  String[] allow = {
                    "hwykb-42-117-87-232.a.free.pinggy.link",
                    "static.example.net"
            };
```

Đưa link của pinggy vào whitelist và ta sẽ tiến hành fetch thử.

![image](https://hackmd.io/_uploads/B1tnZuZnge.png)

Thành công fetch được file bí mật.

