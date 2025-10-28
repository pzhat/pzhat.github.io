---
title: Broken Access Control Vulnerability Lab
categories: [pentesting, Web-Exploitation]
tags: [Web]
---

# Broken Access Control Vulnerability Lab

### What is Broken Access Control (BAC)

Broken Access Control là một loại lỗ hổng bảo mật web xảy ra khi người dùng có thể truy cập vào các tài nguyên hoặc thực hiện các hành động vượt quá quyền hạn cho phép của họ. Đây là một trong những rủi ro bảo mật nghiêm trọng nhất đối với các ứng dụng web, theo danh sách của OWASP Top 10.

### Source Code

[Github](https://github.com/pzhat/BAC-lab)

### Lab Overview

Với BAC mình làm một lab đơn giản để demo 2 lỗ hổng bao gồm:

- **Lỗ hổng 1**: Truy Cập Trái Phép Đối Tượng Trực Tiếp (Insecure Direct Object Reference - IDOR)

- **Lỗ hổng 2**: Thiếu Kiểm Soát Truy Cập Cấp Chức Năng (Missing Function-Level Access Control)

![image](https://hackmd.io/_uploads/HkYX0lYhel.png)

Ở level này tôi để 2 user là 1 user admin và 1 user thường.

### Tiến hành phân tích các lỗ hổng và POC

#### Level 1:

```java 
   @GetMapping("/profile/{id}")
    public String userProfile(@PathVariable Long id, Model model) {
        model.addAttribute("user", userRepository.findById(id).orElse(null));
        return "profile";
    }
```

#### Phân tích Sink : 

- **Source**: Là biến id trong đường dẫn @GetMapping("/profile/{id}"). Giá trị này hoàn toàn do người dùng kiểm soát qua URL trên trình duyệt.

- **Endpoint**: Là phương thức userRepository.findById(id). Đây là một hàm nhạy cảm vì nó truy xuất dữ liệu trực tiếp từ cơ sở dữ liệu.

- **Lỗ hổng**: Dữ liệu từ "Source" (biến id) được truyền thẳng vào "Sink" (findById) mà không có bất kỳ bước kiểm tra quyền hạn nào. Chương trình không hề đặt câu hỏi: "Người dùng đang đăng nhập có được phép xem profile với id này không?". Nó chỉ đơn giản là nhận lệnh và thực thi.

Ở đây biến id được truyền thẳng vào sink nên ta hoàn toàn có thể thay đổi id từ id user thường lên user admin.

![image](https://hackmd.io/_uploads/BkcV-bFngl.png)

Đăng nhập vào user alice với username là `alice` và password là `password` sau khi click vào user profile id là alice hiện các thông tin của user alice.

Nhưng ở đây khi truy vấn biến id thì không có một lớp xử lý nào nên ta hoàn toàn có thể thực thi IDOR, bây giờ ta sẽ tiến hành thử thay đổi biến id ở trên url.

`http://localhost:8080/profile/1` ở đây với id là 1 profile hiển thị lên là của user alice.

Bây giờ tiến hành thay đổi id từ 1 thành 2 để xem liệu có view được user khác ngoài alice không.

![image](https://hackmd.io/_uploads/BJrEX-Knxx.png)

`http://localhost:8080/profile/2` sau khi thay đổi thì user profile đã hiển thị của user id là 2 là admin nên có thể kết luận đây là lỗ hổng IDOR cho phép ta xem được profile của người khác dù không có quyền truy cập.

#### Level 2:

```java 
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/", "/login").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/", true)
                        .permitAll()
                )
                .logout(logout -> logout
                        // URL sẽ chuyển đến sau khi đăng xuất
                        .logoutSuccessUrl("/")
                        .permitAll()
                );

        return http.build();
    }
```

```java 
    @GetMapping("/admin")
    public String adminPage(Model model) {
        model.addAttribute("users", userRepository.findAll());
        return "admin";
    }
```

#### Phân Tích "Sink"

- **Source**: Là yêu cầu của người dùng truy cập vào một đường dẫn bất kỳ, ví dụ GET /admin.

- **Endpoin**: Là phương thức adminPage() trong WebController, nơi thực thi chức năng quản trị (lấy tất cả user: userRepository.findAll()).

- **Lỗ hổng**: Cấu hình SecurityConfig không định nghĩa các quy tắc truy cập dựa trên vai trò (role-based access control) cho đường dẫn /admin. Quy tắc .anyRequest().authenticated() chỉ kiểm tra xem người dùng đã đăng nhập hay chưa, chứ không kiểm tra xem họ có phải là ADMIN hay không. Cánh cổng vào khu vực admin đã được để ngỏ cho bất kỳ ai có chìa khóa (đã đăng nhập).

Ở đây có thể thấy rằng trong config không hề có định nghĩa các role nó chỉ kiểm tra xem user đã đăng nhập hay chưa chứ không hề kiểm tra xem user có phải là admin hay không.

![image](https://hackmd.io/_uploads/B1ERE-t3ge.png)

Ở đây mình vẫn đang sử dụng user là alice là user thường với role là `USER` vậy liệu ta có thể truy cập được admin panel bằng endpoint `/admin` hay không? Bây giờ tiến hành thay đổi thêm phần endpoint `/admin` vào url.

![image](https://hackmd.io/_uploads/ryZDSWKhxx.png)

Thành công truy cập được admin panel bằng cách sử dụng url `![image](https://hackmd.io/_uploads/ryKOB-Fnle.png)
` thành công lợi dụng BAC để truy cập trái phép chức năng của admin.

