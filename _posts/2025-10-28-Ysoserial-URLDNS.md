---
title: Java Deserialze - URLDNS Chain analysis (ysoserial)

---

# Java Deserialze - URLDNS Chain analysis (ysoserial)

![image](https://hackmd.io/_uploads/r1R3sp6Rgl.png)

### Java Deserialize là gì?

- Java cung cấp cho người dùng hàm `writeObject()` để tiến hành quá trình `serialize` các object ở đây quá trình serialize sinh ra để chuyển một đối tượng Java thành chuỗi byte để lưu trữ (file, DB) hoặc truyền qua mạng (socket, RMI, JMS).
- Và để có thể đọc được dữ liệu được serialize từ `ObjectInputStream` ta có quá trình `deserialize` ở java sử dụng hàm `readObject()` cho quá trình đó.

### Khai thác Java Object Injection

- Rủi ro sẽ đến với các đối tượng xử lý deserialize các `Untrusted Data`.
- Attacker có thể lợi dụng các magic method, cách mà OOP vận hành từ đó tạo ra `exploit chain` hoàn chỉnh và tiến hành sử dụng payload.

### Tiến hành Setup môi trường test

![image](https://hackmd.io/_uploads/S1UCyu2Clg.png)

Tiến hành truy cập Respository của ysoserial tại : https://github.com/frohoff/ysoserial

Bây giờ tiến hành tải toàn bộ project về phân tích.

![image](https://hackmd.io/_uploads/rysIqt20le.png)

Với project java như này để dễ cho việc đặt break point và debug thì tôi sử dụng IntelliJ IDEA để phân tích và debug.

![image](https://hackmd.io/_uploads/rkAYti30le.png)

Truy cập vào Project sau đó truy cập đến thẳng `/src/main/java/ysoserial/payloads/URLDNS` ở đây tôi không cần cài thêm cái gì nữa vì `IntelliJ` hầu như có sẵn hết rồi chỉ việc debug.

### Một số điều về URLDNS

- Một trong những ưu điểm của `URLDNS` là nó ==không yêu cầu== bất kì `library/dependencies` nào nên có thể dùng để nhận biết Deserialization ở trên bất kì version của Java.
- Đây là một trong số các chain đơn giản nhất của ysoserial.
- Chain này ==không có tác dụng để RCE== nó chỉ đơn giản có tác dụng là chạy ==DNS request== chức năng nó tương tự như là DNSLookup.
- URLDNS là một “gadget chain” dùng trong các cuộc thử nghiệm deserialization ==Java OOB (out‑of‑band)== khi mà attacker nhận được kết quả truy vấn DNS thì chứng tỏ payload đã thực thi.
- Chain tận dụng các lớp/behavior có sẵn trên classpath của JVM mục tiêu (ví dụ các lớp trong java.net, JNDI, hoặc các thư viện bên thứ ba) để khiến JVM thực hiện lookup.

### Tiến hành phân tích source và payload

Tiến vào trong payload ta thấy rằng có rất nhiều dòng comment để giải thích luồng hoạt động của payload cho ta dễ hiểu được cách mà payload đó hoạt động ở đây có dòng : 

```comment
 *   Gadget Chain:
 *     HashMap.readObject()
 *       HashMap.putVal()
 *         HashMap.hash()
 *           URL.hashCode()
```

Ở đây họ comment cho mình luôn gadget chain của payload này cụ thể ở đây nó sẽ lần lượt gọi đến theo thứ tự : 

```java 
HashMap.readObject() --> HashMap.putVal() --> HashMap.hash() --> URL.hashCode()
```

Bây giờ ta đi vào các thành phần bên trong payload.

![image](https://hackmd.io/_uploads/Sk3HkhhAgg.png)

```java 
public class URLDNS implements ObjectPayload<Object> {

        public Object getObject(final String url) throws Exception {

                //Avoid DNS resolution during payload creation
                //Since the field <code>java.net.URL.handler</code> is transient, it will not be part of the serialized payload.
                URLStreamHandler handler = new SilentURLStreamHandler();

                HashMap ht = new HashMap(); // HashMap that will contain the URL
                URL u = new URL(null, url, handler); // URL to use as the Key
                ht.put(u, url); //The value can be anything that is Serializable, URL as the key is what triggers the DNS lookup.

                Reflections.setFieldValue(u, "hashCode", -1); // During the put above, the URL's hashCode is calculated and cached. This resets that so the next time hashCode is called a DNS lookup will be triggered.

                return ht;
        }

        public static void main(final String[] args) throws Exception {
                PayloadRunner.run(URLDNS.class, args);
        }
```

Ở comment nói khá đầy đủ nhưng mình vẫn sẽ phân tích từng đoạn một : 

- Hàm `getObject(final)` được gọi khi mà bắt đầu quá trình serialize

```java 
URLStreamHandler handler = new SilentURLStreamHandler();
```

- Ở đây từ `URLStreamHandler` ta tạo một handle khác tuỳ chỉnh để có thể tránh việc nó thực hiện DNS resolution trong quá trình tạo payload nghĩa là nếu trong quá trình tạo ra payload nếu không có handle này nó sẽ tự động truy vấn trong lúc gen payload.

```java 
 HashMap ht = new HashMap(); // HashMap that will contain the URL
 URL u = new URL(null, url, handler); // URL to use as the Key
 ht.put(u, url); //The value
```

- Tạo một HashMap và dùng URL làm key, giá trị chỉ là chuỗi url (Serializable).
- Việc dùng URL làm key là quan trọng: HashMap sử dụng hashCode() của key để tính bucket; khi HashMap được deserialize, mã sẽ tính lại hashCode cho từng key, và đó là lúc URL có thể thực hiện lookup.

```java 
Reflections.setFieldValue(u, "hashCode", -1);
```

- Gọi reflection, ta để ý ở trên giá trị `u` đã được `put` ở bên trên sau đó nó được hashcode tính là tiến hành cache bây giờ chỉ cần giá trị `hashcode` được gọi thì nó sẽ tiến hành DNS request sau đó cài hashcode là `-1` thì nó sẽ tự dọn đi giá trị cũ hashmap sau chỉ cần có giá trị mới nó sẽ lặp lại quá trình trigger.

```java 
 return ht;
```

- Trả về HashMap chứa URL key. Khi object này được serialized rồi gửi tới server mục tiêu và server gọi ObjectInputStream.readObject(), HashMap.readObject() sẽ khôi phục các entry và gọi put/rehash, dẫn tới gọi URL.hashCode() => DNS lookup.

### Debug

Bây giờ ta sẽ Debug từ hàm main để xem nó như thế nào.

![image](https://hackmd.io/_uploads/H1V002nCxl.png)

Đầu tiên ta sẽ click phải vào hàm main sau đó đi đến `Edit Run Configuration` ở đây là URLDNS nó hiện ra cho bạn sau đó sử dụng bất kì công cụ nào để bắt request cũng được bạn có thể dùng `Burp Collab` ở đây mình dùng [RequestRepo](https://requestrepo.com/) để bắt được DNS request trả về.

Sau khi apply và ok thì ta sẽ bấm debug hàm main này chờ xem kết quả trả về ở đây là gì.

![image](https://hackmd.io/_uploads/B17tJTnRex.png)

Kết quả trả về khá là khả quan nó đã connect đến target sau đó gen payload tiến hành serialize sau đó deserialize cuối cùng là disconnect với target bây giờ truy cập target xem có request nào không.

![image](https://hackmd.io/_uploads/rycxep2Cll.png)

Thành công bắt trọn được 2 DNS request vậy ta chắc chắn rằng payload thực hiện DNS request tốt bây giờ tiến hành đặt breakpoint để đi theo flow của gadget chains.

Đầu tiên ta thử breakpoint ở hàm main trước.

![image](https://hackmd.io/_uploads/BkJxrCnRxe.png)

![image](https://hackmd.io/_uploads/Hk4JX1TCxg.png)

Debug đã nhận bây giờ dùng phím F7 để có thể tiếp tục chạy đến xem thử flow xử lý của code payload này.

![image](https://hackmd.io/_uploads/HyK8XJTClg.png)

Khi chạy đến nơi xử lý HashMap ta thấy rằng giá trị URL đã được gắn vào key đó.

![image](https://hackmd.io/_uploads/r1a6mkpCgx.png)

Sau khi chạy đến đoạn `ht.put(u, url);` thì ta thấy nó bắt đầu trigger DNS request giá trị các trường được gắn bên dưới ta sẽ khám phá nơi hàm `put` này được khai báo để xem nó có gọi đến gadget nào không.

![image](https://hackmd.io/_uploads/rykQDJTAxe.png)

Ở đây ta thấy nó trỏ đến hàm này mà ta để ý rằng trong đoạn comment của chain có

![image](https://hackmd.io/_uploads/H1qCP16Alg.png)

Mà ta để ý rằng hàm readObject nằm bên trong `rt.jar` bây giờ nó gọi đến `putVal` hay là `HashMap.putVal()` 

![image](https://hackmd.io/_uploads/SyzuRkpCgg.png)

![image](https://hackmd.io/_uploads/ByAJNxpCle.png)

Tra đường đi của hàm readObject ta thấy rằng nó được gọi ở đây ở ngay hàm `readObject` ở đây ta có thể thử đặt breakpoint để debug.

![image](https://hackmd.io/_uploads/SJlC4la0lg.png)

Có thể thấy các key value đã được gán vào bây giờ ta sẽ thử trỏ đến method `hash(key)` xem thử nó gọi đến đâu tiến hành F7 và chọn vào method hash.

![image](https://hackmd.io/_uploads/ByHhHlaAxg.png)

Từ method readObject() gọi tới method hash() và có truyền vào biến key, giá trị của key chính là URL Object của target mình cần resolve DNS.

Tại đây nó gọi tới method hash của object key vừa được truyền vào cụ thể là `key.hashcode()` hay lúc này là `URL.hashcode()`.

![image](https://hackmd.io/_uploads/ry-5DgpAxe.png)

Method `hashCode()` nằm ở class URL tiến hành check xem thử có giá trị hashCode nào được cache không trong trường hợp nó đã được cache thì nó sẽ return về giá trị luôn có nghĩa là nếu hashCode != -1 thì nó sẽ return luôn và đoạn chain nó sẽ đứt ở đây vì thế thứ ta cần là để nó thoả mãn điều kiện if để `URL.hashCode()` được call đến `handler.hashCode()`. Vì thế ở đây để điều kiện nó luôn `= -1` thì ta sẽ sử dụng java reflection.

![image](https://hackmd.io/_uploads/r19OfVp0lx.png)

Ta có thể thấy rằng trong payload tác giả đã để sẵn một hàm `Reflection` và set giá trị `hashCode()` luôn luôn là `-1`.

Ở bên dưới ta còn thấy object `hashCode()` còn được handler gọi đến ta sẽ đi đến thử handler này xem nó xử lý gì.

![image](https://hackmd.io/_uploads/B1mDbV60ee.png)

Vì ở đây là một giá trị private field ta sẽ dùng thử reflection để dựng lại URLDNS chain xem thử nó có đúng với luồng hoạt động mà ta đã đi không.

```java 
URL u1 = new URL(null, "https://a7kvklhv.requestrepo.com/", handler);
ht.put(u1, "https://a7kvklhv.requestrepo.com/");
Field test = URL.class.getDeclaredField("hashCode");
test.setAccessible(true);
test.set(u1, -1);
return ht;
```

Tạo biến URL mới bao gồm 3 giá trị bên trong sử dụng lại ht khi đã gọi HashMap sau đó lấy Field HashCode từ class URL sau đó ta sẽ set cho Field đó là Accessible là true vì khi không set thì nó mặc định Field đã là private thì mình không thể reflect đến được sau đó ta tiến hành set giá trị object của class URL ở đây ta set là `-1`.

![image](https://hackmd.io/_uploads/Sy9f9NTAex.png)

![image](https://hackmd.io/_uploads/Hk6rqEaCge.png)

Ta có thể thấy debug đã đúng như ta dự đoán giá trị hashCode của object `u1` đã được set thành `-1` thành công kiểm chứng được reflected ta sẽ thử đổi thành 1 xem liệu nó có thay đổi không nếu thanh đổi được thì gadget đã đúng với hướng.

![image](https://hackmd.io/_uploads/ryzR5Ep0xl.png)

Thành công đổi hashCode thành 1 vậy là ta đã dựng được đúng.

Sau quá trình phân tích reflected ta tiếp tục debug với handler xem nó xử lý gì tiếp ở sau.

Như các bạn đã thấy thì URL.hashCode() sẽ call tới handler.hashCode(), handler ở đây là object của class `URLStreamHandler` 

![image](https://hackmd.io/_uploads/SywBaV6Cll.png)

![image](https://hackmd.io/_uploads/SJhLAVaRge.png)

Hàm này được khai báo abstract ta sẽ thử debug đọc từng dòng trong class `URLStreamHandler`.

![image](https://hackmd.io/_uploads/BkQryraCgx.png)

Tìm thấy một hàm rất khả nghi ở đây vì ở đây nó thực hiện `getHostAddress(u)` sau đó nếu mà biến `u != null` thì thực hiện gọi đến `hashCode()` nên ta sẽ thử đặt một cái breakpoint ngay hàm này xem.

![image](https://hackmd.io/_uploads/H15KeBpAex.png)

Ở đây nếu debug tiếp nó sẽ gọi về url DNS của mình ta tiếp tục follow.

![image](https://hackmd.io/_uploads/ByQa4HpCxl.png)

Ta thấy rằng ở đây InetAddress `.getByName()` đã gọi đến host trong khi đó nó trỏ đến URL của ta thêm vào vậy đây chính là sink của cả payload là nơi thực thi resolve DNS. 









 



