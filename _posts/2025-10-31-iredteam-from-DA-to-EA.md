---
title: Ired.Team From Domain Admin to Enterprise Admin
categories: [RedTeam, Windows]
tags: [RedTeam]
---

# Ired.Team From Domain Admin to Enterprise Admin 

### Overview

Ở lab này ta sẽ lợi dụng mối quan hệ giữa **Parent-Child** domain từ đó lợi dụng mối quan hệ đó và gây nên leo thang đặc quyền.

### Build lab

![image](https://hackmd.io/_uploads/BJhTNPJk-x.png)

SetUp domain đặt tên là `offense.local` đây là domain cha với IP là `192.168.10.10/24` và `DNS: 127.0.0.1`.

![image](https://hackmd.io/_uploads/BkRX1OR0ge.png)

- Đã cài xong `Active Directory Domain Services (AD DS).`

- Đã promote máy thành `Domain Controller` cho domain: `offense.local`.

- Đã có `DNS Server` chạy trên DC.

- Đang dùng `VMware host-only network.`

Sau đó setup máy `red.offense` đưa nó vào domain `offense.local`.

![image](https://hackmd.io/_uploads/SJ3Drv1kZx.png)

Gán ip sau đó set DNS trỏ đến ip của máy `parent.local`.

- Network Adapter: `Host-only`

- IP: `192.688.10.20/24`

- DNS: `192.168.10.10 (MANTVYDAS DC - offense local).`

### Parent-child domain

![image](https://hackmd.io/_uploads/BkbC5by1-x.png)

Ở đây cài đặt domain `red.offense` là con của `offense.local` ở đây khi mình truy cập vào `Active Directory Domains and Trusts` ở đây ta thấy nó cho ta thấy mối quan hệ giữa 2 domains và bên cạnh đó và `default trust` của 2 domains đó.

![image](https://hackmd.io/_uploads/HJlVIPJyWx.png)

Ở đây ta sử dụng lệnh ở cả 2 domain để kiểm tra :

```powershell 
Get-ADTrust -Filter *
```

![image](https://hackmd.io/_uploads/H11-PDy1Wg.png)

![image](https://hackmd.io/_uploads/HkKmPP11Wl.png)

- Console đầu tiên show cho ta thấy được mối quan hệ giữa 2 domain trust ở đây là console của `offense.local` nó cho ta thấy nó là `Name : red.offense.local`.
- Console thứ 2 cũng thể hiện mối quan hệ tương tự giữa `2 domains`.
- Ta để ý rằng cái Direction là `BiDirectional` điều đó có nghĩa là các thành viên có thể xác thực từ domain này sang domain khác khi họ muốn truy cập vào các resources được chia sẻ.

![image](https://hackmd.io/_uploads/SkssDvy1bl.png)

![image](https://hackmd.io/_uploads/Byp2DvyyZl.png)

Sử dụng lệnh `nltest /domain_trusts`.Thông tin tương tự nhưng rất đơn giản có thể được thu thập từ tệp nhị phân Windows.

Tương tự ta sử dụng lệnh dưới đây để lấy được thông tin tương tự như bên trên : 

```powershell
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
```

![image](https://hackmd.io/_uploads/rkYzuvkkbx.png)

![image](https://hackmd.io/_uploads/rkDXODkJZx.png)

`SourceName` với `TargetName` đã thể hiện và TrustType là `ParentChild`.

![image](https://hackmd.io/_uploads/SJTmguyybx.png)

![image](https://hackmd.io/_uploads/HyLrlOJ1-x.png)

### Forest Trust

![image](https://hackmd.io/_uploads/HJ38edy1bl.png)

Tạo một máy `DC-BLUE` có domain là `defense.local` sau đó đưa 2 cái DC là `MANTVYDAS` và `BLUE` vào cùng dải ip và cùng DNS Zone.

![image](https://hackmd.io/_uploads/Syk5b_ykWg.png)

![image](https://hackmd.io/_uploads/ByK9b_11We.png)

SetUp DNS Forward ở cả 2 máy bây giờ 2 máy hoàn toàn có thể nslookup được cho nhau.

![image](https://hackmd.io/_uploads/SyQ4BdyJbx.png)

Tiến hành config forest trust cho `defense.local` cho `offense.local`ở đây ta tạo incoming trust.

![image](https://hackmd.io/_uploads/SJR8L_JkZx.png)

![image](https://hackmd.io/_uploads/SysDI_Jy-l.png)

Giờ ta hoàn toàn có thể truy cập dữ liệu của máy `defense.local` bằng máy `offense.local` nhưng máy `defense` sẽ không thể làm được điều ngược lại lí do là vì nó không được máy `offense` trust, user trên `dc-mantvydas.offense.local` không thể chia sẻ thư mục với `defense\administrator` ==(vì offensive.local không tin tưởng defense.local)==.

### From DA to EA

Bây giờ ta sẽ đi đến với kỹ thuật biến từ `Domain Admin` thành `Enterprise Admin` dựa theo kỹ thuật có sẵn.

```powershell 
# Tạo user
New-ADUser -Name "spotless" -SamAccountName "spotless" -Enabled $true -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force)

# Gán vào Domain Admins
Add-ADGroupMember -Identity "Domain Admins" -Members "spotless"
```

Ta sẽ tạo user ở `DC-RED` là user `spotless` và đưa user đó vào thành `Domain Admin`.

Bây giờ nó đã là `child admin` ở đây mình sẽ không dùng empire powershell mà demo tấn công theo cách khác ở đây ta bỏ qua bước AD recon với lateral movement vì empire bị lỗi ta sẽ vào thẳng shell của dc-red luôn.

#### Bước 1: Xác nhận trust parent-child

![image](https://hackmd.io/_uploads/SkO2GbWkWe.png)

#### Bước 2: Xác nhận Domain Admin

![image](https://hackmd.io/_uploads/SyYJQ-bk-x.png)

#### Bước 3: Lấy SID của Enterprise Admins (parent)

![image](https://hackmd.io/_uploads/rJLc7-Z1bg.png)

Ta có SID là `S-1-5-21-3710096372-560042618-2387674259-519`.

![image](https://hackmd.io/_uploads/rJNG8ZZJWx.png)

Sau đó ta lấy SID của `krbtgt` là `S-1-5-21-1522518357-539094533-3136975768-502`.

#### Bước 4: Bắt đầu chạy `psexec.exe` mở CMD mới với quyền SYSTEM

![image](https://hackmd.io/_uploads/ByChUZbyWg.png)

#### Bước 5: Tạo golden ticket trong mimikatz

![image](https://hackmd.io/_uploads/ByyWDZby-l.png)

#### Bước 6: Nạp ticket và kiểm tra

![image](https://hackmd.io/_uploads/S1o4PWWkWe.png)

#### Bước 7: 

Sau khi tạo ticket tôi spawn ra cmd mới và kiểm tra user.

![image](https://hackmd.io/_uploads/B1VCs-WJbe.png)

![image](https://hackmd.io/_uploads/SkeHlX-J-x.png)






















