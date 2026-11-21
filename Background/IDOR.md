## Khái niệm và nguyên nhân
> **IDOR** (Insecure Direct Object Reference-Lỗ hổng tham chiếu trực tiếp đối tượng không an toàn) là một dạng lỗ hổng kiểm soát truy cập (access control) xảy ra khi ứng dụng dùng trực tiếp dữ liệu đầu vào do người dùng cung cấp để truy xuất đối tượng mà không kiểm tra quyền truy cập đầy đủ. Kẻ tấn công có thể thay đổi giá trị này để vượt qua cơ chế phân quyền và truy cập trái phép vào tài nguyên
- Trên thực tế, các trang web thường muốn cung cấp nội dung khác nhau cho người dùng khác nhau: ví dụ, một trang web mua sắm có thể cho phép mỗi người dùng xem lịch sử mua hàng của họ
  - Ứng dụng xác định danh tính người dùng thông qua xác thực (authentication), bằng mật khẩu hoặc các phương thức khác
  - Thông thường, sau khi xác thực thành công, máy chủ tạo một session và gửi session cookie về trình duyệt. Ở các yêu cầu tiếp theo, máy chủ dựa vào cookie này để biết yêu cầu đến từ người dùng nào đã được xác thực 
- Tuy nhiên, ngoài việc kiểm tra xem yêu cầu có đến từ người dùng đã được xác thực hay không, máy chủ còn phải phân quyền (authorization) và kiểm soát truy cập ở cấp độ từng tài nguyên: xác định người dùng đó có quyền truy cập vào đúng đối tượng được yêu cầu hay không 
  - Ví dụ, người dùng đã xác thực chỉ xem được lịch sử mua hàng của chính mình
- Nếu máy chủ không kiểm tra quyền sở hữu hoặc quyền truy cập đối với tài nguyên, kẻ tấn công chỉ cần đăng nhập bằng tài khoản hợp lệ rồi thay đổi giá trị tham chiếu (vd: order_id=1001 thành order_id=1002) là có thể truy cập dữ liệu của người dùng khác => đây là leo thang đặc quyền theo chiều ngang (horizontal privilege escalation)
> **Nguyên nhân cốt lõi của lỗ hổng IDOR (Insecure Direct Object Reference)** là ứng dụng sử dụng dữ liệu do người dùng cung cấp (như ID, tên file, tham số trên URL/API) để truy cập trực tiếp đến tài nguyên nội bộ mà không kiểm tra quyền truy cập (authorization) ở phía máy chủ
## Kịch bản tấn công phổ biến
##### Thao túng URL
- Dạng tấn công IDOR phổ biến nhất là thay đổi tham chiếu đối tượng trực tiếp (direct object reference) nằm trong URL. Trong vd dưới đây, 1234 là ID của bản ghi người dùng trong cơ sở dữ liệu của máy chủ 
- Nếu kẻ tấn công thay đổi số này thành bất kỳ số nào khác (ví dụ: "1235") và truy cập được thông tin của người dùng khác, ứng dụng đã tồn tại lỗ hổng IDOR
```
# The attacker is logged in as user 1234
https://example.org/user/id/1234

# The attacker changes the id in the URL and gains access to a different user
https://example.org/user/id/1235
```
Ví dụ mã dễ bị tấn công (Express.js). Giá trị trên URL được lấy qua req.params.id và dùng để truy vấn bản ghi tương ứng trong cơ sở dữ liệu. Mã có kiểm tra xác thực (isAuthenticated()), nhưng không kiểm tra ID của người dùng đã xác thực có khớp với ID được yêu cầu hay không. Vì vậy, một người dùng đã xác thực (kẻ tấn công) vẫn xem được trang của người dùng khác (nạn nhân)
```
app.get("/user/id/:id", (req, res) => {
  const user = db.users.find(req.params.id);
  if (req.isAuthenticated()) {
    // Authentication is not enough!
    res.render("user", { user });
  }
});
```
=>Cách khắc phục: Cần bổ sung kiểm tra phân quyền (authorization check) ở phía máy chủ, chẳng hạn hiển thị trang người dùng khi ID của phiên đăng nhập khớp với ID được yêu cầu. Nếu không thỏa mãn, trả về status code phù hợp

```
app.get("/user/id/:id", (req, res) => {
  const user = db.users.find(req.params.id);
  if (req.isAuthenticated() && req.session.userId === req.params.id) {
    res.render("user", { user });
  } else {
    return res.status(401).json({ message: "Unauthorized" });
  }
});
```
##### Thao tác dữ liệu
Tương tự như việc thao túng URL, kẻ tấn công có thể sửa giá trị của các phần từ <form> như nút radio, hộp kiểm (checkbox) hoặc trường <input> ẩn bằng công cụ dành cho nhà phát triển (DevTools) của trình duyệt, hoặc chặn và sửa request bằng proxy như Burp Suite. Ví dụ, ứng dụng không đặt ID trên URL mà truyền ID người dùng qua một trường ẩn trong biểu mẫu:
```
<form action="updateUser" method="POST">
  <input type="hidden" name="user_id" value="1234" />
  <button type="submit">Update profile</button>
</form>
```
Nếu máy chủ không kiểm soát truy cập (access control), kẻ tấn công có thể đổi giá trị user_id trong trường <input> ẩn thành ID của người dùng khác và sửa đổi hồ sơ của người đó mà không có quyền.
##### Truy cập tập tin
- Đây là trường hợp đặc biệt của IDOR: truy cập tệp hoặc thư mục không được bảo vệ bởi cơ chế kiểm soát truy cập
  - Ví dụ, ứng dụng lưu các tệp PDF tải lên trong một thư mục và đặt tên theo thứ tự tuần tự. Kẻ tấn công có thể đoán tên tệp và tải xuống toàn bộ nếu không có kiểm soát truy cập
  - Về mặt lý thuyết, các tệp khác trong các thư mục không được bảo vệ, chẳng hạn như các tệp cấu hình máy chủ, cũng có thể bị truy cập trái phép, dẫn đến thêm các rủi ro bảo mật khác (như lộ thông tin nhạy cảm)
```
https://example.org/static/pdfs/1.pdf
https://example.org/static/pdfs/2.pdf
```

