## Khái niệm và nguyên nhân
> **IDOR** (Insecure Direct Object Reference) là lỗ hổng tham chiếu trực tiếp đối tượng không an toàn cho phép kẻ tấn công khai thác việc kiểm soát truy cập không đầy đủ và việc để lộ không an toàn các định danh đối tượng, chẳng hạn như khóa cơ sở dữ liệu hoặc đường dẫn tệp
- Trên thực tế, các trang web thường muốn cung cấp nội dung khác nhau cho người dùng khác nhau: ví dụ, một trang web mua sắm có thể cho phép mỗi người dùng xem lịch sử mua hàng của họ
  - Các trang web có thể xác định người dùng bằng cách xác thực họ, sử dụng một phương pháp như mật khẩu hoặc xác thực.
  - Thông thường, sau khi một trang web đã xác thực người dùng, họ sẽ đặt một cookie phiên trong trình duyệt của người dùng đó: sau đó, khi người dùng thực hiện yêu cầu, máy chủ sẽ biết rằng yêu cầu đó đến từ người dùng đã xác thực này
- Tuy nhiên, ngoài việc kiểm tra xem yêu cầu có đến từ người dùng đã được xác thực hay không, máy chủ còn phải thực hiện kiểm soát truy cập đối với các tài nguyên mà người dùng yêu cầu: nghĩa là, họ phải kiểm tra xem người dùng này có được phép truy cập vào tài nguyên cụ thể được yêu cầu hay không
  - Ví dụ, mỗi người dùng đã được xác thực chỉ được xem lịch sử mua hàng của chính họ
- Nếu máy chủ không triển khai kiểm soát truy cập tài nguyên, thì kẻ tấn công đã đăng nhập vào trang web có thể truy cập vào các tài nguyên thuộc về người dùng khác.
> **Nguyên nhân cốt lõi của lỗ hổng IDOR (Insecure Direct Object Reference)** là ứng dụng sử dụng dữ liệu do người dùng cung cấp (như ID, tên file, tham số trên URL/API) để truy cập trực tiếp đến tài nguyên nội bộ mà không kiểm tra quyền truy cập (authorization) ở phía máy chủ
## Kịch bản tấn công phổ biến
##### Thao túng URL
- Một kiểu tấn công IDOR phổ biến liên quan đến việc thao túng các tham chiếu đối tượng trực tiếp trong URL. "1234" trong các URL sau là mã định danh cho bản ghi người dùng trong cơ sở dữ liệu của máy chủ
- Nếu kẻ tấn công thay đổi số này thành bất kỳ số nào khác (ví dụ: "1235") và truy cập được thông tin của người dùng khác, ứng dụng của bạn sẽ dễ bị tổn thương bởi lỗ hổng IDOR

```
# The attacker is logged in as user 1234
https://example.org/user/id/1234

# The attacker changes the id in the URL and gains access to a different user
https://example.org/user/id/1235
```
Ví dụ, trong đoạn mã Express bên dưới, giá trị được cung cấp trong URL có sẵn dưới dạng req.params.id, và chúng ta sử dụng giá trị đó để truy xuất bản ghi tương ứng trong cơ sở dữ liệu
Chúng ta cũng kiểm tra xem yêu cầu có đến từ người dùng đã được xác thực hay không bằng cách (gọi ```isAuthenticated```). Nhưng điều quan trọng là, chúng ta không kiểm tra xem ID của người dùng đã được xác thực có khớp với ID trong URL hay không, và điều này cho phép một người dùng đã được xác thực (kẻ tấn công) truy cập vào trang dành cho một người dùng đã được xác thực khác (nạn nhân).
```
app.get("/user/id/:id", (req, res) => {
  const user = db.users.find(req.params.id);
  if (req.isAuthenticated()) {
    // Authentication is not enough!
    res.render("user", { user });
  }
});
```
Thay vào đó, bạn nên thiết lập các quy tắc để ủy quyền truy cập thông tin người dùng. Ví dụ: chỉ hiển thị trang người dùng nếu ID người dùng đã đăng nhập khớp với ID người dùng được yêu cầu. Nếu không, hãy trả về phản hồi HTTP.401 ```Unauthorized```

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
Tương tự như việc giả mạo URL, kẻ tấn công có thể thao túng nội dung của một trang bằng cách sửa đổi giá trị của ```<form>``` các phần tử, chẳng hạn như nút radio, hộp kiểm hoặc ```<input>``` các phần tử (ẩn) trong công cụ dành cho nhà phát triển của trình duyệt. Ví dụ, có thể ứng dụng của bạn không cung cấp ID người dùng trong URL mà thay vào đó truyền ID người dùng trong một phần tử biểu mẫu ẩn
```
<form action="updateUser" method="POST">
  <input type="hidden" name="user_id" value="1234" />
  <button type="submit">Update profile</button>
</form>
```
Nếu không có cơ chế kiểm soát truy cập phía máy chủ, kẻ tấn công có thể thao túng giá ```user_id``` trị trong phần tử ẩn ```<input>``` thành một ID người dùng khác và có thể sửa đổi hồ sơ mà không cần ủy quyền
##### Truy cập tập tin
- Một trường hợp đặc biệt của các cuộc tấn công IDOR là truy cập vào các tệp hoặc thư mục không được bảo vệ bởi cơ chế kiểm soát truy cập
  - Ví dụ, nếu bạn cung cấp một thư mục để tải lên các tệp PDF và các tệp tải lên được đặt tên theo thứ tự tuần tự, kẻ tấn công có thể đoán được tên tệp và tải xuống tất cả chúng nếu không có cơ chế kiểm soát truy cập
  - Về mặt lý thuyết, các tệp khác trong các thư mục không được bảo vệ, chẳng hạn như các tệp cấu hình máy chủ, cũng có thể bị lấy cắp, dẫn đến các lỗ hổng bảo mật bổ sung.
```
https://example.org/static/pdfs/1.pdf
https://example.org/static/pdfs/2.pdf
```

