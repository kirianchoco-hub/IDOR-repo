# Links2CPN: Automated BOLA Attack Detection in REST APIs via OpenAPI to Colored Petri Nets Transformation

## Giới thiệu
**Links2CPN** là một công cụ mã nguồn mở (Python 3) được thiết kế để tự động phát hiện các cuộc tấn công **Broken Object Level Authorization (BOLA)** — lỗ hổng bảo mật đứng đầu trong OWASP API Security Top 10 — trên các RESTful API. Công cụ này hoạt động bằng cách chuyển đổi đặc tả OpenAPI (phiên bản 3.1.0) thành mô hình **Colored Petri Nets (CPNs)**, sau đó áp dụng kỹ thuật **Conformance Checking** (kiểm tra tính tuân thủ) từ lĩnh vực Process Mining để phân tích nhật ký thực thi của máy chủ web (event logs) nhằm phát hiện các hành vi bất thường.
Công cụ được phát triển bởi nhóm nghiên cứu tại Đại học Liên bang Amazonas (Brazil) và Đại học Zaragoza (Tây Ban Nha), với kết quả thực nghiệm cho thấy khả năng phát hiện tấn công BOLA với **độ chính xác trên 95%** trong các kịch bản thử nghiệm.
## Mục tiêu và Động lực
RESTful API là mục tiêu phổ biến của các cuộc tấn công mạng. Lỗ hổng **BOLA** cho phép kẻ tấn công truy cập, sửa đổi hoặc xóa dữ liệu của người dùng khác bằng cách thay đổi định danh đối tượng (object ID) trong yêu cầu HTTP. Ví dụ, thay vì truy cập `/basket/1` (giỏ hàng của chính mình), kẻ tấn công có thể gửi yêu cầu `/basket/2` để lấy dữ liệu giỏ hàng của người khác.
**Links2CPN** giải quyết vấn đề này bằng cách:
1. **Hình thức hóa** đặc tả OpenAPI thành mô hình toán học CPN.
2. **Tự động hóa** việc phát hiện các vi phạm luồng dữ liệu (data flow) và luồng điều khiển (control flow) thông qua phân tích event logs.
3. **Giảm thiểu** sự phụ thuộc vào kiểm thử thủ công.
## Kiến trúc và Phương pháp hoạt động
Links2CPN hoạt động theo quy trình hai bước chính:
### Bước 1: Chuyển đổi mô hình (Model-to-Model Transformation)
Công cụ phân tích tệp đặc tả OpenAPI (định dạng JSON/YAML) và thực hiện thuật toán chuyển đổi để tạo ra một mạng Petri màu (CPN). Quá trình này bao gồm
- **Algorithm 1**: Tạo CPN từ đặc tả OpenAPI.
- **Algorithm 2**: Tạo các transition (chuyển tiếp) cho mỗi đường dẫn (path) và phương thức HTTP (operation). Mỗi transition được gắn nhãn theo định dạng `HTTPMethod-path-HTTPStatusCode` (ví dụ: `get-/rest/basket/{bid}-200`).
- **Algorithm 3**: Kết nối các transition dựa trên trường `links` trong phần `responses` của OpenAPI. Điều này cho phép mô hình hóa luồng dữ liệu giữa các endpoint (ví dụ: sau khi login thành công, client nhận được `bid` và `token`, sau đó dùng `bid` để gọi endpoint lấy giỏ hàng).

> **Lưu ý**: Công cụ yêu cầu đặc tả OpenAPI phải có trường `links` để liên kết các phản hồi (responses) với các operation khác. Mặc dù trường này ít được sử dụng trong thực tế (chỉ 9/1955 đặc tả trên APIs.guru sử dụng), nhưng nó cần thiết để xây dựng mô hình CPN chính xác.

### Bước 2: Kiểm tra tính tuân thủ (Conformance Checking)
Sau khi có mô hình CPN và nhật ký sự kiện (JSON event logs) từ máy chủ web (bao gồm HTTP method, path, headers, request body, response body, và authorization header), công cụ thực hiện:
- **Replay** từng trace (dấu vết) trong event log lên mô hình CPN.
- So sánh hành vi thực tế với hành vi được mô hình hóa.
- Phát hiện các sai lệch (deviations) về luồng điều khiển và luồng dữ liệu, chẳng hạn như:
  - Truy cập tài nguyên với `bid` không khớp với `bid` nhận được từ phản hồi login.
  - Thực hiện các operation mà không có đủ quyền (token không hợp lệ).
- Xuất ra **Error log file** đánh dấu các cuộc tấn công BOLA tiềm năng.

## Ví dụ minh họa (Running Example)
Bài báo sử dụng ứng dụng **OWASP Juice Shop** làm ví dụ. Quy trình tương tác:
1. Client gửi `POST /login` với thông tin đăng nhập.
2. Server trả về `{"bid": "1", "token": "eyJ..."}`.
3. Client gửi `GET /basket/1` với token hợp lệ.
4. Server trả về dữ liệu giỏ hàng.

**Kịch bản tấn công BOLA**: Kẻ tấn công gửi `GET /basket/2` (thay đổi `bid`) với token của mình. Mô hình CPN sẽ phát hiện rằng `bid` trong request không khớp với `bid` được sinh ra từ transition login trước đó, từ đó đánh dấu đây là hành vi bất thường.
Mô hình CPN thu được (Hình 3 trong bài báo) bao gồm:
- Transition `post-/rest/user/login-200` (tạo ra `bid` và `token`).
- Transition `get-/rest/basket/{bid}-200` (tiêu thụ `bid`).
- Cung nối (arc) giữa hai transition được gắn nhãn `bid`, thể hiện ràng buộc dữ liệu.
## Kết quả thực nghiệm
- **Độ chính xác**: >95% trong các kịch bản phát hiện BOLA.
- **Case study 1**: OWASP Juice Shop (lỗ hổng BOLA cơ bản).
- **Case study 2**: Memos (dịch vụ ghi chú mã nguồn mở, lỗ hổng BOLA liên quan đến thao tác lưu trữ ghi chú, đã được vá năm 2022).
- **Đánh giá người dùng**: Công cụ được thử nghiệm trên các đặc tả OpenAPI thực tế.
## Cài đặt và Sử dụng
### Yêu cầu hệ thống
- Python 3.x
- Thư viện phụ thuộc (xem `requirements.txt` trong repository)
- CPN Tools (để trực quan hóa và phân tích mô hình CPN, tùy chọn)
### Cài đặt
```bash
git clone https://github.com/ailton07/Links2CPN.git
cd Links2CPN
pip install -r requirements.txt
