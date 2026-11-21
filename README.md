# Phát hiện lỗ hổng IDOR tự động trên ứng dụng Web dựa trên Mô hình Ngôn ngữ Lớn (LLM)

> **Đề tài Nghiên cứu Khoa học Học viên, Sinh viên (Năm học 2026 – 2027)**  
> **Mã nhiệm vụ:** `26.V4.50`  
> **Đơn vị chủ quản:** Viện Công nghệ thông tin và Truyền thông – Học viện Kỹ thuật Quân sự  
> **Trạng thái hiện tại:** Đang triển khai (Hoàn thành Báo cáo tiến độ lần 1 – `30%` khối lượng)

---

## 1. Tổng quan đề tài (Overview)

**IDOR (Insecure Direct Object Reference)** là lỗ hổng kiểm soát truy cập nghiêm trọng phát sinh khi ứng dụng Web cho phép người dùng truy cập trực tiếp vào các tài nguyên nội bộ thông qua tham số định danh do người dùng cung cấp mà thiếu cơ chế kiểm tra phân quyền hợp lệ (RBAC).

Các công cụ quét tự động truyền thống thường gặp hạn chế lớn khi phát hiện IDOR do thiếu khả năng hiểu **ngữ cảnh nghiệp vụ** và **chính sách phân quyền (RBAC)** của từng ứng dụng. Mục tiêu của đề tài là nghiên cứu, xây dựng công cụ tự động phát hiện lỗ hổng IDOR bằng cách kết hợp phân tích đặc tả API (**OpenAPI**), mô hình hóa đồ thị (**Links2CPN**) và khả năng suy luận của **Mô hình Ngôn ngữ Lớn (LLM)** nhằm kiểm tra chéo (cross-check) giữa hành vi truy cập thực tế và chính sách RBAC dự kiến, qua đó giảm thiểu tỷ lệ dương tính giả (False Positive) và âm tính giả (False Negative).

---

## 2. Tiến độ & Lộ trình nghiên cứu (Roadmap & Progress)

### Giai đoạn 1: Nghiên cứu cơ sở lý thuyết & Khảo sát (Đã hoàn thành - 30%)
- [x] Hệ thống hóa lý thuyết tổng quan về lỗ hổng IDOR (khái niệm, nguyên nhân, kịch bản tấn công, minh họa trực quan và hướng khắc phục).
- [x] Khảo sát, đánh giá sơ bộ các công cụ tự động phát hiện lỗ hổng hiện nay (phương pháp truyền thống và phương pháp ứng dụng AI).
- [x] Tìm hiểu cơ chế kiểm soát truy cập dựa trên vai trò (**RBAC**) và mối liên hệ giữa cấu hình RBAC sai lệch với lỗ hổng IDOR.

### Giai đoạn 2: Thiết kế giải pháp & Chuẩn hóa dữ liệu (Đang triển khai)
- [ ] Đề xuất kiến trúc tích hợp LLM vào quy trình phát hiện IDOR dựa trên mô hình đặc tả **OpenAPI** và công cụ **Links2CPN**.
- [ ] Thu thập và chuẩn hóa tập dữ liệu về cấu hình RBAC (vai trò, quyền hạn, tài nguyên) đa dạng định dạng từ các ứng dụng mẫu.

### Giai đoạn 3: Xây dựng công cụ & Thực nghiệm đánh giá (Kế hoạch tiếp theo)
- [ ] Xây dựng module kiểm tra chéo (cross-check) giữa hành vi truy cập thực tế và chính sách RBAC dự kiến để xác thực kết quả từ LLM.
- [ ] Chạy thử nghiệm thực tế, đo lường hiệu năng (Precision, Recall, tỷ lệ dương tính giả/âm tính giả) và tinh chỉnh mô hình.

---

## 3. Cấu trúc kho lưu trữ (Repository Structure)

*(Cấu trúc dự kiến phục vụ quá trình nghiên cứu và phát triển của nhóm)*

```text
├── docs/               # Tài liệu lý thuyết, báo cáo tiến độ, slide thuyết trình
│   └── Bao_cao_tien_do_lan_1.pdf
├── research/           # Tài liệu khảo sát công cụ cũ, OpenAPI, Links2CPN và mô hình RBAC
├── datasets/           # Tập dữ liệu cấu hình RBAC & đặc tả OpenAPI từ các ứng dụng mẫu
├── src/                # Mã nguồn công cụ (sẽ cập nhật trong Giai đoạn 2 & 3)
│   ├── parser/         # Xử lý đặc tả OpenAPI & tích hợp Links2CPN
│   ├── llm_engine/     # Module tích hợp LLM suy luận phân quyền & sinh kịch bản
│   └── cross_check/    # Module kiểm tra chéo hành vi thực tế và chính sách RBAC
└── README.md
