# Links2CPN: Phát hiện tấn công BOLA trong REST API bằng chuyển đổi OpenAPI → Colored Petri Nets

> **Báo cáo tóm tắt và phân tích công cụ Links2CPN**
> Nguồn: Santos Filho, A., Rodríguez, R. J., Feitosa, E. L. (2025). *Automated broken object-level authorization attack detection in REST APIs through OpenAPI to colored petri nets transformation*. International Journal of Information Security, 24:83. DOI: [10.1007/s10207-024-00970-5](https://doi.org/10.1007/s10207-024-00970-5)
> Mã nguồn công cụ: <https://github.com/ailton07/openapi-links-to-CPNs>

---

## Mục lục

1. [Tổng quan](#1-tổng-quan)
2. [Bối cảnh và vấn đề](#2-bối-cảnh-và-vấn-đề)
3. [Kiến thức nền tảng](#3-kiến-thức-nền-tảng)
4. [Phương pháp](#4-phương-pháp)
5. [Kiến trúc và triển khai công cụ](#5-kiến-trúc-và-triển-khai-công-cụ)
6. [Định dạng nhật ký (event log)](#6-định-dạng-nhật-ký-event-log)
7. [Đánh giá thực nghiệm](#7-đánh-giá-thực-nghiệm)
8. [Hạn chế và các mối đe dọa đến tính hợp lệ](#8-hạn-chế-và-các-mối-đe-dọa-đến-tính-hợp-lệ)
9. [So sánh với các công trình liên quan](#9-so-sánh-với-các-công-trình-liên-quan)
10. [Nhận xét](#10-nhận-xét)
11. [Hướng phát triển](#11-hướng-phát-triển)
12. [Tài liệu tham khảo chính](#12-tài-liệu-tham-khảo-chính)

---

## 1. Tổng quan

| Mục | Nội dung |
|---|---|
| **Tên công cụ** | Links2CPN |
| **Mục tiêu** | Tự động phát hiện tấn công *Broken Object Level Authorization* (BOLA) trong REST API |
| **Đầu vào** | (1) Đặc tả OpenAPI 3.x **có trường `links`**; (2) nhật ký máy chủ web (JSON event log) |
| **Đầu ra** | Mô hình Colored Petri Net (CPN) và tệp log lỗi liệt kê các yêu cầu bị nghi là tấn công BOLA |
| **Ngôn ngữ / thư viện** | Python 3, [Snakes](https://snakes.ibisc.univ-evry.fr/) (thư viện Petri net), `openapi-schema-validator` |
| **Kỹ thuật cốt lõi** | Biến đổi mô hình (model-to-model) + *conformance checking* (token-based replay) |
| **Chế độ hoạt động** | Phân tích **offline** trên log |
| **Kết quả chính** | Phát hiện BOLA với độ chính xác > 95% trong các kịch bản đề xuất |

**Ý tưởng chính:** Đặc tả OpenAPI được chuyển thành một CPN mô tả luồng hợp lệ của các thao tác API. Sau đó, nhật ký thực thi của máy chủ được "phát lại" (replay) trên CPN. Nếu một yêu cầu cố truy cập đối tượng (ví dụ `bid`, `memoId`) **không khớp** với giá trị mà máy chủ đã cấp trước đó cho chính người dùng đó, transition không thể kích hoạt (fire) → bị coi là vi phạm luồng dữ liệu → nghi ngờ tấn công BOLA.

---

## 2. Bối cảnh và vấn đề

### 2.1. REST API và OpenAPI

- **REST** là phong cách kiến trúc phần mềm cho dịch vụ web, với các ràng buộc: Client–Server, Stateless, Cache, Uniform Interface, Layered System và Code-On-Demand (tùy chọn).
- **OpenAPI Specification (OAS)** là chuẩn mô tả REST API độc lập ngôn ngữ, dạng JSON/YAML, gồm các trường như `openapi`, `info`, `servers`, `paths`, `components`, `security`... Trong đó `paths` liệt kê endpoint và các thao tác (`Operation`), kèm `parameters`, `requestBody`, `responses` và tùy chọn **`links`** (mô tả quan hệ giữa phản hồi và thao tác khác).

### 2.2. BOLA

*Broken Object Level Authorization* là lỗ hổng cho phép kẻ tấn công đọc, sửa hoặc xoá dữ liệu mà lẽ ra chỉ người dùng được ủy quyền mới được thao tác (ví dụ đổi trạng thái đơn hàng, xoá tài khoản). Đây là rủi ro #1 trong *OWASP API Security Top 10 2019* và liên quan tới nhóm *Broken Access Control* trong OWASP Top 10 2023.

Cách khai thác điển hình rất đơn giản: gửi `GET /basket/{bid}` với `bid` khác với giá trị máy chủ cấp cho người dùng khi đăng nhập.

---

## 3. Kiến thức nền tảng

### 3.1. Colored Petri Nets (CPN)

CPN mở rộng Petri net cổ điển bằng **dữ liệu (màu)**, thời gian và phân cấp:

- **Place** (vị trí): chứa token, mỗi place có *color set* (kiểu dữ liệu).
- **Transition** (chuyển tiếp): có *guard* (điều kiện), kích hoạt khi các place đầu vào có đủ token phù hợp *binding*.
- **Arc** (cung): gắn biểu thức, quyết định token nào được lấy/sinh ra.
- Trạng thái hệ thống = số lượng token + giá trị (màu) của chúng tại các place.

Trong bài báo, mọi transition có mức ưu tiên bằng 1.

### 3.2. Conformance checking (process mining)

Là nhóm kỹ thuật so sánh **hành vi dự kiến (mô hình)** với **hành vi quan sát (event log)**. Links2CPN dùng thuật toán *token-based replay* cho CPN của Carrasquel và cộng sự (2021): phát lại từng trace trên CPN để phát hiện sai lệch về luồng điều khiển và luồng dữ liệu.

---

## 4. Phương pháp

Quy trình gồm hai bước chính:

```mermaid
flowchart LR
    A[OpenAPI spec<br/>có trường links] -->|1. Model-to-model<br/>transformation| B[CPN model]
    C[JSON event logs<br/>từ web server] --> D
    B -->|2. Conformance<br/>checking / replay| D{Replay}
    D --> E[Error log<br/>cảnh báo BOLA]
```

### 4.1. Bước 1 – Chuyển đổi OpenAPI → CPN

Thuật toán gồm 3 phần:

**Algorithm 1 – Tạo CPN từ đặc tả OpenAPI**
1. Gọi `createTransitionsForPaths` (Algorithm 2).
2. Gọi `connectTransitionsForPaths` (Algorithm 3).
3. Xoá các transition và place không có kết nối.

**Algorithm 2 – Tạo transition cho các path**
- Với mỗi *path* → mỗi *operation* → mỗi *response*:
  - Tạo một transition được gắn nhãn `HTTPMethod-path-HTTPStatusCode` (ví dụ `get-/rest/basket/{bid}-200`) và id là `operationId`.
  - Tạo một *place tiền điều kiện* (preset) cho transition đó.
  - Nếu operation có tham số, cung đi ra từ place được gắn nhãn bằng tên tham số (ví dụ `bid`).

**Algorithm 3 – Kết nối các transition**
- Nếu một response có `links` trỏ tới operation khác, transition của response đó được nối tới **place tiền điều kiện** của transition thuộc operation đích. Cung này được gắn nhãn bằng tham số trong `links`.

### 4.2. Ví dụ minh họa (Juice Shop)

Từ đặc tả có `POST /rest/user/login` (response 200 có `links → getBasketById`) và `GET /rest/basket/{bid}`:

- Transition `post-/rest/user/login-200` → (cung gắn hàm lấy `authentication.bid` từ response body) → place `bid get-/rest/basket/{bid}` → (cung `bid`) → transition `get-/rest/basket/{bid}-200`.
- Ý nghĩa: sau khi đăng nhập, máy chủ "cấp" cho người dùng một token mang giá trị `bid`. Chỉ yêu cầu `GET /rest/basket/{bid}` với đúng `bid` đó mới làm transition kích hoạt được.

### 4.3. Bước 2 – Phát hiện BOLA bằng replay

Replay lần lượt từng dòng log trên CPN. Một transition **không thể kích hoạt** vì một trong hai lý do:

| Trường hợp | Nguyên nhân | Ý nghĩa |
|---|---|---|
| (i) | Không có token ở place đầu vào | **Vi phạm luồng điều khiển** (control-flow violation) |
| (ii) | Token có giá trị khác kỳ vọng | **Vi phạm luồng dữ liệu** (data-flow violation) |

Tác giả giả định rằng **vi phạm luồng dữ liệu tương ứng với tấn công BOLA**, nên phát hiện loại vi phạm này trên CPN tức là phát hiện BOLA.

---

## 5. Kiến trúc và triển khai công cụ

- **Ngôn ngữ:** Python 3.
- **Thư viện:** `Snakes` (tạo, biến đổi, thao tác Petri net) và `openapi-schema-validator` (kiểm tra và diễn giải OpenAPI 3.x).
- **Hai thành phần chính:**
  1. *Transformer*: đọc OpenAPI → sinh CPN (Algorithm 1–3).
  2. *Conformance checker*: nạp JSON event log → replay trên CPN → ghi lỗi.
- **Mô hình CPN** tương thích để phân tích thêm bằng **CPN Tools**.
- **Mã nguồn, log mẫu và kết quả đánh giá** được công bố trong repository GitHub của tác giả.

### Kế hoạch cải tiến kiến trúc (theo bài báo)

- Áp dụng **Strategy pattern** để hỗ trợ nhiều chiến lược xử lý log tuỳ định dạng đầu vào.
- Áp dụng **Adapter pattern** để chuẩn hoá định dạng log nội bộ, giảm phụ thuộc vào từng loại máy chủ.

---

## 6. Định dạng nhật ký (event log)

Log cần chứa: URL, tham số URL, phương thức HTTP, status code, IP client, header HTTP (Authorization), timestamp, **request body** và **response body**. Đây là mở rộng của Common Log Format (CLF). Công cụ hiện làm việc với log đã chuyển sang JSON; log của Apache2/nginx cần chỉnh sửa nhỏ khi phân tích.

Ví dụ một bản ghi:

```json
{
  "timestamp": "2022-11-01T22:35:33.107Z",
  "ip": "::1",
  "message": "GET /rest/user/whoami 200 4ms",
  "method": "GET",
  "uri": "/rest/user/whoami",
  "requestBody": {},
  "responseBody": { "user": { "id": "123" } },
  "statusCode": 200,
  "headerAuthorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."
}
```

**Về chi phí hiệu năng:** tác giả cho rằng overhead của việc ghi log thêm body là nhỏ và có thể giảm bằng ghi log bất đồng bộ hoặc API gateway có sẵn tính năng logging.

---

## 7. Đánh giá thực nghiệm

### 7.1. Ba kịch bản đánh giá

| Kịch bản | Ứng dụng | Mục tiêu |
|---|---|---|
| Ví dụ chạy thử | OWASP Juice Shop | Kiểm tra tính đúng đắn trên môi trường kiểm soát |
| Đánh giá với người dùng | OWASP Juice Shop (CTF với sinh viên) | Đánh giá trong kịch bản gần thực tế hơn |
| Phần mềm thực tế | Memos (ứng dụng ghi chú mã nguồn mở) | Kiểm tra trên lỗ hổng BOLA đã từng được báo cáo |

### 7.2. Ví dụ chạy thử trên Juice Shop

Hai lỗ hổng BOLA được kiểm tra:

- **Vulnerability 1 – View cart:** xem giỏ hàng người khác (`GET /rest/basket/{bid}` với `bid` khác).
- **Vulnerability 2 – Manipulate cart:** thêm sản phẩm vào giỏ hàng người khác (`POST /api/BasketItems/` với `BasketId` khác).

Công cụ phát hiện thành công cả hai. Ví dụ thông báo lỗi khi gặp tấn công V1 (log dòng 29):

```text
Fire error, line 29: transition not enabled for
{
  "bid ->": { "bid": "None", "user_id": "::ffff:179.176.231.14" },
  "request ->": { "uri": "/rest/basket/7", "method": "GET", ... }
}
```

Nghĩa là không có token `bid = 7` nào dành cho người dùng này tại place tương ứng.

### 7.3. Đánh giá với người dùng (CTF)

- **Đối tượng:** 15 sinh viên Khoa học máy tính (UFAM), học phần *Computer Network Security*.
- **Thời gian:** 25/01/2023 – 08/02/2023, chạy Juice Shop trên AWS EC2.
- **Thu được:** 12 báo cáo tấn công, khoảng 4.000 dòng log, 2.000 request được phân tích.
- Các tác giả **phân tích thủ công** log để làm chuẩn (ground truth), rồi so với kết quả của công cụ.

**Bảng 1 – Dữ liệu thu được**

| | V1 | V2 |
|---|---:|---:|
| Tổng số request | 517 | 192 |
| Số lần thử tấn công (attack attempts) | 101 | 88 |
| Tấn công thành công | 98 | 20 |
| Request bị công cụ phân loại là tấn công | 101 | 88 |

**Bảng 2 – Kết quả phân loại**

*(a) So sánh "thử tấn công" với kết quả phát hiện*

| | V1 | V2 |
|---|---:|---:|
| Accuracy / Precision / Recall / F1 | 1,00 | 1,00 |
| Ma trận nhầm lẫn (TP / FP / FN / TN) | 101 / 0 / 0 / 416 | 88 / 0 / 0 / 104 |

*(b) So sánh "tấn công thành công" với kết quả phát hiện*

| Chỉ số | V1 | V2 |
|---|---:|---:|
| Accuracy | 0,99 | 0,64 |
| Precision | 0,97 | 0,22 |
| Recall | 1,00 | 1,00 |
| F1-score | 0,98 | 0,37 |
| Ma trận nhầm lẫn (TP / FP / FN / TN) | 98 / 3 / 0 / 416 | 20 / 68 / 0 / 104 |

**Diễn giải:**

- Công cụ phát hiện **mọi lần thử tấn công** (cả thất bại lẫn thành công) với độ chính xác tuyệt đối trong dữ liệu này.
- Khi chỉ xét **tấn công thành công**, Recall luôn bằng 1 nhưng Precision của V2 thấp (0,22) vì công cụ không phân biệt được lần thử thất bại với lần thành công. Tác giả đề xuất bổ sung heuristic, chẳng hạn xét status code của phản hồi hoặc nhờ chuyên gia phân tích thủ công.
- Tỷ lệ thành công của V1 là 97,02% (98/101), của V2 là 22,72% (20/88). Tác giả cho rằng điều này có thể do độ khó khác nhau (2 sao so với 3 sao theo hướng dẫn của Juice Shop); 3 trong 12 sinh viên nộp báo cáo không khai thác được V2.

### 7.4. Phần mềm thực tế: Memos

- API Memos từng có lỗ hổng BOLA ở thao tác lưu trữ (archive) ghi chú, đã được sửa năm 2022. Nhóm tác giả **hoàn nguyên bản vá** để tái tạo lỗ hổng.
- Luồng: `GET /api/v1/memo` (liệt kê ghi chú) và `POST /api/v1/memo` (tạo ghi chú) cấp các `memoId` hợp lệ; `PATCH /api/v1/memo/{memoId}` (5 mã phản hồi 200, 400, 401, 404, 500) dùng để lưu trữ ghi chú.
- Tấn công: `PATCH /api/v1/memo/6` với `memoId` không thuộc người dùng. Log gồm 11 dòng; công cụ báo lỗi tại dòng 11 và phát hiện thành công.

---

## 8. Hạn chế và các mối đe dọa đến tính hợp lệ

### 8.1. Hạn chế kỹ thuật

1. **Phụ thuộc vào trường `links` của OpenAPI.** Trường này hiếm được sử dụng: trong 1.955 đặc tả từ APIs.guru, chỉ **9** đặc tả có `links`. Tác giả giả định đội phát triển sẽ chủ động bổ sung (thủ công, bằng công cụ sinh từ chú thích mã nguồn, hoặc có AI hỗ trợ).
2. **Đặc tả phải chính xác**, gồm cả các trường hợp lỗi; nếu không, hiệu năng phát hiện sẽ giảm.
3. **Log phải tập trung.** Với hệ thống phân tán cao có thể khó thực hiện; nếu có nhiều tệp log cùng khoảng thời gian, cần sắp xếp theo thời gian trước khi xử lý.
4. **Chỉ phân tích offline**, chưa phát hiện theo thời gian thực.
5. **Chỉ nhận JSON log** do công cụ tạo ra từ log máy chủ; cần điều chỉnh để dùng với máy chủ khác.
6. **Gắn với đặc tả OpenAPI cụ thể** (3.x), có thể phải thích nghi với phiên bản tương lai.
7. **Không phân biệt thử tấn công và tấn công thành công** nếu không có thêm heuristic (xem Precision của V2).
8. Yêu cầu **ghi thêm request/response body** vào log, làm tăng một ít chi phí lưu trữ và ghi.

### 8.2. Tính hợp lệ của nghiên cứu (theo bài báo)

- **Ngoại tại (External validity):** mẫu không mang tính đại diện thống kê; dùng như các case study. Tác giả nhận định Petri net có thể kết hợp với khai phá dữ liệu / phát hiện bất thường để bắt các kiểu tấn công chưa biết.
- **Tái lập (Reliability):** công cụ, ví dụ và dữ liệu đánh giá được công khai trên GitHub.

---

## 9. So sánh với các công trình liên quan

| Hướng tiếp cận | Công trình | Đặc điểm | So với Links2CPN |
|---|---|---|---|
| Phân tích tĩnh đặc tả OpenAPI | Barabanov và cs. (2022) | Gắn cờ endpoint *có thể* dễ bị IDOR/BOLA, cần chuyên gia xác minh | Bổ trợ: Links2CPN phát hiện tấn công thực tế trên log |
| Mở rộng OpenAPI | Haddad & Malki (2022), OAS ESS | Thêm kiểm soát ủy quyền khai báo, module ủy quyền lúc chạy; phải sửa đặc tả, gắn với FastAPI | Links2CPN không can thiệp vào ứng dụng, chỉ phân tích log |
| Kiểm thử bảo mật | NAUTILUS, VOAPI | Sinh chuỗi request để tìm lỗ hổng; chủ yếu là kiểm thử xâm nhập | Links2CPN hướng tới **phát hiện** tấn công |
| Mô hình Petri net cho REST | Service Nets, REST Chart, Kallab và cs. | Mô hình hóa REST, không dựa trên chuẩn OpenAPI hoặc không xét nhiều người dùng đồng thời | Links2CPN dựa trên chuẩn OpenAPI và biểu diễn được nhiều người dùng |
| UML / FSM | Alowisheq, Rauf, WAPIML, Zuzak | Mô hình hóa cấu trúc, trạng thái | Không tập trung vào luồng dữ liệu |

Theo các tác giả, theo hiểu biết của họ chưa có giải pháp nào trong tài liệu nhắm trực tiếp vào việc **phát hiện tấn công BOLA** bằng cách dùng OpenAPI làm mô hình chuẩn.

---

## 10. Nhận xét

**Điểm mạnh**

- Cách tiếp cận có **cơ sở hình thức** (CPN + conformance checking), kết quả phát hiện mang tính xác định.
- Tận dụng chuẩn **OpenAPI** phổ biến; mô hình CPN trực quan và có thể phân tích thêm bằng CPN Tools.
- **Không cần sửa mã ứng dụng** (chỉ cần ghi log phù hợp).
- Có **công cụ mã nguồn mở** và dữ liệu thực nghiệm để tái lập.
- Phát hiện đầy đủ (Recall = 1) trong tất cả các thí nghiệm.

**Điểm cần lưu ý (nhận xét của người viết báo cáo)**

- Con số "độ chính xác > 95%" trong tóm tắt chủ yếu dựa trên việc so với *lần thử tấn công*. Khi so với *tấn công thành công*, độ chính xác của V2 chỉ là 0,64 và Precision 0,22. Cần đọc con số này cùng ngữ cảnh.
- Tập dữ liệu **thiên về tấn công** (nhiều request tấn công, ít lưu lượng hợp lệ), chưa phản ánh phân bố lưu lượng thực tế; tác giả cũng thừa nhận và dự định đánh giá lại với tỷ lệ request hợp lệ cao hơn.
- Quy mô thử nghiệm nhỏ (hai ứng dụng, một nhóm 15 sinh viên); log chuẩn (ground truth) được gắn nhãn thủ công bởi chính tác giả.
- Trong phần định nghĩa chỉ số của bài báo, các khái niệm TP/TN được mô tả theo cách hơi đảo ngược (coi "tấn công" là lớp âm tính khi định nghĩa, nhưng bảng kết quả dùng lớp tấn công làm lớp dương); người đọc nên dựa vào các ma trận nhầm lẫn ở Bảng 2 thay vì các định nghĩa chữ.
- Phụ thuộc mạnh vào `links` và chất lượng đặc tả, là rào cản đáng kể cho việc áp dụng rộng rãi.

---

## 11. Hướng phát triển

- Giảm yêu cầu về `links` bằng cách **sinh mô hình từ chú thích mã nguồn**.
- **Đánh giá rộng hơn** với phân bố lưu lượng thực tế, tỷ lệ request hợp lệ cao hơn.
- Kết hợp **fuzzing** để sinh tương tác HTTP, biến công cụ thành công cụ kiểm thử xâm nhập REST API.
- **Phân tích thời gian thực**, tích hợp trực tiếp vào máy chủ web (ví dụ dùng **eBPF**).
- Mô-đun hoá xử lý log (Strategy / Adapter) để hỗ trợ nhiều loại máy chủ.
- Kết hợp **học máy / phát hiện bất thường** để bắt các kiểu tấn công chưa biết.

---

## 12. Tài liệu tham khảo chính

1. Santos Filho, A., Rodríguez, R. J., Feitosa, E. L. *Automated broken object-level authorization attack detection in REST APIs through OpenAPI to colored petri nets transformation*. Int. J. Inf. Secur. 24, 83 (2025). <https://doi.org/10.1007/s10207-024-00970-5>
2. Links2CPN – OpenAPI Links to CPNs (GitHub): <https://github.com/ailton07/openapi-links-to-CPNs>
3. Jensen, K., Kristensen, L. M. *Coloured Petri Nets: Modelling and Validation of Concurrent Systems*. Springer (2009).
4. Carrasquel, J. C., Mecheraoui, K., Lomazova, I. A. *Checking Conformance Between Colored Petri Nets and Event Logs*. Springer (2021).
5. Barabanov, A. và cs. *Automatic detection of access control vulnerabilities via API specification processing*. arXiv:2201.10833 (2022).
6. Haddad, R., Malki, R. E. *OpenAPI specification extended security scheme*. arXiv:2212.06606 (2022).
7. OpenAPI Specification v3.1.0: <https://spec.openapis.org/oas/v3.1.0>
8. OWASP Juice Shop: <https://owasp.org/www-project-juice-shop/>
9. OWASP API Security Project: <https://owasp.org/www-project-api-security/>
10. Memos: <https://github.com/usememos/memos>
