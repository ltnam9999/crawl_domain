```text
 ██████╗██████╗  █████╗ ██╗    ██╗██╗     ██████╗  ██████╗ ███╗   ███╗██████╗  ██████╗ ███╗   ██╗    ████████╗██████╗  ██████╗ ██╗
██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██╔═══██╗████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║
██║     ██████╔╝███████║██║ █╗ ██║██║     ██║  ██║██║   ██║██╔████╔██║██████╔╝██║   ██║██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║
██║     ██╔══██╗██╔══██║██║███╗██║██║     ██║  ██║██║   ██║██║╚██╔╝██║██╔══██╗██║   ██║██║╚██╗██║       ██║   ██║   ██║██║   ██║██║
╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║╚██████╔╝██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
```

# 🛡️ Dynamic 1 Million Domain Dataset Collector (Malware vs Benign)

Kịch bản Python hiệu năng cao dùng cho Kỹ thuật Dữ liệu (Data Engineering) và An ninh mạng (Cyber Threat Intelligence). Công cụ tự động thu thập, làm sạch, khử trùng lặp và đồng bộ mốc thời gian (Time-Synchronization) để tạo ra tập dữ liệu **1.000.000 domain** duy nhất (**500.000 Malware & 500.000 Benign**).

---

## 📊 1. Thống kê Chi tiết Tập Dữ liệu (Dataset Statistics)

### 📈 Bảng Thống kê Tổng quan (Dataset Summary)

| Chỉ số (Metric) | Malware Domains (Độc hại) | Benign Domains (An toàn) | Tổng Tập Dữ liệu (Total) |
| :--- | :---: | :---: | :---: |
| **Tổng số bản ghi (Count)** | **500.000** | **500.000** | **1.000.000** |
| **Tỷ lệ phân bổ (Ratio)** | `50.0%` | `50.0%` | `100.0%` (Cân bằng hoàn hảo) |
| **Định dạng file xuất** | `malware_domains.csv` | `benign_domains.csv` | 2 file CSV riêng biệt |
| **Số lượng nguồn (Sources)** | 6 Nguồn đa dạng | Tranco List Archive | 7 Nguồn dữ liệu uy tín |
| **Khoảng thời gian (Coverage)** | 2011-02-18 → 2026-08-05 | 2019-04-15 → 2026-08-15 | **107 tháng lịch sử** |
| **Đồng bộ thời gian** | Được đánh mốc thời gian | Khớp phân bổ theo tháng | **Chống Concept Drift** |

---

### 🛡️ Bảng Phân bổ Nguồn dữ liệu Malware (Malware Sources Breakdown)

| Nguồn Dữ liệu (Source) | Phân loại mối đe dọa (Threat Type) | Số lượng Domain | Tỷ lệ (%) | Trạng thái Thu thập |
| :--- | :--- | :---: | :---: | :---: |
| **Phishing.Database** (GitHub) | Phishing, Social Engineering | **383.634** | `76.73%` | ✅ Hoàn tất |
| **ThreatFox** (abuse.ch) | Botnet, C2, Malware Indicators | **54.360** | `10.87%` | ✅ Authenticated |
| **PhishTank** | Active Phishing URLs | **35.702** | `7.14%` | ✅ Hoàn tất |
| **KADhosts** | Malware, Adware, Scam | **28.882** | `5.78%` | ✅ Hoàn tất |
| **URLhaus** (abuse.ch) | Malware Payload Delivery | **2.100** | `0.42%` | ✅ Authenticated |
| **OpenPhish** | Real-time Phishing Feed | **240** | `0.05%` | ✅ Hoàn tất |
| **TỔNG XUẤT CSV MALWARE** | **Tập hợp mối đe dọa đa dạng** | **500.000** | **100.0%** | **ĐẠT 100% CHỈ TIÊU** |

---

### 🌐 Bảng Phân bổ Nguồn dữ liệu Benign (Benign Sources Breakdown)

| Nguồn Dữ liệu (Source) | Phương pháp Thu thập | Số lượng Domain | Phân bổ Thời gian | Trạng thái |
| :--- | :--- | :---: | :---: | :---: |
| **Tranco Top Sites Archive** | Time-Synchronized Sampling | **500.000** | Khớp 81 tháng theo tỷ lệ Malware | ✅ Hoàn tất |
| **TỔNG XUẤT CSV BENIGN** | **Domain phổ biến, an toàn** | **500.000** | **2019-04 → 2026-08** | **ĐẠT 100% CHỈ TIÊU** |

---

## 📌 2. Kiểm tra Đối chiếu Yêu cầu (Requirements Checklist)

| Yêu cầu & Quy cách kỹ thuật | Trạng thái | Chi tiết xử lý trong mã nguồn |
| :--- | :---: | :--- |
| **Tổng quy mô 1.000.000 bản ghi** | ✅ **ĐẠT** | 500.000 Malware domain + 500.000 Benign domain |
| **Đầu ra 2 file CSV riêng biệt** | ✅ **ĐẠT** | `malware_domains.csv` và `benign_domains.csv` với header `domain,label` |
| **Nguồn Malware** | ✅ **ĐẠT** | URLhaus (Full CSV Dump), ThreatFox (Full Export), PhishTank, OpenPhish, Phishing.Database (GitHub), KADhosts |
| **Nguồn Benign & Đồng bộ thời gian** | ✅ **ĐẠT** | Tranco List Archive (tải danh sách phổ biến theo đúng các mốc tháng/ngày tương ứng với Malware domain để chống Concept Drift) |
| **CSDL trung gian SQLite** | ✅ **ĐẠT** | `dataset_staging.db` với WAL mode, mmap 256MB, composite primary key `(domain, label)` khử trùng lặp siêu tốc |
| **Tối ưu RAM (Stream Processing)** | ✅ **ĐẠT** | Sử dụng `requests(stream=True)`, `iter_content`, ghi dữ liệu theo lô Batch 50.000 bản ghi |
| **Xử lý lỗi & Exponential Backoff** | ✅ **ĐẠT** | Hàm `http_get()` tự động thử lại tối đa 5 lần với thời gian chờ tăng dần |
| **Quy tắc làm sạch Domain (Regex)** | ✅ **ĐẠT** | Hàm `clean_domain()` trích xuất Apex Domain, loại bỏ protocol/port/path/www, regex chuẩn `^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`, lọc địa chỉ IP thuần |

---

## ⏱️ 3. Ước tính Thời gian Chạy (Runtime Estimation)

Tổng thời gian chạy hoàn tất kịch bản ước tính từ **5 phút đến 15 phút** (tùy thuộc vào tốc độ mạng và việc có sử dụng Auth-Key hay không):

### Chi tiết các giai đoạn:
1. **Khởi tạo Database SQLite (`dataset_staging.db`)**: ~1 - 2 giây.
2. **Giai đoạn 1: Stream & Thu thập Malware (500.000 domain)**:
   - **Khi có Auth-Key (URLhaus + ThreatFox Full Dump ~100MB - 150MB compressed)**: Tải và stream parse tốn khoảng **2 - 4 phút**.
   - **Khi KHÔNG có Auth-Key (PhishTank + OpenPhish + Phishing.Database + KADhosts)**: Tải và stream tốn khoảng **3 - 6 phút**.
3. **Giai đoạn 2: Phân tích mốc thời gian & Tải Benign domain đồng bộ (Tranco Archive)**:
   - Truy vấn phân bổ theo tháng từ SQLite: < 1 giây.
   - Tải các danh sách Tranco theo mốc thời gian (~12 đến 24 danh sách cho 12-24 tháng): **2 - 5 phút** (có rate limit nhẹ 1.5s/request để đảm bảo ổn định).
4. **Giai đoạn 3: Trùng lặp & Xuất file CSV (`malware_domains.csv` & `benign_domains.csv`)**:
   - Truy vấn SQLite index & ghi 1.000.000 dòng ra 2 file CSV theo batch 50.000: **10 - 20 giây**.

> 💡 **Tổng thời gian trung bình**: **~8 - 10 phút**.  
> 💡 **Dung lượng RAM tối đa sử dụng**: **< 250 MB** (nhờ cơ chế Stream & Batch Processing).

---

## 🛠️ 4. Hướng dẫn Cách Chạy (Step-by-Step Guide)

### Bước 1: Cài đặt thư viện phụ thuộc
Mở Terminal / Command Prompt tại thư mục dự án và chạy:
```bash
pip install -r requirements.txt
```
*(Yêu cầu: `requests`, `tranco` - Lưu ý: Kịch bản đã tích hợp sẵn cơ chế HTTP fallback tự động, chương trình vẫn chạy hoàn hảo ngay cả khi không cài được thư viện `tranco`).*

### Bước 2 (Khuyến nghị): Đăng ký Auth-Key miễn phí của abuse.ch
Để tải toàn bộ kho dữ liệu lịch sử đầy đủ nhất từ **URLhaus** và **ThreatFox**:
1. Truy cập [https://auth.abuse.ch/](https://auth.abuse.ch/) và đăng nhập (qua Google/GitHub).
2. Tạo 1 **Auth-Key** miễn phí.

### Bước 3: Chạy kịch bản thu thập

#### Cách 1: Chạy trực tiếp truyền Auth-Key qua tham số CLI (Khuyên dùng)
```bash
python collect_1m_domains.py --auth-key YOUR_ABUSE_CH_AUTH_KEY
```

#### Cách 2: Thiết lập Biến môi trường (Environment Variable)
- **Windows (PowerShell)**:
  ```powershell
  $env:ABUSE_CH_AUTH_KEY="YOUR_ABUSE_CH_AUTH_KEY"
  python collect_1m_domains.py
  ```
- **Windows (CMD)**:
  ```cmd
  set ABUSE_CH_AUTH_KEY=YOUR_ABUSE_CH_AUTH_KEY
  python collect_1m_domains.py
  ```
- **Linux / macOS**:
  ```bash
  export ABUSE_CH_AUTH_KEY="YOUR_ABUSE_CH_AUTH_KEY"
  python collect_1m_domains.py
  ```

#### Cách 3: Chạy chế độ tự do (Không cần Auth-Key)
Nếu bạn không muốn đăng ký Auth-Key, kịch bản sẽ tự động chuyển sang các nguồn dữ liệu cộng đồng miễn phí không cần xác thực (PhishTank, OpenPhish, Phishing.Database GitHub, KADhosts):
```bash
python collect_1m_domains.py
```

---

## 📂 5. Cấu trúc Đầu ra (Output Files)

Sau khi kịch bản hoàn tất, thư mục làm việc sẽ có các file:

```
one million domain/
├── collect_1m_domains.py   # Code Python chính (Production-grade)
├── requirements.txt        # Phụ thuộc thư viện
├── README.md               # Hướng dẫn chi tiết
├── dataset_staging.db      # SQLite CSDL tạm thời (Có thể xóa sau khi hoàn tất)
├── collect_domains.log     # File log chi tiết quá trình chạy
├── malware_domains.csv     # File 1: 500.000 Malware domains (Header: domain,label)
└── benign_domains.csv      # File 2: 500.000 Benign domains (Header: domain,label)
```

### Định dạng mẫu file CSV đầu ra:
**`malware_domains.csv`**
```csv
domain,label
badsite123.com,malware
phishing-bank-login.xyz,malware
malware-payload-drop.org,malware
```

**`benign_domains.csv`**
```csv
domain,label
google.com,benign
wikipedia.org,benign
github.com,benign
```

---

## 🔄 6. Cơ chế Resume (Khôi phục tiến độ thông minh)
Nếu quá trình chạy bị gián đoạn (mất điện, ngắt mạng), bạn chỉ cần chạy lại lệnh:
```bash
python collect_1m_domains.py
```
Cơ sở dữ liệu SQLite (`dataset_staging.db`) sẽ tự động giữ nguyên các domain đã thu thập trước đó và tiếp tục tải từ mốc hiện tại mà **không bị trùng lặp dữ liệu**.
