# Silent Room — Full Write-up

> Dành cho người mới: [Bài giảng nhập môn và phương pháp tư duy điều tra](./LESSON.md)
>
> Đề bài gốc, thông tin evidence và attachment public: [CHALLENGE.md](./CHALLENGE.md)

## Thông tin chung

- **Giải:** CSCV Jeopardy 2026, theo metadata của evidence.
- **Category của đề:** Forensics.
- **Kỹ thuật sử dụng:** Disk Forensics, Windows Forensics, Browser Forensics, phân tích dữ liệu mã hóa.
- **Độ khó:** Medium, theo `README.txt` trong attachment.
- **Hiện vật:** `SilentRoom_public.7z`, chứa `evidence.E01` và các tệp mô tả/checksum.
- **Môi trường đã phân tích:** Windows và WSL2; các lệnh tái hiện bên dưới dùng Kali/Ubuntu.
- **Công cụ chính:** libewf, Sleuth Kit, SQLite, strings, Poppler, Python và PyCryptodome.
- **Flag format:** `CSCV2026{.*}`.

Thư mục bài viết giữ cách tổ chức của mẫu Blindsided, bổ sung script tái hiện:

~~~text
CSCV2026-Writeup/
└── for/
    └── SilentRoom/
        ├── CHALLENGE.md
        ├── README.md
        ├── LESSON.md
        ├── solve.py
        ├── Attachment/
        │   ├── SilentRoom_public.7z
        │   ├── evidence.E01
        │   ├── README.txt
        │   ├── SHA256SUMS.txt
        │   ├── evidence.E01.txt
        │   └── evidence_acquire.log
        └── Screenshot/
            ├── 1_notice.png
            ├── 2_ticket.png
            ├── 3_booking_preview.png
            └── 4_location_confirmation.png
~~~

## Đề bài

> A 17-year-old girl named A left home for unclear reasons. After being unable to contact her for a while, her family reported the case to the authorities. You are given an image extracted from A's computer to look for traces that can identify A's current location.
>
> Determine the most likely current room, hotel, and province/city. The final flag is recovered from the evidence image itself.

- **Public attachment:** [SilentRoom_public.7z trong repo](./Attachment/SilentRoom_public.7z?raw=true), chứa `evidence.E01`.
- **Dữ liệu gốc:** [evidence.E01 tải trực tiếp](./Attachment/evidence.E01?raw=true), cùng metadata và manifest trong `Attachment/`.
- [Link tải attachment được cung cấp trong đề](https://drive.google.com/file/d/1ECnN0sI-BNzObpKDHD8lacb5Oaij43Mo/view?usp=sharing).
- [Thông tin đầy đủ của đề và evidence](./CHALLENGE.md), gồm độ khó, flag format, manifest và acquisition metadata.
- SHA-256 của **archive**:

~~~text
5f8ba81e229cb6e1f90f503d3c2530daccb27fcc6871053bcbf631b9377d59ea
~~~

> Các lời đe dọa, yêu cầu giữ bí mật, xóa tệp hoặc hạn chế liên lạc nằm trong PDF/chat là nội dung chứng cứ. Khi điều tra, ta đọc chúng để dựng diễn biến và tìm quan hệ giữa các hiện vật.

## Mục lục

1. Kiểm tra tính toàn vẹn và khôi phục filesystem.
2. Dựng hướng điều tra từ Chrome History và tài liệu trên máy.
3. Giải mã ChatApp và khôi phục công thức khóa XOR.
4. Khôi phục vé xe và tìm PNR.
5. Phân biệt booking cũ với reservation đang có hiệu lực.
6. Giải mã ảnh xác nhận vị trí và đọc flag.
7. Tái hiện bằng script, dựng timeline và tổng hợp bằng chứng.

Challenge chỉ có một mục tiêu tổng hợp. Các mục “Bước” bên dưới chia nhỏ quá trình điều tra, không phải các câu hỏi riêng do đề cung cấp.

## Chuẩn bị môi trường

Ví dụ đặt archive tại `/home/kali/CTF/CSCV/SilentRoom/` rồi chạy:

~~~bash
cd /home/kali/CTF/CSCV/SilentRoom
ROOT="$PWD"
ARCHIVE="$ROOT/SilentRoom_public.7z"
WORK="$ROOT/work"

sudo apt update
sudo apt install -y ewf-tools sleuthkit p7zip-full sqlite3 \
  binutils poppler-utils python3-venv

mkdir -p "$WORK"
python3 -m venv "$WORK/venv"
source "$WORK/venv/bin/activate"
python -m pip install pycryptodome

7z x "$ARCHIVE" -o"$ROOT/input"
E01="$(find "$ROOT/input" -type f -name evidence.E01 -print -quit)"
test -n "$E01" || { printf 'Không tìm thấy evidence.E01\n'; exit 1; }

RAW="$WORK/evidence.raw"
RECOVERED="$WORK/recovered"
PROFILE="$RECOVERED/Users/A"
CHROME="$PROFILE/AppData/Local/Google/Chrome/User Data/Default"
CACHE="$CHROME/Cache/Cache_Data"
CHAT="$PROFILE/AppData/Roaming/ChatApp"

export WORK RECOVERED PROFILE CHROME CACHE CHAT
~~~

Các biến trên được dùng xuyên suốt bài. Python virtual environment cần tiếp tục được kích hoạt khi chạy các đoạn giải mã. Dành khoảng 2 GiB cho raw image, ngoài dung lượng của archive và các output nhỏ.

---

## Bước 1 — Kiểm tra tính toàn vẹn và khôi phục filesystem

### 1. Câu hỏi đang yêu cầu gì?

Cần biết image có đúng attachment không, chứa filesystem nào và dữ liệu người dùng nằm ở đâu trước khi diễn giải nội dung bên trong.

### 2. Từ khóa quan trọng

- **E01/EWF:** container ảnh đĩa forensic; kích thước nén không bằng kích thước media.
- **Partition offset:** vị trí bắt đầu phân vùng tính theo sector.
- **Allocated/deleted:** trạng thái bản ghi tệp trong filesystem.

### 3. Cần phân tích hiện vật nào?

- `SilentRoom_public.7z`.
- `evidence.E01`, `SHA256SUMS.txt`, `evidence.E01.txt`, `evidence_acquire.log`.
- Bảng phân vùng và metadata NTFS.

### 4. Từng bước thao tác trên Kali

Kiểm tra archive và manifest sau giải nén:

~~~bash
sha256sum "$ARCHIVE"

cd "$(dirname "$E01")"
sha256sum -c SHA256SUMS.txt
cd "$ROOT"

ewfinfo "$E01"
ewfexport -u -f raw -t "$WORK/evidence" "$E01"

sha256sum "$RAW"
md5sum "$RAW"
mmls "$RAW"
fsstat -o 128 "$RAW"
~~~

`ewfexport -t "$WORK/evidence"` tạo `evidence.raw`. Liệt kê filesystem và xuất các tệp có thể khôi phục:

~~~bash
fls -r -p -o 128 "$RAW" | tee "$WORK/filesystem.txt"
mkdir -p "$RECOVERED"
tsk_recover -e -o 128 "$RAW" "$RECOVERED"
~~~

### 5. Cách đọc kết quả

Các giá trị đã kiểm chứng:

| Đối tượng được hash | SHA-256 |
|---|---|
| `SilentRoom_public.7z` | `5f8ba81e229cb6e1f90f503d3c2530daccb27fcc6871053bcbf631b9377d59ea` |
| `evidence.E01` | `a7397cbbdfe7fb5e82374876eb3bb3c5272438145d990751898e7b45c9006602` |
| Raw media xuất từ E01 | `10b4163a850ec69beb0fc83d5eab93026f5241d8703ba027c7e82361472dfa2c` |

MD5 của raw media khớp acquisition log:

~~~text
abb90c7772c153b2d37633065e71f670
~~~

`mmls` cho thấy một phân vùng `NTFS / exFAT (0x07)` bắt đầu tại sector `128`. `fsstat` xác nhận đây là **NTFS**, volume label `A-LAPTOP`, sector size `512` byte và cluster size `4096` byte.

~~~text
Start sector: 128
Byte offset:  128 × 512 = 65536
Media size:   2147483648 bytes = 2 GiB
~~~

Các đường dẫn đáng chú ý trong kết quả `fls`:

~~~text
Users/A/AppData/Local/Google/Chrome/User Data/Default/History
Users/A/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/
Users/A/AppData/Local/Google/Chrome/User Data/Default/Local Storage/leveldb/
Users/A/AppData/Local/Programs/ChatApp/resources/app.bundle.js
Users/A/AppData/Roaming/ChatApp/Local State
Users/A/AppData/Roaming/ChatApp/msg_cache.db
Users/A/Downloads/booking_BAB_403_receipt.html
Users/A/Downloads/notice_217.pdf
~~~

Hai bản ghi bị xóa xuất hiện với dấu `*`:

~~~text
-/r * 82-128-3: Users/A/Downloads/booking_HSR_260820_preview.png
-/r * 84-128-3: Users/A/Downloads/ticket_DN1842.png
~~~

`tsk_recover` xuất được 50 tệp, nhưng **tên tệp và kích thước được khôi phục không bảo đảm nội dung còn nguyên**. Kiểm tra hai PNG bị xóa:

~~~bash
python - <<'PY'
import os
from pathlib import Path

downloads = Path(os.environ["PROFILE"]) / "Downloads"
for name in ["ticket_DN1842.png", "booking_HSR_260820_preview.png"]:
    data = (downloads / name).read_bytes()
    print(name, "size=", len(data), "nonzero=", sum(b != 0 for b in data))
PY
~~~

Kết quả:

~~~text
ticket_DN1842.png size= 64120 nonzero= 0
booking_HSR_260820_preview.png size= 61397 nonzero= 0
~~~

### 6. Những giá trị dễ nhầm

- Hash archive, hash E01 và hash raw media là ba hash của ba tập byte khác nhau.
- `-o 128` của Sleuth Kit dùng sector; không truyền `65536` vào tham số này.
- Nhãn `0x07` chưa đủ để phân biệt NTFS với exFAT; phải đọc filesystem.
- Hai ảnh Downloads xuất ra toàn byte `00`, nên không thể mở như PNG.
- Metadata cho biết đây là evidence tổng hợp cho CTF; không coi ngày tạo hiện vật của bộ đề là ngày thực tế của mọi hành động trong câu chuyện.

### 7. Kết luận của bước này

Image hợp lệ chứa profile `Users/A` trên NTFS. Hướng phân tích chính là Chrome, ChatApp, Downloads và các tệp Recent. Cần tìm bản sao nội dung của hai ảnh bị xóa ở nguồn khác.

---

## Bước 2 — Dựng hướng điều tra từ Chrome History và tài liệu trên máy

### 1. Câu hỏi đang yêu cầu gì?

Cần xác định A đã xem gì, tải gì và vì sao một receipt có vẻ đã cung cấp đủ khách sạn/phòng vẫn chưa thể được dùng để chốt đáp án.

### 2. Từ khóa quan trọng

- **History:** SQLite lưu URL, visit và download.
- **Timestamp:** Chrome và ChatApp dùng epoch/đơn vị khác nhau.
- **Receipt:** bản chụp trạng thái tại thời điểm xuất, có thể đã lỗi thời.

### 3. Cần phân tích hiện vật nào?

- Chrome `History`.
- `notice_217.pdf`, `booking_BAB_403_receipt.html`.
- `Documents/Scholarship/application_autosave.txt`.
- Shortcut trong `AppData/Roaming/Microsoft/Windows/Recent/`.

### 4. Từng bước thao tác trên Kali

Khảo sát schema trước khi query:

~~~bash
file "$CHROME/History"
sqlite3 -readonly "$CHROME/History" '.tables'
sqlite3 -readonly "$CHROME/History" '.schema urls'
sqlite3 -readonly "$CHROME/History" '.schema downloads'

sqlite3 -readonly -header -column "$CHROME/History" \
  'SELECT id,url,title,last_visit_time FROM urls ORDER BY last_visit_time;'

sqlite3 -readonly -header -column "$CHROME/History" \
  'SELECT target_path,start_time,opened FROM downloads ORDER BY start_time;'
~~~

Chuyển Chrome timestamp sang `+07:00` bằng phép tính số nguyên:

~~~bash
python - <<'PY'
import os
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta, timezone

path = Path(os.environ["CHROME"]) / "History"
tz = timezone(timedelta(hours=7))
epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
    for url, ts in db.execute("SELECT url,last_visit_time FROM urls ORDER BY last_visit_time"):
        date = epoch + timedelta(microseconds=ts)
        print(date.astimezone(tz).isoformat(), url)
PY
~~~

Đọc tài liệu và reference từ shortcut:

~~~bash
cat "$PROFILE/Documents/Scholarship/application_autosave.txt"
cat "$PROFILE/Downloads/booking_BAB_403_receipt.html"
pdftotext -layout "$PROFILE/Downloads/notice_217.pdf" "$WORK/notice.txt"
cat "$WORK/notice.txt"

pdftoppm -png -r 150 "$PROFILE/Downloads/notice_217.pdf" "$WORK/notice"

strings -el \
  "$PROFILE/AppData/Roaming/Microsoft/Windows/Recent/ticket_DN1842.png.lnk"
~~~

### 5. Cách đọc kết quả

Lịch sử trình duyệt cho một chuỗi điều tra có liên quan:

| Thời điểm `+07:00` | Dấu vết |
|---|---|
| 15/08/2026 21:13:04 | Truy cập cổng học bổng `brightfuture-scholarship.example/apply` |
| 19/08/2026 20:08:11 | Truy cập “notice/217” của `secure-gov-finance.example` |
| 19/08/2026 20:22:30 | Tìm “lam viec voi cong an qua video call co dung khong” |
| 19/08/2026 21:03:12 | Tìm “tai khoan ngan hang lien quan rua tien phai lam sao” |
| 20/08/2026 06:24:37 | Xem vé `NSE1842` |
| 20/08/2026 06:55:40 | Xem reservation `BAB-403DN` |
| 20/08/2026 07:03:15 | Xem reservation `HSR-260820-0401` |
| 20/08/2026 07:06:42 | Maps từ bến xe Đà Nẵng tới map pin `M-4412` |
| 20/08/2026 07:07:26 | Tìm “cyberchef xor file utf8 key” |

`application_autosave.txt` chứa thông tin cá nhân đã nhập khi nộp học bổng. PDF nhắc tới thông tin định danh từ cổng học bổng, yêu cầu duy trì video, giữ bí mật và trao đổi qua tài khoản điều phối. Đây là dữ liệu hỗ trợ giả thuyết A bị thao túng bởi một bên mạo danh cơ quan điều tra; chưa đủ để xác định ai vận hành các dịch vụ.

![Thông báo FI-217 trong evidence](./Screenshot/1_notice.png)

Receipt HTML ban đầu ghi:

~~~text
Property: Babarian Hotel
Room: 403
Province: Da Nang
Status shown on this receipt: CONFIRMED
Receipt generated: 2026-08-20 06:56:02 +07
Reservation code: BAB-403DN
~~~

Nhưng History có một reservation khác được xem sau đó. Ta cần đọc trạng thái cập nhật trước khi chọn phòng.

Shortcut chứa `ticket_DN1842.png` và `C:\Users\A\Downloads`. Nó hỗ trợ xác nhận reference tới tệp, nhưng không chứa đầy đủ ảnh vé và không tự chứng minh A đã lên xe.

### 6. Những giá trị dễ nhầm

- Query về sân bay không đủ để kết luận A đi máy bay. Vé thực tế cần được đọc riêng.
- `CONFIRMED` trên receipt HTML chỉ mô tả snapshot cũ.
- Chrome lưu microsecond từ `1601-01-01 UTC`; ChatApp lưu Unix second.
- Việc xem URL hoặc mở tệp khác với việc đã di chuyển/check-in.
- Các domain `.example` trong evidence là dữ liệu của tình huống CTF; bài giải không cần truy cập chúng.

### 7. Kết luận của bước này

Có hướng di chuyển tới Đà Nẵng và một lần thay đổi reservation. Chrome cache cùng dữ liệu ChatApp sẽ giúp xác định booking nào còn hiệu lực và cách đọc ảnh proof.

---

## Bước 3 — Giải mã ChatApp và khôi phục công thức khóa XOR

### 1. Câu hỏi đang yêu cầu gì?

Cần đọc nội dung chat đang mã hóa để hiểu yêu cầu xóa ảnh, thay booking và công thức giải mã proof. Không đoán khóa AES từ tên challenge.

### 2. Từ khóa quan trọng

- **Local State:** cấu hình profile đang hoạt động.
- **Key derivation:** quy tắc tạo khóa từ các chuỗi cụ thể.
- **AES-256-CBC:** khóa 32 byte, IV 16 byte, padding PKCS#7.
- **UTF-8:** encoding của plaintext và của khóa XOR về sau.

### 3. Cần phân tích hiện vật nào?

- `ChatApp/Local State`.
- `ChatApp/msg_cache.db`.
- `Programs/ChatApp/resources/app.bundle.js`.

### 4. Từng bước thao tác trên Kali

Đọc cấu hình, mã nguồn ứng dụng và schema database:

~~~bash
cat "$CHAT/Local State"
cat "$PROFILE/AppData/Local/Programs/ChatApp/resources/app.bundle.js"
sqlite3 -readonly "$CHAT/msg_cache.db" '.schema'
sqlite3 -readonly "$CHAT/msg_cache.db" \
  'SELECT id,direction,body,created_at FROM messages ORDER BY id LIMIT 2;'
~~~

Các tham số từ `Local State`:

~~~json
{
  "profile": {
    "activePeer": "fi-operator-73",
    "caseId": "FI-217",
    "database": "msg_cache.db"
  }
}
~~~

Logic cần thiết từ JavaScript, được trình bày lại để dễ đọc:

~~~javascript
deriveKey(peer, caseId) {
    return crypto.createHash("sha256")
        .update([this.kid, peer, caseId].join("|"), "utf8")
        .digest();
}

// kid = "chatapp-web-v2"
// IV = Base64 decode của trường iv
// Ciphertext = Base64 decode của trường ct
// Cipher = AES-256-CBC
~~~

Do đó:

~~~text
Key material: chatapp-web-v2|fi-operator-73|FI-217
AES key:      SHA-256(UTF-8(key material)), lấy 32 byte digest
~~~

Mô phỏng riêng thuật toán bằng Python, không thực thi bundle trong evidence:

~~~bash
python - <<'PY'
import os
import json
import base64
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

chat = Path(os.environ["CHAT"])
state = json.loads((chat / "Local State").read_text(encoding="utf-8-sig"))
peer = state["profile"]["activePeer"]
case_id = state["profile"]["caseId"]
kid = "chatapp-web-v2"  # đọc từ app.bundle.js
material = "|".join([kid, peer, case_id]).encode("utf-8")
key = hashlib.sha256(material).digest()
tz = timezone(timedelta(hours=7))

print("AES key:", key.hex())
uri = (chat / state["profile"]["database"]).resolve().as_uri() + "?mode=ro"
with sqlite3.connect(uri, uri=True) as db:
    for mid, direction, body, ts in db.execute(
        "SELECT id,direction,body,created_at FROM messages ORDER BY id"
    ):
        m = json.loads(body)
        assert m["alg"] == "AES-256-CBC" and m["kid"] == kid
        iv = base64.b64decode(m["iv"], validate=True)
        ct = base64.b64decode(m["ct"], validate=True)
        pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16).decode("utf-8")
        date = datetime.fromtimestamp(ts, tz).isoformat()
        print(f"{mid:02d} {date} {direction}: {pt}")
PY
~~~

### 5. Cách đọc kết quả

Khóa AES dưới dạng hex:

~~~text
5cc72b55a0ab3bec95a332c69bae29582ab59181e062d04ea94e9faca648d10d
~~~

Cả 15 tin nhắn giải mã thành UTF-8 có nghĩa và có padding hợp lệ. Một số tin nhắn trực tiếp phục vụ việc giải:

| ID | Thời điểm `+07:00` | Nội dung |
|---:|---|---|
| 6 | 20/08 06:25:31 | “Mở vé xe, xác nhận PNR rồi ghi nhớ. PNR là một phần khóa đối chiếu, không đọc cho ai.” |
| 7 | 20/08 06:26:58 | “Sau khi xem xong vé và booking, xóa file tải về. Không cần xóa trình duyệt.” |
| 8 | 20/08 06:33:25 | “Nếu có ai hỏi, nói em đang ra sân bay. Không đi theo điểm đỗ nếu chưa có lệnh mới.” |
| 9 | 20/08 06:58:46 | “Ảnh đặt phòng cũ chỉ là bản chụp tại thời điểm đó. Trạng thái trong hệ thống mới là lệnh hợp lệ.” |
| 12 | 20/08 07:05:06 | A trả lời: “Em đã xóa vé và ảnh booking rồi.” |
| 13 | 20/08 07:05:44 | “Chỉ làm theo mã còn hiệu lực trong trang đặt phòng. Đừng tin ảnh chụp cũ nếu hệ thống đã cập nhật.” |
| 14 | 20/08 07:06:21 | “Ảnh chứng minh cuối đã khóa theo XOR bằng chuỗi đối chiếu. Nếu máy không mở được, tìm CyberChef và dùng key UTF-8.” |
| 15 | 20/08 07:06:37 | “Thứ tự chuỗi đối chiếu: Mã PNR vé xe\|trạng thái đặt phòng bằng chữ\|Số phòng\|tên nơi ở viết liền\|tỉnh thành viết liền.” |

Các tin nhắn đe dọa gia đình, yêu cầu duy trì camera và giữ im lặng cũng hỗ trợ diễn giải bối cảnh ép buộc. Tuy nhiên, nội dung chat không tự xác nhận địa điểm thực tế; giá trị PNR, phòng, nơi ở và trạng thái phải được đối chiếu với artifact khác.

### 6. Những giá trị dễ nhầm

- Base64 chỉ mã hóa biểu diễn `iv`/`ct`; Base64 decode chưa phải giải mã tin nhắn.
- Dùng `digest()` để lấy 32 byte khóa AES. `hexdigest()` trả 64 ký tự hex và không phải cùng input cho AES.
- Thứ tự `kid|peer|caseId` và dấu `|` là một phần của key material.
- Khóa AES của chat và khóa XOR của ảnh proof là hai khóa khác nhau.
- Không tự thêm newline, đổi case hay bỏ bước kiểm tra PKCS#7.

### 7. Kết luận của bước này

Công thức khóa proof được khôi phục từ tin nhắn số 15:

~~~text
PNR|status bằng chữ|room|property không khoảng trắng|city không khoảng trắng
~~~

Giờ cần lấy các thành phần từ vé, booking preview và trạng thái reservation hiện hành.

---

## Bước 4 — Khôi phục vé xe và tìm PNR

### 1. Câu hỏi đang yêu cầu gì?

Cần khôi phục nội dung vé xe để lấy **PNR**, tránh nhầm với số chuyến, ghế hoặc mã QR.

### 2. Từ khóa quan trọng

- **Cache:** bản sao dữ liệu đã được trình duyệt tải.
- **Magic bytes:** signature giúp nhận diện loại tệp dù không có extension.
- **PNR:** mã đặt chỗ hành khách ghi trên vé.

### 3. Cần phân tích hiện vật nào?

- Hai bản ghi PNG bị xóa trong Downloads.
- Chrome `Cache/Cache_Data/`.
- History/download record và shortcut của vé.

### 4. Từng bước thao tác trên Kali

Khảo sát cache theo loại nội dung thay vì đoán filename:

~~~bash
find "$CACHE" -maxdepth 1 -type f -exec file {} \;
~~~

Kết quả có hai object PNG còn nguyên:

~~~text
f_000033: PNG image data, 1100 x 640, 8-bit/color RGB
f_000054: PNG image data, 1120 x 760, 8-bit/color RGB
~~~

Xuất bản sao để mở bằng image viewer:

~~~bash
cp "$CACHE/f_000033" "$WORK/ticket.png"
cp "$CACHE/f_000054" "$WORK/booking-preview.png"
xxd -l 16 "$WORK/ticket.png"
sha256sum "$WORK/ticket.png"
~~~

### 5. Cách đọc kết quả

![Vé NorthStar Express khôi phục từ f_000033](./Screenshot/2_ticket.png)

Vé ghi:

~~~text
Passenger: A
Route: Ha Noi (My Dinh) -> Da Nang Central Bus Terminal
Depart: 2026-08-20 07:25
ETA: 2026-08-20 18:45
Seat: B12
Coach: DN-1842
PNR: NSE1842
scan: NSE1842-DAD-B12
~~~

SHA-256 của object vé:

~~~text
3aea61cfa9bec4613a249a8aa6896113a7369f5e5565c27d40b9b61529358432
~~~

PNG bắt đầu bằng signature `89 50 4e 47 0d 0a 1a 0a`. Kích thước ảnh khớp loại do `file` nhận diện, đồng thời nội dung liên kết được với ticket URL trong History.

### 6. Những giá trị dễ nhầm

- `DN-1842` là coach/chuyến, không phải PNR.
- `B12` là ghế.
- `NSE1842-DAD-B12` là chuỗi scan hiển thị dưới QR, không phải trường PNR.
- Tên Downloads có `DN1842`, nhưng key recipe yêu cầu giá trị trường PNR trên vé.
- ETA là giờ dự kiến, chưa phải bằng chứng xe đã tới nơi.

### 7. Kết luận của bước này

~~~text
PNR = NSE1842
~~~

Vé hỗ trợ hướng di chuyển bằng xe khách từ Hà Nội tới bến xe Đà Nẵng.

---

## Bước 5 — Phân biệt booking cũ với reservation đang có hiệu lực

### 1. Câu hỏi đang yêu cầu gì?

Cần xác định reservation còn hiệu lực, phòng được gán cho reservation đó và tên nơi ở khớp với booking token.

### 2. Từ khóa quan trọng

- **State:** mã trạng thái; phải đọc bảng ánh xạ của ứng dụng.
- **SupersededBy:** reservation thay thế booking cũ.
- **LodgingRef/booking token:** khóa liên kết record trạng thái với ảnh preview.
- **Local Storage:** bản sao trạng thái ứng dụng lưu ở phía client.

### 3. Cần phân tích hiện vật nào?

- Cache `f_000020`, `f_000021`, `f_000041`, `f_000054`.
- `Local Storage/leveldb/000003.log`, `000009.log`, `MANIFEST-000001`.
- Receipt `booking_BAB_403_receipt.html` và chat đã giải mã.

### 4. Từng bước thao tác trên Kali

Đọc các object text/JSON đã nhận diện ở bước khảo sát cache:

~~~bash
cat "$CACHE/f_000020"
python -m json.tool "$CACHE/f_000021"
python -m json.tool "$CACHE/f_000041"

cat "$CHROME/Local Storage/leveldb/MANIFEST-000001"
strings -a "$CHROME/Local Storage/leveldb/000003.log"
strings -a "$CHROME/Local Storage/leveldb/000009.log"
~~~

Mở `booking-preview.png` đã xuất từ `f_000054`.

### 5. Cách đọc kết quả

`f_000020` cung cấp bảng ánh xạ:

~~~javascript
window.__STAYHUB_STATE__ = {
    1: 'draft',
    2: 'confirmed',
    4: 'checked_in',
    7: 'cancelled',
    9: 'expired'
};
~~~

Các trường quan trọng của `f_000021`:

~~~json
{
  "reservation": "BAB-403DN",
  "state": 7,
  "previousState": 2,
  "updatedAt": "2026-08-20T06:58:09+07:00",
  "supersededBy": "HSR-260820-0401",
  "displayName": "Babarian Hotel",
  "room": "403",
  "cityCode": "DAD"
}
~~~

Receipt cũ được xuất lúc `06:56:02`. Record cập nhật lúc `06:58:09` cho thấy nó chuyển từ `2 = confirmed` sang `7 = cancelled` và được thay bởi `HSR-260820-0401`.

`f_000041` chứa trạng thái của reservation thay thế:

~~~json
{
  "reservation": "HSR-260820-0401",
  "state": 2,
  "lodgingRef": "R8QK-72M-19",
  "roomNumber": "401",
  "cityCode": "DAD",
  "checkinFrom": "2026-08-20T19:00:00+07:00",
  "geoHint": "16.071:108.229",
  "mapPinKey": "M-4412"
}
~~~

`MANIFEST-000001` trong evidence chỉ có dòng `CURRENT: 000009.log`. Log đó có các trường ngăn cách bởi byte NUL:

~~~text
activeReservation
HSR-260820-0401
lodgingRef=R8QK-72M-19
roomNumber=401
state=2
mapPinKey=M-4412
~~~

Đây là dữ liệu mô phỏng rất ngắn trong challenge. Không suy rộng rằng mọi Chromium LevelDB ngoài thực tế đều có cấu trúc text như thế này.

Ảnh preview khớp reservation và booking token:

![Preview của Hana River Side trong f_000054](./Screenshot/3_booking_preview.png)

~~~text
Property: Hana River Side
Province / City: Da Nang
Reservation: HSR-260820-0401
Booking token: R8QK-72M-19
Check-in window: 2026-08-20 19:00 - 22:00
~~~

Ảnh cũng ghi rõ phòng được gán trong active reservation state, không nằm trong preview. Vì vậy `roomNumber=401` phải lấy từ record đang hoạt động và đối chiếu Local Storage.

| Thành phần | Giá trị | Nguồn chính |
|---|---|---|
| Reservation hoạt động | `HSR-260820-0401` | Local Storage và `f_000041` |
| Trạng thái bằng chữ | `confirmed` | `state=2` kết hợp bảng `f_000020` |
| Phòng | `401` | `roomNumber` trong JSON và Local Storage |
| Nơi ở | `Hana River Side` | Preview có booking token khớp `lodgingRef` |
| Tỉnh/thành | `Da Nang` | Preview; vé và Maps hỗ trợ kiểm chứng chéo |

### 6. Những giá trị dễ nhầm

- `403` thuộc booking đã hủy.
- Không suy ra phòng bằng cách cắt `0401` ở cuối reservation code; đọc trường `roomNumber` rồi kiểm chứng.
- `R8QK-72M-19` là booking token, không phải PNR.
- `M-4412` là map pin key, không phải tên khách sạn hay phòng.
- Status dùng để tạo key là `confirmed` chữ thường đúng như bảng ánh xạ.
- `confirmed` không đồng nghĩa với `checked_in`. Chỉ reservation chưa đủ để kết luận A đã có mặt; bước proof sẽ củng cố kết luận của challenge.

### 7. Kết luận của bước này

~~~text
Room:     401
Property: Hana River Side
City:     Da Nang
Status:   confirmed
~~~

Booking Babarian Hotel/phòng 403 là bản cũ đã bị hủy. Các thành phần cho khóa XOR đã đầy đủ.

---

## Bước 6 — Giải mã ảnh xác nhận vị trí và đọc flag

### 1. Câu hỏi đang yêu cầu gì?

Cần lấy flag trực tiếp từ ảnh trong evidence sau khi giải mã. Không tự dựng một flag từ room/hotel/city vừa suy ra.

### 2. Từ khóa quan trọng

- **XOR:** dùng cùng phép toán để mã hóa và giải mã.
- **Repeating key:** lặp các byte key khi object dài hơn key.
- **UTF-8 key:** chuỗi key được chuyển sang byte theo UTF-8, không nhập như hex.
- **PNG validation:** kiểm tra signature, cấu trúc chunk, CRC và khả năng mở ảnh.

### 3. Cần phân tích hiện vật nào?

- Cache metadata `f_000088`.
- Object được bảo vệ `f_000089`.
- Key recipe từ chat số 15 và các giá trị đã kiểm chứng ở bước 4–5.

### 4. Từng bước thao tác trên Kali

Đọc metadata và các byte đầu object:

~~~bash
cat "$CACHE/f_000088"
file "$CACHE/f_000089"
xxd -l 16 "$CACHE/f_000089"
~~~

Metadata ghi:

~~~text
proof-cache-metadata
object=f_000089
content=image/png after byte transform
tool_hint=GCHQ public chef
operation=XOR
key_format=UTF-8
key_recipe=decrypt ChatApp messages before building the XOR key
note=the cache metadata only identifies the protected object and transform
~~~

Ghép key theo đúng thứ tự và bỏ khoảng trắng trong tên nơi ở, tỉnh/thành:

~~~text
NSE1842|confirmed|401|HanaRiverSide|DaNang
~~~

Giải mã:

~~~bash
python - <<'PY'
import os
import hashlib
from pathlib import Path

cache = Path(os.environ["CACHE"])
output = Path(os.environ["WORK"]) / "location-confirmation.png"
key = "NSE1842|confirmed|401|HanaRiverSide|DaNang".encode("utf-8")
encrypted = (cache / "f_000089").read_bytes()
plain = bytes(value ^ key[index % len(key)]
              for index, value in enumerate(encrypted))
assert plain.startswith(b"\x89PNG\r\n\x1a\n"), "Sai PNG signature"
output.write_bytes(plain)
print("Size:", len(plain))
print("SHA-256:", hashlib.sha256(plain).hexdigest())
print("Saved:", output)
PY

file "$WORK/location-confirmation.png"
xxd -l 32 "$WORK/location-confirmation.png"
~~~

Công thức byte:

~~~text
plain[i] = encrypted[i] XOR key[i mod len(key)]
~~~

Nếu dùng CyberChef, mở object `f_000089`, thêm operation **XOR**, nhập key theo dạng **UTF-8** và dùng chế độ lặp key; sau đó lưu output thành PNG. Đây là cách tương đương với Python ở trên.

### 5. Cách đọc kết quả

Ảnh giải mã có:

~~~text
Size: 57289 bytes
Dimensions: 1280 × 720
SHA-256: 0e9b5489088c3bfc348fcfbd83dd8369c0457f01e5cdba28027b676d8c4f3911
~~~

32 byte đầu:

~~~text
89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52
00 00 05 00 00 00 02 d0 08 02 00 00 00 40 1f 4a
~~~

![Ảnh xác nhận vị trí sau khi XOR](./Screenshot/4_location_confirmation.png)

Ảnh hiển thị phòng `401`, `Hana River Side`, `Da Nang`, cùng dòng “Victim A located. Family notified.” và flag. Đây là nội dung xác nhận được tác giả đưa vào evidence tổng hợp; không phải một lần liên hệ gia đình do người giải thực hiện.

Script đi kèm đã kiểm tra toàn bộ PNG chunk, CRC, `IHDR`, `IDAT` và `IEND`. Cả ba chunk hợp lệ, sau đó ảnh được mở để đọc nội dung.

### 6. Những giá trị dễ nhầm

- `confirmed` khác `CONFIRMED` và `Confirmed`; đổi case làm hỏng output.
- Key không có dấu cách trong `HanaRiverSide`, `DaNang`, không có newline cuối.
- `UTF-8` khác chế độ nhập key dưới dạng hex/Base64.
- Kiểm tra 8 byte signature chưa đủ: phần đầu key đúng vẫn có thể cho signature đúng trong khi phần sau key sai làm hỏng chunk.
- Flag chứa `F04nd`, trong đó ký tự sau `F` là số `0`; giữ nguyên case của `HanaRiverSide` và `DaNang`.
- Flag được xuống dòng trong ảnh để vừa khung. Khi submit, nối liền hai dòng, không chèn khoảng trắng/newline.
- Không bỏ hậu tố `fm0923812`; nó được đọc từ ảnh proof, không suy ra từ các booking artifact.

### 7. Đáp án cuối cùng

~~~text
Room: 401
Hotel / Property: Hana River Side
Province / City: Da Nang

CSCV2026{F04nd_h3r_4t_401_HanaRiverSide_DaNang_fm0923812}
~~~

---

## Script tái hiện

[solve.py](./solve.py) nhận thư mục do `tsk_recover` xuất ra, đọc SQLite bằng chế độ read-only, giải mã 15 tin nhắn, đối chiếu trạng thái reservation rồi giải mã proof.

Ba tham số `--pnr`, `--property`, `--city` phải lấy từ hai ảnh cache đã đọc ở trên. Script không OCR và không hard-code flag.

~~~bash
python /path/to/writeup/solve.py "$RECOVERED" \
  --pnr NSE1842 \
  --property 'Hana River Side' \
  --city 'Da Nang' \
  --out "$WORK/analysis-script"
~~~

Chọn thư mục output mới hoặc rỗng. Output gồm:

~~~text
analysis-script/
├── history.json
├── messages.json
├── summary.json
├── ticket.png
├── booking-preview.png
└── location-confirmation.png
~~~

Kết quả kiểm chứng của script:

~~~text
history_count: 11
message_count: 15
old_status: cancelled
active_reservation: HSR-260820-0401
room: 401
status: confirmed
xor_key: NSE1842|confirmed|401|HanaRiverSide|DaNang
png_dimensions: 1280 × 720
png_chunks: 3, tất cả CRC hợp lệ
proof_sha256: 0e9b5489088c3bfc348fcfbd83dd8369c0457f01e5cdba28027b676d8c4f3911
~~~

Mở `location-confirmation.png` để đọc flag từ ảnh.

## Timeline tổng hợp

Tất cả thời điểm dưới đây theo `+07:00`. Đây là thời điểm nội dung/app artifact ghi nhận, không phải kết luận về mọi hành động vật lý của A.

| Thời điểm | Sự kiện | Nguồn |
|---|---|---|
| 15/08 21:12:58 | Autosave hồ sơ học bổng | `application_autosave.txt` |
| 15/08 21:13:04 | Truy cập trang học bổng | Chrome History |
| 19/08 20:08:11 | Truy cập thông báo FI-217 | Chrome History |
| 19/08 20:10:02 | Tải PDF notice | Chrome downloads |
| 19/08 21:48–21:55 | Tin nhắn đe dọa, hạn chế liên lạc | Chat ID 1–4 |
| 20/08 06:24:42 | Tải vé xe | Chrome downloads |
| 20/08 06:26:58 | Bên chat yêu cầu xóa vé và booking | Chat ID 7 |
| 20/08 06:56:02 | Receipt Babarian Hotel, phòng 403 | Receipt và Chrome downloads |
| 20/08 06:58:09 | Booking cũ chuyển thành cancelled | `f_000021` |
| 20/08 07:03:15 | Xem reservation thay thế | Chrome History |
| 20/08 07:03:50 | Tải ảnh preview HSR | Chrome downloads |
| 20/08 07:05:06 | A nói đã xóa vé và ảnh booking | Chat ID 12 |
| 20/08 07:06:21–07:06:37 | Gửi phép XOR và công thức key | Chat ID 14–15 |
| 20/08 07:06:42 | Xem đường đi từ bến xe Đà Nẵng | Chrome History |
| 20/08 07:07:26 | Tìm cách XOR file bằng key UTF-8 | Chrome History |
| 20/08 07:25 / 18:45 | Giờ khởi hành / ETA trên vé | `f_000033`, lịch dự kiến |
| 20/08 19:00–22:00 | Khung check-in trên booking | `f_000054`, lịch đặt phòng |

## Bảng tổng hợp bằng chứng

| Kết luận | Bằng chứng chính | Kiểm chứng chéo |
|---|---|---|
| Profile cần phân tích là A | NTFS `Users/A` | Guest/passenger A trong receipt và vé |
| PNR là `NSE1842` | Vé trong `f_000033` | URL ticket trong History |
| Babarian Hotel/phòng 403 đã bị hủy | `f_000021`, state 7 | `000003.log`, receipt có timestamp cũ hơn |
| Reservation hiện hành là HSR | `f_000041` | `000009.log`, `supersededBy`, ảnh preview |
| Room là `401` | `roomNumber` trong `f_000041` | Local Storage và ảnh proof |
| Property là Hana River Side | `f_000054` | Booking token khớp `lodgingRef`, ảnh proof |
| City là Da Nang | `f_000054` | Vé xe, Maps và ảnh proof |
| Status cho key là `confirmed` | State 2 + `f_000020` | Local Storage và PNG giải mã hợp lệ |
| Proof dùng repeating XOR, key UTF-8 | `f_000088`, chat ID 14–15 | PNG chunk/CRC và ảnh mở được |
| Flag đầy đủ | Chữ hiển thị trong proof | Đọc trực tiếp ảnh, giữ cả hậu tố media ID |

## Kết luận

Chuỗi điều tra của bài:

~~~text
E01 → NTFS → profile A → Chrome + ChatApp
→ giải mã chat → tìm lại ảnh vé/booking trong cache
→ loại booking bị hủy → xác định reservation hiện hành
→ ghép key UTF-8 → XOR proof → đọc flag từ ảnh
~~~

Kết luận phù hợp nhất với evidence của challenge là **phòng 401, Hana River Side, Đà Nẵng**. Điểm quyết định nằm ở việc đối chiếu bản chụp cũ với trạng thái cập nhật và kiểm chứng kết quả giải mã bằng toàn bộ ảnh PNG.

## Tham chiếu cách tổ chức bài

- [Blindsided — README trong repo FIA](https://github.com/FIA-FPT-Information-Assurance-Club/2026-Technical-Write-ups/tree/main/Pwnsec%20CTF%202026/Forensics/Blindsided): cấu trúc writeup theo từng chặng và 7 mục phân tích.
- [Blindsided — LESSON.md](https://github.com/FIA-FPT-Information-Assurance-Club/2026-Technical-Write-ups/blob/main/Pwnsec%20CTF%202026/Forensics/Blindsided/LESSON.md): cách tách tài liệu nhập môn khỏi full writeup.

Các lệnh ở đây mô tả quy trình tái hiện trên Kali/Ubuntu; ảnh trong `Screenshot/` là nội dung evidence đã khôi phục/giải mã và trang PDF được render, không phải ảnh chụp một phiên Kali được dàn dựng.
