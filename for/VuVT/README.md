# VuVT — Full Write-up

> Dành cho người mới: phương pháp đối chiếu chứng cứ và khôi phục dữ liệu bị mã hóa.

[Đề bài và bộ dữ liệu gốc](./CHALLENGE.md) · [Tải VuVT.7z](https://github.com/Wolfsenpai123/CSCV2026-Writeup/releases/download/vuvt-challenge/VuVT.7z)

## Thông tin chung

- **Thể loại:** Windows Forensics, Network Forensics, Memory Forensics, Malware Analysis, Cryptography.
- **Hiện vật:** `sysmon.evtx`, `network.pcapng`, `mem.raw` và các thư mục thu thập từ máy Windows.
- **Môi trường thực tế:** Windows, PowerShell và Python.
- **Công cụ chính:** Wireshark/TShark, Get-WinEvent, Volatility 3, pefile, Capstone và cryptography.
- **Định dạng flag:** `CSCV2026{...}`.
- **Cảnh báo:** xem mọi executable trong bộ dữ liệu là không an toàn. Chỉ đọc metadata, mã máy và dữ liệu; không double-click hoặc chạy các chương trình của challenge. Tệp giải mã cũng không được tự động thực thi.

Bài viết sử dụng bố cục hướng dẫn của mẫu **Blindsided — Full Write-up**: mỗi phần giải thích mục tiêu, thuật ngữ, hiện vật, thao tác, cách đọc kết quả và những lỗi dễ nhầm. VuVT không cung cấp bộ câu hỏi riêng, nên bảy phần dưới đây là **câu hỏi dẫn dắt điều tra**, không phải danh sách câu hỏi chính thức.

Các lệnh được viết cho PowerShell, đúng với môi trường đã sử dụng. Đường dẫn gốc có thể thay đổi theo nơi bạn lưu challenge.

## Đề bài

> Ring... tuttt... tuttt...
>
> SOC: Alo, Vũ ấy hả em.
>
> VuVT: Anh ơi, em chỉ chạy update thôi mà sao máy em tự nhiên bị mã hóa rồi...
>
> SOC: Đừng động vào máy nữa. Bọn anh sẽ kiểm tra.

Một bộ dữ liệu được thu thập từ máy tính gặp sự cố. Hãy điều tra chuyện đã xảy ra và tìm thông tin cần thiết để khôi phục kết quả cuối cùng.

## Mục lục

1. Khảo sát bộ dữ liệu và gói cập nhật.
2. Xác định tiến trình gây mã hóa bằng Sysmon.
3. Khôi phục campaign từ lưu lượng mạng.
4. Phân tích thuật toán và cấu trúc tệp mã hóa.
5. Dựng khóa và đối chiếu với RAM.
6. Khôi phục nonce bị bỏ khỏi tệp.
7. Giải mã, kiểm chứng và lấy flag.

## Chuẩn bị môi trường

Trong lần phân tích này, dữ liệu nằm tại:

```text
D:\CTF\CSCV2026-Writeup\VuVT
```

Cài các thư viện phân tích vào môi trường Python của máy phân tích:

```powershell
py -m pip install volatility3 pefile capstone cryptography
```

Wireshark/TShark cần có sẵn trên máy. Các script đi kèm bài viết là `inspect_pe.py` để đọc mã máy và `solve.py` để khôi phục dữ liệu; cả hai không chạy executable thu được từ máy nạn nhân.

Thiết lập đường dẫn:

```powershell
$CHALLROOT = 'D:\CTF\CSCV2026-Writeup'
Set-Location -LiteralPath $CHALLROOT

$EVIDENCE = Join-Path $CHALLROOT 'VuVT'
$PROFILE = Join-Path $EVIDENCE 'Users\bkav'
$PCAP = Join-Path $EVIDENCE 'network.pcapng'
$EVTX = Join-Path $EVIDENCE 'sysmon.evtx'
$MEM = Join-Path $EVIDENCE 'mem.raw'
$DATA = Join-Path $EVIDENCE 'Users\Public\MetaData\Data'
$PACKAGE = Join-Path $PROFILE 'Downloads\UpdateX7A91C'
$BIN = Join-Path $PACKAGE 'update.exe'

$WRITEUP = Join-Path $CHALLROOT 'for\VuVT'
$WORK = Join-Path $CHALLROOT 'analysis_output'
$OUT = Join-Path $WORK 'restored'
New-Item -ItemType Directory -Path $WORK -Force | Out-Null

$TSHARK = 'C:\Program Files\Wireshark\tshark.exe'
$PYTHON_PREFIX = (py -c 'import sys; print(sys.prefix)').Trim()
$VOL = Join-Path $PYTHON_PREFIX 'Scripts\vol.exe'
```

Nếu TShark hoặc Volatility được cài ở nơi khác, thay `$TSHARK` hoặc `$VOL` bằng đường dẫn thực tế.

---

## Phần 1 — Bộ dữ liệu có gì và nên bắt đầu từ đâu?

### 1. Câu hỏi đang yêu cầu gì?

Trước khi tìm flag, cần hiểu nguồn chứng cứ và vị trí dữ liệu bị mã hóa. Mục tiêu là chọn các đầu mối đáng kiểm tra, chưa kết luận chương trình độc hại chỉ từ tên tệp.

### 2. Từ khóa quan trọng

- **EVTX:** nhật ký sự kiện Windows.
- **PCAPNG:** bản ghi các gói tin mạng.
- **Memory dump:** ảnh chụp RAM, có thể chứa tiến trình và khóa.
- **Hash:** dấu vân tay nội dung, dùng đối chiếu các bản sao.
- **Authenticode:** chữ ký số của executable; không chứng minh cả gói tải về là an toàn.

### 3. Cần phân tích hiện vật nào?

Thư mục gốc `VuVT`, `Downloads` của người dùng `bkav` và `Users\Public\MetaData\Data`.

### 4. Từng bước thao tác

```powershell
Get-ChildItem -LiteralPath $EVIDENCE
Get-ChildItem -LiteralPath $PACKAGE |
    Select-Object Name, Length
Get-ChildItem -LiteralPath $DATA |
    Select-Object Name, Length

Get-ChildItem -LiteralPath $PACKAGE -Filter '*.exe' |
    Get-FileHash -Algorithm SHA256

Get-ChildItem -LiteralPath $PACKAGE -Filter '*.exe' |
    ForEach-Object {
        $sig = Get-AuthenticodeSignature -LiteralPath $_.FullName
        [pscustomobject]@{
            Name = $_.Name
            Status = $sig.Status
            Signer = $sig.SignerCertificate.Subject
            OriginalFilename = $_.VersionInfo.OriginalFilename
        }
    }
```

Các thao tác trên chỉ đọc hiện vật, không khởi chạy executable.

### 5. Cách đọc kết quả

Các thành phần chính:

```text
VuVT/
├── mem.raw
├── network.pcapng
├── sysmon.evtx
└── Users/
    ├── bkav/Downloads/
    │   ├── UpdateX7A91C.7z
    │   └── UpdateX7A91C/
    │       ├── 7z2409-x64.exe
    │       ├── explorer.exe
    │       ├── key.exe
    │       ├── system.exe
    │       ├── update.exe
    │       └── updater.exe
    └── Public/MetaData/Data/
        ├── 1337dakl.txt.enc
        ├── 7z2409-x64.exe.enc
        ├── flag.jpeg.enc
        ├── hi.txt.enc
        ├── IMG_4287.jpeg.enc
        ├── IMG_4288.jpeg.enc
        └── ptit.txt.enc
```

`mem.raw` có 2.147.418.112 byte, gần 2 GiB. Có bảy tệp `.enc` và một gói cập nhật phù hợp với lời kể của nạn nhân.

Kiểm tra executable cho thấy:

| Tệp | Quan sát |
| --- | --- |
| `explorer.exe` | Có chữ ký Microsoft Windows hợp lệ |
| `key.exe` | Có chữ ký UniKey hợp lệ, original filename là `UniKeyNT.exe` |
| `system.exe` và `updater.exe` | Nội dung giống nhau, cùng SHA-256 |
| `update.exe` | Là đầu mối cần đối chiếu hành vi trong Sysmon |

Chữ ký và tên tệp giúp phân loại, nhưng kết luận thành phần gây mã hóa phải dựa trên hành vi.

### 6. Những giá trị dễ nhầm

- `key.exe` không đồng nghĩa với “tệp chứa khóa”; ở đây metadata nhận diện UniKey.
- `explorer.exe` trong Downloads khác đường dẫn `C:\Windows\explorer.exe`.
- `flag.jpeg.enc` chưa chắc chứa flag thật.
- Không chạy các executable để “xem nó làm gì”.

### 7. Kết luận của phần này

Có đủ ba nguồn để điều tra: **log, mạng và RAM**. Bắt đầu bằng Sysmon để tìm tiến trình đã tạo các tệp mã hóa.

---

## Phần 2 — Chương trình nào thực sự gây mã hóa?

### 1. Câu hỏi đang yêu cầu gì?

Cần tìm executable và phiên tiến trình cụ thể tạo các tệp `.enc`. Đây là bước phân biệt `update.exe` với các tệp khác trong cùng gói.

### 2. Từ khóa quan trọng

- **Event ID 1:** tạo tiến trình.
- **Event ID 3:** kết nối mạng.
- **Event ID 11:** tạo tệp.
- **PID:** mã số tiến trình, có thể được tái sử dụng.
- **ProcessGuid:** định danh giúp liên kết các event thuộc cùng phiên tiến trình.

### 3. Cần phân tích hiện vật nào?

`sysmon.evtx` và `Downloads\UpdateX7A91C\update.exe`.

### 4. Từng bước thao tác

Có thể đọc nhanh từng loại event:

```powershell
wevtutil qe "$EVTX" /lf:true /q:"*[System[(EventID=1)]]" /f:text
wevtutil qe "$EVTX" /lf:true /q:"*[System[(EventID=3)]]" /f:text
wevtutil qe "$EVTX" /lf:true /q:"*[System[(EventID=11)]]" /f:text
```

Để lọc và vẫn giữ hai trường thời gian riêng biệt, đọc XML của event:

```powershell
$events = Get-WinEvent -FilterHashtable @{
    Path = $EVTX
    Id = 1, 3, 11
}

$rows = foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    $fields = @{}
    foreach ($item in $xml.Event.EventData.Data) {
        $fields[[string]$item.Name] = [string]$item.'#text'
    }
    [pscustomobject]@{
        RecordId = $event.RecordId
        EventId = $event.Id
        Computer = [string]$xml.Event.System.Computer
        SystemTime = [string]$xml.Event.System.TimeCreated.SystemTime
        UtcTime = $fields['UtcTime']
        ProcessId = $fields['ProcessId']
        ProcessGuid = $fields['ProcessGuid']
        Image = $fields['Image']
        ParentImage = $fields['ParentImage']
        TargetFilename = $fields['TargetFilename']
        DestinationIp = $fields['DestinationIp']
        DestinationPort = $fields['DestinationPort']
        Hashes = $fields['Hashes']
    }
}

$rows | Where-Object { $_.Image -like '*\update.exe' } |
    Sort-Object RecordId | Format-List

Get-FileHash -LiteralPath $BIN -Algorithm SHA256
```

### 5. Cách đọc kết quả

Event ID 1, Record ID 3387:

```text
UtcTime:     2026-08-25 04:35:05.459
ProcessId:   2844
ProcessGuid: {BAD0321B-1B79-6A8D-B600-000000000500}
Image:       C:\Users\bkav\Downloads\UpdateX7A91C\update.exe
ParentImage: C:\Windows\explorer.exe
SHA256:      103E6A45DF3C16ECE88A9FF4C9A3D067E2EBDD634ACCE1EDFF5E0262AB7DF0C1
```

Hash khớp với binary có trong dữ liệu. Event ID 11 tiếp tục ghi nhận cùng `update.exe` tạo bảy tệp mã hóa dưới:

```text
C:\Users\Public\MetaData\Data\
```

Thời gian `UtcTime` của các lần tạo tệp nằm trong khoảng `04:35:06.006–04:35:06.163` ngày 25/08/2026.

**Lưu ý về timestamp:** Event mạng Record ID 3396, cùng PID và ProcessGuid, có:

```text
EventData.UtcTime:   2026-08-25 04:34:58.079
System.TimeCreated: 2026-08-25T04:35:07.1779364Z
Destination:        192.168.56.1:8080
```

Một trường thời gian đứng trước thời điểm tạo tiến trình; PCAP cũng có request trước mốc tạo tiến trình trong log. Không nên giấu bất nhất này hoặc tự kết luận log đã bị sửa. Trong bộ dữ liệu này, liên kết dựa vào **ProcessGuid, PID, Image, hash và đối chứng RAM**, không dựa riêng vào thứ tự timestamp. Chưa đủ bằng chứng xác định nguyên nhân lệch thời gian.

### 6. Những giá trị dễ nhầm

- `updater.exe` và `update.exe` là hai tệp khác nhau.
- PID `3164` là tiến trình cha, không phải tiến trình mã hóa.
- Không chỉ nhìn tên `update` để kết luận độc hại.
- Không ép các trường thời gian bất nhất thành một timeline chính xác giả tạo.

### 7. Đáp án cuối cùng

```text
C:\Users\bkav\Downloads\UpdateX7A91C\update.exe
PID: 2844
```

---

## Phần 3 — Chương trình nhận thông tin gì từ server?

### 1. Câu hỏi đang yêu cầu gì?

Cần xem trao đổi mạng liên quan gói cập nhật và tiến trình gây mã hóa. Phân tích tĩnh ở phần sau sẽ cho thấy giá trị `campaign` trong response là một đầu vào tạo khóa.

### 2. Từ khóa quan trọng

- **HTTP request/response:** yêu cầu của client và dữ liệu server trả về.
- **TCP stream:** các gói thuộc cùng một cuộc trao đổi TCP.
- **Campaign:** mã chiến dịch; phải giữ đúng nội dung và case.
- **Host/port/path:** các thành phần cần giữ khi dựng URL.

### 3. Cần phân tích hiện vật nào?

`network.pcapng` và Event ID 3 của `update.exe`.

### 4. Từng bước thao tác

Trong Wireshark, mở PCAP và dùng filter rộng:

```text
http.request
```

Hoặc liệt kê bằng TShark:

```powershell
& $TSHARK -r $PCAP -Y 'http.request' -T fields `
    -e frame.number -e tcp.stream -e frame.time_utc `
    -e ip.src -e http.request.method -e http.request.full_uri
```

Sau khi thấy endpoint `/api/check`, xác nhận request:

```text
http.request.uri contains "/api/check"
```

Chọn request → **Follow → TCP Stream**. Kết quả trên bộ dữ liệu này thuộc stream 2:

```powershell
& $TSHARK -r $PCAP -q -z 'follow,tcp,ascii,2'
```

### 5. Cách đọc kết quả

Máy nạn nhân `192.168.56.10` tạo các request đáng chú ý:

| Frame | Stream | Thời gian UTC 25/08/2026 | URL |
| ---: | ---: | --- | --- |
| 183 | 0 | `04:34:07.236723` | `http://192.168.56.1:1337/` |
| 196 | 1 | `04:34:09.808358` | `http://192.168.56.1:1337/UpdateX7A91C.7z` |
| 2741 | 2 | `04:34:58.444098` | `http://192.168.56.1:8080/api/check` |

Stream 2 chứa:

```http
GET /api/check HTTP/1.1
User-Agent: update.exe/1.0
Host: 192.168.56.1:8080
```

Response HTTP 200, Content-Type `application/json`:

```json
{"campaign":"X7A91C","status":"ok"}
```

HTTP response có Date `Tue, 25 Aug 2026 04:35:06 GMT`, cũng cho thấy không nên coi mọi timestamp của các nguồn là đồng nhất.

### 6. Những giá trị dễ nhầm

- `192.168.56.10` là nạn nhân; `192.168.56.1` là server trong capture.
- Port `1337` phục vụ gói tải về; port `8080` phục vụ API.
- `status` không phải campaign.
- Không chuyển `X7A91C` thành chữ thường.

### 7. Đáp án cuối cùng

```text
API: http://192.168.56.1:8080/api/check
Campaign: X7A91C
```

---

## Phần 4 — Tệp bị mã hóa bằng gì và có cấu trúc thế nào?

### 1. Câu hỏi đang yêu cầu gì?

Cần xác định thuật toán, độ dài khóa, nonce, tag, AAD và thứ tự dữ liệu ghi vào tệp. Chỉ biết “AES” chưa đủ để giải mã.

### 2. Từ khóa quan trọng

- **AES-256-GCM:** mã hóa xác thực, dùng khóa 32 byte.
- **Nonce:** giá trị đầu vào riêng cho lần mã hóa.
- **Tag:** mã xác thực, không phải nonce.
- **AAD:** dữ liệu được xác thực nhưng không mã hóa.
- **Magic:** các byte nhận diện định dạng tệp.

### 3. Cần phân tích hiện vật nào?

`update.exe` và các tệp `.enc`, đặc biệt `hi.txt.enc`.

### 4. Từng bước thao tác

Helper đi kèm chỉ đọc PE và disassemble mã máy:

```powershell
py "$WRITEUP\inspect_pe.py" "$BIN"
py "$WRITEUP\inspect_pe.py" "$BIN" --around 0x4055e7 --count 100
py "$WRITEUP\inspect_pe.py" "$BIN" --around 0x405cdb --count 60
py "$WRITEUP\inspect_pe.py" "$BIN" --around 0x405832 --end 0x405930

Format-Hex -Path (Join-Path $DATA 'hi.txt.enc') |
    Select-Object -First 3
```

Có thể import binary vào Ghidra để lần theo các lời gọi tương ứng. Những địa chỉ dưới đây là **virtual address của PE**, với image base `0x400000`.

### 5. Cách đọc kết quả

Các chuỗi đáng chú ý gồm `SHA256`, `ChainingModeGCM`, `"campaign"`, endpoint API và đường dẫn thư mục Public.

Đối chiếu tham số ở các vị trí:

| Địa chỉ | Vai trò |
| --- | --- |
| `0x4052dc` | Gọi `BCryptOpenAlgorithmProvider` |
| `0x4053e4` | Đặt chaining mode GCM qua `BCryptSetProperty` |
| `0x405498` | `BCryptGenerateSymmetricKey` với secret dài 32 byte |
| `0x4055e7` | `BCryptEncrypt`; auth info có nonce 12 byte, tag 16 byte, AAD rỗng |
| `0x405cdb` | `BCryptGenRandom` tạo nonce 12 byte |
| `0x405832–0x405912` | Ghi magic, tag và ciphertext |

Cấu trúc tệp:

| Offset | Kích thước | Nội dung |
| --- | --- | --- |
| `0x00` | 8 byte | ASCII `1337DaKL` |
| `0x08` | 16 byte | GCM authentication tag |
| `0x18` | Phần còn lại | Ciphertext |

24 byte đầu `hi.txt.enc`:

```text
31 33 33 37 44 61 4b 4c 30 33 28 b6 5a 5f 66 68
1c 54 de 9f ea bb 9f 23
```

Cách tách dữ liệu:

```python
magic = raw[:8]
tag = raw[8:24]
ciphertext = raw[24:]
```

Quan trọng: **nonce được tạo trong RAM nhưng không được ghi vào định dạng tệp này**. GCM không dùng padding PKCS#7 như AES-CBC; ciphertext có cùng độ dài plaintext, nên overhead ở đây là 24 byte.

### 6. Những giá trị dễ nhầm

- 16 byte sau magic là tag, không phải IV.
- Không áp dụng một solver AES-CBC chỉ vì thấy chữ AES.
- Không tự giả định nonce toàn số 0.
- Những tham số trên đến từ mã máy, không chỉ từ strings.

### 7. Đáp án cuối cùng

```text
AES-256-GCM
Nonce: 12 byte, sinh ngẫu nhiên, không lưu trong tệp
Tag: 16 byte
AAD: rỗng
File: magic(8) || tag(16) || ciphertext
```

---

## Phần 5 — Khóa được tạo thế nào và RAM xác nhận điều gì?

### 1. Câu hỏi đang yêu cầu gì?

Cần dựng lại công thức tạo khóa, lấy đúng đầu vào từ hiện vật, rồi kiểm tra digest có trong bộ nhớ tiến trình hay không.

### 2. Từ khóa quan trọng

- **Computer name:** tên máy, khác username.
- **Current process ID:** PID của chính chương trình đang chạy.
- **SHA-256 digest:** 32 byte, không phải chuỗi hex 64 ký tự.
- **Memory map dump:** các vùng nhớ được trích của một tiến trình.

### 3. Cần phân tích hiện vật nào?

`update.exe`, Sysmon, response HTTP và `mem.raw`.

### 4. Từng bước thao tác

Xem các vùng mã tạo key material và hash:

```powershell
py "$WRITEUP\inspect_pe.py" "$BIN" --around 0x406ca9 --count 80
py "$WRITEUP\inspect_pe.py" "$BIN" --around 0x406e23 --end 0x4070e0
py "$WRITEUP\inspect_pe.py" "$BIN" --around 0x407247 --end 0x407340
```

Tính digest từ đầu vào đã phục hồi:

```powershell
py -c "import hashlib; print(hashlib.sha256(b'desktop-7nnknik|2844|X7A91C').hexdigest())"
```

Đối chiếu tiến trình và trích bộ nhớ:

```powershell
& $VOL -q -f $MEM windows.pslist --pid 2844
& $VOL -q -o $WORK -f $MEM windows.memmap --pid 2844 --dump
```

Lần đầu Volatility có thể cần lấy symbols Windows. Dump dùng tiếp theo là `$WORK\pid.2844.dmp`. Tìm digest thô trong dump mà không tải toàn bộ tệp vào RAM:

```powershell
$KEYCHECK = @'
import hashlib
import mmap
import sys

key = hashlib.sha256(b"desktop-7nnknik|2844|X7A91C").digest()
with open(sys.argv[1], "rb") as handle:
    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as dump:
        offset = dump.find(key)
print(hex(offset) if offset >= 0 else "not found")
'@
$KEYCHECK | py - "$WORK\pid.2844.dmp"
```

### 5. Cách đọc kết quả

Phân tích tĩnh cho thấy:

- `GetComputerNameA` tại `0x406ca9`, hostname được lowercase ở vùng `0x406e23`.
- `GetCurrentProcessId` tại `0x406cf8`, PID được đổi thành chuỗi thập phân.
- Vùng `0x406fc2–0x4070c7` ghép ba thành phần bằng dấu `|`.
- Vùng `0x407247–0x40731c` hash bằng SHA-256.

Pseudocode để hiểu logic, không phải mã chạy malware:

```python
material = hostname.lower() + "|" + str(pid) + "|" + campaign
key = SHA256(material.encode())
```

Các đầu vào:

| Thành phần | Giá trị | Chứng cứ |
| --- | --- | --- |
| Computer name | `DESKTOP-7NNKNIK` | Trường Computer trong Sysmon |
| PID | `2844` | Event ID 1 và Volatility pslist |
| Campaign | `X7A91C` | JSON response trong PCAP |

Chuỗi trước khi hash:

```text
desktop-7nnknik|2844|X7A91C
```

Khóa ở dạng hex:

```text
3c0249e672188f75d3f6a845d534ecfc1bdd2c7c681562393f636d24d4409830
```

Volatility xác nhận:

```text
PID:        2844
PPID:       3164
Image:      update.exe
Wow64:      True
CreateTime: 2026-08-25 04:35:05 UTC
ExitTime:   N/A
```

Digest thô xuất hiện ở offset `0x36b78` trong `pid.2844.dmp` đã trích ở lần phân tích này. Đây là **file offset của dump được tạo**, không phải địa chỉ ảo hoặc offset trực tiếp trong `mem.raw`.

### 6. Những giá trị dễ nhầm

- `bkav` là username, không phải hostname.
- Chỉ lowercase hostname; campaign giữ `X7A91C`.
- Dùng PID `2844`, không dùng PPID `3164`.
- Khóa AES là `digest()`, không phải `hexdigest().encode()`.
- Việc tìm thấy khóa là đối chứng; kiểm tra tag khi giải mã sẽ tiếp tục xác nhận khóa.

### 7. Đáp án cuối cùng

```text
Key material: desktop-7nnknik|2844|X7A91C
AES key (hex): 3c0249e672188f75d3f6a845d534ecfc1bdd2c7c681562393f636d24d4409830
```

---

## Phần 6 — Không có nonce trong tệp thì khôi phục bằng cách nào?

### 1. Câu hỏi đang yêu cầu gì?

Đã có khóa, ciphertext và tag, nhưng AES-GCM còn cần nonce. Ta phải tìm cách phục hồi nonce đúng của từng tệp thay vì đoán hoặc brute-force.

### 2. Từ khóa quan trọng

- **GHASH:** phép tính xác thực trên các block 128 bit.
- **H:** hash subkey, tính từ khóa AES.
- **J0:** block khởi tạo của GCM; với nonce 96 bit có dạng đặc biệt.
- **Full tag:** tag đủ 128 bit; điều kiện quan trọng của cách khôi phục này.

### 3. Cần phân tích hiện vật nào?

Khóa vừa dựng, tag/ciphertext trong từng `.enc` và các tham số GCM đã xác định từ binary.

### 4. Từng bước thao tác

Theo định nghĩa GCM trong [NIST SP 800-38D, phần 7.1](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf), với nonce 96 bit:

```text
H  = AES_K(0^128)
J0 = nonce || 00000001
T  = AES_K(J0) XOR S
```

Trong đó `S` là GHASH của AAD và ciphertext. Với AAD rỗng, đầu vào GHASH là:

```text
ciphertext || zero_padding || [0]_64 || [len(ciphertext) * 8]_64
```

Zero padding chỉ làm tròn đầu vào GHASH lên block 16 byte; **không phải padding của plaintext**. Hai số độ dài ở block cuối được ghi big-endian, đơn vị bit.

Vì biết khóa, ta tính được `H` và `S`, sau đó:

```text
J0 = AES_K^-1(T XOR S)
nonce = J0[:12]
```

Kiểm tra bốn byte cuối `J0` bằng `00 00 00 01`, rồi giải mã bằng thư viện AES-GCM để xác thực tag. Hàm tương ứng trong [solve.py](./solve.py):

```python
def recover_nonce(key, tag, ciphertext):
    s = ghash(key, ciphertext)
    encrypted_j0 = bytes(t ^ v for t, v in zip(tag, s))
    j0 = aes_block(key, encrypted_j0, decrypt=True)
    if j0[12:] != b"\0\0\0\1":
        raise ValueError("Invalid recovered J0")
    return j0[:12]
```

### 5. Cách đọc kết quả

`hi.txt.enc` có nonce khôi phục:

```text
24c696f9341fd8e7882b44f0
```

Sau khi ghép `ciphertext + tag` theo giao diện của thư viện, `AESGCM.decrypt(nonce, ciphertext + tag, None)` xác thực thành công.

Đây **không phải phá AES** hay dò khóa/nonce. Ta đã biết khóa; phép đảo AES một block giúp lấy `J0` từ quan hệ xác thực của GCM. Cách này áp dụng vì mẫu có nonce 96 bit, tag đầy đủ và AAD đã biết.

### 6. Những giá trị dễ nhầm

- Không thể khái quát rằng “tag GCM luôn tiết lộ nonce” khi chưa biết khóa.
- Nếu tag bị cắt ngắn hoặc AAD chưa biết, không áp dụng nguyên xi công thức này.
- Nonce mỗi tệp khác nhau; không dùng nonce của `hi.txt.enc` cho mọi tệp.
- Kiểm tra đuôi `J0` là một bước sanity check; vẫn phải xác thực tag bằng AES-GCM.

### 7. Kết luận của phần này

Có thể **phục hồi nonce riêng của từng tệp từ khóa, tag và ciphertext**, sau đó giải mã kèm kiểm tra xác thực.

---

## Phần 7 — Khôi phục dữ liệu và lấy flag

### 1. Câu hỏi đang yêu cầu gì?

Giải mã toàn bộ bảy tệp, kiểm chứng kết quả và tìm flag thật. Một output “trông có vẻ đọc được” chưa đủ; cần tag hợp lệ và đối chứng nội dung khi có thể.

### 2. Từ khóa quan trọng

- **Authentication:** thư viện kiểm tra tính toàn vẹn bằng tag.
- **Plaintext:** dữ liệu gốc sau giải mã.
- **Known original:** bản gốc có sẵn để so sánh hash.
- **Output riêng:** tránh thay đổi hiện vật gốc.

### 3. Cần phân tích hiện vật nào?

Thư mục `Users\Public\MetaData\Data`, script [solve.py](./solve.py), dump tiến trình nếu muốn đối chiếu khóa và bản 7-Zip có sẵn trong gói tải về.

### 4. Từng bước thao tác

Chạy solver với các đầu vào đã tìm được:

```powershell
py "$WRITEUP\solve.py" `
    --data "$DATA" `
    --memory "$WORK\pid.2844.dmp" `
    --computer 'DESKTOP-7NNKNIK' `
    --pid 2844 `
    --campaign 'X7A91C' `
    --out "$OUT"
```

`--memory` là tùy chọn để đối chiếu digest với dump đã trích. Nếu bỏ tùy chọn này, solver vẫn dùng công thức khóa đã xác định:

```powershell
py "$WRITEUP\solve.py" --data "$DATA" --out "$OUT"
```

Solver kiểm tra magic, khôi phục nonce, xác thực GCM và ghi plaintext vào output riêng. Nếu output đã tồn tại, script chỉ chấp nhận nội dung giống hệt; không ghi đè tệp khác nội dung.

Đọc tệp text và so sánh hai bản 7-Zip:

```powershell
Get-Content -LiteralPath (Join-Path $OUT 'hi.txt') -Raw

Get-FileHash -LiteralPath (Join-Path $OUT '7z2409-x64.exe') -Algorithm SHA256
Get-FileHash -LiteralPath (Join-Path $PACKAGE '7z2409-x64.exe') -Algorithm SHA256
```

Không chạy executable đã khôi phục.

### 5. Cách đọc kết quả

Cả bảy tệp đều vượt qua kiểm tra tag:

| Tệp khôi phục | Nonce | Số byte plaintext |
| --- | --- | ---: |
| `1337dakl.txt` | `f13ba19b255ae4f590c25cfd` | 12 |
| `7z2409-x64.exe` | `df8f031f5e50e9b0eaea27ff` | 1.637.343 |
| `flag.jpeg` | `97595686149cf7a4afe5cd6f` | 384.569 |
| `hi.txt` | `24c696f9341fd8e7882b44f0` | 34 |
| `IMG_4287.jpeg` | `5a3ea1093656db3093d8df16` | 1.479.402 |
| `IMG_4288.jpeg` | `257c8a8ff3bf9cb6cdddce85` | 1.275.129 |
| `ptit.txt` | `adea20882fde1b4d6e74f57c` | 68 |

SHA-256 của bản 7-Zip được giải mã khớp hoàn toàn với bản có sẵn:

```text
bdd1a33de78618d16ee4ce148b849932c05d0015491c34887846d431d29f308e
```

Các JPEG có header `FF D8` và trailer `FF D9`. Kiểm tra riêng `flag.jpeg` thấy ảnh có chữ “good luck” và “Hi”; flag thực tế nằm trong `hi.txt`.

Nội dung `hi.txt`:

```text
CSCV2026{c0rr3l4t3_b3f0r3_d3crypt}
```

Tệp có 34 byte; SHA-256:

```text
bf0751c5f2c5fe78599eca206b1f3966adfc352eeb77ce47c749f4b4f3a2f7a4
```

### 6. Những giá trị dễ nhầm

- Không dừng ở tên `flag.jpeg`.
- Không “bỏ qua lỗi tag” để lấy plaintext chưa được xác thực.
- Không thêm newline hoặc sửa nội dung trước khi so sánh hash.
- VuVT không yêu cầu nối đáp án rồi hash như bài Blindsided; flag được khôi phục trực tiếp.

### 7. Đáp án cuối cùng

```text
CSCV2026{c0rr3l4t3_b3f0r3_d3crypt}
```

## Kết luận

Các hiện vật cho thấy người dùng tải `UpdateX7A91C.7z`, giải nén và chạy các chương trình trong gói. Thành phần gây mã hóa là `update.exe`:

1. Sysmon gắn `update.exe`, PID 2844 với các tệp `.enc`.
2. PCAP cung cấp campaign `X7A91C` từ API.
3. Phân tích tĩnh chỉ ra khóa là SHA-256 của hostname lowercase, PID và campaign, nối bằng `|`.
4. RAM xác nhận tiến trình và chứa digest khóa đã dựng.
5. Binary dùng AES-256-GCM nhưng chỉ lưu magic, tag và ciphertext.
6. Với khóa đã biết, nonce được phục hồi từ quan hệ tag/GHASH.
7. Giải mã có xác thực khôi phục cả bảy tệp; `hi.txt` chứa flag.

Thông điệp của challenge đúng với flag: **đối chiếu chứng cứ trước khi giải mã**. Đúng binary, đúng phiên tiến trình, đúng campaign và đúng cấu trúc tệp mới dẫn đến dữ liệu được xác thực.

## Tệp đi kèm

- [inspect_pe.py](./inspect_pe.py): hỗ trợ phân tích tĩnh PE x86 và các vùng mã được dẫn trong bài.
- [solve.py](./solve.py): dựng khóa, kiểm tra RAM tùy chọn, khôi phục nonce và giải mã.
