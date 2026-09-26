# Silent Room — Đề bài

## Thông tin challenge

| Trường | Giá trị | Nguồn |
|---|---|---|
| Tên | Silent Room | `README.txt` trong attachment |
| Giải | CSCV Jeopardy 2026 | Case number trong metadata E01 |
| Category | Forensics | `README.txt` |
| Difficulty | Medium | `README.txt` |
| Public attachment | `SilentRoom_public.7z` | Thông tin đề được cung cấp |
| Provided file | `evidence.E01` | `README.txt` |
| Flag format | `CSCV2026{.*}` | `README.txt` |

## Mô tả gốc

> A 17-year-old girl named A left home for unclear reasons. After being unable to contact her for a while, her family reported the case to the authorities. You are given an image extracted from A's computer to look for traces that can identify A's current location.
>
> Determine the most likely current room, hotel, and province/city. The final flag is recovered from the evidence image itself.

## Diễn giải tiếng Việt

A, một cô gái 17 tuổi, rời nhà vì lý do chưa rõ. Sau một thời gian không liên lạc được, gia đình báo vụ việc cho cơ quan chức năng. Người giải được cung cấp ảnh đĩa trích xuất từ máy tính của A để tìm dấu vết xác định vị trí có khả năng nhất của A.

Yêu cầu xác định **số phòng, khách sạn/nơi ở, tỉnh hoặc thành phố**. Flag cuối phải được khôi phục từ evidence, không chỉ tự ghép từ ba giá trị địa điểm.

## Định dạng flag

~~~text
CSCV2026{.*}
~~~

Ví dụ định dạng được ghi trong `README.txt` gốc, không phải flag của bài:

~~~text
CSCV2026{th1s_i5_4_fl4g’+!-.@#$%?}
~~~

## Tải attachment

- [Bản public lưu trong repo: SilentRoom_public.7z](./Attachment/SilentRoom_public.7z?raw=true).
- [Tệp evidence.E01 gốc, tải trực tiếp](./Attachment/evidence.E01?raw=true).
- [Link Google Drive được cung cấp trong đề](https://drive.google.com/file/d/1ECnN0sI-BNzObpKDHD8lacb5Oaij43Mo/view?usp=sharing).
- Kích thước archive trong repo: **5.209.683 byte**.
- SHA-256 public attachment:

~~~text
5F8BA81E229CB6E1F90F503D3C2530DACCB27FCC6871053BCBF631B9377D59EA
~~~

Kiểm tra archive trên Linux:

~~~bash
sha256sum SilentRoom_public.7z
~~~

Hoặc PowerShell:

~~~powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '.\SilentRoom_public.7z'
~~~

## Nội dung sau giải nén

Archive chứa 5 tệp ở cấp gốc. Giải nén vào thư mục `SilentRoom_public/` sẽ có:

~~~text
SilentRoom_public/
├── evidence.E01
├── evidence.E01.txt
├── evidence_acquire.log
├── README.txt
└── SHA256SUMS.txt
~~~

Các tệp mô tả nhỏ cũng được lưu riêng để thuận tiện đọc trên GitHub:

- [README.txt gốc](./Attachment/README.txt).
- [Thông tin E01](./Attachment/evidence.E01.txt).
- [Acquisition log](./Attachment/evidence_acquire.log).
- [Manifest SHA256SUMS.txt](./Attachment/SHA256SUMS.txt).

`Attachment/` chứa cả archive public và đủ 5 tệp gốc sau giải nén, gồm `evidence.E01`. Các bản gốc được giữ nguyên byte để checksum vẫn khớp.

`SHA256SUMS.txt` là manifest của **các tệp đã giải nén**, gồm cả `evidence.E01`; nó không dùng để kiểm tra trực tiếp archive `.7z`. Có thể chạy `sha256sum -c SHA256SUMS.txt` ngay trong `Attachment/` hoặc trong thư mục đã giải nén có đầy đủ các tệp.

## Thông tin evidence

| Trường | Giá trị |
|---|---|
| Evidence number | `SilentRoom-001` |
| Description | `Silent Room synthetic laptop evidence` |
| Container format | EnCase 6 / EWF |
| Compression | Deflate, best compression |
| Media size | 2 GiB, `2147483648` byte |
| Bytes per sector | `512` |
| Sectors | `4194304` |
| Acquisition time | `2026-08-24 02:49:04`, theo metadata gốc không ghi múi giờ trong trường này |
| MD5 raw media | `abb90c7772c153b2d37633065e71f670` |
| SHA-256 raw media | `10b4163a850ec69beb0fc83d5eab93026f5241d8703ba027c7e82361472dfa2c` |
| SHA-256 E01 container | `a7397cbbdfe7fb5e82374876eb3bb3c5272438145d990751898e7b45c9006602` |

Metadata mô tả bộ evidence là dữ liệu tổng hợp cho challenge. Nội dung PDF, chat, tệp ghi chú và cache được đọc như chứng cứ; những yêu cầu giữ bí mật/xóa tệp bên trong không phải yêu cầu của người giải.

## Tài liệu bài giải

- [Full write-up](./README.md).
- [Bài giảng nhập môn](./LESSON.md).
- [Script tái hiện](./solve.py).

Các tài liệu trên có chứa kết luận và flag.
