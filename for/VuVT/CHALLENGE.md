# VuVT — Đề bài

**Thể loại:** Forensics

**Flag format:** `CSCV2026{...}`

## Tiếng Việt

> Ring... tuttt... tuttt...
>
> SOC: Alo, Vũ ấy hả em.
>
> VuVT: Anh ơi, em chỉ chạy update thôi mà sao máy em tự nhiên bị mã hóa rồi...
>
> SOC: Đừng động vào máy nữa. Bọn anh sẽ kiểm tra.

Một bộ dữ liệu được thu thập từ máy tính gặp sự cố.

Hãy điều tra xem chuyện gì đã thực sự xảy ra và tìm ra thông tin cần thiết để khôi phục kết quả cuối cùng.

## English

> Ring... tuttt... tuttt....
>
> SOC: Moshi moshi, Is that you Vu?
>
> VuVT: Holy moly, I've just running some kind of updates and now my device got encrypted.
>
> SOC: Do not touch your keyboard. We'll come and investigate

Then a data sample was collected from the incident

Investigate to figure it out what happened and find the information to restore the final results.

## Attachment

[Hiện vật chính trong repo](./Source/README.md) · [Source script phân tích](./Scripts/README.md). Bộ đề gốc đầy đủ, gồm RAM, nằm trong Release bên dưới.

- [Tải VuVT.7z — nguyên bộ đề gốc](https://github.com/Wolfsenpai123/CSCV2026-Writeup/releases/download/vuvt-challenge/VuVT.7z).
- [Trang Release](https://github.com/Wolfsenpai123/CSCV2026-Writeup/releases/tag/vuvt-challenge).
- Kích thước: **1.111.647.576 byte**, khoảng 1,04 GiB.
- SHA-256:

```text
6f288735439e29673fe74bec6eea7e1802f4b9defae5c800b61f88909209a9bd
```

[SHA256SUMS.txt](./Attachment/SHA256SUMS.txt) được cung cấp để đối chiếu. Archive được tải lên nguyên trạng, không thay bằng các hiện vật được trích chọn trong quá trình giải.

**Cảnh báo:** bộ đề chứa executable không an toàn và dữ liệu thu thập từ máy Windows của challenge. Không chạy EXE, DLL hoặc script tìm thấy bên trong. Phân tích trên máy chuyên dụng/môi trường cô lập và giữ nguyên bản gốc.

## Chuẩn bị để làm lại

Ví dụ clone repo vào `D:\CTF\CSCV2026-Writeup`, tải `VuVT.7z` về thư mục đó rồi kiểm tra:

```powershell
Set-Location -LiteralPath 'D:\CTF\CSCV2026-Writeup'
Get-FileHash -LiteralPath '.\VuVT.7z' -Algorithm SHA256
```

Sau khi hash khớp, tạo thư mục `VuVT` và giải nén archive vào bên trong bằng công cụ giải nén của máy phân tích. Archive chứa các đường dẫn `Users/...`, `mem.raw`, `network.pcapng` và `sysmon.evtx` ở cấp gốc, nên thư mục đích cần là:

```text
D:\CTF\CSCV2026-Writeup\VuVT\
```

Nếu có nhiều bản sao các hiện vật trong profile, bài giải sử dụng bản `mem.raw`, `network.pcapng` và `sysmon.evtx` ở gốc thư mục `VuVT`.

Cài dependency cho các script:

```powershell
py -m pip install -r '.\for\VuVT\requirements.txt'
```

[Đọc full write-up](./README.md) để tiếp tục điều tra. Bài giải có spoiler và flag.
