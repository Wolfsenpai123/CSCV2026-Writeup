# Source / hiện vật chính của VuVT

Các hiện vật dùng trực tiếp trong lời giải được đưa vào repo để có thể tải từng tệp mà không cần lấy toàn bộ archive trước. **17 tệp được sao chép nguyên trạng**, đã so sánh SHA-256 với bản phân tích.

```text
Source/
├── network.pcapng
├── sysmon.evtx
├── LocaleMetaData/sysmon_1033.MTA
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
        └── 7 tệp .enc
```

[SHA256SUMS.txt](./SHA256SUMS.txt) chứa hash của từng hiện vật, với đường dẫn tính từ thư mục này.

## RAM và bộ đề đầy đủ

`mem.raw` gần 2 GiB và các thành phần khác của profile Windows không được lặp lại trong lịch sử Git. **Toàn bộ dữ liệu gốc**, kể cả RAM, vẫn được giữ nguyên trong:

- [VuVT.7z — tải nguyên bộ đề](https://github.com/Wolfsenpai123/CSCV2026-Writeup/releases/download/vuvt-challenge/VuVT.7z).
- [Release vuvt-challenge](https://github.com/Wolfsenpai123/CSCV2026-Writeup/releases/tag/vuvt-challenge).
- [Hướng dẫn và hash archive](../CHALLENGE.md).

## Mã nguồn và an toàn

Bộ đề thu được cung cấp binary của `update.exe`, **không có mã nguồn C/C++ gốc của chương trình đó**. Source các script dùng khi giải nằm tại [Scripts](../Scripts/README.md); bản solver chạy bằng tham số nằm tại [solve.py](../solve.py).

**Không chạy EXE, shortcut hoặc script thu được trong challenge.** Các executable ở đây được lưu làm chứng cứ để phân tích tĩnh, không phải phần mềm cung cấp để cài đặt.

## Giải mã trực tiếp các tệp trong repo

Từ thư mục gốc repo:

```powershell
py -m pip install -r '.\for\VuVT\requirements.txt'
py '.\for\VuVT\solve.py' --data '.\for\VuVT\Source\Users\Public\MetaData\Data' --out '.\recovered'
```

Lệnh này dùng khóa được dựng theo các đầu vào đã điều tra trong [write-up](../README.md). Nếu muốn kiểm chứng với RAM, tải bộ đề đầy đủ, trích dump tiến trình bằng Volatility rồi dùng tùy chọn `--memory`.
