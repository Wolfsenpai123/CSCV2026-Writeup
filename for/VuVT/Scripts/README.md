# Source các script giải VuVT

Thư mục này lưu **nguyên bản hai script đã dùng khi điều tra**, không phải mã nguồn của malware:

- [analyze_update.py](./analyze_update.py): đọc PE, tìm chuỗi và disassemble các vùng mã liên quan đến BCrypt.
- [recover_vuvt.py](./recover_vuvt.py): bản solver ban đầu, dựng khóa, đối chiếu dump tiến trình, khôi phục nonce và giải mã có xác thực.

`recover_vuvt.py` giữ nguyên các đường dẫn của lần phân tích tại `D:\CTF\cscv`. Nếu dùng bản này ở máy khác, cần thay `SOURCE`, `DEST` và `MEMORY_DUMP` trước khi chạy. Script chỉ đọc hiện vật và giải mã, không thực thi EXE của challenge.

## Bản khuyến nghị để làm lại

Hai bản gọn hơn đã có ở cấp trên:

- [solve.py](../solve.py): nhận đường dẫn qua tham số, hỗ trợ đối chiếu RAM tùy chọn.
- [inspect_pe.py](../inspect_pe.py): helper phân tích tĩnh được dùng trong write-up.
- [requirements.txt](../requirements.txt): dependency.

Ví dụ chạy từ gốc repo, dùng hiện vật đã được bổ sung trực tiếp:

```powershell
py -m pip install -r '.\for\VuVT\requirements.txt'
py '.\for\VuVT\solve.py' --data '.\for\VuVT\Source\Users\Public\MetaData\Data' --out '.\recovered'
py '.\for\VuVT\inspect_pe.py' '.\for\VuVT\Source\Users\bkav\Downloads\UpdateX7A91C\update.exe'
```

[Full write-up](../README.md) · [Hiện vật challenge](../Source/README.md).

Không có mã nguồn C/C++ gốc của `update.exe` trong những hiện vật thu được. Không nhầm các script phân tích này với source tạo malware.
