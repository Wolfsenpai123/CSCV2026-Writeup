# CSCV2026 Writeup

Write-up các challenge CSCV Jeopardy 2026, gồm đề bài, dữ liệu challenge và script tái hiện.

## Forensics

| Challenge | Đề bài và dữ liệu | Write-up | Solver |
| --- | --- | --- | --- |
| VuVT | [Đề bài](./for/VuVT/CHALLENGE.md) · [Hiện vật](./for/VuVT/Source/) · [Tải bộ đề gốc](https://github.com/Wolfsenpai123/CSCV2026-Writeup/releases/download/vuvt-challenge/VuVT.7z) | [Full write-up](./for/VuVT/README.md) | [solve.py](./for/VuVT/solve.py) · [Source scripts](./for/VuVT/Scripts/) |
| Insidotage  | [Đề bài](./for/LinuxMemory/README.md#đề-bài) | [Full write-up](./for/LinuxMemory/README.md) · [Bài nhập môn](./for/LinuxMemory/LESSON.md) | [Scripts](./for/LinuxMemory/Scripts/) |
| Cryptominer | [Đề bài](./for/InsiderCryptominer/README.md#mô-tả-đề) · [Bằng chứng đã phục hồi](./for/InsiderCryptominer/evidence/) | [Full write-up](./for/InsiderCryptominer/README.md) · [Bài nhập môn](./for/InsiderCryptominer/LESSON.md) | [solve.py](./for/InsiderCryptominer/solve.py) · [Kiểm chứng offline](./for/InsiderCryptominer/scripts/verify_saved.py) |
| Silent Room | [Đề bài](./for/SilentRoom/CHALLENGE.md) · [Attachment public](./for/SilentRoom/Attachment/SilentRoom_public.7z?raw=true) | [Full write-up](./for/SilentRoom/README.md) · [Bài giảng nhập môn](./for/SilentRoom/LESSON.md) | [solve.py](./for/SilentRoom/solve.py) |

Write-up có chứa đáp án và flag. Dữ liệu VuVT chứa executable không an toàn; chỉ phân tích tĩnh trên máy phân tích hoặc môi trường cô lập, không chạy các chương trình trong bộ đề.

Bộ đề lớn được đính kèm trong [Releases](https://github.com/Wolfsenpai123/CSCV2026-Writeup/releases/tag/vuvt-challenge), không đưa vào lịch sử Git. Link tải và SHA-256 nằm trong trang đề bài.
