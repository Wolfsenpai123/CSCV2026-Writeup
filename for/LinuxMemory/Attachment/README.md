# Bộ đề gốc — Insidotage

Bộ đề của challenge được lưu trong [GitHub Release `insidotage-challenge`](https://github.com/Wolfsenpai123/CSCV2026-Writeup/releases/tag/insidotage-challenge).

Tệp gốc `dist.zip` có dung lượng **4.699.282.479 byte**. ZIP được chia theo byte thành 5 phần để phù hợp giới hạn attachment của GitHub. Ghép các phần theo thứ tự sẽ khôi phục chính xác ZIP gốc.

## Tải về

Tải đủ cả 5 phần vào cùng một thư mục:

| Phần | Kích thước (byte) | Link |
|---|---:|---|
| `dist.zip.001` | 1.073.741.824 | [Tải phần 1](https://github.com/Wolfsenpai123/CSCV2026-Writeup/releases/download/insidotage-challenge/dist.zip.001) |
| `dist.zip.002` | 1.073.741.824 | [Tải phần 2](https://github.com/Wolfsenpai123/CSCV2026-Writeup/releases/download/insidotage-challenge/dist.zip.002) |
| `dist.zip.003` | 1.073.741.824 | [Tải phần 3](https://github.com/Wolfsenpai123/CSCV2026-Writeup/releases/download/insidotage-challenge/dist.zip.003) |
| `dist.zip.004` | 1.073.741.824 | [Tải phần 4](https://github.com/Wolfsenpai123/CSCV2026-Writeup/releases/download/insidotage-challenge/dist.zip.004) |
| `dist.zip.005` | 404.315.183 | [Tải phần 5](https://github.com/Wolfsenpai123/CSCV2026-Writeup/releases/download/insidotage-challenge/dist.zip.005) |

Bảng SHA-256 nằm trong [SHA256SUMS.txt](./SHA256SUMS.txt), gồm từng phần, ZIP gốc và hai hiện vật sau giải nén.

Nếu dùng GitHub CLI, có thể tải cả 5 phần bằng:

```text
gh release download insidotage-challenge --repo Wolfsenpai123/CSCV2026-Writeup --pattern "dist.zip.*" --dir downloads/Insidotage
```

## Ghép và giải nén trên Windows hoặc Linux

Cần Python 3.8 trở lên, không cần thư viện bổ sung. Chạy từ thư mục gốc repo đã clone:

```text
python for/LinuxMemory/Scripts/restore_attachment.py downloads/Insidotage cases/Insidotage
```

Script kiểm tra SHA-256 của từng phần, ghép thành `downloads/Insidotage/dist.zip`, đối chiếu SHA-256 của ZIP, rồi giải nén và đối chiếu SHA-256 của hai hiện vật. Các tệp đã tồn tại chỉ được dùng lại khi hash khớp. Tổng dung lượng cho các phần, ZIP đã ghép và dữ liệu giải nén cần khoảng **20 GB trống**.

Kết quả:

```text
cases/Insidotage/
└── dist/
    ├── mem.dmp
    └── network.pcapng
```

## SHA-256 của bộ đề

| Tệp | Kích thước (byte) | SHA-256 |
|---|---:|---|
| `dist.zip` | 4.699.282.479 | `6ca9a77540be8fa3d63a1ac496143ec32fa0c3f4aae0517b0a9f9289b554c170` |
| `dist/mem.dmp` | 8.589.332.605 | `6150c09e3f87816fd303f26547bd0a25ade56ce61c88418f42ffee246d474812` |
| `dist/network.pcapng` | 1.003.199.776 | `c18700e721f4fed4f52252297d202c91f2d8b9878d715620b13f96b790cb088b` |

## Bắt đầu phân tích

Quay lại [đề bài và full write-up](../README.md). Trong các lệnh của bài, đặt `$caseRoot` thành đường dẫn `cases/Insidotage` trên máy của bạn; `$writeupDir` là đường dẫn `for/LinuxMemory` trong repo đã clone.
