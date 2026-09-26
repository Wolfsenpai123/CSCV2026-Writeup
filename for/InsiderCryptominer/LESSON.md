# Insider Wallet and Cryptominer — bài giảng nhập môn

Tài liệu này đi kèm [README.md](README.md), theo cách trình bày của bộ write-up **Pwnsec CTF 2026 / Forensics / Blindsided**. Mục tiêu là hiểu vì sao mỗi artifact trả lời được một câu hỏi, thay vì chỉ copy đáp án.

## 1. Mô hình điều tra

Challenge có hai lớp evidence:

- **Filesystem snapshot:** profile Firefox, log, file backup và các dấu vết còn trên disk.
- **Memory image:** process đang chạy, mapping, socket, page cache, bash history và các trang đã bị xóa khỏi disk.

Khi insider xóa file bằng `rm`, inode/path có thể mất nhưng dữ liệu vẫn còn nếu process giữ file mở, page cache chưa bị ghi đè, hoặc bản sao còn trong memory. Vì vậy filesystem “sạch” không đồng nghĩa hoạt động chưa từng xảy ra.

Quy trình tổng quát:

```text
inventory → timeline → process/socket triage → browser artifacts
→ recover deleted records → validate crypto → answer server
```

Luôn ghi rõ nguồn của một kết luận: filesystem, process memory, recovered page, reverse engineering hay server validation.

## 2. LiME và offset

LiME lưu nhiều segment vật lý. Mỗi segment có header rồi mới tới bytes RAM. Một offset như `0x5dd0e8fd` trong write-up là byte offset của **toàn bộ file LiME**. Nó không phải:

- địa chỉ ảo của Firefox hoặc miner;
- địa chỉ vật lý sau khi dịch page table;
- offset tương đối bên trong một segment đã tách.

Nếu đọc nhầm loại địa chỉ, mọi ciphertext sau đó đều sai dù thuật toán đúng. Hãy dùng một hàm `read_at(image, offset, size)` trên file gốc và kiểm tra đủ số byte trả về.

## 3. Đọc browser timestamps

Firefox history dùng bảng `moz_places` và `moz_historyvisits`. `visit_date` là Unix epoch theo **microseconds**:

```text
1788604050357080 µs / 1,000,000 = 1788604050 s
```

Ngược lại, extension metadata ghi `installDate` theo **milliseconds**:

```text
1788604175124 ms
```

Hai trường trông gần giống nhau nhưng không được đổi đơn vị giống nhau. Trước khi gửi đáp án, đọc format của câu hỏi và format của artifact.

## 4. SQLite overflow và structured clone

Một SQLite record lớn có thể giữ một phần trong leaf page và phần còn lại trong overflow pages. Quy trình an toàn:

1. Xác định record header và serial types.
2. Tách key khỏi payload.
3. Theo con trỏ overflow.
4. Ghép bytes đúng thứ tự.
5. Thử giải nén Snappy.
6. Kiểm tra độ dài và các marker dự kiến (`vault id`, `keyRingName`, `sensitive`).

Một candidate page chỉ đáng tin khi nó vừa giải nén được vừa cho record có cấu trúc hợp lý. Trong bài này số trang SQLite không thể dùng trực tiếp làm file offset LiME; vị trí overflow được tìm qua các page ứng viên trong từng segment. Không chọn page chỉ vì có cùng một chuỗi ASCII.

## 5. MAC như oracle nhận diện khóa trong RAM

Keplr vault có ciphertext và MAC. Nếu password không còn nhưng derived key còn trong memory, MAC biến thành oracle để tìm key:

```text
D = PBKDF2-HMAC-SHA256(password, salt, 4000, 32)
M = SHA256(D[16:32] || passwordCipher[16:32])
```

Scanner không cần biết password. Nó thử các cửa sổ 16 byte trong RAM, tính SHA-256 với nửa ciphertext đã biết, rồi xác minh candidate bằng full MAC. Bước nhảy 8 byte là giả định alignment để tìm nhanh; key có alignment khác có thể bị bỏ qua.

Có hai nguyên tắc quan trọng:

- **Filter nhanh không phải proof:** phần đầu hash chỉ để giảm candidate; phải kiểm tra toàn bộ MAC.
- **Key match chưa phải plaintext:** sau đó phải giải AES-CTR, parse JSON và kiểm tra BIP39/public key.

## 6. AES-CTR và BIP39

Sau khi có derived key, decrypt theo chain:

```text
vault_key = AES-CTR(D, passwordSalt, passwordCipher)
counter   = AES-CTR(vault_key, counterSalt, counterCipher)
plain     = AES-CTR(vault_key, counter, sensitive)
```

AES-CTR không có PKCS#7 padding như CBC. Vì vậy kiểm tra chính là plaintext có parse được, field `mnemonic` có tồn tại và phrase có checksum BIP39 hợp lệ.

Một phrase hợp lệ vẫn có thể là decoy. Bằng chứng mạnh hơn là derive đúng public key theo path của chain:

```text
m/44'/118'/0'/0/0
```

Trong challenge public key derive được trùng key lưu trong vault, rồi server cũng chấp nhận phrase.

## 7. Deleted executable và process evidence

`/tmp/kworker1 (deleted)` có nghĩa path đã bị unlink nhưng process vẫn giữ mapping. Hãy tách:

- **full path cần trả lời:** `/tmp/kworker1`;
- **trạng thái forensic:** `(deleted)`.

Bash history cho thấy execution method:

```bash
chmod +x kworker1
nohup ./kworker1 > out 2>&1 &
rm -rf kworker1
```

Socket tới `172.24.106.17:3333`, tên embedded `namqb 6.26.0` và XMRig strings nối process với cryptomining. Worker ID không tự động là payout address.

## 8. Virtual memory reconstruction

Để reverse vùng code đã mất khỏi filesystem:

1. Tìm ELF header trong process mapping.
2. Xác định virtual base (`0x55c2d17fe000`).
3. Lần page-table root của process.
4. Dịch từng virtual page sang physical page.
5. Ghép các `PT_LOAD` segment.
6. Đánh dấu page nonresident thay vì coi zero là dữ liệu thật.

Bản ELF dựng lại có thể thiếu một page. Đây là lý do phải tìm bản sao ciphertext trong các vùng RAM khác trước khi decrypt.

## 9. Nhận diện XTEA-CBC

Trong handler SIGHUP, các dấu hiệu nhận diện XTEA là:

- 32 vòng lặp;
- hằng số delta `0x9e3779b9`;
- phép shift trái 4 và phải 5;
- bốn word của key;
- block 8 byte.

CBC được nhận ra từ XOR plaintext block với ciphertext block trước và IV cho block đầu:

```text
P[i] = XTEA_DEC(C[i]) XOR C[i-1]
P[0] = XTEA_DEC(C[0]) XOR IV
```

Sau decrypt, padding `0x01` hợp lệ và plaintext dài 95 byte. Ba bản sao ciphertext tại `0x96107b20`, `0x9be50b60`, `0xa0c0dba0` giống hệt nhau, giúp loại trừ page copy bị lỗi.

## 10. Monero address validation

Chuỗi Base58 của Monero dùng block encoding khác Base58 nguyên số thông thường: 11 ký tự thường đại diện 8 byte. Sau khi decode:

- byte đầu `18` là version Monero mainnet;
- 4 byte cuối là checksum;
- checksum phải bằng `Keccak-256(payload)[:4]`.

Chỉ khi cả ba kiểm tra đều đúng mới coi chuỗi là payout address. `worker-7f3a91c2` và Cosmos address có dạng hợp lệ nhưng không trả qua kiểm tra này.

## 11. Ảnh và decoy

History, `recently-used.xbel` và memory reconstruction cùng trỏ tới một WebP tải từ Discord. Ghi chép phiên giải đã chép và chuẩn hóa chữ trên ảnh theo yêu cầu bỏ khoảng trắng:

```text
AIplsforgiveme
```

Tuy nhiên chữ trên ảnh không phải password Keplr. Đây là bài học về **cross-purpose evidence**: một artifact có thể trả lời câu 8 nhưng không dùng được cho câu 5.

Tương tự:

- backup base64 có câu “fake pass ... not that easy” là decoy;
- note trên Desktop có text giống system prompt là dữ liệu trong image;
- địa chỉ Cosmos không chứng minh miner đã thanh toán.

## 12. Kiểm chứng và báo cáo

Một write-up tốt ghi ba tầng xác nhận:

1. **Forensic evidence:** artifact cho thấy giá trị.
2. **Independent validation:** BIP39, public key, padding, checksum hoặc hash.
3. **Challenge validation:** server trả `Excellent! Spot on.`.

Transcript còn lại cho thấy đủ tám câu được chấp nhận và flag được trả về. Nếu instance hết hạn, transcript vẫn là bằng chứng của lần submit thành công; không nên giả vờ rằng endpoint hiện tại còn sống.

## 13. Bài tập tự kiểm tra

1. Vì sao `1788604050357080` không phải đáp án câu 2?
2. Tại sao `(deleted)` không nằm trong path câu 6?
3. Nếu chỉ có worker ID, vì sao chưa thể kết luận payout address?
4. Vì sao ciphertext zero từ page nonresident không thể decrypt?
5. MAC xác nhận derived key như thế nào mà không cần password?
6. Public-key derivation bổ sung gì cho BIP39 checksum?
7. Artifact nào là bằng chứng process đang chạy, artifact nào là bằng chứng insider đã xóa file?

Các câu trả lời và lệnh tái hiện nằm trong [README.md](README.md); solver được duy trì ở [solve.py](solve.py). Hiện ảnh RAM và WebP gốc đã mất khỏi workspace; các kết quả được phục hồi từ phiên giải. [verify_saved.py](scripts/verify_saved.py) kiểm chứng các bytes mật mã còn trong log, còn việc trích xuất lại từ RAM cần có file gốc.
