##Meteor Shower — CTF Write-up
## 1. Thông tin bài
- **Tên bài:** Meteor Shower
- **Mảng:** Reverse Engineering
- **File được cung cấp:** `meteor_shower.nes`
- **Môi trường phân tích:** Kali Linux
- **Công cụ:** file, xxd, strings, Python, py65, assembly

## 2. Mô tả và mục tiêu
Đề bài cung cấp một ROM game NES có tên Meteor Shower.
Mục tiêu là phân tích chương trình để tìm một cụm từ bí mật.
Theo yêu cầu đề, cụm từ được đặt trong `FortID{}` và các từ
được nối bằng dấu gạch dưới `_`.
## 3. Nhận diện file
Trước tiên, kiểm tra loại file và phần header:
```bash
file meteor_shower.nes
xxd -l 16 meteor_shower.nes
```
Kết quả nhận diện:
```text
NES ROM image (iNES): 2x16k PRG, 1x8k CHR [H-mirror]
```
File thuộc định dạng ROM NES, gồm:

| Thành phần | Dung lượng | Vai trò |
|---|---:|---|
| Header | 16 byte | Thông tin định dạng ROM |
| PRG-ROM | 32 KiB | Mã chương trình và dữ liệu |
| CHR-ROM | 8 KiB | Dữ liệu đồ họa |

Từ kết quả này, hướng phân tích là đọc mã máy 6502 và
tìm các điều kiện kiểm tra trong chương trình.
