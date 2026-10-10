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
<img width="637" height="152" alt="image" src="https://github.com/user-attachments/assets/97c73699-0c9f-4d22-8f18-17079c254dbe" />
*Hình 1. Nhận diện ROM NES và kiểm tra header trên Kali Linux.*
## 4. Disassemble mã máy 6502
Sau khi xác định file là ROM NES, bước tiếp theo là chuyển
mã máy trong PRG-ROM thành assembly 6502 để đọc logic chương trình.
### 4.1. Chuẩn bị công cụ
Sử dụng thư viện `py65`, có hỗ trợ disassembler và mô phỏng CPU 6502.
Trên Kali Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install py65
```

Các lệnh được thực hiện trong thư mục chứa file `meteor_shower.nes`.

### 4.2. Xác định địa chỉ nạp PRG-ROM

ROM có 16 byte header, tiếp theo là 32 KiB PRG-ROM.

Với mapper 0 và cấu hình của ROM này, PRG-ROM được ánh xạ
vào không gian địa chỉ CPU từ `0x8000` đến `0xFFFF`.

Do đó:
```python
prg = rom[16:16 + 32768]
```
Công thức chuyển địa chỉ CPU thành offset trong file:
```text
file_offset = 0x10 + (cpu_address - 0x8000)
```
Ví dụ:
```text
CPU address 0x8718
→ file offset 0x10 + 0x8718 - 0x8000
→ file offset 0x728
```
Cần phân biệt địa chỉ CPU với offset file để tránh đọc sai dữ liệu.

### 4.3. Tạo bản disassembly

Tạo file `disassemble.py`:

```python
from pathlib import Path
from py65.devices.mpu6502 import MPU
from py65.disassembler import Disassembler

rom = Path("meteor_shower.nes").read_bytes()
prg = rom[16:16 + 32768]

# Đặt PRG-ROM vào đúng vùng địa chỉ CPU.
cpu = MPU()
cpu.memory[0x8000:0x10000] = list(prg)

dis = Disassembler(cpu)

# RESET vector nằm ở CPU $FFFC-$FFFD, theo little-endian.
reset = cpu.memory[0xFFFC] | (cpu.memory[0xFFFD] << 8)
print(f"; RESET vector: ${reset:04X}")

address = reset

# Xuất tuyến tính toàn bộ vùng PRG.
# Kết quả chứa cả dữ liệu bị diễn giải thành lệnh.
while address < 0x10000:
    size, instruction = dis.instruction_at(address)
    raw = bytes(cpu.memory[address:address + size]).hex(" ")
    print(f"{address:04X}: {raw:9} {instruction}")
    address += size
```

Chạy:

```bash
python disassemble.py > disasm.txt
less disasm.txt
```

Kết quả bắt đầu tại:

```asm
8000: 78        SEI
8001: d8        CLD
8002: a2 40     LDX #$40
8004: 8e 17 40  STX $4017
8007: a2 ff     LDX #$FF
8009: 9a        TXS
```
<img width="582" height="338" alt="image" src="https://github.com/user-attachments/assets/ad54a9c6-98be-435b-a0ad-d53c52d0a082" />

Ý nghĩa một số lệnh:

| Lệnh | Ý nghĩa |
|---|---|
| `SEI` | Vô hiệu hóa ngắt IRQ có thể che |
| `CLD` | Xóa cờ decimal |
| `LDX #$40` | Đưa giá trị `0x40` vào thanh ghi X |
| `STX $4017` | Ghi giá trị X vào địa chỉ `$4017` |
| `LDX #$FF` | Đưa `0xFF` vào X |
| `TXS` | Chép X sang con trỏ stack |

Đây là phần khởi tạo. Chưa có dấu hiệu cho thấy nó trực tiếp
kiểm tra chuỗi bí mật, nên tiếp tục lần theo luồng thực thi.

**Lưu ý:** PRG-ROM chứa cả code và dữ liệu. Disassembler tuyến tính
không tự phân biệt chính xác hai loại này. Cần theo dõi các lệnh
nhảy, gọi hàm và tham chiếu dữ liệu để xác định vùng nào là code.

## 5. Phân tích vòng lặp chính

### 5.1. Một số ký hiệu assembly cần biết

Trong cú pháp đang sử dụng:

- `$` biểu thị số hệ thập lục phân.
- `#` biểu thị giá trị trực tiếp.
- `A`, `X`, `Y` là các thanh ghi.
- `JSR` gọi một subroutine.
- `RTS` trở về từ subroutine.
- `JMP` nhảy đến địa chỉ khác.

Ví dụ:

```asm
LDA #$04
```

Đưa trực tiếp số `4` vào A.

Trong khi đó:

```asm
LDA $04
```

Đọc giá trị tại địa chỉ RAM `$04` vào A.

Phân biệt hai cách viết này rất quan trọng khi đọc chương trình.

### 5.2. Tìm vòng xử lý theo frame
```asm 
sed -n '/^8059:/,/^806E:/p' disasm.txt
```

Trong bản disassembly có đoạn:

```asm
8059: LDA $00
805B: BEQ $8059
805D: LDA #$00
805F: STA $00

8061: JSR $80C1
8064: JSR $80EF

8067: LDA $05
8069: BEQ $806E
806B: JSR $83D4

806E: LDA $04
```
<img width="393" height="276" alt="image" src="https://github.com/user-attachments/assets/259acc15-10fa-4c4b-b398-6e9cfe8de784" />

*Hình 3. Vòng lặp chính gọi hàm đọc tay cầm tại $80c1 và hàm xử lý A/B tại $80ef.*
Đầu tiên:

```asm
8059: LDA $00
805B: BEQ $8059
```

Chương trình lặp lại khi giá trị tại `$00` vẫn bằng 0.

Trong hàm xử lý NMI có đoạn:

```asm
80B6: LDA #$01
80B8: STA $00
```

Như vậy, NMI đặt `$00 = 1` để báo có frame mới.
Vòng chính phát hiện giá trị này, xóa về 0 rồi xử lý lượt tiếp theo.

### 5.3. Xác định chức năng các hàm được gọi

Vòng chính lần lượt gọi:

```asm
8061: JSR $80C1
8064: JSR $80EF
```

Tiếp tục đọc nội dung của từng hàm, có thể xác định:

| Địa chỉ | Chức năng xác định từ mã |
|---|---|
| `$80C1` | Đọc tay cầm qua thanh ghi `$4016` |
| `$80EF` | Xử lý và ghi chuỗi nút A/B |
| `$83D4` | Chọn và vẽ màn hình |

Tên chức năng trong bảng là tên đặt lại trong quá trình phân tích,
không phải tên hàm có sẵn trong ROM.

Hàm `$80C1` chứa thao tác:

```asm
80C5: LDA #$01
80C7: STA $4016
80CA: LDA #$00
80CC: STA $4016
```

Sau đó đọc lặp lại từ `$4016`:

```asm
80D3: LDA $4016
80D6: AND #$01
```

Đây là dấu hiệu để nhận diện đoạn đọc trạng thái tay cầm.

### 5.4. Phân biệt nút đang giữ và nút mới nhấn

Cuối hàm đọc tay cầm:

```asm
80E6: LDA $02
80E8: EOR #$FF
80EA: AND $01
80EC: STA $03
```

Các biến được sử dụng như sau:

| RAM | Ý nghĩa |
|---|---|
| `$01` | Trạng thái nút hiện tại |
| `$02` | Trạng thái nút ở lần đọc trước |
| `$03` | Các nút mới được nhấn |

Giải thích:

1. Đọc trạng thái cũ từ `$02`.
2. XOR với `0xFF` để đảo các bit.
3. AND với trạng thái hiện tại tại `$01`.
4. Lưu kết quả vào `$03`.

Pseudocode:

```python
new_buttons = ((~previous_buttons) & 0xFF) & current_buttons
```

Điều này cho thấy game phân biệt việc giữ một nút
với việc vừa nhấn nút đó.

### 5.5. Chọn hàm cần phân tích tiếp

Ngay sau khi đọc tay cầm, chương trình gọi `$80EF`.

Hàm này xét hai bit thấp của trạng thái nút bằng:

```asm
80F5: LDA $03
80F7: AND #$03
```

Sau đó kiểm tra các giá trị `1` và `2`:

```asm
80FB: LDA $01
80FD: AND #$03
80FF: CMP #$01
8101: BEQ $8108
8103: CMP #$02
8105: BEQ $810D
```

Hai giá trị này tương ứng với nút A và B.

Vì hàm xử lý A/B được gọi trực tiếp trong vòng chính,
đây là vị trí cần phân tích tiếp để tìm cơ chế ghi
và kiểm tra chuỗi nút bí mật.

## 6. Phân tích cơ chế ghi chuỗi A/B

### 6.1. Xác định giá trị của nút A và B

Từ vòng lặp chính, tiếp tục phân tích hàm tại `$80EF`:

```bash
sed -n '/^80EF:/,/^8111:/p' disasm.txt
```

Hàm kiểm tra các nút mới nhấn bằng cách đọc `$03`
và giữ lại hai bit thấp:

```asm
80F5: LDA $03
80F7: AND #$03
80F9: BEQ $8142
```

Nếu không có nút A/B mới được nhấn, chương trình bỏ qua.

Sau đó, trạng thái hiện tại được kiểm tra:

```asm
80FB: LDA $01
80FD: AND #$03
80FF: CMP #$01
8101: BEQ $8108
8103: CMP #$02
8105: BEQ $810D
```

Hai nhánh tương ứng:

```asm
8108: LDA #$00
810A: JMP $810F
810D: LDA #$01
810F: STA $0F
```

Từ đó suy ra:

| Nút | Giá trị sau khi lọc | Bit được lưu tại $0F |
|---|---:|---:|
| A | 1 | 0 |
| B | 2 | 1 |

Nhấn đồng thời A và B cho giá trị 3, không khớp hai nhánh,
nên không ghi bit.

<img width="522" height="396" alt="image" src="https://github.com/user-attachments/assets/67cf949a-3888-4560-8a91-31cb81d03f29" />


*Hình 4. Đoạn assembly chuyển nút A thành bit 0 và nút B thành bit 1.*

### 6.2. Cách ghi bit vào buffer

Xem đoạn mã tiếp theo:

```bash
sed -n '/^8111:/,/^8142:/p' disasm.txt
```

Các biến được sử dụng:

| Địa chỉ RAM | Vai trò |
|---|---|
| `$0C` | Số bit đã ghi |
| `$0D` | Chỉ số byte trong buffer |
| `$0E` | Mặt nạ xác định vị trí bit |
| `$0F` | Bit vừa nhận từ nút A/B |
| `$0400–$040B` | Buffer chứa chuỗi bit |

Nếu bit nhận được là 1, chương trình dùng OR để bật
bit tương ứng trong buffer:

```asm
8117: LDA $0400,X
811A: ORA $0E
811C: STA $0400,X
```

Nếu bit là 0, chương trình bỏ qua thao tác OR.

Sau đó, mặt nạ được dịch sang phải:

```asm
811F: LSR $0E
```

Mặt nạ bắt đầu từ `0x80`, nên các bit được ghi theo thứ tự:

```text
80 → 40 → 20 → 10 → 08 → 04 → 02 → 01
```

Đây là thứ tự MSB-first: từ bit cao xuống bit thấp.

### 6.3. Điều kiện gọi hàm kiểm tra
```asm
sed -n '/^8111:/,/^8142:/p' disasm.txt
```
Sau mỗi bit hợp lệ, bộ đếm tăng một đơn vị:

```asm
8129: INC $0C
812B: LDA $0C
812D: CMP #$5F
812F: BNE $8142
8131: JSR $8158
```

Vì `0x5F = 95`, hàm kiểm tra tại `$8158`
chỉ được gọi sau khi đã ghi đủ 95 bit.

<img width="548" height="537" alt="image" src="https://github.com/user-attachments/assets/7204b78d-2777-4170-a6ab-babdf9407585" />


*Hình 5. Cơ chế ghi bit vào buffer và điều kiện gọi checker sau 95 bit.*

Như vậy, dữ liệu đầu vào của nhánh bí mật là một chuỗi
95 lần nhấn A/B. Bước tiếp theo là phân tích hàm `$8158`
để xác định chuỗi nào được chấp nhận.

## 7. Phân tích hàm kiểm tra tại `$8158`

Sau khi nhận đủ 95 bit từ các nút A/B, chương trình gọi hàm
`$8158`. Hàm này so sánh từng bit đầu vào với một bit được tính
từ hai bảng dữ liệu trong ROM.

### 7.1. Khởi tạo các biến và lấy bit đầu vào

Trích xuất phần đầu hàm bằng lệnh:

```bash
sed -n '/^8158:/,/^817B:/p' disasm.txt
```

<img width="760" height="483" alt="image" src="https://github.com/user-attachments/assets/af1adfb5-d9b8-4451-9215-7ea4bb9320fa" />


*Hình 6. Disassembly phần khởi tạo và lấy bit đầu vào của checker trên Kali Linux.*

Các biến RAM được sử dụng:

| Địa chỉ | Vai trò | Giá trị khởi tạo |
|---|---|---|
| `$14` | Chỉ số bit `i` | 0 |
| `$15` | Chỉ số bảng `j` | 11 |
| `$16` | Biến tích lũy sai lệch | 0 |
| `$0F` | Bit đầu vào đang xét | Được cập nhật mỗi vòng |

Chương trình tính vị trí bit trong byte bằng `i & 7`, sau đó
dịch phải `i` ba lần để tính chỉ số byte `i >> 3`.

Byte đầu vào được đọc từ `$0400 + (i >> 3)`. Bảng mặt nạ tại
`$8609` được dùng để chọn bit tương ứng. Kết quả được chuẩn hóa
thành 0 hoặc 1 rồi lưu vào `$0F`.

Do buffer được ghi theo thứ tự bit cao trước, thao tác này tương
đương:

```python
input_bit = (buffer[i >> 3] >> (7 - (i & 7))) & 1
```

### 7.2. Tính bit mong đợi bằng XOR

Trích xuất phần còn lại của checker:

```bash
sed -n '/^817D:/,/^81A7:/p' disasm.txt
```

<img width="791" height="512" alt="image" src="https://github.com/user-attachments/assets/c4376fda-9fa7-44a8-8437-d0d4f4c3512f" />


*Hình 7. Các phép XOR, cập nhật chỉ số và điều kiện trả về của checker.*

Đoạn assembly tính bit mong đợi:

```asm
817D: LDX $15
817F: LDA $8718,X
8182: EOR $8798,X
8185: EOR $14
8187: AND #$01
```

Đặt `tableA` là bảng bắt đầu tại địa chỉ CPU `$8718` và
`tableB` là bảng bắt đầu tại `$8798`.

Trong assembly 6502, `EOR` thực hiện phép XOR. Vì vậy, đoạn mã
trên tương đương:

```python
expected_bit = (tableA[j] ^ tableB[j] ^ i) & 1
```

Lệnh `AND #$01` chỉ giữ lại bit thấp nhất, nên kết quả luôn
bằng 0 hoặc 1.

Chương trình tiếp tục so sánh với bit đầu vào:

```asm
8189: EOR $0F
818B: ORA $16
818D: STA $16
```

Có thể biểu diễn bằng:

```python
mismatch |= expected_bit ^ input_bit
```

Nếu hai bit giống nhau, phép XOR cho kết quả 0.
Nếu hai bit khác nhau, phép XOR cho kết quả 1.

Do kết quả được tích lũy bằng OR, chỉ cần một bit sai thì
`mismatch` sẽ khác 0 ở cuối vòng lặp.

### 7.3. Quy luật cập nhật chỉ số bảng

Đoạn cập nhật chỉ số:

```asm
818F: LDA $15
8191: CLC
8192: ADC #$25
8194: AND #$7F
8196: STA $15
8198: INC $14
819A: LDA $14
819C: CMP #$5F
819E: BNE $8162
```

`CLC` xóa cờ carry trước phép cộng.
Vì `$25 = 37` và `$7F = 127`, ta có:

```python
j = (j + 37) & 0x7F
i += 1
```

Phép AND với `0x7F` giữ chỉ số trong khoảng 0 đến 127,
tương đương lấy modulo 128 ở đây.

Ban đầu `j = 11`, nên ở vòng lặp thứ `i`:

```python
j = (11 + 37 * i) & 0x7F
```

Lệnh `CMP #$5F` kiểm tra mốc 95, vì vậy hàm xử lý
các bit có chỉ số từ 0 đến 94.

Kết hợp các bước, công thức bit hợp lệ là:

```python
j = (11 + 37 * i) & 0x7F
expected_bit = (tableA[j] ^ tableB[j] ^ i) & 1
```

### 7.4. Điều kiện checker thành công

Phần cuối hàm:

```asm
81A0: LDA $16
81A2: BNE $81A6
81A4: SEC
81A5: RTS
81A6: CLC
81A7: RTS
```

Nếu `$16 = 0`, toàn bộ 95 bit đều khớp. Hàm thực hiện `SEC`
để trả về với cờ carry bằng 1.

Nếu `$16` khác 0, có ít nhất một bit sai. Hàm thực hiện `CLC`
để trả về với cờ carry bằng 0.

Tại nơi gọi hàm, lệnh `BCC $813F` rẽ nhánh khi carry bằng 0.
Nếu kiểm tra thành công, chương trình tiếp tục đặt `$04 = 4`
và `$05 = 5`.

Như vậy, có thể khôi phục trực tiếp chuỗi bit đúng bằng cách
đọc hai bảng dữ liệu và áp dụng công thức trên cho 95 vị trí,
không cần thử tất cả các chuỗi A/B.
