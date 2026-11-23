c# hybrid-crypto
 
Cái ý tưởng của cái bài này rất là đơn giản, thì thằng A muốn gửi cho thẳng B một cái tin nhắn nào đó qua email, zalo, messenger, etc thì có thằng C muốn đọc cái tin nhắn đó, thì cái mục tiêu của mình là chỉ đơn giản mã hoá cái tin nhắn mà thằng A muốn gửi trước khi gửi cho thằng B. Chấm hết.
 
 
 
# Mã hoá (Có bao nhiêu cách? )
 
 
# Cách 1: AES
 
Pro: 
 
Ưu điểm của nó là nó nhanh, chỉ cần mất 0,05 ms để mã hoá một cái tấm hình 475kb
 
 
Cons: 
 
Nhược điểm của nó là bên A và bên B phải có chung một cái khoá bí mật, và nếu mà trong cái tin nhắn gửi giữa A và B được ghi cái khoá bí mật đó thì thằng C thấy và biết được cái khoá bí mật đó
 
=> tin nhắn được mã hoá nhanh, nhưng mà cái vấn đề là để có được cái tốc độ nhanh này thì mình phải đánh đổi là cái khoá bí mật đó phải dùng chung bởi "Người gửi (A)" và "Người nhận (B)", nghĩa là tụi nó phải nhắn với nhau cái khoá bí mật đó, nếu mà không nhắn thì thằng nhận không giải mã được để đọc được tin nhắn thằng gửi muốn nói. Thì cuối nó sẽ có một cái vấn đề là do là khi thằng gửi muốn gửi cái tin nhắn kèm với cái khoá bí mật đó cho thằng nhận thì thằng ăn cướp có thể chen ngang để đọc được cái tin nhắn đó bằng cách là nó lấy cái mã khoá bí mật thằng gửi muốn đưa cho thằng nhận. Đó là vấn đề của thằng AES.
 
 
# Cách 2: RSA
 
Pro:
 
Ưu điểm của nó là bên A chỉ cần cái public key của thằng B, (Nghĩa là hai bên nhắn tin với nhau không cần nhắn cái khoá với nhau nha AES)
 
 
Cons: 
 
Nhược điểm là nó chậm hơn AES, và mỗi lần mã hoá chỉ mã hoá được có 318 byte à, nếu mà mã hoá một cái tấm hình thì nó sẽ bị fail liền, cái result sẽ là "ValueError: encryption failed"
 
 
 
Solution: Là mình sẽ đưa 2 loại mã hoá vô chung, cái hình thì mã hoá bởi AES, còn cái khoá của AES thì mã hoá bằng RSA.
 
 
 
Từ đây mình gọi A là Alice (người gửi), B là Bob (người nhận), C là Trudy (thằng ăn cướp) cho giống trong video nha.
 
 
# Tạo khoá (Bob làm)
 
## Bước 0: Bob tạo một cặp khoá RSA 3072 bit (`hybridcrypto/rsa_oaep.py`)
 
Ra 2 file:
 
`bob_public.pem` là public key. Bob gửi cho Alice, ai thấy cũng không sao.
 
`bob_private.pem` là private key. Bob giữ kín, không gửi cho ai, không commit lên GitHub.
 
Ví dụ: public key giống một cái ổ khoá đang mở, ai cũng bấm khoá lại được. Private key là cái chìa duy nhất mở được ổ đó, và chỉ Bob có.
 
 
# Mã hoá (Alice làm)
 
Alice muốn gửi file `tin_nhan.txt`:
 
"Chào Bob, mã két sắt là 2468. Đừng nói cho ai nhé! Alice"
 
Với máy tính thì file nào cũng chỉ là một dãy byte. Tin nhắn này có 56 ký tự nhưng nặng 67 byte, vì chữ có dấu như "à" tốn 2 byte.
 
Cả phần mã hoá do `hybridcrypto/crypto.py` (hàm `encrypt_file`) điều khiển, nó gọi lần lượt các bước dưới đây.
 
## Bước 1: Tạo khoá AES (`hybridcrypto/aes_gcm.py`)
 
Máy tự tạo một khoá AES ngẫu nhiên 32 byte (256 bit). Mỗi file có một khoá mới tinh, dùng xong là bỏ, không ghi ra ổ đĩa.
 
Ví dụ: `47 81 d9 38 c7 97 2c 28 ...` (32 byte)
 
## Bước 2: Tạo nonce (`hybridcrypto/aes_gcm.py`)
 
Nonce là 12 byte ngẫu nhiên đi kèm khoá AES, để cùng một tin nhắn mà mã 2 lần thì ra 2 kết quả khác nhau. Không bao giờ dùng lại nonce với cùng một khoá.
 
Ví dụ: `15 48 77 9f d0 5b ...` (12 byte)
 
## Bước 3: AES mã nội dung file (`hybridcrypto/aes_gcm.py`)
 
Bỏ tin nhắn 67 byte + khoá AES + nonce vô AES GCM, ra 83 byte ciphertext:
 
67 byte dữ liệu đã mã + 16 byte tag = 83 byte
 
Tag giống con tem niêm phong: ai sửa dù chỉ 1 byte thì lúc giải mã sẽ bị phát hiện liền.
 
## Bước 4: RSA bọc khoá AES (`hybridcrypto/rsa_oaep.py`)
 
Giờ còn cái khoá AES 32 byte, không gửi trần ra được. Alice lấy public key của Bob bọc nó lại bằng RSA OAEP, ra một cái hộp 384 byte (gọi là wrapped_key). Chỉ private key của Bob mở được cái hộp này.
 
Ví dụ: bọc cùng một khoá 2 lần thì ra 2 cái hộp khác hẳn nhau:
 
lần 1: `50 8e 0d 81 a6 f5 ...`
 
lần 2: `6b 33 aa f5 25 0e ...`
 
Vì OAEP trộn thêm số ngẫu nhiên, nên Trudy nhìn cái hộp không đoán được gì.
 
## Bước 5: Đóng gói thành `tin_nhan.hyb` (`hybridcrypto/container.py`)
 
Gom hết vô 1 file theo thứ tự cố định:
 
| Phần | Kích thước | Ý nghĩa |
| --- | --- | --- |
| `48 59 42 52` | 4 byte | Chữ "HYBR", nhìn vô là biết file của nhóm mình |
| `01` | 1 byte | Version 1 |
| `01 80` | 2 byte | Bằng 384, cho biết cái hộp khoá dài bao nhiêu để lúc mở tách ra được |
| wrapped_key | 384 byte | Khoá AES đã bọc (Bước 4) |
| nonce | 12 byte | Bước 2 |
| ciphertext + tag | 83 byte | Bước 3 |
 
Tổng: 7 + 384 + 12 + 83 = 486 byte
 
=> Đây là file duy nhất Alice gửi đi. Khoá AES gốc không nằm trong file, chỉ có bản đã bọc.
 
 
# Gửi đi
 
Alice gửi đúng 1 file `tin_nhan.hyb` qua email, Zalo, messenger, gì cũng được. (Phần này không có file nào trong repo lo, vì gửi bằng app nào cũng được.)
 
Trudy chặn được thì cũng chỉ thấy một đống byte:
 
`48 59 42 52 01 01 80 50 8e 0d 81 a6 f5 21 89 d8 ...`
 
Muốn đọc tin nhắn thì phải có khoá AES. Muốn có khoá AES thì phải mở được cái hộp 384 byte. Muốn mở hộp thì phải có private key của Bob. Mà private key thì Bob giữ kín, chưa từng gửi đi.
 
=> Trudy bó tay.
 
 
# Giải mã (Bob làm)
 
Bob nhận `tin_nhan.hyb`. Cả phần giải mã do `hybridcrypto/crypto.py` (hàm `decrypt_file`) điều khiển.
 
## Bước 1: Tách file (`hybridcrypto/container.py`)
 
Kiểm đúng chữ HYBR, đúng version 1, rồi tách ra 3 phần: cái hộp khoá (wrapped_key), nonce, ciphertext.
 
## Bước 2: Mở hộp lấy lại khoá AES (`hybridcrypto/rsa_oaep.py`)
 
Bob dùng `bob_private.pem` mở cái hộp 384 byte, lấy ra khoá AES `47 81 d9 38 c7 97 ...`, giống hệt cái khoá Alice tạo ở Bước 1.
 
## Bước 3: AES giải mã và kiểm tem (`hybridcrypto/aes_gcm.py`)
 
Dùng khoá AES + nonce để giải mã ciphertext, đồng thời kiểm tag. Tag khớp nghĩa là file không bị ai sửa.
 
Kết quả: `tin_nhan_giai_ma.txt`
 
"Chào Bob, mã két sắt là 2468. Đừng nói cho ai nhé! Alice"
 
=> Giống từng chữ với file gốc.
 
 
# Tấn công (Trudy làm)
 
## Tấn công 1: Trudy sửa file trên đường đi
 
Trudy không đọc được, nên Trudy thử phá: sửa đúng 1 byte trong `tin_nhan.hyb` (byte thứ 413: `95` thành `94`, chỉ lệch đúng 1 bit) rồi gửi tiếp cho Bob.
 
Bob giải mã như bình thường. Tách file và mở hộp khoá vẫn qua, nhưng tới bước kiểm tem thì tag không khớp, báo lỗi `InvalidTag` (`hybridcrypto/aes_gcm.py`). Chương trình dừng luôn, không ghi ra file nào (`hybridcrypto/crypto.py`).
 
=> Trudy không đọc được, mà sửa lén cũng không được. Bob luôn biết file có bị đụng vào hay không.
 
## Tấn công 2: Trudy dùng private key của mình
 
Trudy cũng có một cặp khoá thật (`trudy_private.pem`), nhưng là của Trudy. Trudy thử lấy khoá đó mở `tin_nhan.hyb`.
 
Chương trình dừng ngay ở bước mở hộp khoá AES (`hybridcrypto/rsa_oaep.py`), báo lỗi không mở được khoá AES, không ghi ra file nào. (Trong video lỗi hiện là `ValueError: Decryption failed`, code bây giờ in ra câu tiếng Việt dễ hiểu hơn.)
 
=> Khoá AES được bọc cho Bob, nên chỉ private key của Bob mở được. Khoá của ai khác cũng vô dụng.
 
## Tấn công 3: Trudy tráo public key của Bob (man in the middle)
 
Lúc Bob gửi `bob_public.pem` cho Alice ở Bước 0, Trudy chặn giữa đường và đưa cho Alice public key của Trudy. Alice tưởng đó là key của Bob nên cứ mã hoá bằng nó. Vậy là Trudy mở được file (vì đó là khoá của Trudy), đọc xong còn mã lại bằng key thật của Bob rồi gửi tiếp, không ai biết gì.
 
Cách chặn: so fingerprint (`hybridcrypto/keyInfo.py`)
 
Fingerprint là "dấu vân tay" của public key: lấy SHA256 của key, ra 64 ký tự, chia thành 16 nhóm cho dễ đọc.
 
Bob đọc fingerprint của mình cho Alice qua một kênh khác, ví dụ gọi điện:
 
`CECE 77EE 64B1 E333 4540 092D 365E 1AE0 6E62 28B9 41D0 E179 C6B2 CAA3 8E84 3EAE`
 
Alice tính fingerprint của cái key mình nhận được rồi so:
 
| Key Alice nhận được | Fingerprint | Kết quả |
| --- | --- | --- |
| Key thật của Bob | `CECE 77EE 64B1 ...` | KHỚP, dùng được |
| Key Trudy tráo | `244C 4499 803C ...` | KHÔNG khớp, đừng dùng |
 
Ví dụ: Trudy chặn được email, chứ không giả được giọng Bob qua điện thoại.
 
=> Chỉ cần so fingerprint một lần trước khi dùng key, Trudy hết đường tráo.
 
## Tấn công 4: Trudy giả làm Alice
 
Public key của Bob thì ai cũng có (Bob phát cho mọi người mà). Nên Trudy cũng tự tạo được một file `.hyb` gửi cho Bob:
 
"Bob ơi, chuyển tiền vào tài khoản của Trudy nhé! Alice"
 
File này mã cho Bob nên Bob giải mã được bình thường, tag cũng khớp, vì cái khoá AES là do chính Trudy tạo ra. Bob không có cách nào biết ai gửi.
 
=> Mã hoá chỉ giữ bí mật, chứ không chứng minh được ai là người gửi.
 
Cách chặn: chữ ký số (`digitalSignature/signature.py`)
 
Alice cũng tạo một cặp khoá riêng cho mình, giống Bước 0. Sau khi mã hoá xong, Alice ký file `tin_nhan.hyb` bằng private key của Alice (lấy SHA256 của file rồi ký bằng RSA PSS), ra file chữ ký `tin_nhan.hyb.sig` (384 byte). Giờ Alice gửi 2 file: `tin_nhan.hyb` và `tin_nhan.hyb.sig`.
 
Bob kiểm chữ ký bằng public key của Alice trước khi giải mã:
 
| File Bob nhận | Ai ký | Kết quả |
| --- | --- | --- |
| File thật của Alice | Alice | Chữ ký hợp lệ, giải mã tiếp |
| File của Trudy | Trudy (ký bằng khoá của Trudy) | Chữ ký KHÔNG hợp lệ, vứt luôn |
 
Ví dụ: giống chữ ký tay. Ai cũng viết được một lá thư rồi ghi tên Alice ở cuối, nhưng chỉ Alice ký được chữ ký của Alice.
 
Thêm nữa: nếu Trudy sửa file `.hyb` như Tấn công 1 thì chữ ký cũng báo sai luôn, Bob chặn được từ trước khi giải mã.
 
=> Có chữ ký thì Bob biết chắc file là do Alice gửi, và chưa bị ai đụng vào.
 
 
# Tóm lại: 4 tấn công, file nào chặn
 
| Tấn công | Trudy làm gì | File chặn | Bị chặn ở đâu |
| --- | --- | --- | --- |
| 1 | Sửa 1 byte trên đường đi | `hybridcrypto/aes_gcm.py` (và `digitalSignature/signature.py` nếu có ký) | Tag không khớp |
| 2 | Dùng private key của mình để mở | `hybridcrypto/rsa_oaep.py` | Không mở được hộp khoá AES |
| 3 | Tráo public key của Bob | `hybridcrypto/keyInfo.py` | Fingerprint không khớp |
| 4 | Giả làm Alice gửi file | `digitalSignature/signature.py` | Chữ ký không hợp lệ |
 
Cả 4 tấn công này đều có trong `demo/share_demo.py`, chạy `python3 demo/share_demo.py --pause` là thấy từng cái bị chặn. Lưu ý thứ tự trong demo hơi khác: demo chạy sửa file, tráo key, giả Alice, rồi mới tới dùng private key của Trudy.
 