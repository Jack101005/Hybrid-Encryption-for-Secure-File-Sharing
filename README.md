# Hybrid Encryption for Secure File Sharing

Đồ án môn **IT Security (61ECE315)** – VGU. Chương trình mã hoá file theo mô hình
**hybrid encryption**: dùng **AES-256-GCM** để mã hoá dữ liệu, và bọc (wrap)
symmetric key bằng **RSA-OAEP**.

## Nhóm
Trịnh Minh Khôi, Hoàng Hải Long, Lưu Đức Duy, Bùi Vĩnh An, Nguyễn Hữu Trí

**Deadline:** 04/12/2026

## Ý tưởng
1. Người nhận có sẵn cặp khoá RSA (mặc định 3072-bit).
2. **Encrypt:** sinh AES-256 key ngẫu nhiên → mã hoá file bằng AES-256-GCM →
   bọc AES key bằng public key của người nhận (RSA-OAEP, SHA-256).
3. Đóng gói tất cả vào 1 file `.hyb`.
4. **Decrypt:** người nhận mở AES key bằng private key của mình → giải mã file +
   kiểm tra tính toàn vẹn (GCM tag).

## Cấu trúc
```
hybridcrypto/     package chính
  aes_gcm.py      AES-256-GCM encrypt/decrypt
  rsa_oaep.py     RSA keypair + OAEP wrap/unwrap key
  container.py    định dạng file .hyb (pack/unpack)
  crypto.py       ghép cấp cao: encrypt_file / decrypt_file
  cli.py          giao diện dòng lệnh: keygen / encrypt / decrypt
tests/            unit test + end-to-end
demo/             kịch bản "2 người share file"
docs/             report + slide
samples/          file mẫu để test
keys/             chỗ để keypair test (KHÔNG commit private key)
```

## Cài đặt
```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Cách dùng (sau khi implement xong)
```bash
# Sinh cặp khoá RSA
python -m hybridcrypto.cli keygen --out keys/

# Mã hoá file bằng public key của người nhận
python -m hybridcrypto.cli encrypt --in samples/sample.txt --out sample.hyb --pubkey keys/public.pem

# Giải mã bằng private key
python -m hybridcrypto.cli decrypt --in sample.hyb --out sample.out.txt --privkey keys/private.pem
```

## Chạy test
```bash
python -m pytest
```

## Trạng thái
🚧 Đang dựng khung — các hàm lõi còn là stub (`NotImplementedError`), sẽ code sau.
