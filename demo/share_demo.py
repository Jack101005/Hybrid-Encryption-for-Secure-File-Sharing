"""Kịch bản demo: Alice gửi file mật cho Bob.

[Mảng: Demo]

Ý tưởng trình bày cho thầy:
  1. Bob tạo cặp khoá RSA, đưa public key cho Alice (private key giữ kín).
  2. Alice mã hoá file bằng public key của Bob -> ra file .hyb.
  3. Alice gửi file .hyb qua kênh công khai (email, USB, chat...).
  4. Chỉ Bob (có private key) mới giải mã được.
  5. Thử: kẻ tấn công sửa file .hyb -> Bob giải mã sẽ báo lỗi (GCM tag).

Sẽ viết chi tiết sau khi các module lõi xong.
"""
from __future__ import annotations


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()
