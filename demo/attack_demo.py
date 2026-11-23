"""Demo Tấn công 1 và Tấn công 2 của Trudy.

Tấn công 1: Trudy sửa 1 bit trong file .hyb trên đường đi, rồi gửi tiếp cho Bob.
Tấn công 2: Trudy dùng private key của chính Trudy để mở file .hyb của Bob.

Chạy từ thư mục gốc của repo:
    python3 demo/attack_demo.py setup      Bob, Trudy tạo khoá; Alice mã hoá; Bob giải mã bình thường
    python3 demo/attack_demo.py attack1    Tấn công 1 (mặc định sửa byte ở vị trí 413)
    python3 demo/attack_demo.py attack2    Tấn công 2
    python3 demo/attack_demo.py all        Chạy cả 3 phần trên liên tục
Thêm --pause để dừng sau mỗi bước (bấm Enter đi tiếp) khi thuyết trình.

Mỗi tấn công được chạy 2 lần:
  1. Từng bước, theo đúng thứ tự trong crypto.decrypt_file, để thấy file nào chặn.
  2. Bằng đúng lệnh thật "python3 -m hybridcrypto.cli decrypt ...", để thấy chương
     trình thật báo lỗi gì và không ghi ra file nào.
Mọi file của demo nằm trong demo/output_tan_cong/ (không bao giờ lên GitHub).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))  # để import được hybridcrypto khi chạy "python3 demo/attack_demo.py"

from cryptography.exceptions import InvalidTag  # noqa: E402

from hybridcrypto import aes_gcm, container, crypto, rsa_oaep  # noqa: E402

WORK = REPO / "demo" / "output_tan_cong"
BOB_PUB, BOB_PRIV = WORK / "bob_public.pem", WORK / "bob_private.pem"
TRUDY_PUB, TRUDY_PRIV = WORK / "trudy_public.pem", WORK / "trudy_private.pem"
MSG = WORK / "tin_nhan.txt"
HYB = WORK / "tin_nhan.hyb"
HYB_BAD = WORK / "tin_nhan_bi_sua.hyb"
MESSAGE = "Chào Bob, mã két sắt là 2468. Đừng nói cho ai nhé! Alice"

PY = "python" if os.name == "nt" else "python3"
PAUSE = False
COLOR = True

for stream in (sys.stdout, sys.stderr):  # để Windows in được tiếng Việt
    try:
        stream.reconfigure(encoding="utf-8")
    except Exception:
        pass


# In ra màn hình

def color(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOR else text


def title(text: str) -> None:
    print()
    print(color("1;36", "=" * 70))
    print(color("1;36", text))
    print(color("1;36", "=" * 70))


def info(text: str = "") -> None:
    print("  " + text)


def ok(file: str, text: str) -> None:
    print(f"  {color('1;32', 'OK  ')} [{file}] {text}")


def stop(file: str, text: str) -> None:
    print(f"  {color('1;31', 'DỪNG')} [{file}] {text}")


def pause() -> None:
    if PAUSE and sys.stdin.isatty():
        input(color("2", "  [Enter] để đi tiếp ..."))


def rel(path: Path) -> str:
    return path.relative_to(REPO).as_posix()


def expect(condition: bool, message: str) -> None:
    """Nếu kết quả khác với mong đợi thì dừng demo, để không trình bày sai."""
    if not condition:
        print(color("1;31", f"  DEMO LỖI: {message}"))
        sys.exit(1)


# Cấu trúc file .hyb

def regions(data: bytes) -> list[tuple[str, int, int]]:
    """Các phần của file .hyb: (tên, vị trí bắt đầu, vị trí kết thúc không tính)."""
    key_end = 7 + int.from_bytes(data[5:7], "big")
    return [
        ("phần đầu: chữ HYBR, version, độ dài", 0, 7),
        ("hộp khoá AES đã bọc (wrapped_key)", 7, key_end),
        ("nonce", key_end, key_end + 12),
        ("nội dung đã mã (ciphertext)", key_end + 12, len(data) - 16),
        ("tag, con tem niêm phong", len(data) - 16, len(data)),
    ]


def region_of(pos: int, data: bytes) -> str:
    for name, start, end in regions(data):
        if start <= pos < end:
            return name
    return "ngoài file"


# Giải mã: từng bước và bằng lệnh thật

def decrypt_step_by_step(hyb_path: Path, private_key_path: Path) -> bytes | None:
    """Làm lại đúng thứ tự của crypto.decrypt_file, in ra file nào lo bước nào."""
    data = hyb_path.read_bytes()

    try:
        c = container.unpack(data)
    except ValueError as e:
        stop("hybridcrypto/container.py", f"Tách file thất bại: {e}")
        return None
    ok("hybridcrypto/container.py", "Tách file: đúng chữ HYBR, đúng version, ra 3 phần")

    private_key = rsa_oaep.load_private_key(str(private_key_path))
    try:
        aes_key = rsa_oaep.unwrap_key(private_key, c.wrapped_key)
    except ValueError as e:
        stop("hybridcrypto/rsa_oaep.py", f"Mở hộp khoá AES bằng {private_key_path.name}: {e}")
        return None
    ok("hybridcrypto/rsa_oaep.py",
       f"Mở hộp khoá AES bằng {private_key_path.name}: lấy được khoá {aes_key[:4].hex(' ')} ...")

    try:
        plaintext = aes_gcm.decrypt(aes_key, c.nonce, c.ciphertext)
    except InvalidTag:
        stop("hybridcrypto/aes_gcm.py", "Kiểm tag GCM: tag KHÔNG khớp, file đã bị sửa (InvalidTag)")
        return None
    ok("hybridcrypto/aes_gcm.py", "Kiểm tag GCM: khớp, file không bị ai sửa")
    return plaintext


def run_real_command(hyb_path: Path, private_key_path: Path, out_path: Path) -> int:
    """Chạy đúng lệnh mà người dùng gõ, rồi xem có file nào được ghi ra không."""
    if out_path.exists():
        out_path.unlink()  # xoá kết quả cũ, để kiểm tra cho công bằng
    args = ["decrypt", "--in", rel(hyb_path), "--out", rel(out_path), "--privkey", rel(private_key_path)]
    print()
    info(color("33", f"$ {PY} -m hybridcrypto.cli " + " ".join(args)))
    result = subprocess.run(
        [sys.executable, "-m", "hybridcrypto.cli", *args],
        cwd=REPO, capture_output=True, text=True, encoding="utf-8",
        env=dict(os.environ, PYTHONIOENCODING="utf-8"),
    )
    for line in (result.stdout + result.stderr).strip().splitlines():
        info("  " + line)
    info(f"Exit code: {result.returncode} (0 là thành công, 1 là bị chặn)")
    if out_path.exists():
        info(f"Đã ghi ra file {rel(out_path)}")
    else:
        info(f"Không có file {rel(out_path)} nào được ghi ra")
    return result.returncode


# Các phần của demo

def setup(bits: int) -> None:
    title("CHUẨN BỊ: Bob và Trudy tạo khoá, Alice mã hoá tin nhắn cho Bob")
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / ".gitignore").write_text("*\n")  # khoá trong thư mục này không bao giờ lên GitHub

    for name, pub, priv in (("Bob", BOB_PUB, BOB_PRIV), ("Trudy", TRUDY_PUB, TRUDY_PRIV)):
        private_key, public_key = rsa_oaep.generate_keypair(bits)
        rsa_oaep.save_private_key(private_key, str(priv))
        rsa_oaep.save_public_key(public_key, str(pub))
        ok("hybridcrypto/rsa_oaep.py", f"{name} tạo cặp khoá RSA {bits} bit: {pub.name}, {priv.name}")

    MSG.write_text(MESSAGE, encoding="utf-8")
    info(f'Tin nhắn của Alice: "{MESSAGE}" ({MSG.stat().st_size} byte)')
    crypto.encrypt_file(str(MSG), str(HYB), str(BOB_PUB))
    ok("hybridcrypto/crypto.py", f"Alice mã hoá bằng public key của Bob: {rel(HYB)} ({HYB.stat().st_size} byte)")

    data = HYB.read_bytes()
    info("Bên trong file .hyb:")
    for name, start, end in regions(data):
        info(f"  vị trí {start:>4} đến {end - 1:>4}   {name} ({end - start} byte)")
    pause()

    title("BÌNH THƯỜNG: Bob giải mã bằng private key của Bob")
    plaintext = decrypt_step_by_step(HYB, BOB_PRIV)
    expect(plaintext is not None, "Bob phải giải mã được file thật")
    info(f'Bob đọc được: "{plaintext.decode("utf-8")}"')
    rc = run_real_command(HYB, BOB_PRIV, WORK / "bob_doc_duoc.txt")
    expect(rc == 0 and (WORK / "bob_doc_duoc.txt").read_bytes() == MSG.read_bytes(),
           "lệnh thật phải giải mã ra đúng tin nhắn gốc")
    pause()


def attack1(pos: int) -> None:
    data = bytearray(HYB.read_bytes())
    if not 0 <= pos < len(data):
        sys.exit(f"--byte phải nằm trong khoảng 0 đến {len(data) - 1}")
    title("TẤN CÔNG 1: Trudy sửa 1 bit của file .hyb trên đường đi")

    where = region_of(pos, bytes(data))  # tính trên file gốc, trước khi sửa
    old = data[pos]
    data[pos] ^= 0x01  # đổi đúng 1 bit
    HYB_BAD.write_bytes(data)
    info(f"Trudy đổi byte ở vị trí {pos}, thuộc vùng {where}: {old:02x} thành {data[pos]:02x}, lệch đúng 1 bit")
    info(f"Rồi gửi tiếp cho Bob: {rel(HYB_BAD)}")
    pause()

    print()
    info("Bob giải mã từng bước, đúng thứ tự trong hybridcrypto/crypto.py (hàm decrypt_file):")
    plaintext = decrypt_step_by_step(HYB_BAD, BOB_PRIV)
    expect(plaintext is None, "file bị sửa thì không được giải mã ra")
    pause()

    print()
    info("Chạy đúng lệnh thật Bob sẽ gõ:")
    out = WORK / "bob_doc_file_bi_sua.txt"
    rc = run_real_command(HYB_BAD, BOB_PRIV, out)
    expect(rc == 1 and not out.exists(), "lệnh thật phải báo lỗi và không ghi file")
    print()
    info(color("1", "=> Trudy không đọc được, mà sửa lén cũng không được. Bob luôn biết file có bị đụng vào."))
    pause()


def attack2() -> None:
    title("TẤN CÔNG 2: Trudy dùng private key của Trudy để mở file")
    info(f"Trudy chặn được {rel(HYB)} (file thật, không sửa gì).")
    info(f"Trudy có private key thật: {TRUDY_PRIV.name}, nhưng khoá AES trong file được bọc cho Bob.")
    pause()

    print()
    info("Trudy giải mã từng bước, đúng thứ tự trong hybridcrypto/crypto.py (hàm decrypt_file):")
    plaintext = decrypt_step_by_step(HYB, TRUDY_PRIV)
    expect(plaintext is None, "private key của Trudy không được mở ra")
    pause()

    print()
    info("Chạy đúng lệnh thật Trudy sẽ gõ:")
    out = WORK / "trudy_doc_trom.txt"
    rc = run_real_command(HYB, TRUDY_PRIV, out)
    expect(rc == 1 and not out.exists(), "lệnh thật phải báo lỗi và không ghi file")
    print()
    info(color("1", "=> Khoá AES được bọc cho Bob, nên chỉ private key của Bob mở được."))
    pause()


def main() -> None:
    global PAUSE, COLOR
    parser = argparse.ArgumentParser(description="Demo tấn công 1 và 2 của Trudy")
    parser.add_argument("command", choices=["setup", "attack1", "attack2", "all"],
                        help="setup, attack1, attack2, hoặc all (chạy cả ba)")
    parser.add_argument("--byte", type=int, default=413,
                        help="Vị trí byte Trudy sửa ở tấn công 1, đếm từ 0 (mặc định 413)")
    parser.add_argument("--pause", action="store_true", help="Dừng sau mỗi bước, bấm Enter để đi tiếp")
    parser.add_argument("--bits", type=int, default=3072, help="Độ dài khoá RSA (mặc định 3072)")
    parser.add_argument("--no-color", action="store_true", help="Tắt màu")
    args = parser.parse_args()

    PAUSE = args.pause
    COLOR = not args.no_color and sys.stdout.isatty()
    if os.name == "nt":
        os.system("")  # bật màu trong terminal Windows

    missing = not all(p.exists() for p in (BOB_PRIV, TRUDY_PRIV, HYB))
    if args.command in ("setup", "all") or missing:
        setup(args.bits)
    if args.command in ("attack1", "all"):
        attack1(args.byte)
    if args.command in ("attack2", "all"):
        attack2()
    print()


if __name__ == "__main__":
    main()
