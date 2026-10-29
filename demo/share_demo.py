"""Kịch bản demo: Alice gửi file mật cho Bob, và 4 cách Trudy tấn công.

Owner: Tri

Every step runs the real CLI command (python3 -m hybridcrypto.cli ...) and
prints it first, so the audience sees exactly what a user would type.
If any result is not what we expect, the demo stops with "DEMO LỖI",
so this script also works as a full integration test.

Run from anywhere:
    python3 demo/share_demo.py                       run everything
    python3 demo/share_demo.py --pause               stop after each step (live demo)
    python3 demo/share_demo.py --file path/to/anh.jpg   use another file
All files go to demo/output/ (ignored by git), so you can open them afterwards.
"""
from __future__ import annotations

import argparse
import filecmp
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PY_SHOWN = "python" if os.name == "nt" else "python3"
MARKER = ".demo_output"

for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8")
    except Exception:
        pass


class Style:
    on = True

    @classmethod
    def wrap(cls, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.on else text


def bold(t): return Style.wrap("1", t)
def green(t): return Style.wrap("32", t)
def red(t): return Style.wrap("31", t)
def yellow(t): return Style.wrap("33", t)
def cyan(t): return Style.wrap("36", t)
def dim(t): return Style.wrap("2", t)


PAUSE = False


def pause() -> None:
    if PAUSE and sys.stdin.isatty():
        input(dim("    [Enter] để tiếp tục ..."))


def step(title: str, *lines: str) -> None:
    print()
    print(bold(cyan("=" * 72)))
    print(bold(cyan(title)))
    print(bold(cyan("=" * 72)))
    for line in lines:
        print("  " + line)


def rel(p) -> str:
    try:
        return str(Path(p).resolve().relative_to(REPO))
    except ValueError:
        return str(p)


def cli(*args, expect_ok: bool = True) -> str:
    shown = " ".join(
        f'"{a}"' if " " in str(a) else (rel(a) if isinstance(a, Path) else str(a)) for a in args
    )
    print()
    print("  " + yellow(f"$ {PY_SHOWN} -m hybridcrypto.cli {shown}"))
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "hybridcrypto.cli", *[str(a) for a in args]],
        cwd=REPO, capture_output=True, text=True, encoding="utf-8", env=env,
    )
    output = (result.stdout + result.stderr).strip()
    for line in output.splitlines():
        print("    " + line.replace(str(REPO) + os.sep, ""))
    ok = result.returncode == 0
    if ok != expect_ok:
        print(red(bold("  DEMO LỖI: kết quả khác với mong đợi, dừng lại.")))
        sys.exit(1)
    if not expect_ok:
        print("    " + green("Bị chặn, đúng như mong đợi."))
    return result.stdout.strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def show_text_if_small(path: Path, label: str) -> None:
    data = path.read_bytes()
    if len(data) > 400:
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    print(f"  {label}:")
    for line in text.strip().splitlines():
        print("    " + bold(line))


def prepare_workdir(workdir: Path) -> None:
    if workdir.exists():
        if (workdir / MARKER).exists():
            shutil.rmtree(workdir)
        elif any(workdir.iterdir()):
            sys.exit(f"{workdir} đã có file khác, hãy chọn --workdir khác.")
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / MARKER).write_text("created by demo/share_demo.py\n")
    # keep everything in this folder out of git (keys, .hyb, .sig, copies)
    (workdir / ".gitignore").write_text("*\n")


def main() -> None:
    global PAUSE
    parser = argparse.ArgumentParser(description="Demo Alice gửi file mật cho Bob")
    parser.add_argument("--file", default=str(REPO / "samples" / "sample.txt"), help="File Alice muốn gửi")
    parser.add_argument("--pause", action="store_true", help="Dừng sau mỗi bước, bấm Enter để đi tiếp")
    parser.add_argument("--bits", type=int, default=3072, help="Độ dài khoá RSA (mặc định 3072)")
    parser.add_argument("--workdir", default=str(REPO / "demo" / "output"), help="Thư mục chứa file của demo")
    parser.add_argument("--no-color", action="store_true", help="Tắt màu")
    args = parser.parse_args()

    PAUSE = args.pause
    Style.on = not args.no_color and sys.stdout.isatty()
    if os.name == "nt":
        os.system("")  # turns on ANSI colors in the Windows terminal

    src = Path(args.file).resolve()
    if not src.is_file():
        sys.exit(f"Không tìm thấy file: {args.file}")

    work = Path(args.workdir).resolve()
    prepare_workdir(work)
    bob, alice, trudy, channel = (work / n for n in ("bob", "alice", "trudy", "kenh_cong_khai"))
    for d in (bob, alice, trudy, channel):
        d.mkdir()
    hyb = channel / f"{src.name}.hyb"
    sig = channel / f"{src.name}.hyb.sig"

    print(bold("DEMO: Hybrid Encryption for Secure File Sharing"))
    print(f"File Alice muốn gửi cho Bob: {rel(src)} ({src.stat().st_size} byte)")
    print(f"Mọi file của demo nằm trong: {rel(work)}")
    show_text_if_small(src, "Nội dung")
    pause()

    # Step 1 and 2: keys
    step("BƯỚC 1: Bob tạo cặp khoá RSA",
         "public.pem đưa cho ai cũng được, private.pem Bob giữ kín.")
    cli("keygen", "--out", bob / "keys", "--bits", args.bits)
    pause()

    step("BƯỚC 2: Alice cũng tạo cặp khoá, để ký tên vào file gửi đi")
    cli("keygen", "--out", alice / "keys", "--bits", args.bits)
    shutil.copy(alice / "keys" / "public.pem", bob / "alice_public.pem")
    print("  Alice gửi public key của mình cho Bob: bob/alice_public.pem")
    pause()

    # Step 3: send Bob's public key and check the fingerprint
    step("BƯỚC 3: Bob gửi public key cho Alice, rồi đọc fingerprint qua điện thoại",
         "Public key đi qua kênh công khai nên có thể bị tráo. Fingerprint được so",
         "qua một kênh khác (gọi điện, Zalo) để chắc đây đúng là khoá của Bob.")
    shutil.copy(bob / "keys" / "public.pem", channel / "bob_public.pem")
    shutil.copy(channel / "bob_public.pem", alice / "bob_public.pem")
    print("  Bob chạy trên máy Bob:")
    bob_fp = cli("fingerprint", "--pubkey", bob / "keys" / "public.pem")
    print()
    print(f"  Bob đọc qua điện thoại: {bold(bob_fp)}")
    print("  Alice so với khoá cô ấy nhận được:")
    cli("fingerprint", "--pubkey", alice / "bob_public.pem", "--expect", bob_fp)
    pause()

    # Step 4 and 5: encrypt and sign
    step("BƯỚC 4: Alice mã hoá file bằng public key của Bob",
         "AES 256 GCM mã cả file, RSA OAEP bọc khoá AES, tất cả nằm trong file .hyb.")
    cli("encrypt", "--in", src, "--out", hyb, "--pubkey", alice / "bob_public.pem")
    head = hyb.read_bytes()[:24]
    print(f"  {rel(hyb)}: {hyb.stat().st_size} byte, 24 byte đầu:")
    print("    " + " ".join(f"{b:02x}" for b in head) + "  ...")
    print(dim("    (48 59 42 52 là chữ HYBR, phần sau là khoá đã bọc và dữ liệu đã mã, không đọc được)"))
    pause()

    step("BƯỚC 5: Alice ký file .hyb bằng private key của Alice",
         "Chữ ký chứng minh file do Alice gửi, vì ai cũng có public key của Bob để tạo .hyb.")
    cli("sign", "--in", hyb, "--privkey", alice / "keys" / "private.pem")
    pause()

    # Step 6: Bob verifies and decrypts
    step("BƯỚC 6: Bob kiểm chữ ký bằng public key của Alice, rồi giải mã")
    cli("verify", "--in", hyb, "--pubkey", bob / "alice_public.pem")
    out = bob / f"nhan_{src.name}"
    cli("decrypt", "--in", hyb, "--out", out, "--privkey", bob / "keys" / "private.pem")
    same = filecmp.cmp(src, out, shallow=False)
    if not same:
        print(red(bold("  DEMO LỖI: file giải mã khác file gốc.")))
        sys.exit(1)
    print()
    print("  " + green(f"File giải mã giống hệt file gốc (SHA256 {sha256(out)[:16]}...)"))
    show_text_if_small(out, "Bob đọc được")
    pause()

    # Attack 1: tamper
    step("TẤN CÔNG 1: Trudy sửa 1 byte của file .hyb trên đường đi")
    bad = trudy / f"{src.name}_bi_sua.hyb"
    data = bytearray(hyb.read_bytes())
    data[-5] ^= 0x01
    bad.write_bytes(data)
    shutil.copy(sig, trudy / f"{bad.name}.sig")
    print(f"  Trudy đổi byte thứ {len(data) - 5} và gửi tiếp cho Bob: {rel(bad)}")
    cli("verify", "--in", bad, "--pubkey", bob / "alice_public.pem", expect_ok=False)
    print("  Dù Bob bỏ qua chữ ký và cứ giải mã, tag của AES GCM vẫn bắt được:")
    cli("decrypt", "--in", bad, "--out", bob / "khong_nen_co.txt",
        "--privkey", bob / "keys" / "private.pem", expect_ok=False)
    pause()

    # Attack 2: swap the public key
    step("TẤN CÔNG 2: Trudy tráo public key của Bob (man in the middle)",
         "Trudy chặn kênh công khai và đưa cho Alice public key của Trudy thay vì của Bob.")
    cli("keygen", "--out", trudy / "keys", "--bits", args.bits)
    shutil.copy(trudy / "keys" / "public.pem", alice / "bob_public_bi_trao.pem")
    print("  Alice so với fingerprint Bob đã đọc qua điện thoại:")
    cli("fingerprint", "--pubkey", alice / "bob_public_bi_trao.pem", "--expect", bob_fp, expect_ok=False)
    print("  Alice phát hiện khoá bị tráo nên không mã hoá gì bằng khoá này.")
    pause()

    # Attack 3: pretend to be Alice
    step("TẤN CÔNG 3: Trudy giả làm Alice gửi file cho Bob",
         "Public key của Bob ai cũng có, nên Trudy tự tạo được file .hyb gửi Bob.")
    fake = trudy / "tin_gia.txt"
    fake.write_text("Bob ơi, chuyển tiền vào tài khoản của Trudy nhé! Alice\n", encoding="utf-8")
    fake_hyb = trudy / "tin_gia.txt.hyb"
    cli("encrypt", "--in", fake, "--out", fake_hyb, "--pubkey", channel / "bob_public.pem")
    cli("sign", "--in", fake_hyb, "--privkey", trudy / "keys" / "private.pem")
    print("  Bob kiểm chữ ký bằng public key của Alice:")
    cli("verify", "--in", fake_hyb, "--pubkey", bob / "alice_public.pem", expect_ok=False)
    print("  File này vẫn giải mã được (vì mã cho Bob), nên chữ ký là thứ duy nhất lộ ra Trudy.")
    pause()

    # Attack 4: wrong private key
    step("TẤN CÔNG 4: Trudy dùng private key của mình để mở file của Alice")
    cli("decrypt", "--in", hyb, "--out", trudy / "doc_trom.txt",
        "--privkey", trudy / "keys" / "private.pem", expect_ok=False)
    pause()

    step("TÓM TẮT")
    print("  " + green("Bảo mật (confidentiality):") + " chỉ private key của Bob mở được khoá AES.")
    print("  " + green("Toàn vẹn (integrity):") + " sửa 1 byte là tag GCM và chữ ký đều báo lỗi.")
    print("  " + green("Xác thực người gửi:") + " chữ ký RSA PSS chặn Trudy giả làm Alice.")
    print("  " + green("Chống tráo khoá:") + " so fingerprint qua kênh khác chặn man in the middle.")
    print()
    print(f"  Mở thư mục {rel(work)} để xem tất cả file vừa tạo.")


if __name__ == "__main__":
    main()
