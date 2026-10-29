"""Giao diện dòng lệnh: keygen, encrypt, decrypt, sign, verify, fingerprint.

[Mảng: CLI + File I/O]

Chạy:  python -m hybridcrypto.cli <lệnh> [tham số]
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag

from digitalSignature import signature
from hybridcrypto import crypto, keyInfo, rsa_oaep


def cmd_keygen(args: argparse.Namespace) -> None:
    if args.bits < 2048:
        raise ValueError("RSA key phải có kích thước ít nhất 2048 bits")

    out_dir = Path(args.out)
    pub_path = out_dir / "public.pem"
    priv_path = out_dir / "private.pem"

    # Never overwrite existing keys: if the old private key is lost,
    # everything encrypted for it becomes unrecoverable.
    for path in (pub_path, priv_path):
        if path.exists():
            raise FileExistsError(f"{path} đã tồn tại; hãy dùng --out directory khác, hoặc di chuyển các khóa cũ trước")

    private_key, public_key = rsa_oaep.generate_keypair(args.bits)

    out_dir.mkdir(parents=True, exist_ok=True)
    rsa_oaep.save_private_key(private_key, priv_path)
    try:
        os.chmod(priv_path, 0o600)  # owner-only; limited effect on Windows
    except OSError:
        pass
    rsa_oaep.save_public_key(public_key, pub_path)
    print(f"Các khóa đã lưu: {pub_path}, {priv_path}")


def cmd_encrypt(args: argparse.Namespace) -> None:
    crypto.encrypt_file(args.inp, args.out, args.pubkey)
    print(f"Encrypted {args.inp} -> {args.out}")


def cmd_decrypt(args: argparse.Namespace) -> None:
    crypto.decrypt_file(args.inp, args.out, args.privkey)
    print(f"Decrypted {args.inp} -> {args.out}")


def cmd_sign(args: argparse.Namespace) -> None:
    sig_path = args.out or f"{args.inp}.sig"
    private_key = rsa_oaep.load_private_key(args.privkey)
    signature.sign_file(private_key, args.inp, sig_path)
    print(f"Signed {args.inp} -> {sig_path}")


def cmd_verify(args: argparse.Namespace) -> int:
    sig_path = args.sig or f"{args.inp}.sig"
    public_key = rsa_oaep.load_public_key(args.pubkey)
    if signature.verify_file(public_key, args.inp, sig_path):
        print(f"Chữ ký hợp lệ: {args.inp} đúng là do chủ của {args.pubkey} ký, và không bị sửa")
        return 0
    return fail("chữ ký KHÔNG hợp lệ: file đã bị sửa, hoặc không phải do chủ public key này ký")


def cmd_fingerprint(args: argparse.Namespace) -> int:
    fp = keyInfo.fingerprint_file(args.pubkey)
    print(fp)
    if args.expect is None:
        return 0
    if keyInfo.keyCompare(args.pubkey, args.expect):
        print("Fingerprint KHỚP: đây đúng là public key của người đó")
        return 0
    return fail("fingerprint KHÔNG khớp: public key này có thể đã bị tráo, đừng dùng nó")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hybridcrypto",
        description="Hybrid file encryption: AES-256-GCM + RSA-OAEP.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_key = sub.add_parser("keygen", help="Sinh cặp khoá RSA")
    p_key.add_argument("--out", default="keys/", help="Thư mục lưu khoá")
    p_key.add_argument("--bits", type=int, default=3072, help="Độ dài khoá RSA")
    p_key.set_defaults(func=cmd_keygen)

    p_enc = sub.add_parser("encrypt", help="Mã hoá 1 file")
    p_enc.add_argument("--in", dest="inp", required=True, help="File đầu vào")
    p_enc.add_argument("--out", required=True, help="File .hyb đầu ra")
    p_enc.add_argument("--pubkey", required=True, help="Public key người nhận (PEM)")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Giải mã 1 file .hyb")
    p_dec.add_argument("--in", dest="inp", required=True, help="File .hyb đầu vào")
    p_dec.add_argument("--out", required=True, help="File giải mã đầu ra")
    p_dec.add_argument("--privkey", required=True, help="Private key (PEM)")
    p_dec.set_defaults(func=cmd_decrypt)

    p_sign = sub.add_parser("sign", help="Ký 1 file bằng private key của người gửi")
    p_sign.add_argument("--in", dest="inp", required=True, help="File cần ký")
    p_sign.add_argument("--privkey", required=True, help="Private key của người gửi (PEM)")
    p_sign.add_argument("--out", help="File chữ ký đầu ra (mặc định: <file>.sig)")
    p_sign.set_defaults(func=cmd_sign)

    p_ver = sub.add_parser("verify", help="Kiểm tra chữ ký của 1 file")
    p_ver.add_argument("--in", dest="inp", required=True, help="File cần kiểm tra")
    p_ver.add_argument("--pubkey", required=True, help="Public key của người gửi (PEM)")
    p_ver.add_argument("--sig", help="File chữ ký (mặc định: <file>.sig)")
    p_ver.set_defaults(func=cmd_verify)

    p_fp = sub.add_parser("fingerprint", help="In fingerprint của public key, hoặc so với fingerprint mong đợi")
    p_fp.add_argument("--pubkey", required=True, help="Public key (PEM)")
    p_fp.add_argument("--expect", help="Fingerprint người kia đọc qua điện thoại, để so sánh")
    p_fp.set_defaults(func=cmd_fingerprint)

    return parser


def fail(message: str) -> int:
    print(f"Error: {message}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        rc = args.func(args)
    except FileNotFoundError as e:
        return fail(f"không tìm thấy file: {e.filename or e}")
    except PermissionError as e:
        return fail(f"không thể truy cập: {e.filename or e}")
    except InvalidTag:
        return fail("xác thực thất bại: file .hyb đã bị sửa hoặc bị hỏng")
    except (ValueError, OSError) as e:
        return fail(str(e))
    except Exception as e:  # last resort: no raw tracebacks for users
        return fail(f"unexpected {type(e).__name__}: {e}")
    return rc or 0


if __name__ == "__main__":
    sys.exit(main())