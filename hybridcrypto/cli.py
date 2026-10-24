"""Giao diện dòng lệnh: keygen / encrypt / decrypt.

[Mảng: CLI + File I/O]

Chạy:  python -m hybridcrypto.cli <lệnh> [tham số]
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization

from hybridcrypto import crypto, rsa_oaep


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
    priv_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    try:
        os.chmod(priv_path, 0o600)  # owner-only; limited effect on Windows
    except OSError:
        pass
    pub_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"Các khóa đã lưu: {pub_path}, {priv_path}")


def cmd_encrypt(args: argparse.Namespace) -> None:
    crypto.encrypt_file(args.inp, args.out, args.pubkey)
    print(f"Encrypted {args.inp} -> {args.out}")


def cmd_decrypt(args: argparse.Namespace) -> None:
    crypto.decrypt_file(args.inp, args.out, args.privkey)
    print(f"Decrypted {args.inp} -> {args.out}")


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

    return parser


def fail(message: str) -> int:
    print(f"Error: {message}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except FileNotFoundError as e:
        return fail(f"không tìm thấy file: {e.filename or e}")
    except PermissionError as e:
        return fail(f"không thể truy cập: {e.filename or e}")
    except InvalidTag:
        return fail("xác thực thất bại: sai khóa, hoặc tệp tin đã bị hỏng hoặc can thiệp")
    except (ValueError, OSError) as e:
        return fail(str(e))
    except Exception as e:  # last resort: no raw tracebacks for users
        return fail(f"unexpected {type(e).__name__}: {e}")
    return 0
