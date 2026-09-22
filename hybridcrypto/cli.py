"""Giao diện dòng lệnh: keygen / encrypt / decrypt.

[Mảng: CLI + File I/O]

Chạy:  python -m hybridcrypto.cli <lệnh> [tham số]
"""
from __future__ import annotations

import argparse
import sys


def cmd_keygen(args: argparse.Namespace) -> None:
    # TODO: rsa_oaep.generate_keypair(args.bits) → save public/private vào args.out
    raise NotImplementedError


def cmd_encrypt(args: argparse.Namespace) -> None:
    # TODO: crypto.encrypt_file(args.inp, args.out, args.pubkey)
    raise NotImplementedError


def cmd_decrypt(args: argparse.Namespace) -> None:
    # TODO: crypto.decrypt_file(args.inp, args.out, args.privkey)
    raise NotImplementedError


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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
