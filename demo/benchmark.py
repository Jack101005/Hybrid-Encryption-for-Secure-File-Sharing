"""Benchmark: why hybrid encryption instead of RSA only.

Owner: Tri

For several file sizes it measures, on this machine:
  AES GCM encrypt and decrypt of the whole file,
  RSA OAEP wrap and unwrap of the 32 byte AES key,
  decrypting the same file with RSA only (cut into 318 byte blocks).

RSA only is measured for real when the file needs at most MAX_REAL_BLOCKS
blocks. For bigger files it is estimated as (number of blocks) x (time of one
block) and marked with *.

Run from the repo root:
    python3 demo/benchmark.py
    python3 demo/benchmark.py --sizes 1 100 1024 10240 --csv docs/report/benchmark.csv
"""
from __future__ import annotations

import argparse
import csv
import math
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so "hybridcrypto" imports

from hybridcrypto import aes_gcm, rsa_oaep  # noqa: E402

MAX_REAL_BLOCKS = 1000


def median_ms(fn, repeat: int) -> float:
    times = []
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        times.append(time.perf_counter() - start)
    return statistics.median(times) * 1000


def oaep_block_size(bits: int) -> int:
    # OAEP with SHA256: key bytes minus 2 x 32 (hash) minus 2
    return bits // 8 - 2 * 32 - 2


def fmt_ms(ms: float) -> str:
    if ms >= 1000:
        return f"{ms / 1000:.2f} s"
    if ms >= 1:
        return f"{ms:.2f} ms"
    return f"{ms * 1000:.0f} µs"


def fmt_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / 1024 / 1024:g} MB"
    return f"{n / 1024:g} KB"


def run(sizes_kb: list[int], bits: int) -> list[dict]:
    print(f"Tạo cặp khoá RSA {bits} bit ...")
    priv, pub = rsa_oaep.generate_keypair(bits)
    key = aes_gcm.generate_key()
    block = oaep_block_size(bits)

    wrapped = rsa_oaep.wrap_key(pub, key)
    t_wrap = median_ms(lambda: rsa_oaep.wrap_key(pub, key), 30)
    t_unwrap = median_ms(lambda: rsa_oaep.unwrap_key(priv, wrapped), 30)

    one_block = os.urandom(block)
    one_block_ct = rsa_oaep.wrap_key(pub, one_block)
    t_block_dec = median_ms(lambda: rsa_oaep.unwrap_key(priv, one_block_ct), 30)

    rows = []
    for kb in sizes_kb:
        n = kb * 1024
        data = os.urandom(n)
        repeat = 7 if n <= 10 * 1024 * 1024 else 3
        nonce, ct = aes_gcm.encrypt(key, data)
        t_aes_enc = median_ms(lambda: aes_gcm.encrypt(key, data), repeat)
        t_aes_dec = median_ms(lambda: aes_gcm.decrypt(key, nonce, ct), repeat)

        blocks = math.ceil(n / block)
        if blocks <= MAX_REAL_BLOCKS:
            enc_blocks = [rsa_oaep.wrap_key(pub, data[i:i + block]) for i in range(0, n, block)]
            start = time.perf_counter()
            back = b"".join(rsa_oaep.unwrap_key(priv, b) for b in enc_blocks)
            t_rsa_only = (time.perf_counter() - start) * 1000
            assert back == data
            estimated = False
        else:
            t_rsa_only = blocks * t_block_dec
            estimated = True

        t_hybrid = t_unwrap + t_aes_dec
        rows.append({
            "size_bytes": n,
            "aes_encrypt_ms": t_aes_enc,
            "aes_decrypt_ms": t_aes_dec,
            "rsa_wrap_ms": t_wrap,
            "rsa_unwrap_ms": t_unwrap,
            "hybrid_decrypt_ms": t_hybrid,
            "rsa_only_blocks": blocks,
            "rsa_only_decrypt_ms": t_rsa_only,
            "rsa_only_estimated": estimated,
            "speedup": t_rsa_only / t_hybrid,
            "hybrid_file_bytes": 7 + bits // 8 + 12 + n + 16,
            "rsa_only_file_bytes": blocks * (bits // 8),
        })
    return rows


def print_table(rows: list[dict], bits: int) -> None:
    head = ["Kích thước", "AES mã", "AES giải mã", "Hybrid giải mã", "Chỉ RSA giải mã", "Nhanh hơn"]
    widths = [11, 11, 12, 15, 18, 11]
    line = "=" * (sum(widths) + 2 * len(widths))
    print()
    print(f"RSA {bits} bit, mỗi khối RSA chứa tối đa {oaep_block_size(bits)} byte")
    print(f"Bọc khoá AES (RSA wrap): {fmt_ms(rows[0]['rsa_wrap_ms'])}    Mở khoá AES (RSA unwrap): {fmt_ms(rows[0]['rsa_unwrap_ms'])}")
    print(line)
    print("  ".join(h.ljust(w) for h, w in zip(head, widths)))
    print(line)
    for r in rows:
        rsa = fmt_ms(r["rsa_only_decrypt_ms"]) + (" *" if r["rsa_only_estimated"] else "")
        cells = [
            fmt_size(r["size_bytes"]),
            fmt_ms(r["aes_encrypt_ms"]),
            fmt_ms(r["aes_decrypt_ms"]),
            fmt_ms(r["hybrid_decrypt_ms"]),
            rsa,
            f"{r['speedup']:.0f} lần",
        ]
        print("  ".join(c.ljust(w) for c, w in zip(cells, widths)))
    print(line)
    print("Hybrid giải mã = 1 lần RSA mở khoá AES + AES giải mã cả file.")
    print("Chỉ RSA = cắt file thành từng khối và RSA giải mã từng khối.")
    if any(r["rsa_only_estimated"] for r in rows):
        print(f"* ước tính = số khối x thời gian 1 khối (đo thật khi tối đa {MAX_REAL_BLOCKS} khối).")
    last = rows[-1]
    extra = last["rsa_only_file_bytes"] / last["size_bytes"] - 1
    print(f"Kích thước file mã ({fmt_size(last['size_bytes'])}): hybrid chỉ thêm "
          f"{last['hybrid_file_bytes'] - last['size_bytes']} byte, chỉ RSA to hơn {extra:.0%}.")


def main() -> None:
    parser = argparse.ArgumentParser(description="So sánh tốc độ hybrid với chỉ dùng RSA")
    parser.add_argument("--sizes", type=int, nargs="+", default=[1, 100, 1024, 10240],
                        help="Các kích thước file, tính bằng KB (mặc định: 1 100 1024 10240)")
    parser.add_argument("--bits", type=int, default=3072, help="Độ dài khoá RSA (mặc định 3072)")
    parser.add_argument("--csv", help="Ghi kết quả ra file CSV để vẽ biểu đồ cho báo cáo")
    args = parser.parse_args()

    rows = run(args.sizes, args.bits)
    print_table(rows, args.bits)
    if args.csv:
        Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        print(f"Đã ghi CSV: {args.csv}")


if __name__ == "__main__":
    main()
