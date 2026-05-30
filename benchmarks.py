#!/usr/bin/env python3
"""
Exercise 2c & 2f — Benchmarking and time estimates.
Run AFTER crack_keepass.py has verified the core cracker works.
"""

import hashlib, struct, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ── re-use parse / check helpers from crack_keepass ──────────────────────────
def parse_kdbx(path):
    data = open(path, "rb").read()
    pos = 12
    fields = {}
    while True:
        fid = data[pos]; pos += 1
        flen = struct.unpack_from("<H", data, pos)[0]; pos += 2
        fdata = data[pos:pos+flen]; pos += flen
        if fid == 0: break
        fields[fid] = fdata
    master_seed    = fields[4]
    transform_seed = fields[5]
    transform_rounds = struct.unpack("<Q", fields[6])[0]
    iv             = fields[7]
    stream_start   = fields[9]
    encrypted_data = data[pos:]
    return master_seed, transform_seed, transform_rounds, iv, stream_start, encrypted_data

def aes_kdf_one(password, master_seed, transform_seed, transform_rounds):
    """One full AES-KDF key derivation (no correctness check)."""
    creds = hashlib.sha256(hashlib.sha256(password).digest()).digest()
    ecb = Cipher(algorithms.AES(transform_seed), modes.ECB(), backend=default_backend()).encryptor()
    tc = creds
    for _ in range(transform_rounds):
        tc = ecb.update(tc)
    return hashlib.sha256(master_seed + hashlib.sha256(tc).digest()).digest()

def pbkdf2_kdf_one(password, master_seed, rounds):
    """Alternative PBKDF2-HMAC-SHA256 key derivation."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=master_seed, iterations=rounds,
                     backend=default_backend())
    return kdf.derive(password)


# ── 2c: measure pw/s with AES-KDF ────────────────────────────────────────────
def benchmark_aes_kdf(transform_seed, master_seed, rounds, duration=3.0):
    password = b"0000"
    count = 0
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < duration:
        aes_kdf_one(password, master_seed, transform_seed, rounds)
        count += 1
    elapsed = time.perf_counter() - t0
    return count / elapsed


def estimate_time(pws_per_sec, charset_size, max_len):
    """Worst-case (exhaustive) keyspace size and time in seconds."""
    keyspace = sum(charset_size**l for l in range(1, max_len+1))
    return keyspace, keyspace / pws_per_sec


# ── 2f: measure PBKDF2 iterations for ~1s ────────────────────────────────────
def calibrate_pbkdf2(master_seed, target_seconds=1.0):
    password = b"0000"
    rounds = 10_000
    while True:
        t0 = time.perf_counter()
        pbkdf2_kdf_one(password, master_seed, rounds)
        elapsed = time.perf_counter() - t0
        if elapsed >= target_seconds * 0.9:
            return rounds, elapsed
        rounds = int(rounds * target_seconds / elapsed * 0.95)


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "databases/Benny.kdbx"
    ms, ts, tr, iv, ss, enc = parse_kdbx(path)

    print("=" * 60)
    print("Exercise 2c — AES-KDF Benchmark")
    print("=" * 60)

    for rounds_label, rounds in [("10 000 (original)", 10_000), ("1 000 000 (newer)", 1_000_000)]:
        print(f"\n  rounds = {rounds_label}")
        rate = benchmark_aes_kdf(ts, ms, rounds)
        print(f"  Throughput : {rate:.2f} pw/s")

        for label, size in [("digits only (10)", 10),
                             ("+ lowercase (36)", 36),
                             ("+ upper+lower (62)", 62)]:
            ks, secs = estimate_time(rate, size, 4)
            h = secs / 3600
            print(f"    {label:30s}  keyspace={ks:>12,.0f}  worst-case={h:>12.2f} h")

    print()
    print("=" * 60)
    print("Exercise 2f — PBKDF2-HMAC-SHA256 calibration")
    print("=" * 60)
    iters, t = calibrate_pbkdf2(ms)
    print(f"\n  ~1s at {iters:,} iterations  (measured {t:.3f}s)")
    rate_p = iters / t  # not useful directly; pw/s = 1/t
    pw_per_sec = 1.0 / t
    print(f"  Throughput : {pw_per_sec:.2f} pw/s")

    for label, size in [("digits only (10)", 10),
                         ("+ lowercase (36)", 36),
                         ("+ upper+lower (62)", 62)]:
        ks, secs = estimate_time(pw_per_sec, size, 4)
        h = secs / 3600
        d = h / 24
        print(f"    {label:30s}  keyspace={ks:>12,.0f}  worst-case={d:>12.2f} days")
