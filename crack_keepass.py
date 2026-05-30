#!/usr/bin/env python3
"""
KeePass 2 Brute-Force Cracker
IT-Security Homework 1 - Exercise 1a
"""

import hashlib
import struct
import sys
import time
from itertools import product
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def parse_kdbx(path: str):
    """Parse a KeePass 2 .kdbx file and return header fields + encrypted data offset."""
    with open(path, "rb") as f:
        data = f.read()

    # Verify signature
    sig1, sig2 = struct.unpack_from("<II", data, 0)
    assert sig1 == 0x9AA2D903, f"Bad sig1: {sig1:#010x}"
    assert sig2 == 0xB54BFB67, f"Bad sig2: {sig2:#010x}"

    pos = 12  # skip 4+4+4 (sig1, sig2, version)
    fields = {}

    while True:
        fid = data[pos]; pos += 1
        flen = struct.unpack_from("<H", data, pos)[0]; pos += 2
        fdata = data[pos:pos + flen]; pos += flen

        if fid == 0:       # end of header
            break
        fields[fid] = fdata

    master_seed    = fields[4]
    transform_seed = fields[5]
    transform_rounds = struct.unpack("<Q", fields[6])[0]
    iv             = fields[7]
    stream_start   = fields[9]
    encrypted_data = data[pos:]

    return master_seed, transform_seed, transform_rounds, iv, stream_start, encrypted_data


def derive_key(password: bytes, master_seed: bytes, transform_seed: bytes,
               transform_rounds: int, encryptor) -> bytes:
    """Derive the AES-256-CBC key for a given password candidate."""
    # Step 1: credentials = SHA-256(SHA-256(password))
    creds = hashlib.sha256(hashlib.sha256(password).digest()).digest()

    # Step 2: apply AES-ECB with transform_seed as key, transform_rounds times
    tc = creds
    for _ in range(transform_rounds):
        tc = encryptor.update(tc)

    # Step 3: transformed_credentials = SHA-256(tc)
    transformed = hashlib.sha256(tc).digest()

    # Step 4: key = SHA-256(master_seed || transformed_credentials)
    return hashlib.sha256(master_seed + transformed).digest()


def check_password(password: bytes, master_seed, transform_seed,
                   transform_rounds, iv, stream_start, encrypted_data) -> bool:
    """Return True if password decrypts correctly (stream_start matches)."""
    # Build a fresh AES-ECB encryptor for the transform (stateful, reset each call)
    ecb_cipher = Cipher(algorithms.AES(transform_seed), modes.ECB(),
                        backend=default_backend())
    encryptor = ecb_cipher.encryptor()

    key = derive_key(password, master_seed, transform_seed, transform_rounds, encryptor)

    # Decrypt the first 32 bytes of the payload
    cbc_cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cbc_cipher.decryptor()
    first_block = decryptor.update(encrypted_data[:32])

    return first_block == stream_start


def brute_force_digits(kdbx_path: str, max_len: int = 4):
    """
    Brute-force a KeePass database assuming the password is
    numeric only (digits 0-9) with length 1..max_len.
    """
    (master_seed, transform_seed, transform_rounds,
     iv, stream_start, encrypted_data) = parse_kdbx(kdbx_path)

    print(f"[*] Database   : {kdbx_path}")
    print(f"[*] Rounds     : {transform_rounds}")
    print(f"[*] Key space  : digits 0–9, length 1–{max_len}")

    digits = "0123456789"
    total_tried = 0
    t0 = time.perf_counter()

    for length in range(1, max_len + 1):
        for combo in product(digits, repeat=length):
            password = "".join(combo).encode()
            total_tried += 1

            if check_password(password, master_seed, transform_seed,
                               transform_rounds, iv, stream_start, encrypted_data):
                elapsed = time.perf_counter() - t0
                rate = total_tried / elapsed
                print(f"\n[+] PASSWORD FOUND: {password.decode()!r}")
                print(f"[*] Tried {total_tried} passwords in {elapsed:.2f}s "
                      f"({rate:.1f} pw/s)")
                return password.decode()

            if total_tried % 500 == 0:
                elapsed = time.perf_counter() - t0
                rate = total_tried / elapsed if elapsed > 0 else 0
                print(f"\r    Tried {total_tried:>6} | {rate:>7.1f} pw/s", end="", flush=True)

    elapsed = time.perf_counter() - t0
    print(f"\n[-] Password not found. Tried {total_tried} in {elapsed:.2f}s")
    return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path/to/database.kdbx> [max_length]")
        sys.exit(1)

    path = sys.argv[1]
    max_length = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    brute_force_digits(path, max_length)
