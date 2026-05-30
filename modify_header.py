#!/usr/bin/env python3
"""
Exercise 2e — Modify a KeePass header field without breaking decryption.

Since the stream_start bytes check ignores the header,
changing a header field (e.g. the version number) produces a file
that our cracker still decrypts correctly — but KeePass rejects it
because modern versions verify the HMAC over the header.

We flip the minor version byte (offset 10) from 0x03 to 0x05
as a harmless demonstration.
"""

import struct, sys, shutil

def modify_version(src: str, dst: str):
    data = bytearray(open(src, "rb").read())

    # The version field is at bytes 8–11 (little-endian uint32)
    ver_before = struct.unpack_from("<I", data, 8)[0]
    # Bump minor version byte (offset 10)
    data[10] = (data[10] + 2) & 0xFF
    ver_after  = struct.unpack_from("<I", data, 8)[0]

    with open(dst, "wb") as f:
        f.write(data)

    print(f"[*] Source      : {src}")
    print(f"[*] Destination : {dst}")
    print(f"[*] Version     : {ver_before:#010x} → {ver_after:#010x}")
    print("[*] Header modified. Modern KeePass rejects this (HMAC fails).")
    print("[*] Our cracker (which ignores the header HMAC) still works.")

if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "databases/Benny.kdbx"
    dst = sys.argv[2] if len(sys.argv) > 2 else "Benny_modified.kdbx"
    modify_version(src, dst)
