import sys
import hashlib
import struct
from itertools import product
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def unlock_kdbx(path):
    with open(path, "rb") as f:
        data = f.read()

    signature1, signature2 = struct.unpack_from("<II", data, 0)
    if signature1 != 0x9AA2D903 or signature2 != 0xB54BFB67:
        raise ValueError("File is wrong")

    pos = 12
    fields = {}

    while True:
        fieldId = data[pos]
        pos += 1
        fieldlength = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        fieldData = data[pos:pos + fieldlength]
        pos += fieldlength

        if fieldId == 0:
            break
        fields[fieldId] = fieldData

    master_seed = fields[4]
    transform_seed = fields[5]
    rounds = struct.unpack("<Q", fields[6])[0]
    iv = fields[7]
    start_stream = fields[9]
    payload = data[pos:]

    return master_seed, transform_seed, rounds, iv, start_stream, payload


def derive_key(password, master_seed, transform_seed, rounds):
    key = hashlib.sha256(hashlib.sha256(password).digest()).digest()

    enc = Cipher(algorithms.AES(transform_seed), modes.ECB(), backend=default_backend()).encryptor()
    for _ in range(rounds):
        key = enc.update(key)

    return hashlib.sha256(master_seed + hashlib.sha256(key).digest()).digest()


def check_password(password, master_seed, transform_seed, rounds, iv, start_stream, payload):
    key = derive_key(password, master_seed, transform_seed, rounds)

    dec = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()

    return dec.update(payload[:32]) == start_stream


def crack(path, max_len=4):
    master_seed, transform_seed, rounds, iv, start_stream, payload = unlock_kdbx(path)

    for length in range(1, max_len + 1):
        for combo in product("0123456789", repeat=length):
            pw = "".join(combo).encode()

            if check_password(pw, master_seed, transform_seed, rounds, iv, start_stream, payload):
                print(f"Found: {pw.decode()!r}")
                return pw.decode()

    print("Not found")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.kdbx> [max_length]")
        sys.exit(1)

    max_len = 4
    if len(sys.argv) > 2:
        max_len = int(sys.argv[2])

    crack(sys.argv[1], max_len)