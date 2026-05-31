# Homework 1 — Breaking and Protecting a KeePass Database

## Files

| File | Purpose |
|------|---------|
| `crack_keepass.py` | Exercise 1a — brute-force cracker |
| `benchmarks.py` | Exercise 2c + 2f — speed measurements & estimates |
| `modify_header.py` | Exercise 2e — header tampering demo |
| `Benny_modified.kdbx` | Exercise 2e — modified database deliverable |

## Requirements

```
pip install cryptography
```

## Usage

```bash
# Crack any group member's database
python3 crack_keepass.py databases/<username>.kdbx

# Run benchmark & PBKDF2 calibration
python3 benchmarks.py databases/<username>.kdbx

# Generate modified database (Exercise 2e)
python3 modify_header.py databases/<username>.kdbx <username>_modified.kdbx
```

## Cracked database

- **File:** `Benny.kdbx`  
- **Password:** `5702`  

(Open with KeePassXC to read the stored login/password for Exercise 1b.)
