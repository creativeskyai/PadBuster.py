[README.md](https://github.com/user-attachments/files/28415196/README.md)
# PadBuster.py
Pad Buster Python Script
# Padding Oracle Attack (AES-CBC)

Fast, parallelized AES-CBC padding oracle decryptor with connection pooling.
Inspired by [PadBuster](https://github.com/strozfriedberg/PadBuster).

## What it does

Exploits a [padding oracle vulnerability](https://en.wikipedia.org/wiki/Padding_oracle_attack) to decrypt AES-CBC ciphertext without knowing the key. Works by sending modified ciphertext to the server and observing whether the padding is accepted or rejected.

## Features

- **Cross-block parallelism** — decrypts all ciphertext blocks simultaneously
- **Per-byte parallelism** — searches multiple guess values in parallel per position
- **Stop-on-hit** — cancels remaining guesses once a valid byte is found
- **Connection pooling** — reuses HTTP connections for speed
- **False-positive guard** — validates pad=1 results to avoid \x02\x02 collisions
- **Global concurrency cap** — prevents rate-limit bans
- **Burp proxy support** — route traffic through Burp for inspection
- **CBC bit-flip helper** — `flip()` function for modifying plaintext via ciphertext manipulation

## Usage

```bash
# Basic usage with required arguments
python padbuster.py --url "https://target.com/" --blob "encrypted_base64_blob"

# Route through Burp Suite proxy
python padbuster.py --url "https://target.com/" --blob "..." --burp

# Custom threading and output
python padbuster.py --url "https://target.com/" --blob "..." --threads 8 --concurrency 32 -o decrypted.txt
```

## CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--url` | (required) | Target URL with the padding oracle |
| `--blob` | (required) | Encrypted blob in the target's base64 encoding |
| `--burp` | off | Proxy through Burp Suite at 127.0.0.1:8080 |
| `--threads` | 4 | Parallel guess threads per byte position |
| `--concurrency` | 16 | Max simultaneous HTTP requests |
| `-o` / `--output` | plaintext.txt | Output file for decrypted plaintext |

## Adapting for a new target

Three things typically change between targets:

### 1. Base64 alphabet
The `b64d()` and `b64e()` functions handle custom base64 alphabets. The default maps `+ -> -`, `/ -> !`, `= -> ~` (Hacker101 CTF format). For standard base64, simplify to:
```python
def b64d(s): return base64.b64decode(s)
def b64e(b): return base64.b64encode(bytes(b)).decode()
```

### 2. Oracle function
The `oracle()` function must return `True` for valid padding, `False` for invalid. Adapt:
- **HTTP method**: GET vs POST
- **Parameter name**: `"post"` in the default, could be `"data"`, `"token"`, cookie, etc.
- **Error detection**: looks for `"PaddingException"` in response body. Could also be:
  - Status code (200 = valid, 500 = invalid)
  - Response length difference
  - Different error message strings
  - Timing difference (blind oracle)

### 3. Block size
Default is 16 bytes (AES-128/192/256). Change `BLOCK_SIZE` if the cipher uses a different block size (rare).

## CBC bit-flip

The `flip()` function modifies ciphertext to change specific plaintext bytes:

```python
from padbuster import flip, b64d, b64e

# Change byte 5 of plaintext block 2 from 'a' to 'b'
new_blob = flip(original_blob, block_index=2, byte_index=5, old=ord('a'), new=ord('b'))
```

This works because in CBC mode, flipping bit N in ciphertext block K flips the same bit in plaintext block K+1 (at the cost of scrambling plaintext block K).

## Performance

- ~256 oracle queries per byte position (worst case)
- 16 bytes per block = ~4,096 queries per block
- With 9 blocks in parallel and 16 concurrent requests: a 10-block ciphertext typically decrypts in 5-15 minutes depending on server response time.

## Credits

Inspired by [PadBuster](https://github.com/strozfriedberg/PadBuster) by Stroz Friedberg (Brian Holyfield). The original Perl tool pioneered automated padding oracle attacks. This Python version adds cross-block parallelism, per-byte threading with stop-on-hit, and connection pooling for significantly faster decryption.

## Origin

Built for the Hacker101 CTF "Encrypted Pastebin" challenge. Generalized as a reusable template.
