#!/usr/bin/env python3
import os, json, random
from Crypto.Util.number import getPrime, bytes_to_long

FLAG = "CYB0X1{fake_flag_for_testing}"
E = 65537

def to_hex(x: int) -> str:
    if x == 0: return "00"
    return x.to_bytes((x.bit_length()+7)//8, "big").hex()

def main():
    bits = 2048
    r = random.randint(240, 300)  
    p = getPrime(bits//2)
    q = getPrime(bits//2)
    n = p*q
    e = E
    m = bytes_to_long(FLAG.encode())
    c = pow(m, e, n)

    msb_p = p >> r
    L = msb_p.bit_length()
    if L < 3:
        raise RuntimeError("regenerate")

    top = min(32, L)
    i = L-1 - random.randrange(top)
    j = L-1 - random.randrange(top)
    while j == i:
        j = L-1 - random.randrange(top)
    msb_noisy = msb_p ^ (1 << i) ^ (1 << j)

    os.makedirs("public", exist_ok=True)
    with open("public/public.json", "w") as f:
        json.dump({
            "n": to_hex(n),
            "e": e,
            "c": to_hex(c),
            "msb_p": to_hex(msb_noisy)
        }, f, separators=(",", ":"))
    print(f"[+] wrote public/public.json  (bits={bits}, r≈{r}, two noisy bits near top within {top})")

if __name__ == "__main__":
    main()
