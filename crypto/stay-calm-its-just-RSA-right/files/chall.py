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
    r = random.randint(224, 288)  
    p = getPrime(bits//2)
    q = getPrime(bits//2)
    n = p*q
    e = E
    m = bytes_to_long(FLAG.encode())
    c = pow(m, e, n)

    msb_p = p >> r

    bl = msb_p.bit_length()
    if bl == 0:
        raise RuntimeError("msb_p empty; regenerate.")
    flip_pos = random.randrange(bl)         
    msb_p_noisy = msb_p ^ (1 << flip_pos)

    os.makedirs("public", exist_ok=True)
    with open("public/public.json", "w") as f:
        json.dump({
            "n": to_hex(n),
            "e": e,
            "c": to_hex(c),
            "msb_p": to_hex(msb_p_noisy)
        }, f, separators=(",", ":"))
    print(f"[+] wrote public/public.json  (bits={bits}, r≈{r}, noise=1-bit, r not published)")

if __name__ == "__main__":
    main()
