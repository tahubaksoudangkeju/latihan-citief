#!/usr/bin/env python3
import os, json, random
from Crypto.Util.number import getPrime, bytes_to_long
from Crypto.Util.number import inverse

FLAG = "CYB0X1{fake_flag_for_testing}"
E = 65537

def to_hex(x: int) -> str:
    if x == 0: return "00"
    return x.to_bytes((x.bit_length()+7)//8, "big").hex()

def main():
    bits = 2048
    p = getPrime(bits//2)
    q = getPrime(bits//2)
    n = p*q
    e = E
    k = random.randint(600, 700)  
    a = p & ((1 << k) - 1)        
    m = bytes_to_long(FLAG.encode())
    c = pow(m, e, n)

    os.makedirs("public", exist_ok=True)
    with open("public/public.json", "w") as f:
        json.dump({
            "n": to_hex(n),
            "e": e,
            "c": to_hex(c),
            "lsb_p": to_hex(a),
            "k": k
        }, f, separators=(",", ":"))
    print(f"[+] wrote public/public.json  (bits={bits}, k={k})")

if __name__ == "__main__":
    main()
