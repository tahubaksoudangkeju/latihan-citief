# XOR my shadow

**Desc:** They say a flag always hides in plain sight… but what if every byte is mirrored against its own reflection? Can you untangle the shadow?

**Given:** compiled binary + `encrypted.bin`  
**Goal:** recover the original flag from the encrypted file. The algorithm is a custom XOR scheme.  

**Build:**
```bash
gcc -O2 -std=c11 -o chall src/encrypt.c

