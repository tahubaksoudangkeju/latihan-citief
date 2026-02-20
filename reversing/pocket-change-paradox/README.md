# Pocket Change Paradox

**Desc:** They said coins add up the same way every time… so why does change keep vanishing?

**Language:** Rust 

**Given:** compiled binary + `encrypted.bin`  
**Mechanics (high level):** each byte turns into a tweaked “coin sum” after shuffling its bits; the right change-making strategy takes you back.

**Build:**
```
cargo init --bin
# overwrite src/main.rs with the provided one
cargo build --release
```

