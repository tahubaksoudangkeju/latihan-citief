# Domino Daydream

**Desc:** They said it’s just adding numbers… so why does one byte topple them all?

**Language:** Go 

**Given:** compiled binary + `encrypted.bin`  
**Mechanics (high level):** a rolling carry state tweaks each byte; windows get flipped; a cheeky checksum hides at the end.

**Build:**
```
go build -o encrypt ./src
```

