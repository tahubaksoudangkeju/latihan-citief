# PWN Challenge: ret2win

## Description
This is a classic "return-to-win" binary exploitation challenge. The goal is to overflow a buffer and redirect execution to the `hitme()` function to get the flag.

## Challenge Details
- **Binary**: `ret2win` (32-bit ELF)
- **Vulnerability**: Buffer overflow in `vuln()` function using `gets()`
- **Objective**: Call `hitme()` function to print the flag
- **Architecture**: x86 (32-bit)
- **Protections**: No stack protector, executable stack, no PIE
- **Difficulty**: Beginner-friendly

## Vulnerability Analysis
```c
void vuln() {
    char buffer[128];
    printf("domisili: ");
    gets(buffer);  // Vulnerable function - no bounds checking
}

void hitme() {
    // This function prints the flag when called
    printf("Flag: ");
    // ... reads and prints flag from flag.txt
}
```

## Exploitation Strategy
1. **Calculate offset**: Find exact number of bytes to overwrite return address
2. **Find target address**: Get address of `hitme()` function  
3. **Craft payload**: `buffer_padding + hitme_address`
4. **Execute**: Send payload to redirect execution to `hitme()`

## Deployment

### Using Docker Compose
```bash
cd server
docker-compose up --build -d
```

The service will be available on port 9996.

### Manual Docker Build
```bash
cd server
docker build -t ret2win .
docker run -p 9996:9996 ret2win
```

## Testing Connection
```bash
nc localhost 9996
```

## Files Structure
```
server/
├── Dockerfile
├── docker-compose.yml
├── README.md
└── files/
    ├── ret2win                    # Challenge binary (32-bit)
    └── flag.txt                   # Flag file
```

## Security Features
- Container runs with `nobody` user
- Resource limits applied
- Read-only filesystem with tmpfs for `/tmp`
- No new privileges allowed


## Hints
- Buffer size is 128 bytes
- Calculate how many bytes needed to reach return address
- Use tools like `objdump`, `gdb`, or `pwntools` for analysis
- Stack layout: `[buffer][saved_registers][return_address]`

## Stopping the Service
```bash
docker-compose down
```
