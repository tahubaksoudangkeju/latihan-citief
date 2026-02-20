# PWN Challenge: cek-var-tapi-beda

## Description
This is a 64-bit binary exploitation challenge that requires ROP (Return Oriented Programming) to call the `win()` function with the correct argument.

## Challenge Details
- **Binary**: `cek-var-tapi-beda-soal64` (64-bit ELF)
- **Vulnerability**: Buffer overflow in `vuln()` function using `gets()`
- **Objective**: Call `win(0xdeadbeef)` to get the flag
- **Architecture**: x86-64
- **Protections**: No stack protector, executable stack, no PIE

## Deployment

### Using Docker Compose
```bash
cd server
docker-compose up --build -d
```

The service will be available on port 9998.

### Manual Docker Build
```bash
cd server
docker build -t cek-var-tapi-beda .
docker run -p 9998:9999 cek-var-tapi-beda
```

## Testing Connection
```bash
nc localhost 9998
```

## Files Structure
```
server/
├── Dockerfile
├── docker-compose.yml
├── README.md
└── files/
    ├── cek-var-tapi-beda-soal64  # Challenge binary
    └── flag.txt                   # Flag file
```

## Security Features
- Container runs with `nobody` user
- Resource limits applied
- Read-only filesystem with tmpfs for `/tmp`
- No new privileges allowed

## Stopping the Service
```bash
docker-compose down
```
