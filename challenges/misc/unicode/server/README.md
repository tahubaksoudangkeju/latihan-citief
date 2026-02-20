# MISC Challenge: Unicode

## Description
This is a Python-based challenge that involves Unicode manipulation and code evaluation. The challenge accepts user input and evaluates it within certain constraints.

## Challenge Details
- **Language**: Python 3.9
- **Type**: Miscellaneous/Code Injection
- **Input Limit**: 8 characters
- **Objective**: Extract the flag through creative use of Python evaluation

## Deployment

### Using Docker Compose
```bash
cd server
docker-compose up --build -d
```

The service will be available on port 9696.

### Manual Docker Build
```bash
cd server
docker build -t unicode-challenge .
docker run -p 9696:9696 unicode-challenge
```

## Testing Connection
```bash
nc localhost 9696
```

## Files Structure
```
server/
├── Dockerfile
├── docker-compose.yml
├── README.md
└── files/
    └── challenge.py           # Main challenge script
```

## Security Features
- Container runs with `nobody` user
- Resource limits applied (64M RAM, 0.3 CPU)
- Read-only filesystem with tmpfs for `/tmp`
- 30-second timeout per connection
- No new privileges allowed

## Challenge Hints
- The challenge evaluates Python code with input length limit
- Think about how to maximize functionality in minimal characters
- Unicode characters might be key to the solution
- Consider Python's built-in functions and variables

## Stopping the Service
```bash
docker-compose down
```
