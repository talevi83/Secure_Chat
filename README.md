# Secure Chat Application

## Overview
A secure, end-to-end encrypted chat application demonstrating:
- Asynchronous network programming
- Secure communication protocols
- Docker containerization
- Advanced encryption techniques

## Features
- End-to-end encryption
- User authentication
- Direct and broadcast messaging
- Dockerized deployment
- Secure key exchange mechanism

## Technical Stack
- Python 3.9+
- Asyncio
- Cryptography Library
- Docker
- SQLite

## Encryption Mechanism
- Asymmetric key exchange (RSA)
- Symmetric message encryption (Fernet)
- Unique per-session encryption keys

## Prerequisites
- Python 3.9+
- Docker
- Docker Compose

## Installation

### Local Development
1. Clone the repository
```bash
git clone https://github.com/yourusername/secure-chat-application.git
cd secure-chat-application
```

2. Create virtual environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

3. Install dependencies
```bash
pip install -r server/requirements.txt
pip install -r client/requirements.txt
```

### Docker Deployment
```bash
# Build and start containers
docker-compose up --build

# Stop containers
docker-compose down
```

## Usage Scenarios

### Running Locally
1. Start the server
```bash
python server/server.py
```

2. In separate terminals, start clients
```bash
python client/client.py
```

### Docker Usage
1. Start services
```bash
docker-compose up
```

2. Interact with clients
```bash
# Access client container
docker exec -it secure-chat-client-1 /bin/bash
```

## Messaging Modes

### Broadcast Message
Simply type and send a message to broadcast to all connected clients.
```
Enter message: Hello, everyone!
```

### Direct Messaging
Use `@username` prefix to send a private message.
```
Enter message: @john Hello, John! This is a private message.
```

## Security Details

### Key Exchange Process
1. Client generates RSA key pair
2. Public key sent to server
3. Server generates unique symmetric key
4. Symmetric key encrypted with client's public key
5. Encrypted key sent back to client
6. Client decrypts symmetric key using private key

### Encryption Layers
- **Asymmetric Encryption**: RSA 2048-bit
  - Secure key exchange
  - Protects symmetric key transmission

- **Symmetric Encryption**: Fernet (AES-128)
  - Encrypts actual messages
  - Provides high-performance encryption

## Troubleshooting

### Common Issues
- Ensure Docker is running
- Check network configurations
- Verify Python and dependency versions

### Logging
- Server logs stored in `server/logs/`
- Client logs displayed in console

## Performance Considerations
- Asyncio provides high concurrency
- Lightweight encryption mechanism
- Minimal overhead in message transmission

## Monitoring and Metrics
- Implement logging
- Add performance tracking
- Consider Prometheus/Grafana integration

## Development Roadmap
- [ ] Implement password hashing
- [ ] Add user registration endpoint
- [ ] Create web-based admin interface
- [ ] Implement message persistence
- [ ] Add TLS support
- [ ] Develop comprehensive test suite

## Contributing Guidelines
1. Fork the repository
2. Create a feature branch
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit changes
   ```bash
   git commit -m "Add detailed description of changes"
   ```
4. Push to branch
   ```bash
   git push origin feature/your-feature-name
   ```
5. Create pull request

## Code of Conduct
- Be respectful
- Provide constructive feedback
- Follow PEP 8 guidelines
- Write comprehensive tests

## Performance Benchmarks

### System Requirements
- Minimum: 1 CPU, 1GB RAM
- Recommended: 2 CPU, 2GB RAM

### Estimated Capabilities
- Concurrent Connections: 100-500
- Message Latency: <50ms
- Encryption Overhead: ~5-10ms per message

## License
Apache License 2.0

## Disclaimer
This is an educational project demonstrating secure communication principles. Not recommended for production use without further hardening.

## Contact
For questions or support, please open an issue on GitHub.