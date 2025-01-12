# Secure Chat Application

## Overview
A secure, end-to-end encrypted chat application featuring:
- End-to-end encryption using RSA and Fernet
- User authentication and registration system
- Direct and broadcast messaging capabilities
- Web-based server monitoring interface
- Configuration management
- Comprehensive logging system

## Features
- **Secure Communication**
  - Asymmetric key exchange (RSA 2048-bit)
  - Symmetric message encryption (Fernet)
  - Unique per-session encryption keys
- **User Management**
  - User registration
  - Secure authentication
  - SQLite database storage
- **Messaging Capabilities**
  - Direct messaging with @username syntax
  - Broadcast messaging to all users
  - Real-time message delivery
- **Server Monitoring**
  - Web-based status dashboard
  - Connected clients tracking
  - Server status monitoring
- **Configuration Management**
  - Flexible configuration system
  - Environment-specific settings
  - Customizable logging levels

## Project Structure
```
secure-chat-application/
├── client/
│   ├── client.py
│   ├── config_manager.py
│   ├── config.ini
│   └── requirements.txt
└── server/
    ├── server.py
    ├── server_status_manager.py
    ├── requirements.txt
    └── templates/
        └── server_status.html
```

## Prerequisites
- Python 3.9+
- Flask (for server monitoring)
- Cryptography library
- Asyncio

## Installation

### Client Setup
1. Navigate to the client directory:
```bash
cd client
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Server Setup
1. Navigate to the server directory:
```bash
cd server
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration
### Client Configuration (config.ini)
```ini
[Server]
host = localhost
port = 8888

[Logging]
level = INFO
debug_mode = False

[Client]
receive_buffer = 4096
```

## Usage

### Starting the Server
1. Navigate to the server directory
2. Activate the virtual environment
3. Run the server:
```bash
python server.py
```
The server will start on localhost:8888 and the monitoring interface will be available at http://localhost:8080

### Running the Client
1. Navigate to the client directory
2. Activate the virtual environment
3. Run the client:
```bash
python client.py
```

### Client Commands
- Register: Choose option 1 and follow the prompts
- Login: Choose option 2 and enter credentials
- Send broadcast message: Type your message and press Enter
- Send direct message: Use @username followed by your message
- Exit: Type 'exit' or choose option 3 from the main menu

## Security Features
- RSA 2048-bit key pairs for secure key exchange
- Fernet symmetric encryption for message content
- SQLite database for user credential storage
- Secure handshake protocol for client-server communication

## Monitoring
Access the server status dashboard at http://localhost:8080 to view:
- Server running status
- Number of connected clients
- Real-time server statistics

## Development

### Adding New Features
1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Submit a pull request

### Running Tests
```bash
python -m unittest discover tests
```

## Troubleshooting

### Common Issues
1. Connection Refused
   - Verify server is running
   - Check correct host/port in config.ini
   - Ensure no firewall blocking

2. Authentication Failed
   - Verify correct username/password
   - Check database connectivity
   - Ensure server is properly initialized

3. Message Encryption Errors
   - Verify key exchange completed successfully
   - Check for connection interruptions
   - Ensure client and server versions match

## License
Apache License 2.0

## Disclaimer
This is an educational project demonstrating secure communication principles. Not recommended for production use without further security hardening.