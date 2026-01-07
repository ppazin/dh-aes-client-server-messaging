# DH-AES Client-Server Messaging

A secure client-server messaging application that establishes a shared secret using Diffie-Hellman key exchange, derives an AES key, and encrypts all communication with AES for secure message delivery via user inboxes.

## Features

- **Diffie-Hellman Key Exchange**: Secure key establishment between client and server using 2048-bit MODP Group (RFC 3526)
- **AES-256-GCM Encryption**: All messages encrypted with AES-256 in GCM mode for confidentiality and authenticity
- **User Inboxes**: Messages are queued for offline users and delivered when they come online
- **Real-time Delivery**: Messages are delivered immediately to online users
- **Multi-client Support**: Server handles multiple concurrent clients with thread-safe operations

## Architecture

### Cryptographic Flow

1. **Key Exchange**: When a client connects, both parties perform Diffie-Hellman key exchange to establish a shared secret
2. **Key Derivation**: The shared secret is used with HKDF-SHA256 to derive a 256-bit AES key
3. **Secure Communication**: All subsequent messages are encrypted with AES-256-GCM using the derived key

### Components

- `crypto_utils.py`: Core cryptography module implementing DH key exchange and AES encryption/decryption
- `server.py`: Multi-threaded server handling client connections, key exchange, authentication, and message routing
- `client.py`: Client application with CLI interface for sending/receiving encrypted messages

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ppazin/dh-aes-client-server-messaging.git
cd dh-aes-client-server-messaging
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Starting the Server

Run the server in one terminal:
```bash
python server.py
```

The server will start listening on `localhost:5555` by default.

### Starting Clients

Run clients in separate terminals:
```bash
python client.py
```

You'll be prompted for:
- Username (any string)
- Server host (default: localhost)
- Server port (default: 5555)

### Client Commands

Once connected, use these commands:

- `send <username> <message>` - Send an encrypted message to a user
- `list` - List all currently online users
- `quit` - Disconnect and exit

### Example Session

**Terminal 1 - Server:**
```bash
$ python server.py
[SERVER] Started on localhost:5555
[SERVER] Waiting for connections...
```

**Terminal 2 - Client 1 (Alice):**
```bash
$ python client.py
Enter your username: alice
Server host (default: localhost): 
Server port (default: 5555): 
[CLIENT] Connected to server at localhost:5555
[CLIENT] Key exchange completed successfully
[CLIENT] Authenticated as alice

=== Secure Messaging Client ===
Commands:
  send <username> <message>  - Send a message
  list                       - List online users
  quit                       - Disconnect and exit
================================

> list
[ONLINE USERS] alice
> 
```

**Terminal 3 - Client 2 (Bob):**
```bash
$ python client.py
Enter your username: bob
Server host (default: localhost): 
Server port (default: 5555): 
[CLIENT] Connected to server at localhost:5555
[CLIENT] Key exchange completed successfully
[CLIENT] Authenticated as bob

> send alice Hello Alice! This message is encrypted with AES-256!
[STATUS] Message delivered to alice
> 
```

**Back to Terminal 2 (Alice receives message):**
```
[NEW MESSAGE] From bob: Hello Alice! This message is encrypted with AES-256!
> 
```

## Security Features

### Diffie-Hellman Key Exchange
- Uses 2048-bit MODP Group from RFC 3526
- Provides forward secrecy - each session has a unique encryption key
- Resistant to passive eavesdropping attacks

### AES-256-GCM Encryption
- 256-bit keys derived using HKDF with SHA-256
- GCM mode provides both confidentiality and authentication
- Random 96-bit IV (Initialization Vector) for each message
- Authentication tags prevent message tampering

### Key Derivation
- HKDF (HMAC-based Key Derivation Function) with SHA-256
- Derives strong encryption keys from the shared secret
- Uses application-specific info parameter for domain separation

## Protocol Details

### Connection Flow

1. **TCP Connection**: Client establishes TCP connection to server
2. **Key Exchange**:
   - Server sends its DH public key (256 bytes)
   - Client sends its DH public key (256 bytes)
   - Both compute shared secret independently
3. **Authentication**:
   - Client sends encrypted username
   - Server confirms authentication
   - Server delivers any pending messages from inbox
4. **Messaging**:
   - All messages exchanged are encrypted with AES-256-GCM
   - Messages formatted as JSON for structured data

### Message Format

All messages after key exchange are:
1. Encrypted with AES-256-GCM
2. Prepended with 4-byte length header
3. Structure: `[4-byte length][12-byte IV][ciphertext][16-byte tag]`

## Technical Details

- **Language**: Python 3.7+
- **Cryptography Library**: `cryptography` (FIPS-compliant primitives)
- **Network**: TCP sockets with length-prefixed messages
- **Concurrency**: Threading for multi-client support
- **Message Queue**: In-memory inbox system for offline users

## Limitations

- In-memory storage only (messages lost on server restart)
- No persistent user accounts or password authentication
- Single server instance (no distributed architecture)
- No message history or persistence

## Future Enhancements

- Persistent message storage (database)
- User authentication with passwords
- End-to-end encryption (client-to-client)
- Group messaging support
- Message read receipts
- File transfer support

## License

This project is for educational purposes as part of advanced computer networks coursework.
