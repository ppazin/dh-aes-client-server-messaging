"""
Secure messaging client with DH key exchange and AES encryption.
"""
import socket
import threading
import json
import sys
from crypto_utils import DHKeyExchange, AESCipher


class MessagingClient:
    """Client for secure messaging."""
    
    def __init__(self, host='localhost', port=5555):
        """Initialize the messaging client."""
        self.host = host
        self.port = port
        self.socket = None
        self.cipher = None
        self.username = None
        self.running = False
    
    def connect(self, username):
        """Connect to the server and perform key exchange."""
        try:
            # Create socket and connect
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            print(f"[CLIENT] Connected to server at {self.host}:{self.port}")
            
            # Perform DH key exchange
            dh = DHKeyExchange()
            self.cipher = self.perform_key_exchange(dh)
            
            if not self.cipher:
                print("[CLIENT] Key exchange failed")
                return False
            
            print("[CLIENT] Key exchange completed successfully")
            
            # Authenticate
            if not self.authenticate(username):
                print("[CLIENT] Authentication failed")
                return False
            
            self.username = username
            print(f"[CLIENT] Authenticated as {username}")
            
            # Start receiving thread
            self.running = True
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            return True
            
        except Exception as e:
            print(f"[CLIENT] Connection error: {e}")
            return False
    
    def perform_key_exchange(self, dh):
        """Perform DH key exchange with server."""
        try:
            # Receive server's public key
            server_public_key = self.receive_data()
            if not server_public_key:
                return None
            
            # Send client's public key
            client_public_key = dh.get_public_key_bytes()
            self.send_data(client_public_key)
            
            # Compute shared secret
            shared_secret = dh.compute_shared_secret(server_public_key)
            
            # Create cipher
            cipher = AESCipher(shared_secret)
            
            return cipher
        except Exception as e:
            print(f"[CLIENT] Key exchange error: {e}")
            return None
    
    def authenticate(self, username):
        """Authenticate with the server."""
        try:
            # Send encrypted username
            self.send_encrypted(username)
            
            # Receive confirmation
            encrypted_data = self.receive_data()
            if not encrypted_data:
                return False
            
            response = self.cipher.decrypt(encrypted_data)
            response_data = json.loads(response)
            
            return response_data.get('type') == 'auth_success'
        except Exception as e:
            print(f"[CLIENT] Authentication error: {e}")
            return False
    
    def send_message(self, recipient, content):
        """Send an encrypted message to a recipient."""
        try:
            message = {
                'type': 'send_message',
                'to': recipient,
                'content': content
            }
            self.send_encrypted(json.dumps(message))
            return True
        except Exception as e:
            print(f"[CLIENT] Error sending message: {e}")
            return False
    
    def list_users(self):
        """Request list of online users."""
        try:
            message = {'type': 'list_users'}
            self.send_encrypted(json.dumps(message))
        except Exception as e:
            print(f"[CLIENT] Error requesting user list: {e}")
    
    def receive_messages(self):
        """Receive and process messages from server."""
        while self.running:
            try:
                encrypted_data = self.receive_data()
                if not encrypted_data:
                    break
                
                message = self.cipher.decrypt(encrypted_data)
                message_data = json.loads(message)
                
                self.process_message(message_data)
                
            except Exception as e:
                if self.running:
                    print(f"[CLIENT] Error receiving message: {e}")
                break
    
    def process_message(self, message_data):
        """Process a message from the server."""
        msg_type = message_data.get('type')
        
        if msg_type == 'new_message':
            sender = message_data.get('from')
            content = message_data.get('content')
            print(f"\n[NEW MESSAGE] From {sender}: {content}")
            print("> ", end='', flush=True)
        
        elif msg_type == 'pending_messages':
            messages = message_data.get('messages', [])
            if messages:
                print(f"\n[INBOX] You have {len(messages)} pending message(s):")
                for msg in messages:
                    sender = msg.get('from')
                    content = msg.get('content')
                    print(f"  From {sender}: {content}")
                print("> ", end='', flush=True)
        
        elif msg_type == 'message_delivered':
            recipient = message_data.get('to')
            print(f"\n[STATUS] Message delivered to {recipient}")
            print("> ", end='', flush=True)
        
        elif msg_type == 'message_queued':
            recipient = message_data.get('to')
            print(f"\n[STATUS] Message queued for {recipient} (offline)")
            print("> ", end='', flush=True)
        
        elif msg_type == 'user_list':
            users = message_data.get('users', [])
            print(f"\n[ONLINE USERS] {', '.join(users)}")
            print("> ", end='', flush=True)
    
    def send_data(self, data):
        """Send data with length prefix."""
        length = len(data).to_bytes(4, byteorder='big')
        self.socket.sendall(length + data)
    
    def receive_data(self):
        """Receive data with length prefix."""
        # Receive length
        length_bytes = self.recv_exact(4)
        if not length_bytes:
            return None
        
        length = int.from_bytes(length_bytes, byteorder='big')
        
        # Receive data
        return self.recv_exact(length)
    
    def recv_exact(self, n):
        """Receive exactly n bytes."""
        data = b''
        while len(data) < n:
            chunk = self.socket.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def send_encrypted(self, message):
        """Encrypt and send a message."""
        encrypted_data = self.cipher.encrypt(message)
        self.send_data(encrypted_data)
    
    def disconnect(self):
        """Disconnect from the server."""
        self.running = False
        if self.socket:
            self.socket.close()
        print("[CLIENT] Disconnected from server")
    
    def run_cli(self):
        """Run interactive command-line interface."""
        print("\n=== Secure Messaging Client ===")
        print("Commands:")
        print("  send <username> <message>  - Send a message")
        print("  list                       - List online users")
        print("  quit                       - Disconnect and exit")
        print("================================\n")
        
        while self.running:
            try:
                user_input = input("> ").strip()
                
                if not user_input:
                    continue
                
                parts = user_input.split(maxsplit=2)
                command = parts[0].lower()
                
                if command == 'quit':
                    break
                
                elif command == 'send':
                    if len(parts) < 3:
                        print("[ERROR] Usage: send <username> <message>")
                    else:
                        recipient = parts[1]
                        message = parts[2]
                        self.send_message(recipient, message)
                
                elif command == 'list':
                    self.list_users()
                
                else:
                    print(f"[ERROR] Unknown command: {command}")
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[ERROR] {e}")
        
        self.disconnect()


def main():
    """Main entry point for the client."""
    print("=== Secure Messaging Client ===")
    
    # Get username
    username = input("Enter your username: ").strip()
    
    if not username:
        print("Username cannot be empty")
        return
    
    # Get server details (optional)
    host = input("Server host (default: localhost): ").strip() or 'localhost'
    port_input = input("Server port (default: 5555): ").strip()
    port = int(port_input) if port_input else 5555
    
    # Create and connect client
    client = MessagingClient(host, port)
    
    if client.connect(username):
        client.run_cli()
    else:
        print("Failed to connect to server")


if __name__ == '__main__':
    main()
