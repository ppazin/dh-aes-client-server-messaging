"""
Secure messaging server with DH key exchange and AES encryption.
"""
import socket
import threading
import json
import time
from crypto_utils import DHKeyExchange, AESCipher


class MessagingServer:
    """Server that handles client connections and message routing."""
    
    def __init__(self, host='localhost', port=5555):
        """Initialize the messaging server."""
        self.host = host
        self.port = port
        self.clients = {}  # username -> (socket, cipher)
        self.inboxes = {}  # username -> list of messages
        self.lock = threading.Lock()
        self.server_socket = None
        self.running = False
    
    def start(self):
        """Start the server and listen for connections."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        
        print(f"[SERVER] Started on {self.host}:{self.port}")
        print("[SERVER] Waiting for connections...")
        
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"[SERVER] New connection from {address}")
                
                # Handle client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                if self.running:
                    print(f"[SERVER] Error accepting connection: {e}")
    
    def handle_client(self, client_socket, address):
        """Handle a client connection."""
        try:
            # Perform DH key exchange
            dh = DHKeyExchange()
            cipher = self.perform_key_exchange(client_socket, dh)
            
            if not cipher:
                print(f"[SERVER] Key exchange failed with {address}")
                client_socket.close()
                return
            
            print(f"[SERVER] Key exchange completed with {address}")
            
            # Authenticate user
            username = self.authenticate_user(client_socket, cipher)
            
            if not username:
                print(f"[SERVER] Authentication failed with {address}")
                client_socket.close()
                return
            
            print(f"[SERVER] User {username} authenticated from {address}")
            
            # Register client
            with self.lock:
                self.clients[username] = (client_socket, cipher)
                if username not in self.inboxes:
                    self.inboxes[username] = []
                
                # Send pending messages
                if self.inboxes[username]:
                    self.send_encrypted(
                        client_socket, 
                        cipher, 
                        json.dumps({
                            'type': 'pending_messages',
                            'messages': self.inboxes[username]
                        })
                    )
                    self.inboxes[username] = []
            
            # Handle client messages
            while self.running:
                try:
                    encrypted_data = self.receive_data(client_socket)
                    if not encrypted_data:
                        break
                    
                    # Decrypt message
                    message = cipher.decrypt(encrypted_data)
                    message_data = json.loads(message)
                    
                    # Process message
                    self.process_message(username, message_data, cipher)
                    
                except Exception as e:
                    print(f"[SERVER] Error handling message from {username}: {e}")
                    break
            
        except Exception as e:
            print(f"[SERVER] Error handling client {address}: {e}")
        finally:
            # Clean up
            with self.lock:
                if username in self.clients:
                    del self.clients[username]
            client_socket.close()
            print(f"[SERVER] Client {address} disconnected")
    
    def perform_key_exchange(self, client_socket, dh):
        """Perform DH key exchange with client."""
        try:
            # Send server's public key
            server_public_key = dh.get_public_key_bytes()
            self.send_data(client_socket, server_public_key)
            
            # Receive client's public key
            client_public_key = self.receive_data(client_socket)
            if not client_public_key:
                return None
            
            # Compute shared secret
            shared_secret = dh.compute_shared_secret(client_public_key)
            
            # Create cipher
            cipher = AESCipher(shared_secret)
            
            return cipher
        except Exception as e:
            print(f"[SERVER] Key exchange error: {e}")
            return None
    
    def authenticate_user(self, client_socket, cipher):
        """Authenticate user."""
        try:
            # Receive encrypted username
            encrypted_data = self.receive_data(client_socket)
            if not encrypted_data:
                return None
            
            username = cipher.decrypt(encrypted_data)
            
            # Send confirmation
            self.send_encrypted(
                client_socket, 
                cipher, 
                json.dumps({'type': 'auth_success', 'username': username})
            )
            
            return username
        except Exception as e:
            print(f"[SERVER] Authentication error: {e}")
            return None
    
    def process_message(self, sender, message_data, cipher):
        """Process a message from a client."""
        msg_type = message_data.get('type')
        
        if msg_type == 'send_message':
            recipient = message_data.get('to')
            content = message_data.get('content')
            
            print(f"[SERVER] Message from {sender} to {recipient}: {content}")
            
            # Prepare message for delivery
            delivery_message = {
                'type': 'new_message',
                'from': sender,
                'content': content,
                'timestamp': time.time()
            }
            
            with self.lock:
                # Try to deliver immediately if recipient is online
                if recipient in self.clients:
                    recipient_socket, recipient_cipher = self.clients[recipient]
                    try:
                        self.send_encrypted(
                            recipient_socket, 
                            recipient_cipher, 
                            json.dumps(delivery_message)
                        )
                        
                        # Send confirmation to sender
                        self.send_encrypted(
                            self.clients[sender][0],
                            cipher,
                            json.dumps({'type': 'message_delivered', 'to': recipient})
                        )
                    except Exception as e:
                        print(f"[SERVER] Error delivering message: {e}")
                        # Store in inbox if delivery fails
                        if recipient not in self.inboxes:
                            self.inboxes[recipient] = []
                        self.inboxes[recipient].append(delivery_message)
                else:
                    # Store in inbox for later delivery
                    if recipient not in self.inboxes:
                        self.inboxes[recipient] = []
                    self.inboxes[recipient].append(delivery_message)
                    
                    # Send confirmation to sender
                    self.send_encrypted(
                        self.clients[sender][0],
                        cipher,
                        json.dumps({'type': 'message_queued', 'to': recipient})
                    )
        
        elif msg_type == 'list_users':
            with self.lock:
                users = list(self.clients.keys())
            
            self.send_encrypted(
                self.clients[sender][0],
                cipher,
                json.dumps({'type': 'user_list', 'users': users})
            )
    
    def send_data(self, sock, data):
        """Send data with length prefix."""
        length = len(data).to_bytes(4, byteorder='big')
        sock.sendall(length + data)
    
    def receive_data(self, sock):
        """Receive data with length prefix."""
        # Receive length
        length_bytes = self.recv_exact(sock, 4)
        if not length_bytes:
            return None
        
        length = int.from_bytes(length_bytes, byteorder='big')
        
        # Receive data
        return self.recv_exact(sock, length)
    
    def recv_exact(self, sock, n):
        """Receive exactly n bytes."""
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def send_encrypted(self, sock, cipher, message):
        """Encrypt and send a message."""
        encrypted_data = cipher.encrypt(message)
        self.send_data(sock, encrypted_data)
    
    def stop(self):
        """Stop the server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()


if __name__ == '__main__':
    server = MessagingServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
        server.stop()
