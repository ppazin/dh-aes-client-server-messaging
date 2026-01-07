"""
Cryptography module for Diffie-Hellman key exchange and AES encryption/decryption.
"""
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class DHKeyExchange:
    """Handles Diffie-Hellman key exchange."""
    
    # Use standard DH parameters (2048-bit MODP Group)
    # RFC 3526 - 2048-bit MODP Group
    P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    G = 2
    
    def __init__(self):
        """Initialize DH key exchange with parameters."""
        # Create DH parameters
        pn = dh.DHParameterNumbers(self.P, self.G)
        self.parameters = pn.parameters(default_backend())
        
        # Generate private key
        self.private_key = self.parameters.generate_private_key()
        
        # Get public key
        self.public_key = self.private_key.public_key()
    
    def get_public_key_bytes(self):
        """Get public key as bytes for transmission."""
        public_numbers = self.public_key.public_numbers()
        # Convert the public key (y) to bytes
        return public_numbers.y.to_bytes(256, byteorder='big')
    
    def compute_shared_secret(self, peer_public_key_bytes):
        """
        Compute shared secret from peer's public key.
        
        Args:
            peer_public_key_bytes: Peer's public key as bytes
            
        Returns:
            Shared secret as bytes
        """
        # Reconstruct peer's public key
        peer_y = int.from_bytes(peer_public_key_bytes, byteorder='big')
        peer_public_numbers = dh.DHPublicNumbers(peer_y, dh.DHParameterNumbers(self.P, self.G))
        peer_public_key = peer_public_numbers.public_key(default_backend())
        
        # Compute shared secret
        shared_key = self.private_key.exchange(peer_public_key)
        return shared_key


class AESCipher:
    """Handles AES encryption and decryption."""
    
    def __init__(self, shared_secret):
        """
        Initialize AES cipher with a shared secret.
        
        Args:
            shared_secret: Shared secret from DH key exchange
        """
        # Derive AES key from shared secret using HKDF
        self.key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key for AES-256
            salt=None,
            info=b'aes-key-derivation',
            backend=default_backend()
        ).derive(shared_secret)
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using AES-GCM.
        
        Args:
            plaintext: String or bytes to encrypt
            
        Returns:
            Encrypted data as bytes (iv + ciphertext + tag)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Generate random IV (12 bytes for GCM)
        iv = os.urandom(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Return IV + ciphertext + tag
        return iv + ciphertext + encryptor.tag
    
    def decrypt(self, encrypted_data):
        """
        Decrypt data encrypted with AES-GCM.
        
        Args:
            encrypted_data: Encrypted data (iv + ciphertext + tag)
            
        Returns:
            Decrypted plaintext as string
        """
        # Extract IV (12 bytes), tag (16 bytes), and ciphertext
        iv = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode('utf-8')
