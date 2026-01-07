"""
Simple tests to verify the cryptographic implementation.
"""
from crypto_utils import DHKeyExchange, AESCipher


def test_dh_key_exchange():
    """Test that DH key exchange produces matching shared secrets."""
    print("Testing Diffie-Hellman Key Exchange...")
    
    # Create two DH instances (simulating client and server)
    dh1 = DHKeyExchange()
    dh2 = DHKeyExchange()
    
    # Exchange public keys
    pub1 = dh1.get_public_key_bytes()
    pub2 = dh2.get_public_key_bytes()
    
    print(f"  Public key 1 length: {len(pub1)} bytes")
    print(f"  Public key 2 length: {len(pub2)} bytes")
    
    # Compute shared secrets
    shared1 = dh1.compute_shared_secret(pub2)
    shared2 = dh2.compute_shared_secret(pub1)
    
    # Verify they match
    assert shared1 == shared2, "Shared secrets don't match!"
    print(f"  ✓ Shared secrets match! Length: {len(shared1)} bytes")
    print()


def test_aes_encryption():
    """Test that AES encryption and decryption work correctly."""
    print("Testing AES Encryption/Decryption...")
    
    # Create a shared secret (simulating DH result)
    shared_secret = b"test_shared_secret_32_bytes_long"
    
    # Create cipher
    cipher = AESCipher(shared_secret)
    
    # Test message
    original_message = "Hello, this is a secure message! 🔒"
    print(f"  Original: {original_message}")
    
    # Encrypt
    encrypted = cipher.encrypt(original_message)
    print(f"  Encrypted length: {len(encrypted)} bytes")
    print(f"  Encrypted (first 32 bytes hex): {encrypted[:32].hex()}")
    
    # Decrypt
    decrypted = cipher.decrypt(encrypted)
    print(f"  Decrypted: {decrypted}")
    
    # Verify
    assert decrypted == original_message, "Decryption failed!"
    print("  ✓ Encryption/Decryption successful!")
    print()


def test_end_to_end():
    """Test complete end-to-end encryption flow."""
    print("Testing End-to-End Flow (DH + AES)...")
    
    # Step 1: DH Key Exchange
    alice_dh = DHKeyExchange()
    bob_dh = DHKeyExchange()
    
    alice_pub = alice_dh.get_public_key_bytes()
    bob_pub = bob_dh.get_public_key_bytes()
    
    alice_shared = alice_dh.compute_shared_secret(bob_pub)
    bob_shared = bob_dh.compute_shared_secret(alice_pub)
    
    print(f"  DH key exchange complete")
    
    # Step 2: Create ciphers
    alice_cipher = AESCipher(alice_shared)
    bob_cipher = AESCipher(bob_shared)
    
    # Step 3: Alice sends message to Bob
    alice_message = "Hi Bob, this is Alice!"
    encrypted_msg = alice_cipher.encrypt(alice_message)
    print(f"  Alice → Bob: '{alice_message}' (encrypted: {len(encrypted_msg)} bytes)")
    
    # Step 4: Bob receives and decrypts
    decrypted_msg = bob_cipher.decrypt(encrypted_msg)
    assert decrypted_msg == alice_message
    print(f"  Bob received: '{decrypted_msg}'")
    
    # Step 5: Bob replies
    bob_message = "Hello Alice, nice to hear from you!"
    encrypted_reply = bob_cipher.encrypt(bob_message)
    print(f"  Bob → Alice: '{bob_message}' (encrypted: {len(encrypted_reply)} bytes)")
    
    # Step 6: Alice receives and decrypts
    decrypted_reply = alice_cipher.decrypt(encrypted_reply)
    assert decrypted_reply == bob_message
    print(f"  Alice received: '{decrypted_reply}'")
    
    print("  ✓ End-to-end encryption successful!")
    print()


if __name__ == '__main__':
    print("=" * 60)
    print("Cryptographic Implementation Tests")
    print("=" * 60)
    print()
    
    try:
        test_dh_key_exchange()
        test_aes_encryption()
        test_end_to_end()
        
        print("=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
