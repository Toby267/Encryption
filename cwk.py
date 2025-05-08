import os
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_encrypt(key, plaintext):
    # Implement AES encryption instantiated in CBC mode.
    # You should use PKCS7 for padding.
    # You should use a 16-byte random IV.
    iv = os.urandom(16)
    cipherAlgorithm = Cipher(algorithms.AES(key), modes.CBC(iv))
    encrypter = cipherAlgorithm.encryptor()
    padder = padding.PKCS7(128).padder()

    paddedData = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encrypter.update(paddedData) + encrypter.finalize()

    return iv, ciphertext

def generate_hmac(key, data):
    # Implement HMAC.
    # You must select an appropriate hash function for your implementation.
    hasher = hmac.HMAC(key, hashes.SHA256())
    hasher.update(data)
    
    mac = hasher.finalize()

    return mac

def encrypt_then_mac(plaintext, aes_key, mac_key):
    # Implement encrypt-then-MAC.
    iv, ciphertext = aes_encrypt(aes_key, plaintext)
    mac = generate_hmac(mac_key, ciphertext)

    return iv, ciphertext, mac

def decrypt_and_verify(iv, ciphertext, mac, aes_key, mac_key):
    # Decrypt the ciphertext and verify the MAC.
    cipherAlgorithm = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decrypter = cipherAlgorithm.decryptor()
    unpadder = padding.PKCS7(128).unpadder()

    paddedData = decrypter.update(ciphertext) + decrypter.finalize()
    
    plaintext = unpadder.update(paddedData) + unpadder.finalize()
    plaintext = plaintext.decode()

    computedMAC = generate_hmac(mac_key, ciphertext)

    if computedMAC != mac:
        raise ValueError("computedMAC not equal to actual MAC")
    
    return plaintext
