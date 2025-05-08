# You can use the following to test your code.
# Note that this is not part of your solution.
import os
from cwk import encrypt_then_mac, decrypt_and_verify

# Basic functionality test.
if __name__ == "__main__":
    aes_key = os.urandom(32)
    mac_key = os.urandom(32)

    plaintext = "Basic functionality test"

    iv, ciphertext, mac = encrypt_then_mac(plaintext, aes_key, mac_key)

    decrypted_message = decrypt_and_verify(iv, ciphertext, mac, aes_key, mac_key)
    assert decrypted_message == plaintext
    print("Basic functionality test passed")

# Empty plaintext
if __name__ == "__main__":
    aes_key = os.urandom(32)
    mac_key = os.urandom(32)

    plaintext = ""

    iv, ciphertext, mac = encrypt_then_mac(plaintext, aes_key, mac_key)

    decrypted_message = decrypt_and_verify(iv, ciphertext, mac, aes_key, mac_key)
    assert decrypted_message == plaintext
    print("Empty plaintext test passed")


# Long plaintext
if __name__ == "__main__":
    aes_key = os.urandom(32)
    mac_key = os.urandom(32)

    plaintext = "M" * 10**6

    iv, ciphertext, mac = encrypt_then_mac(plaintext, aes_key, mac_key)

    decrypted_message = decrypt_and_verify(iv, ciphertext, mac, aes_key, mac_key)
    assert decrypted_message == plaintext
    print("Long plaintext test passed")


# Modified ciphertext test
if __name__ == "__main__":
    aes_key = os.urandom(32)
    mac_key = os.urandom(32)

    plaintext = "Modified ciphertext test"

    iv, ciphertext, mac = encrypt_then_mac(plaintext, aes_key, mac_key)
    modified_ciphertext = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0x01])
    try:
        decrypted_message = decrypt_and_verify(iv, modified_ciphertext, mac, aes_key, mac_key)
        print("Modified ciphertext test failed")
    except ValueError as e:
        print("Modified ciphertext test passed")


# Modified MAC test
if __name__ == "__main__":
    aes_key = os.urandom(32)
    mac_key = os.urandom(32)

    plaintext = "Modified MAC test"

    iv, ciphertext, mac = encrypt_then_mac(plaintext, aes_key, mac_key)
    modified_mac = mac[:-1] + bytes([mac[-1] ^ 0x01])

    try:
        decrypted_message = decrypt_and_verify(iv, ciphertext, modified_mac, aes_key, mac_key)
        print("Modified MAC test failed")
    except ValueError as e:
        print("Modified MAC test passed")