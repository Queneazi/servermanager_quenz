from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64


def encrypt_AES_CBC(password, data):
    # Generate a salt
    salt = os.urandom(16)

    # Derive a key from the password and salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Generate a random initialization vector (IV)
    iv = os.urandom(16)

    # Create AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the data to be encrypted
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Concatenate IV, salt, and ciphertext
    encrypted_data = iv + salt + ciphertext

    # Encode to base64 for storage or transmission
    encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')

    return encrypted_base64


def decrypt_AES_CBC(password, encrypted_base64):
    # Decode from base64
    encrypted_data = base64.b64decode(encrypted_base64)

    # Extract IV, salt, and ciphertext
    iv = encrypted_data[:16]
    salt = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    # Derive the key from the password and salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Create AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Return the decrypted data as a string
    return unpadded_data.decode('utf-8')


