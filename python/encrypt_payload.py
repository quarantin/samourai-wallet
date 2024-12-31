#!/usr/bin/env python


import base64
import json
import hashlib
import os
import random
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def pbkdf2_hmac_sha256(password, salt, iterations, key_length):
    """
    Derive a key using PBKDF2-HMAC-SHA256.

    :param password: The input password (string or bytes).
    :param salt: The salt value (bytes).
    :param iterations: The number of iterations.
    :param key_length: The desired length of the derived key.
    :return: The derived key (bytes).
    """
    # Ensure password is in bytes
    if isinstance(password, str):
        password = password.encode('utf-8')

    # Generate the derived key
    return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen=key_length)

def aes_encrypt(key, iv, plaintext):
    """
    Encrypt the entire plaintext using AES-256-CBC.
    
    :param key: The encryption key (32 bytes for AES-256).
    :param iv: The initialization vector (16 bytes for CBC mode).
    :param plaintext: The plaintext to encrypt (bytes).
    :return: The ciphertext (bytes).
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')  # Convert string to bytes

    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256.")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes.")
    
    # Pad the plaintext to a multiple of the block size (16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
    # Create AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext

# Example usage
# iterations = 15000
# FIXME: iteartion count should be 15000, this is just for debug
iterations = 1
key_length = 48

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <password> <payload.json>")
    sys.exit(1)

password = sys.argv[1]
payload_file = sys.argv[2]

with open(payload_file) as fd:
    plaintext = fd.read()

salt = os.urandom(8)

derived = pbkdf2_hmac_sha256(password, salt, iterations, key_length)
key = derived[0:32]
iv = derived[32:48]
ciphertext = aes_encrypt(key, iv, plaintext)

payload = b"Salted__" + salt + ciphertext

jsondata = {
    "version": 2,
    "payload": base64.b64encode(payload).decode("utf-8"),
    "external": False,
}

print(json.dumps(jsondata))
