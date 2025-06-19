# crypto/aes.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

# AES-GCM não precisa de padding
# Para CBC seria necessário usar o padding abaixo

def encrypt_message(key, plaintext):
    # Gerar nonce (IV)
    iv = os.urandom(12)  # 96 bits para GCM
    
    # Cria cipher AES-GCM
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    # Retorna (iv, tag, ciphertext), todos base64
    return {
        'iv': base64.b64encode(iv).decode(),
        'tag': base64.b64encode(encryptor.tag).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }

def decrypt_message(key, iv, tag, ciphertext):
    iv = base64.b64decode(iv)
    tag = base64.b64decode(tag)
    ciphertext = base64.b64decode(ciphertext)
    
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()
