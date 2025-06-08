# symmetric/aes_encryption.py

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def generate_key():
    """Gera uma chave AES de 256 bits (32 bytes)"""
    return AESGCM.generate_key(bit_length=256)

def encrypt_message(key, plaintext):
    """
    Criptografa uma mensagem usando AES-GCM
    :param key: chave AES (32 bytes)
    :param plaintext: string da mensagem
    :return: nonce + ciphertext
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96 bits recomendado para GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ciphertext  # Retorna juntos

def decrypt_message(key, encrypted_data):
    """
    Descriptografa uma mensagem usando AES-GCM
    :param key: chave AES (32 bytes)
    :param encrypted_data: nonce + ciphertext
    :return: mensagem original como string
    """
    aesgcm = AESGCM(key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()
