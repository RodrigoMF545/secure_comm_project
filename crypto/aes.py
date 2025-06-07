from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_aes(key, iv, plaintext):
    """
    Função para criptografar dados com AES
    :param key: chave secreta (16, 24 ou 32 bytes)
    :param iv: vetor de inicialização (16 bytes)
    :param plaintext: mensagem para criptografar
    :return: texto cifrado
    """
    # TODO: implementar criptografia AES
    pass


def decrypt_aes(key, iv, ciphertext):
    """
    Função para descriptografar dados com AES
    :param key: chave secreta (16, 24 ou 32 bytes)
    :param iv: vetor de inicialização (16 bytes)
    :param ciphertext: texto cifrado
    :return: mensagem original (plaintext)
    """
    # TODO: implementar descriptografia AES
    pass
