from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto.prng_utils import generate_secure_key, generate_secure_iv
from crypto.hmac_utils import generate_hmac, verify_hmac

def generate_key():
    """
    Gera uma chave AES de 256 bits (32 bytes) usando random_generator
    :return: chave gerada (bytes)
    """
    return generate_secure_key(32)  # 32 bytes para AES-256

def encrypt_message(key, plaintext):
    """
    Criptografa uma mensagem usando AES-GCM e adiciona HMAC para integridade extra
    :param key: chave AES (32 bytes)
    :param plaintext: mensagem a ser criptografada (bytes)
    :return: tupla (nonce, ciphertext, hmac)
    :raises ValueError: se os parâmetros forem inválidos
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("A chave deve ser bytes de 32 bytes (AES-256).")
    if not isinstance(plaintext, bytes):
        raise ValueError("A mensagem deve ser bytes.")

    try:
        # Gera nonce usando random_generator
        nonce = generate_secure_iv()[:12]  # 12 bytes para GCM
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        # Gera HMAC para integridade adicional
        hmac_value = generate_hmac(key, nonce + ciphertext)
        return nonce, ciphertext, hmac_value
    except Exception as e:
        raise Exception(f"Erro ao criptografar mensagem: {str(e)}")

def decrypt_message(key, nonce, ciphertext, hmac_value):
    """
    Descriptografa uma mensagem usando AES-GCM e verifica HMAC
    :param key: chave AES (32 bytes)
    :param nonce: nonce usado na criptografia (12 bytes)
    :param ciphertext: texto cifrado (bytes)
    :param hmac_value: HMAC recebido (bytes)
    :return: mensagem descriptografada (bytes)
    :raises ValueError: se os parâmetros forem inválidos ou HMAC falhar
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("A chave deve ser bytes de 32 bytes (AES-256).")
    if not all(isinstance(x, bytes) for x in [nonce, ciphertext, hmac_value]):
        raise ValueError("Nonce, ciphertext e HMAC devem ser bytes.")
    if len(nonce) != 12:
        raise ValueError("O nonce deve ter 12 bytes.")

    try:
        # Verifica HMAC antes de descriptografar
        if not verify_hmac(key, nonce + ciphertext, hmac_value):
            raise ValueError("HMAC inválido: mensagem comprometida.")
        # Inicializa o cifrador AES-GCM
        aesgcm = AESGCM(key)
        # Descriptografa e verifica o tag
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except Exception as e:
        raise Exception(f"Erro ao descriptografar mensagem: {str(e)}")