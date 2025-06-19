# crypto/prng_utils.py

from secrets import token_bytes

def generate_iv(length=12):
    """
    Gera um IV (Initialization Vector) seguro de length bytes.
    Por padrão, 12 bytes (96 bits) recomendado para AES-GCM.
    """
    return token_bytes(length)

def generate_nonce(length=16):
    """
    Gera um nonce seguro de length bytes.
    """
    return token_bytes(length)

def generate_random_key(length=32):
    """
    Gera uma chave aleatória segura de length bytes.
    32 bytes = 256 bits, ideal para AES-256.
    """
    return token_bytes(length)
