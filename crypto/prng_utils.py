import os

def generate_secure_key(size):
    """
    Gera uma chave segura de tamanho especificado
    :param size: tamanho da chave (em bytes)
    :return: chave gerada (bytes)
    :raises ValueError: se o tamanho for inválido
    """
    if not isinstance(size, int) or size <= 0:
        raise ValueError("O tamanho da chave deve ser um inteiro positivo.")
    try:
        # Gera uma chave criptograficamente segura usando os.urandom
        return os.urandom(size)
    except Exception as e:
        raise Exception(f"Erro ao gerar chave segura: {str(e)}")

def generate_secure_iv():
    """
    Gera um vetor de inicialização (IV) seguro de 16 bytes
    :return: vetor de inicialização (bytes)
    """
    try:
        # Gera um IV de 16 bytes (adequado para AES) usando os.urandom
        return os.urandom(16)
    except Exception as e:
        raise Exception(f"Erro ao gerar IV seguro: {str(e)}")