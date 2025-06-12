import hmac
import hashlib

def generate_hmac(key, message):
    """
    Função para gerar HMAC usando SHA256
    :param key: chave secreta (bytes)
    :param message: mensagem a ser autenticada (bytes)
    :return: HMAC da mensagem (bytes)
    :raises ValueError: se os parâmetros forem inválidos
    """
    # Validações de entrada
    if not isinstance(key, bytes):
        raise ValueError("A chave deve ser do tipo bytes.")
    if not isinstance(message, bytes):
        raise ValueError("A mensagem deve ser do tipo bytes.")
    if not key:
        raise ValueError("A chave não pode ser vazia.")

    try:
        # Gera o HMAC usando SHA256
        hmac_obj = hmac.new(key, message, hashlib.sha256)
        return hmac_obj.digest()
    except Exception as e:
        raise Exception(f"Erro ao gerar HMAC: {str(e)}")

def verify_hmac(key, message, hmac_value):
    """
    Função para verificar se o HMAC de uma mensagem corresponde ao esperado
    :param key: chave secreta (bytes)
    :param message: mensagem a ser autenticada (bytes)
    :param hmac_value: HMAC recebido (bytes)
    :return: True se o HMAC for válido, False caso contrário
    :raises ValueError: se os parâmetros forem inválidos
    """
    # Validações de entrada
    if not isinstance(key, bytes):
        raise ValueError("A chave deve ser do tipo bytes.")
    if not isinstance(message, bytes):
        raise ValueError("A mensagem deve ser do tipo bytes.")
    if not isinstance(hmac_value, bytes):
        raise ValueError("O HMAC recebido deve ser do tipo bytes.")
    if not key:
        raise ValueError("A chave não pode ser vazia.")

    try:
        # Gera o HMAC da mensagem fornecida
        expected_hmac = hmac.new(key, message, hashlib.sha256).digest()
        # Compara com o HMAC recebido de forma segura (constante-time)
        return hmac.compare_digest(expected_hmac, hmac_value)
    except Exception as e:
        raise Exception(f"Erro ao verificar HMAC: {str(e)}")