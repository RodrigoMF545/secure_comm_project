import hmac
import hashlib

def generate_hmac(key, message):
    """
    Função para gerar HMAC usando SHA256
    :param key: chave secreta
    :param message: mensagem a ser autenticada
    :return: HMAC da mensagem
    """
    # TODO: implementar HMAC
    pass

def verify_hmac(key, message, hmac_value):
    """
    Função para verificar se o HMAC de uma mensagem corresponde ao esperado
    :param key: chave secreta
    :param message: mensagem a ser autenticada
    :param hmac_value: HMAC recebido
    :return: True se o HMAC for válido, False caso contrário
    """
    # TODO: implementar verificação do HMAC
    pass
