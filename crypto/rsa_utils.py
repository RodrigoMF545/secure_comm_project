from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generate_rsa_keys():
    """
    Função para gerar chaves RSA pública e privada
    :return: chave privada e chave pública
    """
    # TODO: implementar geração de chaves RSA
    pass

def rsa_sign(private_key, data):
    """
    Função para assinar uma mensagem com chave privada
    :param private_key: chave privada
    :param data: dados a serem assinados
    :return: assinatura
    """
    # TODO: implementar assinatura RSA
    pass


def rsa_verify(public_key, signature, data):
    """
    Função para verificar a assinatura de uma mensagem
    :param public_key: chave pública
    :param signature: assinatura
    :param data: dados a serem verificados
    :return: True se a assinatura for válida, False caso contrário
    """
    # TODO: implementar verificação da assinatura RSA
    pass