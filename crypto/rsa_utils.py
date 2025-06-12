from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def generate_rsa_keys():
    """
    Função para gerar chaves RSA pública e privada
    :return: tupla (chave privada, chave pública) como objetos rsa.RSAPrivateKey e rsa.RSAPublicKey
    """
    try:
        # Gera chave privada RSA com 3072 bits
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # Valor padrão recomendado
            key_size=3072,
            backend=default_backend()
        )
        # Obtém a chave pública correspondente
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as e:
        raise Exception(f"Erro ao gerar chaves RSA: {str(e)}")

def rsa_sign(private_key, data):
    """
    Função para assinar uma mensagem com chave privada
    :param private_key: chave privada (rsa.RSAPrivateKey)
    :param data: dados a serem assinados (bytes)
    :return: assinatura (bytes)
    :raises ValueError: se os parâmetros forem inválidos
    """
    # Validações de entrada
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("A chave privada deve ser um objeto RSAPrivateKey.")
    if not isinstance(data, bytes):
        raise ValueError("Os dados devem ser do tipo bytes.")

    try:
        # Assina os dados usando PSS padding e SHA256
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    except Exception as e:
        raise Exception(f"Erro ao assinar dados: {str(e)}")

def rsa_verify(public_key, signature, data):
    """
    Função para verificar a assinatura de uma mensagem
    :param public_key: chave pública (rsa.RSAPublicKey)
    :param signature: assinatura (bytes)
    :param data: dados a serem verificados (bytes)
    :return: True se a assinatura for válida, False caso contrário
    :raises ValueError: se os parâmetros forem inválidos
    """
    # Validações de entrada
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("A chave pública deve ser um objeto RSAPublicKey.")
    if not isinstance(signature, bytes):
        raise ValueError("A assinatura deve ser do tipo bytes.")
    if not isinstance(data, bytes):
        raise ValueError("Os dados devem ser do tipo bytes.")

    try:
        # Verifica a assinatura usando PSS padding e SHA256
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        # Retorna False se a verificação falhar
        return False