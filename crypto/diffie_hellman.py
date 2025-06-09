from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_diffie_hellman_parameters():
    """
    Gera parâmetros DH para troca de chaves
    :return: parâmetros de DH (objeto dh.DHParameters)
    """
    try:
        # Gera parâmetros DH com chave de 2048 bits para segurança
        parameters = dh.generate_parameters(
            generator=2,  # Valor padrão para DH
            key_size=2048,
            backend=default_backend()
        )
        return parameters
    except Exception as e:
        raise Exception(f"Erro ao gerar parâmetros Diffie-Hellman: {str(e)}")

def perform_key_exchange(private_key, public_key):
    """
    Realiza a troca de chaves usando Diffie-Hellman
    :param private_key: chave privada do usuário (objeto dh.DHPrivateKey)
    :param public_key: chave pública do outro usuário (objeto dh.DHPublicKey)
    :return: chave compartilhada (bytes)
    :raises ValueError: se as chaves forem inválidas
    """
    # Validações de entrada
    if not isinstance(private_key, dh.DHPrivateKey):
        raise ValueError("A chave privada deve ser um objeto DHPrivateKey.")
    if not isinstance(public_key, dh.DHPublicKey):
        raise ValueError("A chave pública deve ser um objeto DHPublicKey.")

    try:
        # Realiza a troca de chaves para obter a chave compartilhada
        shared_key = private_key.exchange(public_key)
        # Deriva uma chave mais segura usando HKDF (opcional, mas recomendado)
        # Aqui, apenas retornamos a chave bruta, mas HKDF pode ser adicionado em sprints futuros
        return shared_key
    except Exception as e:
        raise Exception(f"Erro ao realizar troca de chaves: {str(e)}")
