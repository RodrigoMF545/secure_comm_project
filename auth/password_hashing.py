import bcrypt

def hash_password(password):
    """
    Função para criar um hash seguro da senha
    :param password: senha do usuário (string)
    :return: hash da senha (bytes)
    """
    try:
        # Converte a senha para bytes (necessário para bcrypt)
        password_bytes = password.encode('utf-8')
        # Gera um salt com fator de trabalho padrão (12 rounds)
        salt = bcrypt.gensalt(rounds=12)
        # Cria o hash da senha
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed
    except Exception as e:
        raise Exception(f"Erro ao criar hash da senha: {str(e)}")

def verify_password(password, hashed_password):
    """
    Função para verificar a senha do usuário
    :param password: senha fornecida pelo usuário (string)
    :param hashed_password: senha armazenada (bytes)
    :return: True se a senha for válida, False caso contrário
    """
    try:
        # Converte a senha para bytes
        password_bytes = password.encode('utf-8')
        # Verifica se a senha corresponde ao hash
        return bcrypt.checkpw(password_bytes, hashed_password)
    except Exception:
        # Retorna False em caso de erro (ex.: hash inválido)
        return False