from password_hashing import hash_password

# Simula um banco de dados de usuários com senha
users_db = {
    "alice": {"hashed_password": hash_password("P@ssw0rd123!")},
    "bob": {"hashed_password": hash_password("S3cur3P@ssw0rd!")},
    "charlie": {"hashed_password": hash_password("Ch@rl13P@ss!")},
}

def add_user(username, hashed_password):
    """
    Função para adicionar um usuário no banco de dados simulado
    :param username: nome do usuário (string)
    :param hashed_password: hash da senha (bytes, gerado por password_hashing.py)
    :return: True se o usuário for adicionado com sucesso
    :raises ValueError: se o usuário já existe ou se os parâmetros são inválidos
    """
    # Validações de entrada
    if not isinstance(username, str) or not username:
        raise ValueError("O nome de usuário deve ser uma string não vazia.")
    if not isinstance(hashed_password, bytes):
        raise ValueError("O hash da senha deve ser em formato bytes.")
    if username in users_db:
        raise ValueError("Usuário já existe no banco de dados.")

    # Adiciona o usuário ao dicionário
    users_db[username] = {"hashed_password": hashed_password}
    return True

def get_user(username):
    """
    Função para obter um usuário do banco de dados simulado
    :param username: nome do usuário (string)
    :return: dicionário com dados do usuário (ex.: {"hashed_password": bytes}) ou None se não encontrado
    :raises ValueError: se o nome de usuário for inválido
    """
    # Validação de entrada
    if not isinstance(username, str) or not username:
        raise ValueError("O nome de usuário deve ser uma string não vazia.")

    # Retorna o usuário ou None se não encontrado
    return users_db.get(username)