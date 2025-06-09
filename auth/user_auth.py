import json
import os
import re
from auth.password_hashing import hash_password, verify_password

# Caminho para o arquivo JSON que armazena as credenciais temporariamente
CREDENTIALS_FILE = "users.json"

def load_users():
    """
    Carrega os dados dos usuários do arquivo JSON.
    :return: Dicionário com os dados dos usuários ou vazio se o arquivo não existir.
    """
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, 'r') as file:
                return json.load(file)
        except (json.JSONDecodeError, IOError) as e:
            raise Exception(f"Erro ao carregar usuários: {str(e)}")
    return {}

def save_users(users):
    """
    Salva os dados dos usuários no arquivo JSON.
    :param users: Dicionário com os dados dos usuários.
    """
    try:
        with open(CREDENTIALS_FILE, 'w') as file:
            json.dump(users, file, indent=4)
    except IOError as e:
        raise Exception(f"Erro ao salvar usuários: {str(e)}")

def validate_username(username):
    """
    Valida o nome de usuário.
    :param username: Nome de usuário a ser validado.
    :return: True se válido, levanta exceção se inválido.
    """
    if not isinstance(username, str):
        raise ValueError("O nome de usuário deve ser uma string.")
    if not 3 <= len(username) <= 20:
        raise ValueError("O nome de usuário deve ter entre 3 e 20 caracteres.")
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        raise ValueError("O nome de usuário deve conter apenas letras, números ou sublinhados.")
    return True

def validate_password(password):
    """
    Valida a senha.
    :param password: Senha a ser validada.
    :return: True se válida, levanta exceção se inválida.
    """
    if not isinstance(password, str):
        raise ValueError("A senha deve ser uma string.")
    if len(password) < 12:
        raise ValueError("A senha deve ter pelo menos 12 caracteres.")
    if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or \
       not re.search(r"[0-9]", password) or not re.search(r"[^a-zA-Z0-9]", password):
        raise ValueError("A senha deve conter letras maiúsculas, minúsculas, números e caracteres especiais.")
    return True

def register_user(username, password):
    """
    Registra um novo usuário, salvando suas credenciais no arquivo JSON.
    :param username: Nome de usuário.
    :param password: Senha do usuário.
    :return: True se o registro for bem-sucedido.
    """
    # Validações de entrada
    validate_username(username)
    validate_password(password)

    # Carrega os usuários existentes
    users = load_users()

    # Verifica se o usuário já existe
    if username in users:
        raise ValueError("Nome de usuário já existe.")

    # Cria o hash da senha
    hashed_password = hash_password(password)

    # Adiciona o novo usuário ao dicionário
    users[username] = {"hashed_password": hashed_password}

    # Salva os dados no arquivo JSON
    save_users(users)
    return True

def login_user(username, password):
    """
    Realiza o login do usuário verificando suas credenciais.
    :param username: Nome de usuário.
    :param password: Senha fornecida.
    :return: True se o login for bem-sucedido, False caso contrário.
    """
    # Validações de entrada
    try:
        validate_username(username)
        validate_password(password)
    except ValueError:
        return False

    # Carrega os usuários existentes
    users = load_users()

    # Verifica se o usuário existe
    if username not in users:
        return False

    # Verifica a senha
    hashed_password = users[username]["hashed_password"]
    return verify_password(password, hashed_password)