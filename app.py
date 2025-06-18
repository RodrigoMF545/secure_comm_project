from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import bcrypt
import jwt
import datetime
import os
from functools import wraps
from crypto.aes import encrypt_message, decrypt_message
from crypto.diffie_hellman import generate_private_key, get_public_bytes, compute_shared_key
from crypto.rsa_utils import generate_rsa_keys, rsa_sign, rsa_verify
import secrets  # Importando o módulo secrets para gerar chaves seguras

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'
socketio = SocketIO(app, cors_allowed_origins="*")

# Simulação de banco de dados em memória
users_db = {}
messages_db = {}
active_users = {}

# Função para hash de senha
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Função para verificar senha
def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Função para gerar JWT token
def generate_token(username):
    payload = {
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

# Função para gerar uma chave AES de 256 bits usando secrets
def generate_aes_key():
    return secrets.token_bytes(32)  # 256 bits = 32 bytes

# Decorator para verificar autenticação
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token é necessário'}), 401
        try:
            token = token.split(' ')[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['username']
        except:
            return jsonify({'message': 'Token inválido'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Rotas HTML
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/chat')
def chat():
    return render_template('chat.html')

# API Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username e password são obrigatórios'}), 400

    if username in users_db:
        return jsonify({'message': 'Usuário já existe'}), 400

    hashed_password = hash_password(password)
    users_db[username] = {
        'password': hashed_password,
        'created_at': datetime.datetime.utcnow()
    }

    token = generate_token(username)
    return jsonify({'message': 'Usuário criado com sucesso', 'token': token}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username e password são obrigatórios'}), 400

    if username not in users_db:
        return jsonify({'message': 'Usuário não encontrado'}), 404

    if not check_password(password, users_db[username]['password']):
        return jsonify({'message': 'Senha incorreta'}), 401

    token = generate_token(username)
    return jsonify({'message': 'Login realizado com sucesso', 'token': token}), 200

@app.route('/api/users')
@token_required
def get_users(current_user):
    user_list = [user for user in users_db.keys() if user != current_user]
    return jsonify({'users': user_list})

# Socket.IO Events
@socketio.on('connect')
def handle_connect():
    print('Cliente conectado')

@socketio.on('disconnect')
def handle_disconnect():
    print('Cliente desconectado')
    for username, user_data in list(active_users.items()):
        if user_data['sid'] == request.sid:
            del active_users[username]
            emit('user_offline', {'username': username}, broadcast=True)
            break

@socketio.on('join')
def handle_join(data):
    print(f"DEBUG JOIN - Recebido token: {data.get('token')}")
    try:
        token = data['token']
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'], options={"verify_exp": False})
        username = decoded['username']

        # Gerar chaves ECDH e RSA
        private_key = generate_private_key()
        public_bytes = get_public_bytes(private_key)
        rsa_private, rsa_public = generate_rsa_keys()

        # Adicionar usuário ativo
        active_users[username] = {
            'sid': request.sid,
            'private_key': private_key,
            'public_key': public_bytes,
            'rsa_private': rsa_private,
            'rsa_public': rsa_public,
            'shared_keys': {}
        }

        join_room(username)
        emit('user_online', {'username': username}, broadcast=True)
        emit('join_success', {
            'username': username,
            'public_key': public_bytes.hex()
        })

        online_users = list(active_users.keys())
        emit('online_users', {'users': online_users})

    except Exception as e:
        print(f"DEBUG JOIN - Erro ao decodificar token: {type(e).__name__} - {str(e)}")
        emit('error', {'message': 'Token inválido'})

@socketio.on('exchange_key')
def handle_exchange_key(data):
    try:
        token = data['token']
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded['username']

        peer_user = data['peer_user']
        peer_public_hex = data['peer_public_key']
        peer_public_bytes = bytes.fromhex(peer_public_hex)

        private_key = active_users[username]['private_key']
        aes_shared_key = compute_shared_key(private_key, peer_public_bytes)

        active_users[username]['shared_keys'][peer_user] = aes_shared_key

        emit('exchange_success', {'peer_user': peer_user})

    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('private_message')
def handle_private_message(data):
    try:
        token = data['token']
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        sender = decoded['username']

        recipient = data['recipient']
        message = data['message']

        aes_key = active_users[sender]['shared_keys'].get(recipient)
        if not aes_key:
            raise Exception(f'Chave não estabelecida entre {sender} e {recipient}')

        encrypted = encrypt_message(aes_key, message)

        chat_id = f"{min(sender, recipient)}_{max(sender, recipient)}"
        if chat_id not in messages_db:
            messages_db[chat_id] = []

        message_data = {
            'sender': sender,
            'recipient': recipient,
            'iv': encrypted['iv'],
            'tag': encrypted['tag'],
            'ciphertext': encrypted['ciphertext'],
            'timestamp': datetime.datetime.utcnow().isoformat()
        }

        messages_db[chat_id].append(message_data)

        # Assinar a mensagem
        plaintext_bytes = message.encode('utf-8')
        signature = rsa_sign(active_users[sender]['rsa_private'], plaintext_bytes)

        decrypted_message_data = {
            'sender': sender,
            'recipient': recipient,
            'message': message,
            'signature': signature.hex(),
            'timestamp': message_data['timestamp']
        }

        emit('message_sent', decrypted_message_data)

        if recipient in active_users:
            socketio.emit('new_message', decrypted_message_data, room=active_users[recipient]['sid'])

    except Exception as e:
        emit('error', {'message': str(e)})

if __name__ == '__main__':
    print("Criando usuários de teste...")
    users_db['alice'] = {
        'password': hash_password('123456'),
        'created_at': datetime.datetime.utcnow()
    }
    users_db['bob'] = {
        'password': hash_password('123456'),
        'created_at': datetime.datetime.utcnow()
    }
    print(f"Usuários criados: {list(users_db.keys())}")

    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
