from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room
import bcrypt
import jwt
import datetime
import json
import os
from functools import wraps

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
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# Decorator para verificar autenticação
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token é necessário'}), 401
        try:
            token = token.split(' ')[1]  # Remove 'Bearer '
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
    # Remove usuário da lista de ativos
    for username, sid in list(active_users.items()):
        if sid == request.sid:
            del active_users[username]
            emit('user_offline', {'username': username}, broadcast=True)
            break

@socketio.on('join')
def handle_join(data):
    try:
        token = data['token']
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded['username']
        
        active_users[username] = request.sid
        join_room(username)
        
        emit('user_online', {'username': username}, broadcast=True)
        emit('join_success', {'username': username})
        
        # Enviar lista de usuários online
        online_users = list(active_users.keys())
        emit('online_users', {'users': online_users})
        
    except Exception as e:
        emit('error', {'message': 'Token inválido'})

@socketio.on('private_message')
def handle_private_message(data):
    try:
        token = data['token']
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        sender = decoded['username']
        
        recipient = data['recipient']
        message = data['message']
        
        # Salvar mensagem
        chat_id = f"{min(sender, recipient)}_{max(sender, recipient)}"
        if chat_id not in messages_db:
            messages_db[chat_id] = []
        
        message_data = {
            'sender': sender,
            'recipient': recipient,
            'message': message,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
        
        messages_db[chat_id].append(message_data)
        
        # Enviar mensagem para o remetente
        emit('message_sent', message_data)
        
        # Enviar mensagem para o destinatário se estiver online
        if recipient in active_users:
            socketio.emit('new_message', message_data, room=active_users[recipient])
        
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('get_chat_history')
def handle_get_chat_history(data):
    try:
        token = data['token']
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = decoded['username']
        
        other_user = data['other_user']
        chat_id = f"{min(current_user, other_user)}_{max(current_user, other_user)}"
        
        chat_history = messages_db.get(chat_id, [])
        emit('chat_history', {'messages': chat_history, 'other_user': other_user})
        
    except Exception as e:
        emit('error', {'message': str(e)})

if __name__ == '__main__':
     # Criar usuários de teste
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