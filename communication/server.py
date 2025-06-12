import socket
import threading
import pickle
import struct

from cryptography.hazmat.primitives import serialization

from auth.user_auth import login_user
from crypto.diffie_hellman import generate_diffie_hellman_parameters, perform_key_exchange
from crypto.rsa_utils import generate_rsa_keys
from crypto.aes import encrypt_message, decrypt_message

# --- Funções utilitárias para envio/recebimento com framing ---

def send_pickle(sock, obj):
    data = pickle.dumps(obj)
    length = struct.pack('!I', len(data))  # 4 bytes big-endian
    sock.sendall(length + data)

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Conexão encerrada inesperadamente.")
        data += packet
    return data

def recv_pickle(sock):
    raw_length = recv_exact(sock, 4)
    length = struct.unpack('!I', raw_length)[0]
    data = recv_exact(sock, length)
    return pickle.loads(data)

# --- Inicialização do servidor ---

dh_parameters = generate_diffie_hellman_parameters()
server_private_key_rsa, server_public_key_rsa = generate_rsa_keys()

# Dicionário para armazenar sessões de clientes (exemplo simples)
client_sessions = {}

def handle_client(conn, addr):
    try:
        print(f"[+] Cliente conectado: {addr}")

        # Recebe dados de autenticação
        auth_data = recv_pickle(conn)
        username = auth_data.get("username")
        password = auth_data.get("password")

        # Autentica usuário com a função do seu user_auth.py
        if not login_user(username, password):
            send_pickle(conn, {"status": "error", "message": "Usuário ou senha inválidos"})
            conn.close()
            return

        # Gera a chave privada DH do servidor para essa sessão
        server_private_key_dh = dh_parameters.generate_private_key()
        server_public_key_dh = server_private_key_dh.public_key()

        # Prepara resposta com parâmetros DH e chaves públicas RSA e DH
        response = {
            "status": "ok",
            "dh_parameters": dh_parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            ),
            "server_public_key_dh": server_public_key_dh.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            "server_public_key_rsa": server_public_key_rsa.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        }
        send_pickle(conn, response)

        # Recebe as chaves públicas DH e RSA do cliente
        client_keys = recv_pickle(conn)
        client_public_key_dh = serialization.load_pem_public_key(client_keys["client_public_key_dh"])
        client_public_key_rsa = serialization.load_pem_public_key(client_keys["client_public_key_rsa"])

        # Gera chave compartilhada DH
        shared_key = perform_key_exchange(server_private_key_dh, client_public_key_dh)

        # Armazena dados da sessão
        client_sessions[addr] = {
            "username": username,
            "shared_key": shared_key,
            "client_public_key_rsa": client_public_key_rsa,
            "server_private_key_rsa": server_private_key_rsa,
            "server_private_key_dh": server_private_key_dh,
        }

        print(f"[✓] Autenticação e troca de chaves concluídas para {username}")

        # Aqui você pode continuar o protocolo de comunicação segura (troca de mensagens etc.)

    except Exception as e:
        print(f"[x] Erro no cliente {addr}: {e}")
    finally:
        conn.close()
        print(f"[-] Cliente desconectado: {addr}")

def start_server(host='localhost', port=12345):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen()
    print(f"[+] Servidor escutando em {host}:{port}")

    try:
        while True:
            conn, addr = sock.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\n[!] Servidor finalizado manualmente.")
    finally:
        sock.close()

if __name__ == "__main__":
    start_server()
