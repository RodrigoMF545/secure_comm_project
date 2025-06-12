import socket
import threading
import pickle
import struct
from cryptography.hazmat.primitives import serialization
from auth.user_auth import login_user
from crypto.diffie_hellman import generate_diffie_hellman_parameters, perform_key_exchange
from crypto.rsa_utils import generate_rsa_keys
from crypto.aes import decrypt_message
from threading import Lock

client_sockets = {}
client_sockets_lock = Lock()

def send_pickle(sock, obj):
    data = pickle.dumps(obj)
    length = struct.pack("!I", len(data))
    sock.sendall(length + data)

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Conexão encerrada")
        data += packet
    return data

def recv_pickle(sock):
    raw_len = recv_exact(sock, 4)
    msg_len = struct.unpack("!I", raw_len)[0]
    data = recv_exact(sock, msg_len)
    return pickle.loads(data)

dh_parameters = generate_diffie_hellman_parameters()
server_private_key_rsa, server_public_key_rsa = generate_rsa_keys()
client_sessions = {}

def handle_client(conn, addr):
    username = None
    try:
        print(f"[+] Cliente conectado: {addr}")
        auth_data = recv_pickle(conn)
        username = auth_data["username"]
        password = auth_data["password"]
        if not login_user(username, password):
            send_pickle(conn, {"status": "error", "message": "Usuário ou senha inválidos"})
            return
        server_private_key_dh = dh_parameters.generate_private_key()
        server_public_key_dh = server_private_key_dh.public_key()
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
        with client_sockets_lock:
            if username in client_sockets:
                old_sock, old_addr = client_sockets[username]
                old_sock.close()
            client_sockets[username] = (conn, addr)
        client_key_data = recv_pickle(conn)
        client_public_key_dh = serialization.load_pem_public_key(client_key_data["client_public_key_dh"])
        client_public_key_rsa = serialization.load_pem_public_key(client_key_data["client_public_key_rsa"])
        shared_key = perform_key_exchange(server_private_key_dh, client_public_key_dh)
        client_sessions[addr] = {
            "username": username,
            "shared_key": shared_key,
            "client_public_key_rsa": client_key_data["client_public_key_rsa"],
            "server_private_key_rsa": server_private_key_rsa,
            "server_private_key_dh": server_private_key_dh
        }
        print(f"[✓] Autenticação e troca de chaves concluídas para {username}")
        while True:
            try:
                msg_data = recv_pickle(conn)
                plaintext = decrypt_message(client_sessions[addr]["shared_key"], msg_data["nonce"], msg_data["ciphertext"], msg_data["hmac"])
                plaintext_str = plaintext.decode()
                parts = plaintext_str.split(":", 1)
                if len(parts) != 2:
                    print(f"[Server] Formato de mensagem inválido de {username}")
                    continue
                recipient, message = parts
                with client_sockets_lock:
                    if recipient not in client_sockets:
                        print(f"[Server] Destinatário {recipient} não encontrado")
                        continue
                    recipient_sock, recipient_addr = client_sockets[recipient]
                recipient_shared_key = client_sessions[recipient_addr]["shared_key"]
                send_plaintext = f"De {username}: {message}".encode()
                signature = rsa_sign(server_private_key_rsa, send_plaintext)
                nonce, ciphertext, hmac_val = encrypt_message(recipient_shared_key, send_plaintext)
                send_pickle(recipient_sock, {
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                    "hmac": hmac_val,
                    "signature": signature,
                    "sender_public_key": server_public_key_rsa.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                })
            except Exception as e:
                print(f"[Server] Erro ao receber mensagem: {e}")
                break
    except Exception as e:
        print(f"[x] Erro: {e}")
    finally:
        if username:
            with client_sockets_lock:
                if username in client_sockets and client_sockets[username][0] == conn:
                    del client_sockets[username]
        conn.close()
        print(f"[-] Cliente desconectado: {addr}")

def start_server(host='localhost', port=12346):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[+] Servidor iniciado em {host}:{port}")
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("[!] Servidor finalizado manualmente")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()