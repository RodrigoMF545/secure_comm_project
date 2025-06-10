import hashlib
import socket
import threading
import pickle

from cryptography.hazmat.primitives import serialization

from auth.user_auth import login_user
from crypto.diffie_hellman import generate_diffie_hellman_parameters, perform_key_exchange
from crypto.rsa_utils import generate_rsa_keys, rsa_verify, rsa_sign
from crypto.aes import encrypt_message, decrypt_message

clients = {}  # username -> (socket, public_key_rsa, shared_key)

def start_server(host, port):
    """
    Inicia o servidor e retorna o socket
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen()
    print(f"[✓] Servidor iniciado na porta {port} e aguardando conexões...")
    return server_sock

def handle_client(client_sock, addr):
    """
    Gerencia a conexão com um cliente, incluindo autenticação e troca de chaves
    """
    try:
        print(f"Recebendo dados de {addr}")
        auth_data = pickle.loads(client_sock.recv(4096))
        username, password = auth_data["username"], auth_data["password"]
        print(f"Tentando autenticar {username} com senha fornecida: {password}")
        if not login_user(username, password):
            print(f"Autenticação falhou para {username}. Verificando banco de dados: {get_user(username)}")
            client_sock.sendall(pickle.dumps({"status": "error", "message": "Autenticação falhou"}))
            client_sock.close()
            return

        dh_parameters = generate_diffie_hellman_parameters()
        server_private_key_rsa, server_public_key_rsa = generate_rsa_keys()
        server_private_key_dh = dh_parameters.generate_private_key()
        server_public_key_dh = server_private_key_dh.public_key()

        # Exportar para formato serializável
        dh_params_bytes = dh_parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        server_public_dh_bytes = server_public_key_dh.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        server_public_rsa_bytes = server_public_key_rsa.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        server_data = {
            "dh_parameters": dh_params_bytes,
            "server_public_key_dh": server_public_dh_bytes,
            "server_public_key_rsa": server_public_rsa_bytes
        }
        print(f"Enviando ao cliente: {server_data}")
        client_sock.sendall(pickle.dumps(server_data))

        client_data = pickle.loads(client_sock.recv(4096))
        client_public_key_dh = serialization.load_pem_public_key(
            client_data["client_public_key_dh"]
        )
        client_public_key_rsa = serialization.load_pem_public_key(
            client_data["client_public_key_rsa"]
        )

        shared_key = perform_key_exchange(server_private_key_dh, client_public_key_dh)
        # Derivar uma chave de 32 bytes para AES-256
        derived_key = hashlib.sha256(shared_key).digest()

        clients[username] = (client_sock, client_public_key_rsa, derived_key)
        print(f"[+] {username} conectado de {addr}")

        while True:
            data = client_sock.recv(4096)
            if not data:
                break
            print(f"Dados recebidos de {username}: {data}")
            try:
                msg_data = pickle.loads(data)
                nonce, ciphertext, hmac_value, signature = (
                    msg_data["nonce"], msg_data["ciphertext"], msg_data["hmac"],
                    msg_data["signature"]
                )
                sender_sock, sender_public_key, sender_shared_key = clients[username]
                message = decrypt_message(sender_shared_key, nonce, ciphertext, hmac_value)

                if not rsa_verify(sender_public_key, signature, message):
                    error_msg = encrypt_message(sender_shared_key, "Servidor: Assinatura inválida".encode('utf-8'))
                    sender_sock.sendall(pickle.dumps({
                        "nonce": error_msg[0], "ciphertext": error_msg[1],
                        "hmac": error_msg[2], "signature": b""
                    }))
                    continue

                message_str = message.decode()
                if ':' in message_str:
                    recipient, content = message_str.split(':', 1)
                    if recipient in clients:
                        recipient_sock, recipient_public_key, recipient_shared_key = clients[recipient]
                        # Enviar a chave pública do remetente e a assinatura original
                        sender_public_key_bytes = sender_public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        server_signature = rsa_sign(server_private_key_rsa, message)  # Assinatura do servidor
                        encrypted = encrypt_message(recipient_shared_key, message)
                        recipient_sock.sendall(pickle.dumps({
                            "nonce": encrypted[0], "ciphertext": encrypted[1],
                            "hmac": encrypted[2], "signature": signature,  # Assinatura original da Alice
                            "sender_public_key": sender_public_key_bytes  # Chave pública do remetente
                        }))
                    else:
                        error_msg = encrypt_message(sender_shared_key, f"Servidor: Usuário '{recipient}' não encontrado.".encode('utf-8'))
                        sender_sock.sendall(pickle.dumps({
                            "nonce": error_msg[0], "ciphertext": error_msg[1],
                            "hmac": error_msg[2], "signature": b""
                        }))
                else:
                    warning = encrypt_message(sender_shared_key, "Servidor: Formato inválido. Use destinatario:mensagem".encode('utf-8'))
                    sender_sock.sendall(pickle.dumps({
                        "nonce": warning[0], "ciphertext": warning[1],
                        "hmac": warning[2], "signature": b""
                    }))

            except Exception as e:
                print(f"[x] Erro ao processar mensagem de {username}: {e}")
                break

    except Exception as e:
        print(f"[x] Erro ao lidar com cliente {addr}: {e}")

    finally:
        print(f"[-] {username} desconectado.")
        clients.pop(username, None)
        client_sock.close()

def get_user(username):
    """
    Função temporária para depuração, assumindo que está em storage.py
    """
    from auth.storage import users_db
    return users_db.get(username)