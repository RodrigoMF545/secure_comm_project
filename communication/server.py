import socket
import threading
import pickle
from auth.user_auth import login_user
from crypto.diffie_hellman import generate_diffie_hellman_parameters, perform_key_exchange
from crypto.rsa_utils import generate_rsa_keys, rsa_verify, rsa_sign
from crypto.aes import encrypt_message, decrypt_message

clients = {}  # username -> (socket, public_key_rsa)

def start_server(host, port):
    """
    Inicia o servidor e retorna o socket
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen()
    return server_sock

def handle_client(client_sock, addr):
    """
    Gerencia a conexão com um cliente, incluindo autenticação e troca de chaves
    """
    try:
        # Recebe e valida credenciais do usuário
        auth_data = pickle.loads(client_sock.recv(4096))
        username, password = auth_data["username"], auth_data["password"]
        if not login_user(username, password):
            client_sock.sendall(pickle.dumps({"status": "error", "message": "Autenticação falhou"}))
            client_sock.close()
            return

        # Gera parâmetros DH e chaves RSA do servidor
        dh_parameters = generate_diffie_hellman_parameters()
        server_private_key_rsa, server_public_key_rsa = generate_rsa_keys()
        server_private_key_dh = dh_parameters.generate_private_key()
        server_public_key_dh = server_private_key_dh.public_key()

        # Envia parâmetros DH, chave pública DH e chave pública RSA ao cliente
        server_data = {
            "dh_parameters": dh_parameters,
            "server_public_key_dh": server_public_key_dh,
            "server_public_key_rsa": server_public_key_rsa
        }
        client_sock.sendall(pickle.dumps(server_data))

        # Recebe chave pública DH e RSA do cliente
        client_data = pickle.loads(client_sock.recv(4096))
        client_public_key_dh = client_data["client_public_key_dh"]
        client_public_key_rsa = client_data["client_public_key_rsa"]

        # Gera chave compartilhada
        shared_key = perform_key_exchange(server_private_key_dh, client_public_key_dh)

        # Registra o cliente
        clients[username] = (client_sock, client_public_key_rsa)
        print(f"[+] {username} conectado de {addr}")

        while True:
            # Recebe mensagem criptografada
            data = client_sock.recv(4096)
            if not data:
                break

            try:
                # Deserializa e verifica a mensagem
                msg_data = pickle.loads(data)
                nonce, ciphertext, hmac_value, signature = (
                    msg_data["nonce"], msg_data["ciphertext"], msg_data["hmac"],
                    msg_data["signature"]
                )
                message = decrypt_message(shared_key, nonce, ciphertext, hmac_value)

                # Verifica a assinatura
                if not rsa_verify(client_public_key_rsa, signature, message):
                    error_msg = encrypt_message(shared_key, "Servidor: Assinatura inválida".encode('utf-8'))
                    client_sock.sendall(pickle.dumps({
                        "nonce": error_msg[0], "ciphertext": error_msg[1],
                        "hmac": error_msg[2], "signature": b""
                    }))
                    continue

                # Processa a mensagem
                message_str = message.decode()
                if ':' in message_str:
                    recipient, content = message_str.split(':', 1)
                    if recipient in clients:
                        recipient_sock, recipient_public_key = clients[recipient]
                        # Assina a mensagem do servidor
                        server_signature = rsa_sign(server_private_key_rsa, message)
                        encrypted = encrypt_message(shared_key, message)
                        recipient_sock.sendall(pickle.dumps({
                            "nonce": encrypted[0], "ciphertext": encrypted[1],
                            "hmac": encrypted[2], "signature": server_signature
                        }))
                    else:
                        error_msg = encrypt_message(shared_key, f"Servidor: Usuário '{recipient}' não encontrado.".encode('utf-8'))
                        client_sock.sendall(pickle.dumps({
                            "nonce": error_msg[0], "ciphertext": error_msg[1],
                            "hmac": error_msg[2], "signature": b""
                        }))
                else:
                    warning = encrypt_message(shared_key, "Servidor: Formato inválido. Use destinatario:mensagem".encode('utf-8'))
                    client_sock.sendall(pickle.dumps({
                        "nonce": warning[0], "ciphertext": warning[1],
                        "hmac": warning[2], "signature": b""
                    }))

            except Exception as e:
                print(f"[x] Erro ao processar mensagem de {username}:", e)
                break

    except Exception as e:
        print(f"[x] Erro ao lidar com cliente {addr}:", e)

    finally:
        print(f"[-] {username} desconectado.")
        clients.pop(username, None)
        client_sock.close()