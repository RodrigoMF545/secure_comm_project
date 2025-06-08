import socket
import threading
from crypto.aes import decrypt_message, encrypt_message

clients = {}  # nome_usuario -> socket

def start_server(host, port):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen()
    return server_sock

def handle_client(client_sock, addr, key):
    try:
        username = client_sock.recv(1024).decode()
        clients[username] = client_sock
        print(f"[+] {username} conectado de {addr}")

        while True:
            data = client_sock.recv(4096)
            if not data:
                break

            try:
                message = decrypt_message(key, data)
                if ':' in message:
                    recipient, content = message.split(':', 1)
                    if recipient in clients:
                        encrypted = encrypt_message(key, f"{username}: {content}")
                        clients[recipient].sendall(encrypted)
                    else:
                        error_msg = encrypt_message(key, f"Servidor: Usuário '{recipient}' não encontrado.")
                        client_sock.sendall(error_msg)
                else:
                    warning = encrypt_message(key, "Servidor: Formato inválido. Use destinatario:mensagem")
                    client_sock.sendall(warning)

            except Exception as e:
                print(f"[x] Erro ao processar mensagem de {username}:", e)
                break

    except Exception as e:
        print(f"[x] Erro ao lidar com cliente {addr}:", e)

    finally:
        print(f"[-] {username} desconectado.")
        clients.pop(username, None)
        client_sock.close()
