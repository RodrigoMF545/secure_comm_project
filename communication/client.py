import socket
import threading
from crypto.aes import encrypt_message, decrypt_message

def connect_to_server(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock

def send_username(sock, username):
    sock.sendall(username.encode())

def send_message(sock, message, key):
    try:
        encrypted = encrypt_message(key, message)
        sock.sendall(encrypted)
    except Exception as e:
        print("[x] Erro no envio:", e)

def receive_messages(sock, key):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("[!] Conexão encerrada pelo servidor.")
                break
            decrypted = decrypt_message(key, data)
            print(f"\n📨 {decrypted}\n>> ", end="")
        except Exception as e:
            print("[x] Erro ao receber mensagem:", e)
            break
