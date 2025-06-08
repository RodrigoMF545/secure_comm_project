import sys
import threading
from communication.client import connect_to_server, send_username, send_message, receive_messages
from communication.server import start_server, handle_client
from crypto.aes import generate_key

HOST = "127.0.0.1"
PORT = 65432
SHARED_KEY = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python main.py [server|client]")
        sys.exit(1)

    role = sys.argv[1]

    if role == "server":
        server_socket = start_server(HOST, PORT)
        print("[✓] Servidor iniciado e aguardando conexões...")

        while True:
            client_sock, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_sock, addr, SHARED_KEY), daemon=True).start()

    elif role == "client":
        sock = connect_to_server(HOST, PORT)
        username = input("Seu nome de usuário: ")
        send_username(sock, username)

        print(f">> Conectado como {username}. Envie mensagens no formato destinatario:mensagem")

        threading.Thread(target=receive_messages, args=(sock, SHARED_KEY), daemon=True).start()

        while True:
            msg = input(">> ")
            if msg.lower() == "sair":
                break
            send_message(sock, msg, SHARED_KEY)

        sock.close()

