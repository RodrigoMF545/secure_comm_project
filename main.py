import sys
import threading
from communication.client import connect_to_server, authenticate_and_exchange_keys, send_message, receive_messages
from communication.server import start_server, handle_client

HOST = "127.0.0.1"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python main.py [server|client]")
        sys.exit(1)

    role = sys.argv[1]

    if role == "server":
        server_socket = start_server(HOST, 12346)
        print("[✓] Servidor iniciado e aguardando conexões...")

        while True:
            client_sock, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()

    elif role == "client":
        sock = connect_to_server(HOST, 12345)
        username = input("Seu nome de usuário: ")
        password = input("Sua senha: ")
        try:
            shared_key, server_public_key_rsa, client_private_key_rsa = authenticate_and_exchange_keys(sock, username, password)
        except ValueError as e:
            print(f"[x] Erro: {e}")
            sock.close()
            sys.exit(1)

        print(f">> Conectado como {username}. Envie mensagens no formato destinatario:mensagem")

        threading.Thread(target=receive_messages, args=(sock, shared_key, server_public_key_rsa), daemon=True).start()

        while True:
            msg = input(">> ")
            if msg.lower() == "sair":
                break
            send_message(sock, msg, shared_key, client_private_key_rsa)

        sock.close()