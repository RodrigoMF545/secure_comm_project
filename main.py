
import sys
import threading
from communication.client import connect_to_server, authenticate_and_exchange_keys, send_message, receive_messages
from communication.server import start_server, handle_client

HOST = "127.0.0.1"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python main.py [server|client]")
        sys.exit(1)

    role = sys.argv[1].lower()

    if role == "server":
        print(f"[+] Servidor escutando em {HOST}:12346")
        start_server(HOST, 12346)
    elif role == "client":
        sock = connect_to_server(HOST, 12345)  # Alterado para 12345 para testes com MITM
        username = input("Digite o nome de usuário: ")
        password = input("Digite a senha: ")
        try:
            shared_key, server_public_key_rsa, client_private_key_rsa = authenticate_and_exchange_keys(sock, username, password)
            print("[+] Conectado! Envie mensagens no formato: destinatário:mensagem")
            threading.Thread(target=receive_messages, args=(sock, shared_key, server_public_key_rsa), daemon=True).start()
            while True:
                message = input("Digite a mensagem (formato: destinatário:mensagem) ou 'sair' para sair: ")
                if message.lower() == "sair":
                    break
                send_message(sock, message, shared_key, client_private_key_rsa)
        except ValueError as e:
            print(f"[x] Erro: {e}")
        finally:
            sock.close()
    else:
        print("Role inválida. Use 'server' ou 'client'.")