import sys
from communication.server import start_server, receive_message
from communication.client import connect_to_server, send_message

HOST = '127.0.0.1'
PORT = 65432

def run_server():
    conn = start_server(HOST, PORT)
    while True:
        msg = receive_message(conn)
        if msg is None:
            print(" Conexão encerrada pelo cliente.")
            break

def run_client():
    sock = connect_to_server(HOST, PORT)
    try:
        while True:
            msg = input("Digite a mensagem (ou 'sair' para encerrar): ")
            if msg.lower() == "sair":
                break
            send_message(sock, msg)
    except KeyboardInterrupt:
        print("\n Cliente encerrado.")

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("server", "client"):
        print("Uso: python main.py [server|client]")
    elif sys.argv[1] == "server":
        run_server()
    else:
        run_client()