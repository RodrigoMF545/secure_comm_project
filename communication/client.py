import hashlib
import socket
import threading
import pickle
import struct

from cryptography.hazmat.primitives import serialization

from auth.user_auth import login_user, validate_username, validate_password
from crypto.diffie_hellman import generate_diffie_hellman_parameters, perform_key_exchange
from crypto.rsa_utils import generate_rsa_keys, rsa_verify, rsa_sign
from crypto.aes import encrypt_message, decrypt_message

# --- Utilitários seguros de envio/recebimento com framing ---

def send_pickle(sock, obj):
    data = pickle.dumps(obj)
    length = struct.pack('!I', len(data))  # 4 bytes big-endian
    sock.sendall(length + data)

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Conexão encerrada inesperadamente.")
        data += packet
    return data

def recv_pickle(sock):
    raw_length = recv_exact(sock, 4)
    length = struct.unpack('!I', raw_length)[0]
    data = recv_exact(sock, length)
    return pickle.loads(data)

# --- Comunicação principal ---

def connect_to_server(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock

def authenticate_and_exchange_keys(sock, username, password):
    try:
        validate_username(username)
        validate_password(password)
        print(f"Credenciais de {username} validadas localmente.")
    except ValueError as e:
        raise ValueError(f"Validação falhou: {e}")

    auth_data = {"username": username, "password": password}
    print(f"Enviando credenciais: {auth_data}")
    send_pickle(sock, auth_data)

    print("Aguardando resposta do servidor...")
    response = recv_pickle(sock)
    print(f"Resposta recebida do servidor: {response}")

    if response.get("status") == "error":
        error_msg = response.get("message", "Autenticação falhou")
        print(f"[x] Erro de autenticação: {error_msg}")
        raise ValueError(error_msg)

    required_keys = ["dh_parameters", "server_public_key_dh", "server_public_key_rsa"]
    if not all(key in response for key in required_keys):
        missing_keys = [key for key in required_keys if key not in response]
        raise ValueError(f"Resposta do servidor incompleta. Chaves ausentes: {missing_keys}")

    # Importar os parâmetros e chaves do servidor
    dh_parameters = serialization.load_pem_parameters(response["dh_parameters"])
    server_public_key_dh = serialization.load_pem_public_key(response["server_public_key_dh"])
    server_public_key_rsa = serialization.load_pem_public_key(response["server_public_key_rsa"])

    client_private_key_rsa, client_public_key_rsa = generate_rsa_keys()
    client_private_key_dh = dh_parameters.generate_private_key()
    client_public_key_dh = client_private_key_dh.public_key()

    client_data = {
        "client_public_key_dh": client_public_key_dh.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        "client_public_key_rsa": client_public_key_rsa.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    }
    send_pickle(sock, client_data)

    shared_key = perform_key_exchange(client_private_key_dh, server_public_key_dh)
    derived_key = hashlib.sha256(shared_key).digest()

    print(f"[✓] Autenticação e troca de chaves bem-sucedidas para {username}")
    return derived_key, server_public_key_rsa, client_private_key_rsa

def send_message(sock, message, key, private_key_rsa):
    try:
        message_bytes = message.encode()
        signature = rsa_sign(private_key_rsa, message_bytes)
        encrypted = encrypt_message(key, message_bytes)
        send_pickle(sock, {
            "nonce": encrypted[0],
            "ciphertext": encrypted[1],
            "hmac": encrypted[2],
            "signature": signature
        })
    except Exception as e:
        print("[x] Erro no envio:", e)

def receive_messages(sock, key, server_public_key_rsa):
    while True:
        try:
            msg_data = recv_pickle(sock)
            nonce, ciphertext, hmac_value, signature, sender_public_key = (
                msg_data["nonce"], msg_data["ciphertext"], msg_data["hmac"],
                msg_data["signature"], msg_data["sender_public_key"]
            )
            message = decrypt_message(key, nonce, ciphertext, hmac_value)
            sender_public_key_obj = serialization.load_pem_public_key(sender_public_key)
            if signature and not rsa_verify(sender_public_key_obj, signature, message):
                print("[x] Assinatura inválida recebida.")
                continue
            print(f"\n📨 {message.decode()}\n>> ", end="")
        except Exception as e:
            print("[x] Erro ao receber mensagem:", e)
