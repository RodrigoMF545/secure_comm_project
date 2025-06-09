import socket
import threading
import pickle
from auth.user_auth import login_user, validate_password, validate_username
from crypto.diffie_hellman import perform_key_exchange
from crypto.rsa_utils import generate_rsa_keys, rsa_sign, rsa_verify
from crypto.aes import encrypt_message, decrypt_message

def connect_to_server(host, port):
    """
    Conecta ao servidor
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock

def authenticate_and_exchange_keys(sock, username, password):
    """
    Autentica o usuário e realiza troca de chaves
    :return: tupla (shared_key, server_public_key_rsa, client_private_key_rsa)
    """
    # Validação local básica (opcional, para feedback)
    try:
        validate_username(username)
        validate_password(password)
        print(f"Credenciais de {username} validadas localmente.")
    except ValueError as e:
        raise ValueError(f"Validação falhou: {e}")

    # Envia credenciais
    auth_data = {"username": username, "password": password}
    sock.sendall(pickle.dumps(auth_data))

    # Recebe resposta de autenticação e parâmetros do servidor
    response = pickle.loads(sock.recv(4096))
    if response.get("status") == "error":
        raise ValueError(response["message"])

    # Gera chaves RSA e DH do cliente
    client_private_key_rsa, client_public_key_rsa = generate_rsa_keys()
    client_private_key_dh = response["dh_parameters"].generate_private_key()
    client_public_key_dh = client_private_key_dh.public_key()

    # Envia chaves públicas do cliente
    client_data = {
        "client_public_key_dh": client_public_key_dh,
        "client_public_key_rsa": client_public_key_rsa
    }
    sock.sendall(pickle.dumps(client_data))

    # Gera chave compartilhada
    shared_key = perform_key_exchange(client_private_key_dh, response["server_public_key_dh"])
    return shared_key, response["server_public_key_rsa"], client_private_key_rsa

def send_username(sock, username):
    """
    Placeholder para compatibilidade (substituído por autenticação)
    """
    pass

def send_message(sock, message, key, private_key_rsa):
    """
    Envia uma mensagem criptografada com HMAC e assinatura
    """
    try:
        message_bytes = message.encode()
        # Assina a mensagem
        signature = rsa_sign(private_key_rsa, message_bytes)
        # Criptografa a mensagem
        encrypted = encrypt_message(key, message_bytes)
        # Envia a mensagem com HMAC e assinatura
        sock.sendall(pickle.dumps({
            "nonce": encrypted[0], "ciphertext": encrypted[1],
            "hmac": encrypted[2], "signature": signature
        }))
    except Exception as e:
        print("[x] Erro no envio:", e)

def receive_messages(sock, key, server_public_key_rsa):
    """
    Recebe e processa mensagens do servidor
    """
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("[!] Conexão encerrada pelo servidor.")
                break
            msg_data = pickle.loads(data)
            nonce, ciphertext, hmac_value, signature = (
                msg_data["nonce"], msg_data["ciphertext"], msg_data["hmac"],
                msg_data["signature"]
            )
            # Verifica a assinatura (se presente)
            message = decrypt_message(key, nonce, ciphertext, hmac_value)
            if signature and not rsa_verify(server_public_key_rsa, signature, message):
                print("[x] Assinatura inválida recebida.")
                continue
            # Descriptografa a mensagem
            print(f"\n📨 {message.decode()}\n>> ", end="")
        except Exception as e:
            print("[x] Erro ao receber mensagem:", e)
            break