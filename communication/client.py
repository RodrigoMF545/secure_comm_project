import socket
import threading
import pickle
import hashlib
from multiprocessing import Process, Queue

from auth.user_auth import login_user, validate_password, validate_username
from crypto.diffie_hellman import perform_key_exchange
from crypto.rsa_utils import generate_rsa_keys, rsa_sign, rsa_verify
from crypto.aes import encrypt_message, decrypt_message
from cryptography.hazmat.primitives import serialization
from tabulate import tabulate
from communication.channel import simulate_channel, run_simulation_monitor

# Lista para armazenar dados de depuração
debug_data = []
simulation_queue = Queue()

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
    try:
        validate_username(username)
        validate_password(password)
        print(f"Credenciais de {username} validadas localmente.")
    except ValueError as e:
        raise ValueError(f"Validação falhou: {e}")

    auth_data = {"username": username, "password": password}
    print(f"Enviando credenciais: {auth_data}")
    serialized_auth_data = pickle.dumps(auth_data)
    sock.sendall(simulate_channel(serialized_auth_data, simulation_queue) or serialized_auth_data)

    print("Aguardando resposta do servidor...")
    response_data = sock.recv(4096)
    print(f"Dados brutos recebidos: {response_data.hex()}")
    simulated_response = simulate_channel(response_data, simulation_queue)
    if simulated_response is None:
        print("[!] Simulação: Usando dados originais devido a perda.")
        response = pickle.loads(response_data)  # Fallback para dados originais
    else:
        try:
            response = pickle.loads(simulated_response)  # Tentar deserializar os dados simulados
            print(f"Resposta deserializada: {response}")
        except Exception as e:
            print(f"[x] Erro ao deserializar simulated_response: {e}. Usando dados originais.")
            response = pickle.loads(response_data)  # Fallback se deserialização falhar
    print(f"Resposta processada: {response}")
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
    debug_data.append(["Server Public DH", response["server_public_key_dh"].decode()])
    debug_data.append(["Server Public RSA", response["server_public_key_rsa"].decode()])

    client_private_key_rsa, client_public_key_rsa = generate_rsa_keys()
    client_private_key_dh = dh_parameters.generate_private_key()
    client_public_key_dh = client_private_key_dh.public_key()
    client_public_rsa_pem = client_public_key_rsa.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    client_public_dh_pem = client_public_key_dh.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    debug_data.append(["Client Public RSA", client_public_rsa_pem])
    debug_data.append(["Client Public DH", client_public_dh_pem])
    # Nota: Chave privada não exibida por segurança

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
    serialized_client_data = pickle.dumps(client_data)
    sock.sendall(simulate_channel(serialized_client_data, simulation_queue) or serialized_client_data)

    shared_key = perform_key_exchange(client_private_key_dh, server_public_key_dh)
    debug_data.append(["Shared Key (Raw)", shared_key.hex()])
    derived_key = hashlib.sha256(shared_key).digest()
    debug_data.append(["AES Key (Derived)", derived_key.hex()])
    print(f"[✓] Autenticação e troca de chaves bem-sucedidas para {username}")
    return derived_key, server_public_key_rsa, client_private_key_rsa

def send_message(sock, message, key, private_key_rsa):
    """
    Envia uma mensagem criptografada com HMAC e assinatura
    """
    try:
        message_bytes = message.encode()
        signature = rsa_sign(private_key_rsa, message_bytes)
        encrypted = encrypt_message(key, message_bytes)
        nonce, ciphertext, hmac_value = encrypted
        debug_data.append(["Sent Message", message])
        debug_data.append(["Nonce", nonce.hex()])
        debug_data.append(["Ciphertext", ciphertext.hex()])
        debug_data.append(["HMAC Sent", hmac_value.hex()])
        debug_data.append(["Signature", signature.hex()])

        # Simular canal antes de enviar
        msg_to_send = {"nonce": nonce, "ciphertext": ciphertext, "hmac": hmac_value, "signature": signature}
        serialized_msg = pickle.dumps(msg_to_send)
        simulated_msg = simulate_channel(serialized_msg, simulation_queue)
        if simulated_msg is None:
            print("[!] Simulação: Mensagem perdida, não enviada.")
            return
        elif simulated_msg != serialized_msg:
            debug_data.append(["Simulated Message", simulated_msg.hex()])
        sock.sendall(simulated_msg if simulated_msg else serialized_msg)
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
                # Iniciar processo de monitor de simulação
                simulation_process = Process(target=run_simulation_monitor, args=(simulation_queue,))
                simulation_process.start()
                print("\n=== Tabela de Dados Gerados ===")
                print(tabulate(debug_data, headers=["Descrição", "Valor"], tablefmt="grid"))
                simulation_process.join()  # Aguardar o término do processo
                break
            # Simular canal ao receber
            simulated_data = simulate_channel(data, simulation_queue)
            if simulated_data is None:
                print("[!] Simulação: Dados perdidos no canal.")
                continue
            debug_data.append(["Received Raw Data", data.hex()])
            debug_data.append(["Simulated Received Data", simulated_data.hex()])
            msg_data = pickle.loads(simulated_data)
            nonce, ciphertext, hmac_value, signature, sender_public_key = (
                msg_data["nonce"], msg_data["ciphertext"], msg_data["hmac"],
                msg_data["signature"], msg_data["sender_public_key"]
            )
            message = decrypt_message(key, nonce, ciphertext, hmac_value)
            sender_public_key_obj = serialization.load_pem_public_key(sender_public_key)
            debug_data.append(["Received Nonce", nonce.hex()])
            debug_data.append(["Received Ciphertext", ciphertext.hex()])
            debug_data.append(["HMAC Received", hmac_value.hex()])
            debug_data.append(["Signature Received", signature.hex()])
            debug_data.append(["Sender Public Key", sender_public_key.decode()])
            if signature and not rsa_verify(sender_public_key_obj, signature, message):
                print("[x] Assinatura inválida recebida.")
                continue
            debug_data.append(["Decrypted Message", message.decode()])
            print(f"\n📨 {message.decode()}\n>> ", end="")
        except Exception as e:
            print("[x] Erro ao receber mensagem:", e)
            break