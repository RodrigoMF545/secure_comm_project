import socket
import threading
import pickle
import hashlib
from multiprocessing import Process, Queue
from auth.user_auth import login_user
from crypto.diffie_hellman import generate_diffie_hellman_parameters, perform_key_exchange
from crypto.rsa_utils import generate_rsa_keys, rsa_verify, rsa_sign
from crypto.aes import encrypt_message, decrypt_message
from cryptography.hazmat.primitives import serialization
from tabulate import tabulate
from communication.channel import simulate_channel, run_simulation_monitor

# Declaração global do dicionário clients
clients = {}  # username -> (socket, public_key_rsa, shared_key)

# Lista para armazenar dados de depuração por cliente
client_debug_data = {}
simulation_queue = Queue()

def start_server(host, port):
    """
    Inicia o servidor e retorna o socket
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen()
    print(f"[✓] Servidor iniciado na porta {port} e aguardando conexões...")
    return server_sock

def handle_client(client_sock, addr):
    """
    Gerencia a conexão com um cliente, incluindo autenticação e troca de chaves
    """
    global clients  # Garantir acesso ao dicionário global
    username = None
    debug_data = []
    try:
        print(f"Recebendo dados de {addr}")
        data = client_sock.recv(4096)
        # Simular canal ao receber
        simulated_data = simulate_channel(data, simulation_queue)
        if simulated_data is None:
            print("[!] Simulação: Usando dados originais devido a perda.")
            simulated_data = data
        debug_data.append(["Received Raw Data", data.hex()])
        debug_data.append(["Simulated Received Data", simulated_data.hex()])
        auth_data = pickle.loads(simulated_data)
        username, password = auth_data["username"], auth_data["password"]
        print(f"Tentando autenticar {username} com senha fornecida: {password}")
        if not login_user(username, password):
            print(f"Autenticação falhou para {username}. Verificando banco de dados: {get_user(username)}")
            error_response = pickle.dumps({"status": "error", "message": "Autenticação falhou"})
            client_sock.sendall(simulate_channel(error_response, simulation_queue) or error_response)
            client_sock.close()
            return

        dh_parameters = generate_diffie_hellman_parameters()
        server_private_key_rsa, server_public_key_rsa = generate_rsa_keys()
        server_private_key_dh = dh_parameters.generate_private_key()
        server_public_key_dh = server_private_key_dh.public_key()
        server_public_rsa_pem = server_public_key_rsa.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        server_public_dh_pem = server_public_key_dh.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        debug_data.append(["Server Public RSA", server_public_rsa_pem])
        debug_data.append(["Server Public DH", server_public_dh_pem])

        dh_params_bytes = dh_parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        server_public_dh_bytes = server_public_key_dh.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        server_public_rsa_bytes = server_public_key_rsa.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        server_data = {
            "dh_parameters": dh_params_bytes,
            "server_public_key_dh": server_public_dh_bytes,
            "server_public_key_rsa": server_public_rsa_bytes
        }
        print(f"Enviando ao cliente: {server_data}")
        # Simular canal antes de enviar
        serialized_server_data = pickle.dumps(server_data)
        simulated_server_data = simulate_channel(serialized_server_data, simulation_queue)
        if simulated_server_data is None:
            print("[!] Simulação: Usando dados originais devido a perda.")
            simulated_server_data = serialized_server_data
        client_sock.sendall(simulated_server_data)

        data = client_sock.recv(4096)
        simulated_data = simulate_channel(data, simulation_queue)
        if simulated_data is None:
            print("[!] Simulação: Usando dados originais devido a perda.")
            simulated_data = data
        debug_data.append(["Received Raw Client Data", data.hex()])
        debug_data.append(["Simulated Client Data", simulated_data.hex()])
        client_data = pickle.loads(simulated_data)
        client_public_key_dh = serialization.load_pem_public_key(
            client_data["client_public_key_dh"]
        )
        client_public_key_rsa = serialization.load_pem_public_key(
            client_data["client_public_key_rsa"]
        )
        debug_data.append(["Client Public DH", client_data["client_public_key_dh"].decode()])
        debug_data.append(["Client Public RSA", client_data["client_public_key_rsa"].decode()])

        shared_key = perform_key_exchange(server_private_key_dh, client_public_key_dh)
        debug_data.append(["Shared Key (Raw)", shared_key.hex()])
        derived_key = hashlib.sha256(shared_key).digest()
        debug_data.append(["AES Key (Derived)", derived_key.hex()])

        clients[username] = (client_sock, client_public_key_rsa, derived_key)
        client_debug_data[username] = debug_data
        print(f"[+] {username} conectado de {addr}")

        while True:
            data = client_sock.recv(4096)
            if not data:
                break
            print(f"Dados recebidos de {username}: {data}")
            try:
                simulated_data = simulate_channel(data, simulation_queue)
                if simulated_data is None:
                    print("[!] Simulação: Usando dados originais devido a perda.")
                    simulated_data = data
                debug_data.append(["Received Raw Message Data", data.hex()])
                debug_data.append(["Simulated Message Data", simulated_data.hex()])
                msg_data = pickle.loads(simulated_data)
                nonce, ciphertext, hmac_value, signature = (
                    msg_data["nonce"], msg_data["ciphertext"], msg_data["hmac"],
                    msg_data["signature"]
                )
                sender_sock, sender_public_key, sender_shared_key = clients[username]
                message = decrypt_message(sender_shared_key, nonce, ciphertext, hmac_value)
                debug_data.append(["Received Nonce", nonce.hex()])
                debug_data.append(["Received Ciphertext", ciphertext.hex()])
                debug_data.append(["HMAC Received", hmac_value.hex()])
                debug_data.append(["Signature Received", signature.hex()])
                debug_data.append(["Decrypted Message", message.decode()])

                if not rsa_verify(sender_public_key, signature, message):
                    error_msg = encrypt_message(sender_shared_key, "Servidor: Assinatura inválida".encode('utf-8'))
                    serialized_error = pickle.dumps({
                        "nonce": error_msg[0], "ciphertext": error_msg[1],
                        "hmac": error_msg[2], "signature": b""
                    })
                    sender_sock.sendall(simulate_channel(serialized_error, simulation_queue) or serialized_error)
                    continue

                message_str = message.decode()
                if ':' in message_str:
                    recipient, content = message_str.split(':', 1)
                    if recipient in clients:
                        recipient_sock, recipient_public_key, recipient_shared_key = clients[recipient]
                        sender_public_key_bytes = sender_public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        server_signature = rsa_sign(server_private_key_rsa, message)
                        encrypted = encrypt_message(recipient_shared_key, message)
                        debug_data.append(["Sent Nonce to Recipient", encrypted[0].hex()])
                        debug_data.append(["Sent Ciphertext to Recipient", encrypted[1].hex()])
                        debug_data.append(["Sent HMAC to Recipient", encrypted[2].hex()])
                        debug_data.append(["Server Signature", server_signature.hex()])
                        # Simular canal antes de enviar ao destinatário
                        msg_to_send = {
                            "nonce": encrypted[0], "ciphertext": encrypted[1],
                            "hmac": encrypted[2], "signature": signature,
                            "sender_public_key": sender_public_key_bytes
                        }
                        serialized_msg = pickle.dumps(msg_to_send)
                        simulated_msg = simulate_channel(serialized_msg, simulation_queue)
                        if simulated_msg is None:
                            print("[!] Simulação: Mensagem perdida para destinatário.")
                            continue
                        recipient_sock.sendall(simulated_msg)
                    else:
                        error_msg = encrypt_message(sender_shared_key, f"Servidor: Usuário '{recipient}' não encontrado.".encode('utf-8'))
                        serialized_error = pickle.dumps({
                            "nonce": error_msg[0], "ciphertext": error_msg[1],
                            "hmac": error_msg[2], "signature": b""
                        })
                        sender_sock.sendall(simulate_channel(serialized_error, simulation_queue) or serialized_error)
                else:
                    warning = encrypt_message(sender_shared_key, "Servidor: Formato inválido. Use destinatario:mensagem".encode('utf-8'))
                    serialized_warning = pickle.dumps({
                        "nonce": warning[0], "ciphertext": warning[1],
                        "hmac": warning[2], "signature": b""
                    })
                    sender_sock.sendall(simulate_channel(serialized_warning, simulation_queue) or serialized_warning)

            except Exception as e:
                print(f"[x] Erro ao processar mensagem de {username}: {e}")
                break

    except Exception as e:
        print(f"[x] Erro ao lidar com cliente {addr}: {e}")

    finally:
        print(f"[-] {username} desconectado.")
        if username:
            print("\n=== Tabela de Dados Gerados para", username, "===")
            print(tabulate(client_debug_data.get(username, []), headers=["Descrição", "Valor"], tablefmt="grid"))
        clients.pop(username, None)
        client_sock.close()

def get_user(username):
    """
    Função temporária para depuração, assumindo que está em storage.py
    """
    from auth.storage import users_db
    return users_db.get(username)