import socket

def connect_to_server(host, port):
    """
    Conecta ao servidor para envio de mensagens criptografadas
    :param host: endereço do servidor
    :param port: porta do servidor
    :return: objeto de socket
    """
    # TODO: implementar conexão ao servidor

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host,port))
        print(f" Conectado ao servidor em {host} : {port}")
        return sock
    except ConnectionRefusedError:
        print("Erro: Não foi possível conectar ao servidor.")
        return None
    

def send_message(sock, message):
    """
    Envia uma mensagem criptografada ao servidor
    :param sock: socket de conexão
    :param message: mensagem a ser enviada
    """
    # TODO: implementar envio de mensagem
    
    if not sock:
        print("Erro: conexão inválida")

    try:
        sock.sendall(message.encode())
        print(f" Enviado: message")
        data = sock.recv(1024)
        print(f"Resposta: {data.decode()}") 
    except Exception as e:
        print(f"[x] Erro no envio: {e}")
    finally:
        sock.close()