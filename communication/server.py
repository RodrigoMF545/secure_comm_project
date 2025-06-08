import socket

def start_server(host, port):
    """
    Inicia o servidor para receber mensagens criptografadas
    :param host: endereço do servidor
    :param port: porta do servidor
    :return: objeto de socket do servidor
    """
    # TODO: implementar inicialização do servidor
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Servidor escutando em {host}:{port}...")

    conn, addr = server_socket.accept()
    print(f"Conexão aceita de {addr}")
    return conn  # retorna o socket da conexão com o cliente


def receive_message(sock):
    """
    Recebe e decifra uma mensagem enviada por um cliente
    :param sock: socket de conexão com o cliente
    :return: mensagem recebida
    """
    # TODO: implementar recebimento de mensagem
    data = sock.recv(1024)
    if not data:
        return None
    message = data.decode()  # futuramente aqui será a decifragem
    print(f" Mensagem recebida: {message}")
    return message