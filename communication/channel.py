import random
import hashlib
import pickle
from multiprocessing import Process, Queue

def simulate_channel(message, simulation_queue=None):
    """
    Função para simular o canal de comunicação, incluindo possíveis interferências ou ataques
    :param message: mensagem a ser enviada (bytes ou dict contendo nonce, ciphertext, hmac, signature)
    :param simulation_queue: fila para enviar logs de simulação
    :return: mensagem possivelmente alterada (bytes ou dict)
    """
    # Convertendo mensagem para bytes se for dicionário
    if isinstance(message, dict):
        original_data = pickle.dumps(message)
    else:
        original_data = message

    # Probabilidades de eventos (valores ajustáveis)
    corruption_chance = 0.1  # 10% de chance de corrupção
    interception_chance = 0.05  # 5% de chance de interceptação
    loss_chance = 0.03  # 3% de chance de perda

    # Simulação de perda (descartar mensagem)
    if random.random() < loss_chance:
        log_msg = f"[!] Simulação: Mensagem perdida no canal. Original: {original_data.hex()}"
        if simulation_queue:
            simulation_queue.put(log_msg)
        print(log_msg)
        return None

    # Simulação de interceptação (substituir por mensagem falsa)
    if random.random() < interception_chance:
        fake_message = b"FALSA_MENSAGEM_INTERCEPTADA_" + hashlib.sha256(str(random.random()).encode()).digest()[:16]
        log_msg = f"[!] Simulação: Mensagem interceptada. Original: {original_data.hex()} Substituída por: {fake_message.hex()}"
        if simulation_queue:
            simulation_queue.put(log_msg)
        print(log_msg)
        if isinstance(message, dict):
            return pickle.loads(pickle.dumps({"nonce": fake_message[:16], "ciphertext": fake_message[16:], "hmac": b"", "signature": b""}))
        return fake_message

    # Simulação de corrupção (alterar alguns bits aleatoriamente)
    if random.random() < corruption_chance:
        data_bytes = bytearray(original_data)
        num_bits_to_corrupt = min(5, len(data_bytes))  # Corromper até 5 bytes
        for _ in range(num_bits_to_corrupt):
            if data_bytes:
                idx = random.randint(0, len(data_bytes) - 1)
                data_bytes[idx] = data_bytes[idx] ^ random.randint(0, 255)  # XOR com valor aleatório
        corrupted_message = bytes(data_bytes)
        log_msg = f"[!] Simulação: Mensagem corrompida. Original: {original_data.hex()} Corrompida: {corrupted_message.hex()}"
        if simulation_queue:
            simulation_queue.put(log_msg)
        print(log_msg)
        if isinstance(message, dict):
            try:
                return pickle.loads(corrupted_message)
            except Exception:
                log_msg = "[!] Simulação: Mensagem corrompida inviável para deserialização."
                if simulation_queue:
                    simulation_queue.put(log_msg)
                print(log_msg)
                return None
        return corrupted_message

    # Canal sem interferência
    log_msg = f"[✓] Simulação: Mensagem transmitida sem interferência. Original: {original_data.hex()}"
    if simulation_queue:
        simulation_queue.put(log_msg)
    print(log_msg)
    return original_data

def run_simulation_monitor(simulation_queue):
    """
    Processo separado para monitorar e exibir logs de simulação
    """
    print("=== Monitor de Simulação Iniciado ===")
    while True:
        try:
            log = simulation_queue.get(timeout=1)  # Timeout para evitar travamento
            print(log)
        except:
            break  # Encerra quando a fila estiver vazia e o programa terminar