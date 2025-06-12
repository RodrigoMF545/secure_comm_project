import time
from multiprocessing import Pool, cpu_count
from password_hashing import verify_password
from storage import users_db

# ==================== CONFIG ====================
USERNAME = "alice"
HASHED_PASSWORD = users_db[USERNAME]["hashed_password"]
WORDLIST_PATH = "rockyou.txt"
MIN_PASSWORD_LENGTH = 8

# Número máximo de senhas testadas por processo antes de imprimir progresso
PRINT_EVERY = 500

# ================ LOAD WORDLIST ================
def load_filtered_wordlist(path):
    with open(path, encoding="latin-1") as f:
        return [line.strip() for line in f if len(line.strip()) >= MIN_PASSWORD_LENGTH]

# ============== ATTACK FUNCTION ===============
def attempt_password(password):
    global attempts
    success = verify_password(password, HASHED_PASSWORD)
    return password if success else None

# ============== MULTI-PROCESS ================
def crack_password(wordlist):
    print(f"[+] Iniciando ataque com {len(wordlist)} senhas usando {cpu_count()} processos...")
    start = time.time()
    
    found_password = None
    with Pool() as pool:
        for i, result in enumerate(pool.imap_unordered(attempt_password, wordlist), 1):
            if i % PRINT_EVERY == 0:
                elapsed = time.time() - start
                print(f"[*] Tentativas: {i} | Tempo: {elapsed:.2f}s | Média: {elapsed / i:.4f}s/tentativa")
            if result:
                found_password = result
                pool.terminate()  # Para todos os processos imediatamente
                break

    total_time = time.time() - start
    if found_password:
        print(f"[+] Senha encontrada: '{found_password}' em {total_time:.2f}s")
    else:
        print("[-] Senha não encontrada na wordlist.")

# ============== MAIN ====================
if __name__ == "__main__":
    try:
        wordlist = load_filtered_wordlist(WORDLIST_PATH)
        crack_password(wordlist)
    except FileNotFoundError:
        print(f"[!] Wordlist '{WORDLIST_PATH}' não encontrada.")
    except Exception as e:
        print(f"[!] Erro: {e}")
