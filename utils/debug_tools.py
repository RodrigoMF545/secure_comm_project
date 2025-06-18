# utils/debug_tools.py

import binascii
from termcolor import colored

# Pretty print de token JWT
def debug_jwt(token):
    print(colored("[DEBUG JWT] Token recebido:", "cyan"))
    print(token)
    print("-" * 80)

# Pretty print de AES
def debug_aes(iv, tag, ciphertext):
    print(colored("[DEBUG AES] Mensagem cifrada", "magenta"))
    print(f"IV         : {binascii.hexlify(iv).decode()}")
    print(f"TAG        : {binascii.hexlify(tag).decode()}")
    print(f"CIPHERTEXT : {binascii.hexlify(ciphertext).decode()}")
    print("-" * 80)

# Pretty print de ECDH
def debug_ecdh(username, peer_user, shared_key):
    print(colored("[DEBUG ECDH] Chave compartilhada ECDH", "green"))
    print(f"{username} -> {peer_user} : {binascii.hexlify(shared_key).decode()}")
    print("-" * 80)

# Pretty print de RSA
def debug_rsa(sender, signature, message, valid=True):
    status = "VALIDA ✅" if valid else "INVALIDA ❌"
    color = "blue" if valid else "red"
    print(colored(f"[DEBUG RSA] Assinatura Digital ({status})", color))
    print(f"Sender    : {sender}")
    print(f"Message   : {message}")
    print(f"Signature : {binascii.hexlify(signature).decode()}")
    print("-" * 80)
