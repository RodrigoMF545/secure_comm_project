# debug_tools.py

def log_token(token, username):
    print(f"[DEBUG] Token JWT gerado para {username}:")
    print(token)
    print("----------------------------------------")

def log_ecdh_keys(username, private_key, public_bytes):
    print(f"[DEBUG] ECDH Keys para {username}:")
    print(f"Private Key: {private_key}")
    print(f"Public Key (hex): {public_bytes.hex()}")
    print("----------------------------------------")

def log_rsa_keys(username, private, public):
    print(f"[DEBUG] RSA Keys para {username}:")
    print(f"Private Key: {private.private_bytes_encoding}")
    print(f"Public Key PEM: {public.public_bytes_encoding}")
    print("----------------------------------------")

def log_aes_encryption(sender, recipient, encrypted_data):
    print(f"[DEBUG] Mensagem AES-GCM cifrada de {sender} -> {recipient}:")
    print(f"IV: {encrypted_data['iv']}")
    print(f"Tag: {encrypted_data['tag']}")
    print(f"Ciphertext: {encrypted_data['ciphertext']}")
    print("----------------------------------------")

def log_signature(sender, signature_hex):
    print(f"[DEBUG] Assinatura digital de {sender}: {signature_hex}")
    print("----------------------------------------")
