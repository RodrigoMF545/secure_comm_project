# Sistema Seguro de Comunicação

Este projeto implementa um sistema seguro de comunicação ponto-a-ponto utilizando criptografia simétrica e assimétrica, autenticação HMAC, troca de chaves com Diffie-Hellman e armazenamento seguro de senhas.

## Funcionalidades:

- Criptografia AES para envio de mensagens seguras
- HMAC para garantir integridade e autenticidade
- Assinaturas digitais com RSA
- Armazenamento seguro de senhas utilizando bcrypt
- Simulação de ataques como MITM e brute-force

## Como rodar:

1. Instalar as dependências: `pip install cryptography pytest`
2. Rodar o servidor: `python server.py`
3. Rodar o cliente: `python client.py`

## 📦 Dependências

Este projeto requer as seguintes bibliotecas:

- `cryptography`: Para criar e verificar certificados digitais, manipulação de chaves e criptografia assimétrica.
- `pycryptodome`: Para realizar criptografia simétrica (AES) e HMAC.
- `bcrypt`: Para armazenar senhas de forma segura com hashing.
- `hashlib`: Para algoritmos de hash.

## 🔧 Instalação

Siga os passos abaixo para configurar o ambiente de desenvolvimento:

### 1. **Clone o repositório**
```bash
git clone https://github.com/RodrigoMF545/secure_comm_project.git
cd secure_comm_project
