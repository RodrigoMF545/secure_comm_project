# 💬 Sistema de Chat Ponta-a-Ponta

Um sistema simples de comunicação em tempo real desenvolvido em Python usando Flask e Socket.IO.

## 🚀 Funcionalidades

- ✅ Autenticação de usuários (registro e login)
- ✅ Comunicação em tempo real
- ✅ Interface web moderna e responsiva
- ✅ Histórico de mensagens
- ✅ Status online/offline dos usuários
- ✅ Criptografia de senhas com bcrypt
- ✅ Autenticação JWT

## 📁 Estrutura do Projeto

```
chat-p2p/
├── app.py              # Aplicação principal Flask
├── requirements.txt    # Dependências Python
├── README.md          # Este arquivo
└── templates/         # Templates HTML
    ├── login.html     # Página de login/registro
    └── chat.html      # Interface do chat
```

## 🛠️ Instalação e Configuração

### 1. Clone ou baixe o projeto

### 2. Instale as dependências

```bash
pip install -r requirements.txt
```

### 3. Execute a aplicação

```bash
python app.py
```

### 4. Acesse no navegador

Abra seu navegador e vá para: `http://localhost:5000`

## 👥 Usuários de Teste

O sistema já vem com dois usuários pré-cadastrados para teste:

- **Usuário:** `alice` - **Senha:** `123456`
- **Usuário:** `bob` - **Senha:** `123456`

## 🔐 Como Usar

### Login/Registro

1. Acesse `http://localhost:5000`
2. Use os usuários de teste ou crie uma nova conta
3. Clique em "Entrar" ou "Registrar"

### Chat

1. Após o login, você verá a interface do chat
2. Na barra lateral esquerda, você verá os usuários online
3. Clique em um usuário para iniciar uma conversa
4. Digite sua mensagem e pressione Enter ou clique em "Enviar"

### Recursos do Chat

- **Status Online:** Veja quem está online (ponto verde) ou offline (ponto cinza)
- **Histórico:** Todas as mensagens são salvas e carregadas automaticamente
- **Tempo Real:** Mensagens são entregues instantaneamente
- **Responsivo:** Funciona bem em desktop e mobile

## 🔧 Tecnologias Utilizadas

- **Backend:** Python, Flask, Flask-SocketIO
- **Frontend:** HTML5, CSS3, JavaScript, Socket.IO
- **Autenticação:** JWT (JSON Web Tokens)
- **Criptografia:** bcrypt para senhas
- **Comunicação:** WebSockets para tempo real

## 📱 Testando a Comunicação

Para testar a comunicação ponta-a-ponta:

1. Abra duas abas do navegador (ou dois navegadores diferentes)
2. Faça login com `alice` em uma aba
3. Faça login com `bob` na outra aba
4. Na aba da Alice, clique em "bob" na lista de usuários
5. Na aba do Bob, clique em "alice" na lista de usuários
6. Envie mensagens entre os dois usuários

## 🎨 Personalização

### Modificar a Chave Secreta

No arquivo `app.py`, linha 12:

```python
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'
```

### Adicionar Novos Usuários

Você pode criar novos usuários através da interface de registro ou adicioná-los diretamente no código.

### Modificar Estilos

Os estilos CSS estão incorporados nos arquivos HTML. Você pode modificá-los diretamente nos templates.

## 🚨 Notas Importantes

- Este é um sistema de demonstração e não deve ser usado em produção sem melhorias de segurança
- As mensagens são armazenadas em memória e serão perdidas quando o servidor for reiniciado
- Para produção, considere usar um banco de dados real (PostgreSQL, MongoDB, etc.)
- Implemente HTTPS para comunicação segura em produção

## 🔒 Segurança

- Senhas são criptografadas com bcrypt
- Autenticação via JWT tokens
- Validação de entrada nos endpoints da API
- Separação de responsabilidades entre frontend e backend

## 🐛 Solução de Problemas

### Erro de Dependências

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Porta já em uso

Modifique a porta no final do arquivo `app.py`:

```python
socketio.run(app, debug=True, host='0.0.0.0', port=5001)
```

### Problemas de Conexão

Verifique se o firewall não está bloqueando a porta 5000.

## 📄 Licença

Este projeto é livre para uso educacional e de demonstração.

---

Desenvolvido com ❤️ em Python
