#!/usr/bin/env python3
"""
Script de inicialização do Chat P2P
Executa: python run.py
"""

import os
import sys
import subprocess

def check_requirements():
    """Verifica se as dependências estão instaladas"""
    try:
        import flask
        import flask_socketio
        import bcrypt
        import jwt
        print("✅ Todas as dependências estão instaladas!")
        return True
    except ImportError as e:
        print(f"❌ Dependência faltando: {e}")
        print("💡 Execute: pip install -r requirements.txt")
        return False

def main():
    print("🚀 Iniciando Chat P2P...")
    print("=" * 40)
    
    if not check_requirements():
        sys.exit(1)
    
    print("🌟 Servidor iniciando em http://localhost:5000")
    print("📱 Usuários de teste:")
    print("   - alice / 123456")
    print("   - bob / 123456")
    print("=" * 40)
    
    # Importa e executa a aplicação
    from app import app, socketio
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)

if __name__ == "__main__":
    main()