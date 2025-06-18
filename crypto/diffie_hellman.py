# crypto/diffie_hellman.py
# crypto/diffie_hellman.py

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def generate_private_key():
    return ec.generate_private_key(ec.SECP256R1(), default_backend())

def get_public_bytes(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def compute_shared_key(private_key, peer_public_key_bytes):
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        peer_public_key_bytes
    )
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)
    
    return derived_key
