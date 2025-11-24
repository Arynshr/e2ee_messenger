import os
import json
import time
import blake3
from typing import Tuple, Optional
from nacl.public import PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.utils import random
from nacl.bindings import crypto_kx_client_session_keys, crypto_kx_server_session_keys

"""
Crypto primitives: X25519 key agreement, XSalsa20-Poly1305 AEAD, BLAKE3 hashing, chained E2EE logging.
"""

class Identity:
    """X25519 keypair for identity and key exchange."""
    def __init__(self, sk: PrivateKey, pk: PublicKey):
        self.sk = sk
        self.pk = pk

    @classmethod
    def generate(cls) -> 'Identity':
        sk = PrivateKey.generate()  # X25519
        return cls(sk, sk.public_key)

    @classmethod
    def load(cls, path: str) -> 'Identity':
        with open(path, 'r') as f:
            data = json.load(f)
        sk = PrivateKey(bytes.fromhex(data['sk_x']))
        pk = PublicKey(bytes.fromhex(data['pk_x']))
        return cls(sk, pk)

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump({
                'sk_x': self.sk.encode().hex(),
                'pk_x': self.pk.encode().hex()
            }, f)

    def derive_log_key(self) -> bytes:
        """BLAKE2b-derived key for log encryption (from private key)."""
        import hashlib
        # Use standard hashlib for consistent 32-byte output
        return hashlib.blake2b(self.sk.encode(), digest_size=32).digest()


def key_exchange(client_sk: PrivateKey, client_pk: PublicKey, server_pk: PublicKey) -> Tuple[bytes, bytes]:
    """Client-side X25519 key exchange (Noise-like). Returns (tx, rx)."""
    return crypto_kx_client_session_keys(client_sk.encode(), client_pk.encode(), server_pk.encode())

def key_exchange_server(server_sk: PrivateKey, server_pk: PublicKey, client_pk: PublicKey) -> Tuple[bytes, bytes]:
    """Server-side (for peer)."""
    return crypto_kx_server_session_keys(server_sk.encode(), server_pk.encode(), client_pk.encode())


def encrypt(box_key: bytes, plaintext: bytes) -> bytes:
    """AEAD encrypt with XSalsa20-Poly1305."""
    box = SecretBox(box_key)
    nonce = random(SecretBox.NONCE_SIZE)
    ciphertext = box.encrypt(plaintext, nonce)
    return nonce + ciphertext

def decrypt(box_key: bytes, ciphertext: bytes) -> Optional[bytes]:
    """AEAD decrypt; None on failure (tamper/leak)."""
    if len(ciphertext) < SecretBox.NONCE_SIZE:
        return None
    box = SecretBox(box_key)
    nonce = ciphertext[:SecretBox.NONCE_SIZE]
    ct = ciphertext[SecretBox.NONCE_SIZE:]
    try:
        return box.decrypt(ct, nonce)
    except:
        return None


def hash_message(msg: bytes, prev_hash: Optional[bytes] = None) -> bytes:
    """BLAKE3 hash; chain with prev for tamper-proof logs."""
    hasher = blake3.blake3()
    if prev_hash:
        hasher.update(prev_hash)
    hasher.update(msg)
    return hasher.digest()  # 32 bytes


class SecureLogger:
    """Chained, E2EE audit log."""
    def __init__(self, identity: Identity, path: str):
        self.path = path
        self.box = SecretBox(identity.derive_log_key())
        self.prev_hash = b'\x00' * 32  # Genesis
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def log_entry(self, direction: str, peer_pk: bytes, msg: bytes, sent_hash: bytes):
        """Log: timestamp, dir, peer, msg, hash, prev_hash. Chain via BLAKE3."""
        entry = {
            't': time.time(),
            'dir': direction,  
            'peer': peer_pk.hex(),
            'msg': msg.decode('utf-8', errors='ignore'),
            'h': sent_hash.hex(),
            'prev': self.prev_hash.hex()
        }
        data = json.dumps(entry).encode()
        
        # Compute new hash from prev_hash + data
        new_hash = hash_message(data, self.prev_hash)
        self.prev_hash = new_hash

        encrypted = self.box.encrypt(data)
        with open(self.path, 'ab') as f:
            f.write(encrypted + b'\n')

    def verify_chain(self) -> bool:
        """Verify log integrity (for demo/export)."""
        prev_hash = b'\x00' * 32
        try:
            with open(self.path, 'rb') as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        data = self.box.decrypt(line.strip())
                        entry = json.loads(data)
                        
                        # Verify previous hash matches
                        if bytes.fromhex(entry['prev']) != prev_hash:
                            return False
                        
                        # Compute expected hash
                        expected = hash_message(data, prev_hash)
                        prev_hash = expected
                    except:
                        return False
            return True
        except FileNotFoundError:
            return True  # Empty log is valid
