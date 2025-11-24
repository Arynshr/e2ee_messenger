"""
Protocol: Msgpack over TLS. Types: connect, msg, ack. Includes hash for leak detection.
"""
import msgpack
import time
from typing import Dict, Any, Optional, cast
from nacl.utils import random as nacl_random

MSG_TYPES = {
    'connect': 1,
    'msg': 2,
    'ack': 3
}

def pack_connect(pk: bytes) -> bytes:
    """Handshake: Send public key."""
    return msgpack.packb({'type': MSG_TYPES['connect'], 'pk': pk})

def unpack_connect(data: bytes) -> Dict[str, Any]:
    """Unpack connection handshake."""
    result = msgpack.unpackb(data, raw=False)
    return cast(Dict[str, Any], result)

def pack_message(to_pk: bytes, msg_hash: bytes, ciphertext: bytes, ts: float) -> bytes:
    """Encrypted msg + metadata for relay."""
    return msgpack.packb({
        'type': MSG_TYPES['msg'],
        'to': to_pk,
        'h': msg_hash,
        'c': ciphertext,
        't': ts
    })

def unpack_message(data: bytes) -> Optional[Dict[str, Any]]:
    """Validate ts (anti-replay, <30s)."""
    try:
        msg = msgpack.unpackb(data, raw=False)
        if not isinstance(msg, dict):
            return None
        
        # Validate timestamp
        timestamp = msg.get('t')
        if timestamp is None or abs(time.time() - float(timestamp)) > 30:
            return None  # Stale or missing timestamp
        
        return cast(Dict[str, Any], msg)
    except (KeyError, ValueError, TypeError):
        return None

def pack_ack(hash_val: bytes) -> bytes:
    """Echo hash for sender verification."""
    return msgpack.packb({'type': MSG_TYPES['ack'], 'h': hash_val})

def unpack_ack(data: bytes) -> Optional[bytes]:
    """Unpack acknowledgment and extract hash."""
    try:
        result = msgpack.unpackb(data, raw=False)
        if not isinstance(result, dict):
            return None
        
        h = result.get('h')
        if h is None:
            return None
        
        # Ensure we return bytes
        if isinstance(h, bytes):
            return h
        elif isinstance(h, (list, tuple)):
            return bytes(h)
        else:
            return None
    except (KeyError, ValueError, TypeError):
        return None

def generate_nonce() -> bytes:
    """Generate random nonce for replay protection."""
    return nacl_random(24)
