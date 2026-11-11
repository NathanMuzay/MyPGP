"""Chiffrement et déchiffrement XOR en modes bloc et flux."""


def _validate_block(data, key, block_mode):
    if not key:
        raise ValueError("the key must not be empty")
    if block_mode and len(data) != len(key):
        raise ValueError("in block mode, the message and key must have the same size")


# Chiffrement

def encrypt(data, key, block_mode=False):
    """Chiffre des octets et renvoie les octets chiffrés en little-endian."""
    _validate_block(data, key, block_mode)
    size = len(key)
    result = bytearray()
    for offset in range(0, len(data), size):
        block = data[offset:offset + size].ljust(size, b"\x00")
        result.extend(byte ^ mask for byte, mask in zip(block[::-1], key))
    return bytes(result)


# Déchiffrement

def decrypt(data, key, block_mode=False):
    """Déchiffre des blocs complets, en conservant les octets de padding."""
    _validate_block(data, key, block_mode)
    size = len(key)
    if len(data) % size:
        raise ValueError("ciphertext must contain complete blocks")
    result = bytearray()
    for offset in range(0, len(data), size):
        block = data[offset:offset + size]
        clear = bytes(byte ^ mask for byte, mask in zip(block, key))
        result.extend(clear[::-1])
    return bytes(result)
