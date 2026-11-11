"""Composition RSA + primitive symétrique, au format pédagogique du sujet."""

import re

if __package__:
    from . import rsa
else:
    import rsa


class HybridCipher:
    """Partage le transport de clé ; la primitive gère les blocs du message.

    Une primitive expose encrypt/decrypt(data, key, block_mode).
    key_size fixe la longueur récupérée lorsque RSA supprime les octets nuls
    terminaux de la représentation little-endian de la clé.
    """

    def __init__(self, symmetric, name, key_size=None):
        self.symmetric = symmetric
        self.name = name
        self.key_size = key_size

    def parse_key(self, key):
        parts = key.split(":")
        if len(parts) != 2:
            raise ValueError(self.name + " key must have the format symmetric-key:exponent-modulus")
        symmetric, asymmetric = parts
        if (not symmetric or len(symmetric) % 2
                or re.fullmatch(r"[0-9a-fA-F]+", symmetric) is None):
            raise ValueError("expected a non-empty hexadecimal value with complete bytes")
        rsa.parse_key(asymmetric)
        return bytes.fromhex(symmetric), asymmetric

    def encrypt(self, data, key, block_mode=False):
        symmetric, asymmetric = self.parse_key(key)
        if self.key_size is not None and len(symmetric) != self.key_size:
            raise ValueError(self.name + " requires a " + str(self.key_size) + "-byte key")
        if (self.key_size is None and not block_mode
                and len(symmetric) > 1 and symmetric[-1] == 0):
            raise ValueError("PGP-XOR stream key must not end in zero: its length would be lost by RSA")
        encrypted_key = rsa.encrypt(symmetric, asymmetric)
        return encrypted_key, self.symmetric.encrypt(data, symmetric, block_mode)

    def decrypt(self, data, key, block_mode=False):
        encrypted_key, asymmetric = self.parse_key(key)
        symmetric = rsa.decrypt(encrypted_key, asymmetric)
        size = self.key_size
        if size is None and block_mode:
            size = len(data)
        if size is not None:
            if len(symmetric) > size:
                raise ValueError("decrypted symmetric key exceeds the expected size")
            symmetric = symmetric.ljust(size, b"\x00")
        return self.symmetric.decrypt(data, symmetric, block_mode)
