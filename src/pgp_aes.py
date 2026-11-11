"""PGP-AES : composition RSA + AES-128."""

if __package__:
    from . import aes
    from .hybrid import HybridCipher
else:
    import aes
    from hybrid import HybridCipher

_scheme = HybridCipher(aes, "PGP-AES", key_size=aes.BLOCK_SIZE)
parse_key = _scheme.parse_key
encrypt = _scheme.encrypt
decrypt = _scheme.decrypt
