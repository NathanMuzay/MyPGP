"""PGP-XOR : composition RSA + XOR."""

if __package__:
    from . import xor
    from .hybrid import HybridCipher
else:
    import xor
    from hybrid import HybridCipher

_scheme = HybridCipher(xor, "PGP-XOR")
parse_key = _scheme.parse_key
encrypt = _scheme.encrypt
decrypt = _scheme.decrypt
