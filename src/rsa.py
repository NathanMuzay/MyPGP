"""RSA sans padding, avec représentation des nombres en little-endian."""

from math import gcd
import re


def _parse_number(value):
    if not value or len(value) % 2 or re.fullmatch(r"[0-9a-fA-F]+", value) is None:
        raise ValueError("expected a non-empty hexadecimal value with complete bytes")
    return int.from_bytes(bytes.fromhex(value), "little")


def _to_bytes(value):
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "little")


def parse_key(key):
    """Lit une clé exposant-module, dont chaque composante est little-endian."""
    parts = key.split("-")
    if len(parts) != 2:
        raise ValueError("RSA key must have the format exponent-modulus")
    exponent, modulus = map(_parse_number, parts)
    if exponent <= 0 or modulus <= 1:
        raise ValueError("RSA exponent must be positive and modulus greater than one")
    return exponent, modulus


def _transform(data, key):
    exponent, modulus = parse_key(key)
    value = int.from_bytes(data, "little")
    if value >= modulus:
        raise ValueError("RSA message must be smaller than the modulus")
    # pow à trois arguments réduit modulo n pendant l'exponentiation.
    # Ne pas calculer value ** exponent : cet entier intermédiaire serait énorme.
    return _to_bytes(pow(value, exponent, modulus))


# Chiffrement

def encrypt(data, key, block_mode=False):
    """Chiffre un message dont la valeur entière doit être inférieure au module."""
    return _transform(data, key)


# Déchiffrement

def decrypt(data, key, block_mode=False):
    """Déchiffre un entier RSA vers sa représentation minimale en octets."""
    return _transform(data, key)


# Génération des clés

def generate_keys(p, q):
    """Renvoie les clés publique et privée à partir de deux premiers hexadécimaux."""
    p, q = _parse_number(p), _parse_number(q)
    if p <= 1 or q <= 1 or p == q:
        raise ValueError("RSA requires two distinct primes greater than one")
    modulus = p * q
    carmichael = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
    exponent = next((e for e in (65537, 257, 17, 5, 3)
                     if e < carmichael and gcd(e, carmichael) == 1), None)
    if exponent is None:
        raise ValueError("no valid Fermat prime exponent for these RSA primes")
    private = pow(exponent, -1, carmichael)
    suffix = "-" + _to_bytes(modulus).hex()
    return _to_bytes(exponent).hex() + suffix, _to_bytes(private).hex() + suffix
