#!/usr/bin/env python3
"""Démonstrations reproductibles des limites du schéma pédagogique."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from src import aes, rsa, xor


def main():
    key = b'\x01\x02'
    first, second = b'AB', b'CD'
    c1, c2 = xor.encrypt(first, key, True), xor.encrypt(second, key, True)
    relation = bytes(a ^ b for a, b in zip(c1, c2))[::-1]
    assert relation == bytes(a ^ b for a, b in zip(first, second))
    recovered_key = bytes(a ^ b for a, b in zip(c1, first[::-1]))
    assert recovered_key == key
    print('XOR : C1 XOR C2 révèle M1 XOR M2 (après conversion des octets).')
    print('XOR : un bloc clair connu permet de retrouver toute la clé répétée.')

    modified = bytes([c1[0] ^ 1]) + c1[1:]
    assert xor.decrypt(modified, key, True) == b'AC'
    print('XOR : modifier un bit du chiffré modifie le clair sans erreur.')

    ciphertext = aes.encrypt(b'A' * 32, bytes(16))
    assert ciphertext[:16] == ciphertext[16:]
    assert aes.encrypt(b'A', bytes(16)) == aes.encrypt(b'A\x00', bytes(16))
    print('AES : deux blocs identiques donnent deux blocs chiffrés identiques.')
    print('Padding nul : A et A suivi de NUL ont le même chiffré AES.')

    public, private = rsa.generate_keys('05', '0b')
    c = rsa.encrypt(b'\x02', public)
    assert c == rsa.encrypt(b'\x02', public)
    e, n = rsa.parse_key(public)
    tampered = (int.from_bytes(c, 'little') * pow(3, e, n)) % n
    tampered_bytes = tampered.to_bytes(max(1, (tampered.bit_length() + 7) // 8), 'little')
    assert rsa.decrypt(tampered_bytes, private) == b'\x06'
    print('RSA brut : chiffrement déterministe ; C × 3^e mod n déchiffre en 3M mod n.')
    print('Ces propriétés persistent quand les primitives sont combinées en hybride.')


if __name__ == '__main__':
    main()
