#!/usr/bin/env python3
"""Mesure les opérations RSA seules ; les premiers sont des fixtures publiques."""

import pathlib
import statistics
import sys
from time import perf_counter

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))

from src import rsa
from rsa_fixtures import P_1024, Q_1024
from test_rsa import P, Q


def measure(operation, repetitions=5):
    times = []
    for _ in range(repetitions):
        start = perf_counter()
        result = operation()
        times.append((perf_counter() - start) * 1000)
    return result, statistics.median(times)


def main():
    print('Python ' + sys.version.split()[0])
    print('Médiane de 5 opérations, en ms, hors lancement du processus et E/S.')
    print('bits du module | génération | chiffrement | déchiffrement')
    for p, q in ((P, Q), (P_1024, Q_1024)):
        (public, private), generation = measure(lambda: rsa.generate_keys(p, q))
        data = b'RSA benchmark'
        cipher, encryption = measure(lambda: rsa.encrypt(data, public))
        clear, decryption = measure(lambda: rsa.decrypt(cipher, private))
        if clear != data:
            raise RuntimeError('RSA round trip failed')
        _, n = rsa.parse_key(public)
        print(f'{n.bit_length():14d} | {generation:10.3f} | {encryption:11.3f} | {decryption:13.3f}')


if __name__ == '__main__':
    main()
