"""Arithmétique RSA multi-précision et limites de représentation."""
from math import gcd, lcm
import unittest

from src import rsa
from rsa_fixtures import P_1024, Q_1024
from test_cli import run


class RsaLargeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public, cls.private = rsa.generate_keys(P_1024, Q_1024)

    def test_key_invariants(self):
        p = int.from_bytes(bytes.fromhex(P_1024), 'little')
        q = int.from_bytes(bytes.fromhex(Q_1024), 'little')
        e, n = rsa.parse_key(self.public)
        d, private_n = rsa.parse_key(self.private)
        self.assertEqual(n.bit_length(), 2048)
        self.assertEqual(n, p * q)
        self.assertEqual(private_n, n)
        self.assertEqual(e, 65537)
        self.assertEqual(gcd(e, lcm(p - 1, q - 1)), 1)
        self.assertEqual(e * d % lcm(p - 1, q - 1), 1)

    def test_residues_including_non_coprime_messages(self):
        _, n = rsa.parse_key(self.public)
        p = int.from_bytes(bytes.fromhex(P_1024), 'little')
        for value in (0, 1, p, n - 1):
            with self.subTest(value=value):
                data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'little')
                self.assertEqual(rsa.decrypt(rsa.encrypt(data, self.public), self.private), data)

    def test_binary_api_and_minimal_representation(self):
        data = bytes(range(1, 256))
        self.assertEqual(rsa.decrypt(rsa.encrypt(data, self.public), self.private), data)
        self.assertEqual(rsa.decrypt(rsa.encrypt(b'A\x00', self.public), self.private), b'A')

    def test_large_cli_roundtrip(self):
        cipher = run('rsa', '-c', self.public, data=b'RSA multi-precision\n')
        self.assertEqual(cipher.returncode, 0, cipher.stderr)
        clear = run('rsa', '-d', self.private, data=cipher.stdout)
        self.assertEqual(clear.returncode, 0, clear.stderr)
        self.assertEqual(clear.stdout, b'RSA multi-precision\n')
