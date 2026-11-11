"""Tests PGP-XOR via l'interface en ligne de commande."""
import unittest

from test_cli import run


class PgpXorTests(unittest.TestCase):
    def test_known_vector(self):
        result = run('pgp-xor', '-c', '-b', '5746:0101-19bb', data=b'AB\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'8f84\n1507\n')
        result = run('pgp-xor', '-d', '-b', '8f84:9d5b-19bb', data=b'1507\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'AB\n')

    def test_roundtrips(self):
        for block, key, data, expected in [
            (False, '0102', b'ABC', b'ABC\x00'),
            (False, '0102', bytes(range(256)), bytes(range(256))),
            (False, '0102', b'', b''),
            (True, '0100', b'AB\n', b'AB\n'),
            (True, '0000', b'AB\n', b'AB\n'),
        ]:
            with self.subTest(block=block, key=key, data=data):
                flags = ['-b'] if block else []
                cipher = run('pgp-xor', '-c', *flags, key + ':0101-19bb', data=data)
                self.assertEqual(cipher.returncode, 0, cipher.stderr)
                encrypted_key, message = cipher.stdout.split(b'\n', 1)
                clear = run('pgp-xor', '-d', *flags,
                            encrypted_key.decode() + ':9d5b-19bb', data=message)
                self.assertEqual(clear.returncode, 0, clear.stderr)
                self.assertEqual(clear.stdout, expected)

    def test_invalid_inputs(self):
        for mode, flags, key, data in [
            ('-c', [], '01', b'A'),
            ('-c', [], ':0101-19bb', b'A'),
            ('-c', [], '0:0101-19bb', b'A'),
            ('-c', [], 'zz:0101-19bb', b'A'),
            ('-c', [], '01:00-19bb', b'A'),
            ('-c', [], '01:0101-19bb:01', b'A'),
            ('-c', [], 'ffff:0101-19bb', b'A'),
            ('-c', [], '0100:0101-19bb', b'ABC'),
            ('-c', [], '0000:0101-19bb', b'ABC'),
            ('-c', ['-b'], '0102:0101-19bb', b'A'),
            ('-d', [], 'ffff:9d5b-19bb', b'00'),
            ('-d', [], '8f84:9d5b-19bb', b'00'),
            ('-d', [], '8f84:9d5b-19bb', b'zz'),
        ]:
            with self.subTest(mode=mode, key=key, data=data):
                result = run('pgp-xor', mode, *flags, key, data=data)
                self.assertEqual(result.returncode, 84)
                self.assertEqual(result.stdout, b'')
                self.assertTrue(result.stderr)
