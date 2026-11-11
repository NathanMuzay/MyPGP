"""PGP-AES : vecteur du sujet, transport de clé et données binaires."""
import unittest

from src import pgp_aes
from test_cli import run
from test_rsa import N, D

KEY = '57696e74657220697320636f6d696e67'
PUBLIC = '010001-' + N
PRIVATE = D + '-' + N
ENCRYPTED_KEY = (
    '97f2af4c1b712008c1e46935f446756443a8a700f20581d138e4e6916afe5c5f9'
    'b9d6eaa0a870374b686f1a024f9bbb88c23c766654579339caf55afd149d41d')
CIPHER = b'744ce22c385958348f0df26eceb62eef\n'


class PgpAesTests(unittest.TestCase):
    def test_subject_vector(self):
        cipher = run('pgp-aes', '-c', '-b', KEY + ':' + PUBLIC,
                     data=b'All men must die\n')
        self.assertEqual(cipher.returncode, 0, cipher.stderr)
        self.assertEqual(cipher.stdout, ENCRYPTED_KEY.encode() + b'\n' + CIPHER)
        clear = run('pgp-aes', '-d', '-b', ENCRYPTED_KEY + ':' + PRIVATE, data=CIPHER)
        self.assertEqual(clear.returncode, 0, clear.stderr)
        self.assertEqual(clear.stdout, b'All men must die\n')

    def test_binary_stream_and_zero_key_bytes(self):
        for key in (KEY, '0102' + '00' * 14, '00' * 16):
            for data in (b'', b'A', b'A' * 15, b'A' * 16, b'A' * 17,
                         bytes(range(256)), b'first\nsecond\n\x00\x00'):
                with self.subTest(key=key, size=len(data)):
                    cipher = run('pgp-aes', '-c', key + ':' + PUBLIC, data=data)
                    self.assertEqual(cipher.returncode, 0, cipher.stderr)
                    encrypted_key, message = cipher.stdout.split(b'\n', 1)
                    clear = run('pgp-aes', '-d', encrypted_key.decode() + ':' + PRIVATE,
                                data=message)
                    self.assertEqual(clear.returncode, 0, clear.stderr)
                    self.assertEqual(clear.stdout, data + b'\x00' * (-len(data) % 16))

    def test_module_api_binary_block(self):
        # L'API traite tous les octets ; seule la CLI bloc impose une ligne.
        data = bytes(range(16))
        encrypted_key, cipher = pgp_aes.encrypt(data, '00' * 16 + ':' + PUBLIC, True)
        self.assertEqual(pgp_aes.decrypt(cipher, encrypted_key.hex() + ':' + PRIVATE, True), data)

    def test_invalid_inputs(self):
        cases = [
            ('-c', [], '00' * 15 + ':' + PUBLIC, b'A'),
            ('-c', [], '00' * 24 + ':' + PUBLIC, b'A'),
            ('-c', [], KEY + ':0101-19bb', b'A'),
            ('-c', ['-b'], KEY + ':' + PUBLIC, b'A'),
            ('-c', [], KEY + ':' + PUBLIC + ':extra', b'A'),
            ('-d', [], '01:' + PRIVATE, b'00' * 15),
            ('-d', [], '01:' + PRIVATE, b'zz'),
            ('-d', [], N + ':' + PRIVATE, CIPHER),
            # Exposant 1 : la clé récupérée dépasse les 16 octets attendus.
            ('-d', [], '01' * 17 + ':01-' + N, CIPHER),
        ]
        for mode, flags, key, data in cases:
            with self.subTest(mode=mode, key=key):
                result = run('pgp-aes', mode, *flags, key, data=data)
                self.assertEqual(result.returncode, 84)
                self.assertEqual(result.stdout, b'')
                self.assertTrue(result.stderr)
