"""Tests de l'interface réelle, avec le vecteur fourni dans le sujet."""
import pathlib
import subprocess
import unittest


PROGRAM = pathlib.Path(__file__).resolve().parents[1] / "my_pgp"
KEY = "576861742069732064656164206d6179206e6576657220646965"
CLEAR = b"You know nothing, Jon Snow\n"
CIPHER = b"20070f2700071c6a4449060a490515164e4e12190b190011063c\n"


def run(*args, data=b""):
    return subprocess.run([str(PROGRAM), *args], input=data, capture_output=True)


class CliTests(unittest.TestCase):
    def test_help(self):
        result = run("-h")
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"USAGE", result.stdout)
        self.assertEqual(result.stderr, b"")

    def test_subject_encryption(self):
        result = run("xor", "-c", "-b", KEY, data=CLEAR)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, CIPHER)

    def test_subject_decryption(self):
        result = run("xor", "-d", "-b", KEY, data=CIPHER)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, CLEAR)

    def test_stream_padding_and_byte_order(self):
        result = run("xor", "-c", "0102", data=b"ABC")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"43430141\n")
        result = run("xor", "-d", "0102", data=result.stdout)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"ABC\x00")

    def test_binary_stream(self):
        data = bytes(range(256)) + b"\n"
        cipher = run("xor", "-c", "aabbcc", data=data)
        clear = run("xor", "-d", "aabbcc", data=cipher.stdout)
        self.assertEqual(cipher.returncode, 0)
        self.assertEqual(clear.returncode, 0)
        self.assertEqual(clear.stdout, data + b"\x00")

    def test_empty_stream(self):
        self.assertEqual(run("xor", "-c", "01").stdout, b"\n")
        self.assertEqual(run("xor", "-d", "01", data=b"\n").stdout, b"")

    def test_invalid_inputs(self):
        cases = [
            ([], b""),
            (["unknown", "-c", "aa"], b""),
            (["aes", "-c", "aa"], b""),
            (["xor", "-g", "aa"], b""),
            (["xor", "-c", ""], b""),
            (["xor", "-c", "a"], b""),
            (["xor", "-c", "zz"], b""),
            (["xor", "-c", "-b"], b""),
            (["xor", "-c", "-b", "aaaa"], b"A\n"),
            (["xor", "-c", "-b", "aaaaaa"], b"A\nB"),
            (["xor", "-d", "aa"], b"zz"),
            (["xor", "-d", "aa"], b"\xff"),
            (["xor", "-d", "aaaa"], b"aa"),
            (["xor", "-c", "aa", "extra"], b""),
        ]
        for args, data in cases:
            with self.subTest(args=args, data=data):
                result = run(*args, data=data)
                self.assertEqual(result.returncode, 84)
                self.assertEqual(result.stdout, b"")
                self.assertTrue(result.stderr)


if __name__ == "__main__":
    unittest.main()
