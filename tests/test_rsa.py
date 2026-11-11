"""Vecteurs RSA du sujet et erreurs de l'interface."""
import unittest

from test_cli import run


P = '4b1da73924978f2e9c1f04170e46820d648edbee12ccf4d4462af89b080c86e1'
Q = 'bb3ca1e126f7c8751bd81bc8daa226494efb3d128f72ed9f6cacbe96e14166cb'
N = ('c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de'
     '139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3')
D = ('81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a'
     '11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209')
CIPHER = ('445b349e7318ad6af16b0bbb718be88ba1c41751f95751cd58857f88fe31f97040'
          '5c6ec3f16d79172543bf4e571b5596d212f3e79cd08ef14abd244e325b80')


class RsaTests(unittest.TestCase):
    def check_result(self, result, expected):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(result.stdout, expected)

    def test_small_keys(self):
        self.check_result(run('rsa', '-g', 'd3', 'e3'),
                          b'public key: 0101-19bb\nprivate key: 9d5b-19bb\n')

    def test_small_message(self):
        for flags in ((), ('-b',)):
            for clear in (b'WF', b'WF\n'):
                self.check_result(run('rsa', '-c', *flags, '0101-19bb', data=clear),
                                  b'8f84\n')
            self.check_result(run('rsa', '-d', *flags, '9d5b-19bb', data=b'8f84\n'),
                              b'WF\n')

    def test_large_subject_vector(self):
        self.check_result(run('rsa', '-g', P, Q),
                          f'public key: 010001-{N}\nprivate key: {D}-{N}\n'.encode())
        clear = b'The night is dark and full of terrors\n'
        self.check_result(run('rsa', '-c', '010001-' + N, data=clear),
                          (CIPHER + '\n').encode())
        self.check_result(run('rsa', '-d', D + '-' + N, data=CIPHER.encode()), clear)

    def test_smaller_fermat_exponent(self):
        self.check_result(run('rsa', '-g', '05', '0b'),
                          b'public key: 11-37\nprivate key: 0d-37\n')

    def test_invalid_inputs(self):
        cases = [
            (('-g', 'd3'), b''), (('-g', 'd3', 'e3', 'ff'), b''),
            (('-g', 'd3', 'd3'), b''), (('-g', '01', 'e3'), b''),
            (('-g', 'zz', 'e3'), b''), (('-g', '02', '03'), b''),
            (('-c', '0101'), b'WF'), (('-c', '01-01-01'), b'WF'),
            (('-c', '00-19bb'), b'WF'), (('-c', '01-00'), b'WF'),
            (('-c', '1-19bb'), b'WF'), (('-c', '0101-19bb'), b'ABC'),
            (('-c', '0101-19bb'), bytes.fromhex('19bb')),
            (('-c', '0101-19bb'), b'A\nB'),
            (('-d', '9d5b-19bb'), b'19bb'),
            (('-d', '9d5b-19bb'), b'zz'),
        ]
        for args, data in cases:
            with self.subTest(args=args, data=data):
                result = run('rsa', *args, data=data)
                self.assertEqual(result.returncode, 84)
                self.assertEqual(result.stdout, b'')
                self.assertTrue(result.stderr)


if __name__ == '__main__':
    unittest.main()
