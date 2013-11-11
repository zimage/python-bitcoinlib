# -*- coding: utf-8 -*-
import unittest
from binascii import unhexlify
from bitcoin.bip38 import Bip38
from bitcoin.key import CKey, CKeyForm

class TestBip38(unittest.TestCase):

    def no_ec_multiply(self, v, compressed = False):
            k = CKey()
            k.generate(unhexlify(v['unencrypted_hex']))
            k.set_compressed(compressed)

            # Test get_secret()
            self.assertEqual(unhexlify(v['unencrypted_hex']), k.get_secret())
            self.assertEqual(v['unencrypted_wif'], k.get_secret(form=CKeyForm.BASE58))

            # Test encryption
            b = Bip38(k, v['passphrase'])
            self.assertEqual(v['encrypted'], b.encrypt_no_ec_multiply())

            # Test decryption
            self.assertEqual(unhexlify(v['unencrypted_hex']), Bip38.decrypt(v['encrypted'], v['passphrase']))

    def test_no_compression_no_ec_multiply(self):
        vec = [ {'passphrase': 'TestingOneTwoThree',
                  'encrypted': '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg',
                  'unencrypted_wif': '5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR',
                  'unencrypted_hex': 'CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5',
                 },
                 {'passphrase': 'Satoshi',
                  'encrypted': '6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq',
                  'unencrypted_wif': '5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5',
                  'unencrypted_hex': '09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE'
                 } ]

        for v in vec:
            self.no_ec_multiply(v)

    def test_compression_no_ec_multiply(self):
        vec = [ {'passphrase': 'TestingOneTwoThree',
                  'encrypted': '6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo',
                  'unencrypted_wif': 'L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP',
                  'unencrypted_hex': 'CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5',
                 },
                 {'passphrase': 'Satoshi',
                  'encrypted': '6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7',
                  'unencrypted_wif': 'KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7',
                  'unencrypted_hex': '09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE'
                 } ]

        for v in vec:
            self.no_ec_multiply(v, compressed = True)

    def test_no_compression_ec_multiply_no_lot_sequence_numbers(self):
        vec = [ {'passphrase': 'TestingOneTwoThree',
                 'passphrase_code': 'passphrasepxFy57B9v8HtUsszJYKReoNDV6VHjUSGt8EVJmux9n1J3Ltf1gRxyDGXqnf9qm',
                 'encrypted': '6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX',
                 'salt': '\xa5\x0d\xba\x67\x72\xcb\x93\x83',
                 'seedb': '\x99\x24\x1d\x58\x24\x5c\x88\x38\x96\xf8\x08\x43\xd2\x84\x66\x72\xd7\x31\x2e\x61\x95\xca\x1a\x6c',
                 'bitboin_address': '1PE6TQi6HTVNz5DLwB1LcpMBALubfuN2z2',
                 'unencrypted_wif': '5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2',
                 'unencrypted_hex': 'A43A940577F4E97F5C4D39EB14FF083A98187C64EA7C99EF7CE460833959A519',
                },
                {'passphrase': 'Satoshi',
                 'passphrase_code': 'passphraseoRDGAXTWzbp72eVbtUDdn1rwpgPUGjNZEc6CGBo8i5EC1FPW8wcnLdq4ThKzAS',
                 'encrypted': '6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd',
                 'salt': '\x67\x01\x0a\x95\x73\x41\x89\x06',
                 'seedb': '\x49\x11\x1e\x30\x1d\x94\xea\xb3\x39\xff\x9f\x68\x22\xee\x99\xd9\xf4\x96\x06\xdb\x3b\x47\xa4\x97',
                 'bitcoin_address': '1CqzrtZC6mXSAhoxtFwVjz8LtwLJjDYU3V',
                 'unencrypted_wif': '5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH',
                 'unencrypted_hex': 'C2C8036DF268F498099350718C4A3EF3984D2BE84618C2650F5171DCC5EB660A',
                } ]
 
        for v in vec:
            k = CKey()
            k.generate(unhexlify(v['unencrypted_hex']))
            k.set_compressed(False)

            # Test get_secret()
            self.assertEqual(unhexlify(v['unencrypted_hex']), k.get_secret())
            self.assertEqual(v['unencrypted_wif'], k.get_secret(form=CKeyForm.BASE58))

            # Test get_intermediate
            b = Bip38(k, v['passphrase'], ec_multiply = True)
            self.assertEqual(v['passphrase_code'], b.get_intermediate(salt = v['salt']))

            # Test encryption
            self.assertEqual(v['encrypted'], Bip38.encrypt_ec_multiply(v['passphrase_code'], seedb=v['seedb']))

            # Test decryption
            self.assertEqual(unhexlify(v['unencrypted_hex']), Bip38.decrypt(v['encrypted'], v['passphrase']))

    def test_no_compression_ec_multiply_lot_sequence_numbers(self):
        vec = [ {'passphrase': 'MOLON LABE',
                 'passphrase_code': 'passphraseaB8feaLQDENqCgr4gKZpmf4VoaT6qdjJNJiv7fsKvjqavcJxvuR1hy25aTu5sX',
                 'encrypted': '6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j',
                 'salt': '\x4f\xca\x5a\x97',
                 'seedb': '\x87\xa1\x3b\x07\x85\x8f\xa7\x53\xcd\x3a\xb3\xf1\xc5\xea\xfb\x5f\x12\x57\x9b\x6c\x33\xc9\xa5\x3f',
                 'bitcoin_address': '1Jscj8ALrYu2y9TD8NrpvDBugPedmbj4Yh',
                 'unencrypted_wif': '5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8',
                 'unencrypted_hex': '44EA95AFBF138356A05EA32110DFD627232D0F2991AD221187BE356F19FA8190',
                 'confirmation_code': 'cfrm38V8aXBn7JWA1ESmFMUn6erxeBGZGAxJPY4e36S9QWkzZKtaVqLNMgnifETYw7BPwWC9aPD',
                 'lot': 263183,
                 'sequence': 1,
                },
                {'passphrase': 'ΜΟΛΩΝ ΛΑΒΕ',
                 'passphrase_code': 'passphrased3z9rQJHSyBkNBwTRPkUGNVEVrUAcfAXDyRU1V28ie6hNFbqDwbFBvsTK7yWVK',
                 'encrypted': '6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH',
                 'salt': '\xc4\x0e\xa7\x6f',
                 'seedb': '\x03\xb0\x6a\x1e\xa7\xf9\x21\x9a\xe3\x64\x56\x0d\x7b\x98\x5a\xb1\xfa\x27\x02\x5a\xaa\x7e\x42\x7a',
                 'bitcoin_address': '1Lurmih3KruL4xDB5FmHof38yawNtP9oGf',
                 'unencrypted_wif': '5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D',
                 'unencrypted_hex': 'CA2759AA4ADB0F96C414F36ABEB8DB59342985BE9FA50FAAC228C8E7D90E3006',
                 'confirmation_code': 'cfrm38V8G4qq2ywYEFfWLD5Cc6msj9UwsG2Mj4Z6QdGJAFQpdatZLavkgRd1i4iBMdRngDqDs51',
                 'lot': 806938,
                 'sequence': 1,
                } ]

        for v in vec:
            k = CKey()
            k.generate(unhexlify(v['unencrypted_hex']))
            k.set_compressed(False)

            # Test get_secret()
            self.assertEqual(unhexlify(v['unencrypted_hex']), k.get_secret())
            self.assertEqual(v['unencrypted_wif'], k.get_secret(form=CKeyForm.BASE58))

            # Test get_intermediate
            b = Bip38(k, v['passphrase'], ec_multiply = True, ls_numbers = True)
            self.assertEqual(v['passphrase_code'], b.get_intermediate(salt = v['salt'], lot=v['lot'], sequence=v['sequence']))

            # Test encryption
            self.assertEqual(v['encrypted'], b.encrypt_ec_multiply(v['passphrase_code'], seedb=v['seedb']))

            # Test decryption
            self.assertEqual(unhexlify(v['unencrypted_hex']), Bip38.decrypt(v['encrypted'], v['passphrase']))

