from bitcoin.key import CKey, CKeyForm
from bitcoin.base58 import CBase58Data, CBitcoinAddress
from bitcoin.serialize import ser_uint160, Hash160
import Crypto.Cipher.AES as AES
import Crypto.Hash.SHA256 as SHA256
import scrypt
from itertools import izip
from array import array
from binascii import hexlify
from struct import *
import ctypes
import ctypes.util
import os

ssl = ctypes.cdll.LoadLibrary (ctypes.util.find_library ('ssl') or 'libeay32')

class Bip38:

    def __init__(self, k, passphrase, ec_multiply=False, ls_numbers=False):
        self.k = k
        self.passphrase = passphrase
        self.ec_multiply = ec_multiply
        self.ls_numbers = ls_numbers

    def generate(self, k, passphrase):
        pass

    def encrypt_no_ec_multiply(self):
        address = self.k.get_pubkey(form = CKeyForm.BASE58)

        addresshash = SHA256.new(SHA256.new(address).digest()).digest()[:4]

        derived = scrypt.hash(self.passphrase, addresshash, N=16384, r=8, p=8, buflen=64)
        dh1 = derived[:32]
        dh2 = derived[32:64]

        cipher = AES.new(dh2)

        pkey = self.k.get_secret()

        p1 = Bip38.xor_zip(pkey[:16], dh1[:16])
        p2 = Bip38.xor_zip(pkey[16:32], dh1[16:32])

        eh1 = cipher.encrypt(p1)
        eh2 = cipher.encrypt(p2)

        flagbyte=array('B', [0])
        flagbyte[0] |= 0xc0
        if self.k.get_compressed() is True: flagbyte[0] |= 0x20
        prefix = '\x42'
        return str(CBase58Data(prefix + flagbyte.tostring() + addresshash + eh1 + eh2, 0x01))

    @staticmethod
    def encrypt_ec_multiply(intermediate, seedb=None):
        i_buffer = CBase58Data.from_str(intermediate)
        ownerentropy = i_buffer[7:7+8]
        passpoint_hex = i_buffer[15:15+33]

        flagbyte=array('B', [0])
        if i_buffer[6:7] == '\x51':
            flagbyte[0] |= 0x04

        if seedb is None:
            seedb = os.urandom(24)

        factorb_hex = SHA256.new(SHA256.new(seedb).digest()).digest()

        NID_secp256k1 = 714
        k = ssl.EC_KEY_new_by_curve_name(NID_secp256k1)
        group = ssl.EC_KEY_get0_group(k)
        pub_key = ssl.EC_POINT_new(group)
        ctx = ssl.BN_CTX_new()
        passpoint = ssl.EC_POINT_new(group)
        ssl.EC_POINT_oct2point(group, passpoint, passpoint_hex, 33, ctx)
        factorb = ssl.BN_bin2bn(factorb_hex, 32, ssl.BN_new())
        ssl.EC_POINT_mul(group, pub_key, None, passpoint, factorb, ctx)

        # FIXME: set correct compression
        ssl.EC_KEY_set_public_key(k, pub_key)
        size = ssl.i2o_ECPublicKey(k, 0)
        mb = ctypes.create_string_buffer(size)
        ssl.i2o_ECPublicKey(k, ctypes.byref(ctypes.pointer(mb)))
       
        generatedaddress = str(CBase58Data(ser_uint160(Hash160(mb.raw)), CBitcoinAddress.PUBKEY_ADDRESS))

        addresshash = SHA256.new(SHA256.new(generatedaddress).digest()).digest()[:4]
        derived = scrypt.hash(passpoint_hex, addresshash + ownerentropy, N=1024, r=1, p=1, buflen=64)
        derived_half1 = derived[:32]
        derived_half2 = derived[32:64]
        #confirmation = Bip38._get_confirmation_code(flagbyte, ownerentropy, factorb_hex, derived_half1, derived_half2, addresshash)
        cipher = AES.new(derived_half2)
        ep1 = cipher.encrypt(Bip38.xor_zip(seedb[:16], derived_half1[:16]))
        ep2 = cipher.encrypt(Bip38.xor_zip(ep1[8:16] + seedb[16:24], derived_half1[16:32]))
        
        prefix = '\x43'
        return str(CBase58Data(prefix + flagbyte.tostring() + addresshash + ownerentropy + ep1[:8] + ep2, 0x01))

    @staticmethod
    def _get_confirmation_code(flagbyte, ownerentropy, factorb, derived_half1, derived_half2, addresshash):
        k = CKey()
        k.set_compressed(True)
        k.generate(secret=factorb)
        pointb = k.get_pubkey()
        if len(pointb) != 33:
            return AssertionError('pointb (' + hexlify(pointb) + ') is ' + str(len(pointb)) + ' bytes. It should be 33 bytes.')

        if pointb[:1] != '\x02' and pointb[:1] != '\x03':
            return ValueError('pointb is not correct.')

	pointbprefix = Bip38.xor_zip(pointb[:1], chr(ord(derived_half2[31:32])&ord('\x01')))
        cipher = AES.new(derived_half2)
        pointbx1 = cipher.encrypt(Bip38.xor_zip(pointb[1:17], derived_half1[:16]))
        pointbx2 = cipher.encrypt(Bip38.xor_zip(pointb[17:33], derived_half1[16:32]))
        encryptedpointb = pointbprefix + pointbx1 + pointbx2
        if len(encryptedpointb) != 33:
            return AssertionError('encryptedpointb is not 33 bytes long.')
        magic = '\x3b\xf6\xa8\x9a'
        return str(CBase58Data(magic + flagbyte.tostring() + addresshash + ownerentropy + encryptedpointb, 0x64))

    def get_intermediate(self, salt=None, lot=0, sequence=0):
        if salt is None:
            if self.ls_numbers is True:
                salt = os.urandom(4)
                ownerentropy = salt + pack('>I',(lot*4096)+sequence)

            else:
                salt = os.urandom(8)
                ownerentropy = salt
        else:
            if self.ls_numbers is True:
                ownerentropy = salt + pack('>I',(lot*4096)+sequence)
            else: ownerentropy = salt

        prefactor = scrypt.hash(self.passphrase, salt, N=16384, r=8, p=8, buflen=32)
        if self.ls_numbers is True:
            passfactor = SHA256.new(SHA256.new(prefactor+ownerentropy).digest()).digest()
        else:
            passfactor = prefactor

        passpoint = Bip38._compute_passpoint(passfactor)

        if self.ls_numbers is True:
            magic = '\xE9\xB3\xE1\xFF\x39\xE2\x51'
        else:
            magic = '\xE9\xB3\xE1\xFF\x39\xE2\x53'

        return str(CBase58Data(magic + ownerentropy + passpoint, 0x2c))

    @staticmethod
    def _decrypt_no_ec_multiply(k_buffer, passphrase):
        if passphrase is None or passphrase == '':
            raise ValueError("Passphrase must not be empty.")

        prefix = k_buffer[0:1]
        flagbyte = k_buffer[1:2]
        salt = k_buffer[2:6]
        p1 = k_buffer[6:22]
        p2 = k_buffer[22:38]

        derived = scrypt.hash(passphrase, salt, N=16384, r=8, p=8, buflen=64)
        dh1 = derived[:32]
        dh2 = derived[32:64]

        cipher = AES.new(dh2)

        decrypted_half1 = cipher.decrypt(p1)
        decrypted_half2 = cipher.decrypt(p2)
        
        pkey1 = Bip38.xor_zip(decrypted_half1[:16], dh1[:16])
        pkey2 = Bip38.xor_zip(decrypted_half2[:16], dh1[16:32])
        return pkey1 + pkey2

    @staticmethod
    def _decrypt_ec_multiply(k_buffer, passphrase):
        if passphrase is None or passphrase == '':
            raise ValueError("Passphrase must not be empty.")

        prefix = k_buffer[0:1]
        flagbyte = k_buffer[1:2]
        ls_numbers = False
        if ''.join(chr(ord(c)&ord(k)) for c,k in izip(flagbyte, '\x04')) == '\x04':
            ls_numbers = True
            ls, = unpack('>I', k_buffer[10:14])
            lot = ls / 4096
            sequence = ls - (lot*4096)
            salt = k_buffer[6:10]
        else:
            salt = k_buffer[6:14]
        
        address_hash = k_buffer[2:6]
        ownerentropy = k_buffer[6:14]

        prefactor = scrypt.hash(passphrase, salt, N=16384, r=8, p=8, buflen=32)
        if ls_numbers is True:
            passfactor = SHA256.new(SHA256.new(prefactor+ownerentropy).digest()).digest()
        else:
            passfactor = prefactor

        passpoint = Bip38._compute_passpoint(passfactor)
        derived = scrypt.hash(passpoint, address_hash + ownerentropy, N=1024, r=1, p=1, buflen=64)
        derived_half1 = derived[:32]
        derived_half2 = derived[32:64]
        cipher = AES.new(derived_half2)

        decrypted_half2 = Bip38.xor_zip(cipher.decrypt(k_buffer[22:22+16]), derived_half1[16:32])
        ep12 = decrypted_half2[0:8]
        decrypted_half1 = Bip38.xor_zip(cipher.decrypt(k_buffer[14:14+8] + ep12), derived_half1[:16])
        seedb = decrypted_half1[0:16] + decrypted_half2[8:16]
        factorb = SHA256.new(SHA256.new(seedb).digest()).digest()

        r = ssl.BN_new()
        pf = ssl.BN_bin2bn(passfactor, 32, ssl.BN_new())
        fb = ssl.BN_bin2bn(factorb, 32, ssl.BN_new())
        NID_secp256k1 = 714
        k = ssl.EC_KEY_new_by_curve_name(NID_secp256k1)
        group = ssl.EC_KEY_get0_group(k)
        ctx = ssl.BN_CTX_new()
        ssl.BN_CTX_start(ctx)
        order = ssl.BN_CTX_get(ctx)
        if ssl.EC_GROUP_get_order(group, order, ctx) == 0:
            raise Exception('Error in EC_GROUP_get_order()')
        ssl.BN_mod_mul(r, pf, fb, order, ctx)
        ssl.BN_CTX_free(ctx) 
        pkey = CKey()
        final =  ctypes.create_string_buffer(32)
        ssl.BN_bn2bin(r, final)
        pkey.generate(secret=final)
        return pkey.get_secret()

    @staticmethod
    def decrypt(k, passphrase):
        if passphrase is None or passphrase == '':
            raise ValueError('Passphrase must not be empty.')
        k_buffer = CBase58Data.from_str(k) 
        if k_buffer[0:1] == '\x42':
            return Bip38._decrypt_no_ec_multiply(k_buffer, passphrase)
        elif k_buffer[0:1] == '\x43':
            return Bip38._decrypt_ec_multiply(k_buffer, passphrase)
        else:
            raise Exception('Unknown key type.')

    @staticmethod
    def _compute_passpoint(passfactor):
        k = CKey()
	k.set_compressed(True)
        k.generate(secret=passfactor)
        return k.get_pubkey()

    @staticmethod
    def xor_zip(a, b):
       return ''.join(chr(ord(c)^ord(k)) for c,k in izip(a, b) )

