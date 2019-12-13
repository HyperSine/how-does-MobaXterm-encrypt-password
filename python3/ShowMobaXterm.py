#!/usr/bin/env python3
import sys, os, platform, random, base64, itertools, winreg
from Crypto.Hash import SHA512
from Crypto.Cipher import AES

if platform.system().lower() != 'windows':
    print('Please run this script in Windows.')
    exit(-1)

class MobaXtermCrypto:

    def __init__(self, SysHostname: bytes, SysUsername: bytes, SessionP: bytes = None):
        self._SysHostname = SysHostname
        self._SysUsername = SysUsername
        self._SessionP = SessionP

    def _KeyCrafter(self, **kargs) -> bytes:
        if kargs.get('ConnHostname') != None and kargs.get('ConnUsername') != None:
            s1 = self._SysUsername + self._SysHostname
            while len(s1) < 20:
                s1 = s1 + s1

            s2 = kargs.get('ConnUsername') + kargs.get('ConnHostname')
            while len(s2) < 20:
                s2 = s2 + s2

            key_space = [
                s1.upper(),
                s2.upper(),
                s1.lower(),
                s2.lower()
            ]
        else:
            s = self._SessionP
            while len(s) < 20:
                s = s + s

            key_space = [
                s.upper(),
                s.upper(),
                s.lower(),
                s.lower()
            ]

        key = bytearray(b'0d5e9n1348/U2+67')
        for i in range(0, len(key)):
            b = key_space[(i + 1) % len(key_space)][i]
            if (b not in key) and (b in b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/'):
                key[i] = b

        return bytes(key)

    def EncryptPassword(self, Plaintext: bytes, ConnHostname: bytes, ConnUsername: bytes) -> str:
        key = self._KeyCrafter(ConnHostname = ConnHostname, ConnUsername = ConnUsername)

        ct = bytearray()
        for char in Plaintext:
            l = char & 0x0f
            ct.append(key[l])
            key = key[-1:] + key[0:-1]

            h = char >> 4
            ct.append(key[h])
            key = key[-1:] + key[0:-1]

        Ciphertext = bytearray()
        obfuscate_chars = bytes(filter(lambda char: char not in key, b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/'))
        for char in ct:
            while random.choice([ True, False, False ]) == False:
                Ciphertext.append(random.choice(obfuscate_chars))
            Ciphertext.append(char)
        while random.choice([ True, False, False ]) == False:
            Ciphertext.append(random.choice(obfuscate_chars))

        return Ciphertext.decode()

    def EncryptCredential(self, Plaintext: bytes) -> str:
        key = self._KeyCrafter()

        ct = bytearray()
        for char in Plaintext:
            l = char & 0x0f
            ct.append(key[l])
            key = key[-1:] + key[0:-1]

            h = char >> 4
            ct.append(key[h])
            key = key[-1:] + key[0:-1]

        Ciphertext = bytearray()
        obfuscate_chars = bytes(filter(lambda char: char not in key, b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/'))
        for char in ct:
            while random.choice([ True, False, False ]) == False:
                Ciphertext.append(random.choice(obfuscate_chars))
            Ciphertext.append(char)
        while random.choice([ True, False, False ]) == False:
            Ciphertext.append(random.choice(obfuscate_chars))

        return Ciphertext.decode()

    def DecryptPassword(self, Ciphertext: str, ConnHostname: bytes, ConnUsername: bytes) -> bytes:
        key = self._KeyCrafter(ConnHostname = ConnHostname, ConnUsername = ConnUsername)

        ct = bytearray()
        for char in Ciphertext.encode('ascii'):
            if char in key:
                ct.append(char)

        if len(ct) % 2 == 0:
            pt = bytearray()
            for i in range(0, len(ct), 2):
                l = key.find(ct[i])
                key = key[-1:] + key[0:-1]
                h = key.find(ct[i + 1])
                key = key[-1:] + key[0:-1]
                assert(l != -1 and h != -1)
                pt.append(16 * h + l)
            return bytes(pt)
        else:
            raise ValueError('Invalid ciphertext.')
    
    def DecryptCredential(self, Ciphertext: str) -> bytes:
        key = self._KeyCrafter()

        ct = bytearray()
        for char in Ciphertext.encode('ascii'):
            if char in key:
                ct.append(char)

        if len(ct) % 2 == 0:
            pt = bytearray()
            for i in range(0, len(ct), 2):
                l = key.find(ct[i])
                key = key[-1:] + key[0:-1]
                h = key.find(ct[i + 1])
                key = key[-1:] + key[0:-1]
                assert (l != -1 and h != -1)
                pt.append(16 * h + l)
            return bytes(pt)
        else:
            raise ValueError('Invalid ciphertext.')

class MobaXtermCryptoSafe:

    def __init__(self, MasterPassword: bytes):
        self._Key = SHA512.new(MasterPassword).digest()[0:32]

    def EncryptPassword(self, Plaintext: bytes) -> str:
        iv = AES.new(key = self._Key, mode = AES.MODE_ECB).encrypt(b'\x00' * AES.block_size)
        cipher = AES.new(key = self._Key, iv = iv, mode = AES.MODE_CFB, segment_size = 8)
        return base64.b64encode(cipher.encrypt(Plaintext))

    def EncryptCredential(self, Plaintext: bytes) -> str:
        return self.EncryptPassword(Plaintext)

    def DecryptPassword(self, Ciphertext: str) -> bytes:
        iv = AES.new(key = self._Key, mode = AES.MODE_ECB).encrypt(b'\x00' * AES.block_size)
        cipher = AES.new(key = self._Key, iv = iv, mode = AES.MODE_CFB, segment_size = 8)
        return cipher.decrypt(base64.b64decode(Ciphertext))
    
    def DecryptCredential(self, Ciphertext: str) -> bytes:
        return self.DecryptPassword(Ciphertext)

def WinRegistryReadValue(Root, SubKey: str, ValueName: str, ExpectValueType: int = None):
    Key = winreg.OpenKey(Root, SubKey)
    Value, ValueType = winreg.QueryValueEx(Key, ValueName)
    if type(ExpectValueType) == int and ValueType != ExpectValueType:
        raise TypeError('Expect %d, but %d is given.' % (ExpectValueType, ValueType))
    return Value

if len(sys.argv) == 2:
    cipher = MobaXtermCryptoSafe(
        sys.argv[1].encode('ansi')
    )
else:
    Value, ValueType = winreg.QueryValueEx(
        winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, 
            'Software\\Mobatek\\MobaXterm'
        ), 
        'SessionP'
    ); assert(ValueType == winreg.REG_SZ)

    cipher = MobaXtermCrypto(
        platform.node().encode('ansi'), 
        os.getlogin().encode('ansi'), 
        Value.encode('ansi')
    )

try:
    Key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Mobatek\\MobaXterm\\C')

    print('Credentials'.center(48, '-'))

    for i in itertools.count(0):
        try:
            ValueName, Value, ValueType = winreg.EnumValue(Key, i)
            assert(ValueType == winreg.REG_SZ)

            CredentialUsername, CredentialPassword = Value.split(':')

            CredentialPassword = cipher.DecryptCredential(
                CredentialPassword
            ).decode('ansi')

            print('[*] Name:     %s' % ValueName)
            print('[*] Username: %s' % CredentialUsername)
            print('[*] Password: %s' % CredentialPassword)
            print('')
        except OSError:
            break
except FileNotFoundError:
    pass

try:
    Key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Mobatek\\MobaXterm\\P')

    print('Passwords'.center(48, '-'))

    for i in itertools.count(0):
        try:
            ValueName, Value, ValueType = winreg.EnumValue(Key, i)
            assert(ValueType == winreg.REG_SZ)

            ConnUsername, ConnHostname = ValueName.split('@')
            if ':' in ConnUsername:
                ConnUsername = ConnUsername.split(':')[-1]
            
            ConnPassword = cipher.DecryptPassword(
                Value, 
                ConnHostname.encode('ansi'), 
                ConnUsername.encode('ansi')
            ).decode('ansi')

            print('[*] Name:     %s' % ValueName)
            print('[*] Password: %s' % ConnPassword)
            print('')
        except OSError:
            break
except FileNotFoundError:
    pass

