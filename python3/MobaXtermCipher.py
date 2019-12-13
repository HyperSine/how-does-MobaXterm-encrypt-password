#!/usr/bin/env python3
import sys, os, platform, random, base64
from Crypto.Hash import SHA512
from Crypto.Cipher import AES

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

if __name__ == '__main__':

    def Help():
        print('Usage:')
        print('    MobaXtermCipher.py <enc|dec> [-sysh sys_hostname] [-sysu sys_username]')
        print('                                 <-h conn_hostname> <-u conn_username>')
        print('                                 <plaintext|ciphertext>')
        print('')
        print('    MobaXtermCipher.py <enc|dec> <-sp SessionP> <plaintext|ciphertext>')
        print('')
        print('    MobaXtermCipher.py <enc|dec> <-p master_password> <plaintext|ciphertext>')
        print('')
        print('        <enc|dec>                "enc" for encryption, "dec" for decryption.')
        print('                                 This parameter must be specified.')
        print('')
        print('        [-sysh sys_hostname]     Hostname of system where MobaXterm runs.')
        print('                                 This parameter is optional. If not specified, use current system hostname.')
        print('')
        print('        [-sysu sys_username]     Username of system where MobaXterm runs.')
        print('                                 This parameter is optional. If not specified, use current system username.')
        print('')
        print('        <-h conn_hostname>       Hostname of MobaXterm connection config.')
        print('                                 This parameter must be specified.')
        print('')
        print('        <-u conn_username>       Username of MobaXterm connection config.')
        print('                                 This parameter must be specified.')
        print('')
        print('        <-sp SessionP>           The value `SessionP` stored in key HKCU\\Software\\Mobatek\\MobaXterm')
        print('                                 This parameter must be specified.')
        print('')
        print('        <-p master_password>     The master password set in MobaXterm.')
        print('                                 This parameter must be specified.')
        print('')
        print('        <plaintext|ciphertext>   Plaintext string or ciphertext string.')
        print('                                 This parameter must be specified.')
        print('')

    def Main(argc: int, argv: list):
        if argc > 2:
            do_encrypt = None
            sys_hostname = None
            sys_username = None
            conn_hostname = None
            conn_username = None
            sessionp = None
            master_password = None
            text = None
            
            if argv[1].lower() == 'enc':
                do_encrypt = True
            elif argv[1].lower() == 'dec':
                do_encrypt = False
            else:
                Help()
                return -1
            
            i = 2
            while i < argc - 1:
                if argv[i].lower() == '-sysh':
                    i += 1
                    if sys_hostname == None:
                        sys_hostname = argv[i]
                        i += 1
                    else:
                        raise ValueError('Option `-sysh` is specified more than once.')
                elif argv[i].lower() == '-sysu':
                    i += 1
                    if sys_username == None:
                        sys_username = argv[i]
                        i += 1
                    else:
                        raise ValueError('Option `-sysu` is specified more than once.')
                elif argv[i].lower() == '-h':
                    i += 1
                    if conn_hostname == None:
                        conn_hostname = argv[i]
                        i += 1
                    else:
                        raise ValueError('Option `-h` is specified more than once.')
                elif argv[i].lower() == '-u':
                    i += 1
                    if conn_username == None:
                        conn_username = argv[i]
                        i += 1
                    else:
                        raise ValueError('Option `-u` is specified more than once.')
                elif argv[i].lower() == '-sp':
                    i += 1
                    if sessionp == None:
                        sessionp = argv[i]
                        i += 1
                    else:
                        raise ValueError('Option `-sp` is specified more than once.')
                elif argv[i].lower() == '-p':
                    i += 1
                    if master_password == None:
                        master_password = argv[i]
                        i += 1
                    else:
                        raise ValueError('Option `-p` is specified more than once.')
                else:
                    raise ValueError('Unknown option %s' % argv[i])
            text = argv[argc - 1]

            if conn_hostname != None and conn_username != None and sessionp == None and master_password == None:
                if sys_hostname == None:
                    sys_hostname = platform.node()
                if sys_username == None:
                    sys_username = os.getlogin()
                
                cipher = MobaXtermCrypto(sys_hostname.encode('ansi'), sys_username.encode('ansi'))

                if do_encrypt:
                    print(
                        cipher.EncryptPassword(
                            text.encode('ansi'), 
                            conn_hostname.encode('ansi'), 
                            conn_username.encode('ansi')
                        )
                    )
                else:
                    print(
                        cipher.DecryptPassword(
                            text, 
                            conn_hostname.encode('ansi'), 
                            conn_username.encode('ansi')
                        ).decode('ansi')
                    )
            elif sys_hostname == None and sys_username == None and conn_hostname == None and conn_username == None and sessionp != None and master_password == None:
                if sys_hostname == None:
                    sys_hostname = platform.node()
                if sys_username == None:
                    sys_username = os.getlogin()
                
                cipher = MobaXtermCrypto(sys_hostname.encode('ansi'), sys_username.encode('ansi'), sessionp.encode('ansi'))

                if do_encrypt:
                    print(
                        cipher.EncryptCredential(
                            text.encode('ansi')
                        )
                    )
                else:
                    print(
                        cipher.DecryptCredential(
                            text
                        ).decode('ansi')
                    )
            elif sys_hostname == None and sys_username == None and conn_hostname == None and conn_username == None and sessionp == None and master_password != None:
                cipher = MobaXtermCryptoSafe(master_password.encode('ansi'))
                if do_encrypt:
                    print(
                        cipher.EncryptPassword(
                            text.encode('ansi')
                        )
                    )
                else:
                    print(
                        cipher.DecryptPassword(
                            text
                        ).decode('ansi')
                    )
            else:
                raise ValueError('Ambiguous parameters are detected.')

            return 0
        else:
            Help()
            return -1

    exit(Main(len(sys.argv), sys.argv))

