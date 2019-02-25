#!/usr/bin/env python3
import base64
from Crypto.Hash import SHA512
from Crypto.Cipher import AES

class PasswordCrypto:

    def _KeyBuilderWithMasterPassword(self):
        return SHA512.new(self._MasterPassword.encode(self._AnsiEncoding)).digest()[0:32]

    def _KeyBuilderWithoutMasterPassword(self, Meta : bytes):
        KeySpace = []
        KeySpace.append((self._OSUserNameBytes + self._OSHostNameBytes).upper())
        KeySpace.append(Meta.upper())
        KeySpace.append((self._OSUserNameBytes + self._OSHostNameBytes).lower())
        KeySpace.append(Meta.lower())

        Key = bytearray(b'0d5e9n1348/U2+67')
        for i in range(0, len(Key)):
            b = KeySpace[(i + 1) % 4][i]
            if (b not in Key) and (b in b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/'):
                Key[i] = b
        
        return bytes(Key)

    def _EncryptWithMasterPassword(self, Plaintext : bytes, Key : bytes):
        Cipher = AES.new(Key, AES.MODE_ECB)
        CV = Cipher.encrypt(b'\x00' * AES.block_size)

        Ciphertext = bytearray(len(Plaintext))
        for i in range(len(Plaintext)):
            Temp = Cipher.encrypt(CV)
            Ciphertext[i] = Plaintext[i] ^ Temp[0]
            CV = CV[1:] + Ciphertext[i:i + 1]
        
        return bytes(Ciphertext)

    def _EncryptWithoutMasterPassword(self, Plaintext : bytes, Key : bytes):
        raise NotImplementedError('Not implement yet.')

    def _DecryptWithMasterPassword(self, Ciphertext : bytes, Key : bytes):
        Cipher = AES.new(Key, AES.MODE_ECB)
        CV = Cipher.encrypt(b'\x00' * AES.block_size)
        
        Plaintext = bytearray(len(Ciphertext))
        for i in range(len(Ciphertext)):
            TempByte = Ciphertext[i:i + 1]
            Temp = Cipher.encrypt(CV)
            Plaintext[i] = Ciphertext[i] ^ Temp[0]
            CV = CV[1:] + TempByte
        
        return bytes(Plaintext)

    def _DecryptWithoutMasterPassword(self, Ciphertext : bytes, Key : bytes):
        if len(Key) > 16:
            raise ValueError('Invalid Key.')
        
        c = bytearray()
        for i in range(len(Ciphertext)):
            if Ciphertext[i] in Key:
                c.append(Ciphertext[i])

        if len(c) % 2 != 0:
            raise ValueError('Invalid ciphertext.')

        p = bytearray()
        for i in range(0, len(c), 2):
            l = Key.find(c[i])
            Key = Key[-1:] + Key[0:-1]
            h = Key.find(c[i + 1])
            Key = Key[-1:] + Key[0:-1]
            if l == -1 or h == -1:
                raise ValueError('Invalid ciphertext.')
            else:
                p.append(16 * h + l)

        return bytes(p)

    def __init__(self, **kargs):
        if kargs.get('OSUserName') != None and kargs.get('OSHostName') != None:
            if type(kargs['OSUserName']) != str or type(kargs['OSHostName']) != str:
                TypeError('Incorrect type of OSUserName or OSHostName')
            else:
                self._KeyBuilder = self._KeyBuilderWithoutMasterPassword
                self._Encryptor = self._EncryptWithoutMasterPassword
                self._Decryptor = self._DecryptWithoutMasterPassword
                self._AnsiEncoding = 'gbk' if kargs.get('AnsiEncoding') == None else kargs['AnsiEncoding']
                self._OSUserNameBytes = kargs['OSUserName'].encode(self._AnsiEncoding)
                self._OSHostNameBytes = kargs['OSHostName'].encode(self._AnsiEncoding)
        elif kargs.get('MasterPassword') != None:
            if type(kargs['MasterPassword']) != str:
                TypeError('Incorrect type of MasterPassword')
            else:
                self._KeyBuilder = self._KeyBuilderWithMasterPassword
                self._Encryptor = self._EncryptWithMasterPassword
                self._Decryptor = self._DecryptWithMasterPassword
                self._AnsiEncoding = 'gbk' if kargs.get('AnsiEncoding') == None else kargs['AnsiEncoding']
                self._MasterPassword = str(kargs['MasterPassword'])
        else:
            raise ValueError('Missing some arguments')

    def Encrypt(self, Plaintext : str, **kargs):
        if type(Plaintext) != str:
            raise TypeError('Incorrect type of Plaintext')
        
        if hasattr(self, '_MasterPassword'):
            return base64.b64encode(self._Encryptor(Plaintext.encode(self._AnsiEncoding), self._KeyBuilder())).decode()
        else:
            raise NotImplementedError('Not implement yet.')

    def Decrypt(self, Ciphertext : str, **kargs):
        if type(Ciphertext) != str:
            raise TypeError('Incorrect type of Ciphertext')
        
        if hasattr(self, '_MasterPassword'):
            return self._Decryptor(base64.b64decode(Ciphertext), self._KeyBuilder()).decode(self._AnsiEncoding)
        else:
            if kargs.get('UserName') != None and kargs.get('ServerName') != None:
                if type(kargs['UserName']) != str or type(kargs['ServerName']) != str:
                    raise TypeError('Incorrect type of UserName or ServerName')
                else:
                    return self._Decryptor(
                        Ciphertext.encode(self._AnsiEncoding), 
                        self._KeyBuilder(kargs['UserName'].encode(self._AnsiEncoding) + kargs['ServerName'].encode(self._AnsiEncoding))
                    ).decode(self._AnsiEncoding)
            else:
                raise ValueError('Missing some arguments')


