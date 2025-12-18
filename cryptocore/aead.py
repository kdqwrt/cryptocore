from abc import ABC, abstractmethod
from typing import Tuple, Optional
import os
from cryptocore.csprng import generate_random_bytes
from cryptocore.mac.hmac import HMAC



class AEADCipher(ABC):
    @abstractmethod
    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:

        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        pass


class EncryptThenMAC:

    def __init__(self, key: bytes, encryption_mode: str = 'ctr',
                 hash_algorithm: str = 'sha256'):

        if len(key) < 32:
            raise ValueError("Ключ должен быть минимум 32 байта")

        self.enc_key = key[:16]
        self.mac_key = key[16:32]

        self.encryption_mode = encryption_mode
        self.hash_algorithm = hash_algorithm

        self._init_cipher()

    def _init_cipher(self):
        from cryptocore.modes.ctr import CTRCipher
        from cryptocore.modes.cbc import CBCCipher
        from cryptocore.modes.cfb import CFBCipher
        from cryptocore.modes.ofb import OFBCipher
        from cryptocore.modes.ecb import ECBCipher

        if self.encryption_mode == 'ctr':
            self.cipher = CTRCipher(self.enc_key)
        elif self.encryption_mode == 'cbc':
            self.cipher = CBCCipher(self.enc_key)
        elif self.encryption_mode == 'cfb':
            self.cipher = CFBCipher(self.enc_key)
        elif self.encryption_mode == 'ofb':
            self.cipher = OFBCipher(self.enc_key)
        elif self.encryption_mode == 'ecb':
            self.cipher = ECBCipher(self.enc_key)
        else:
            raise ValueError(f"Неподдерживаемый режим шифрования: {self.encryption_mode}")

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes, Optional[bytes]]:


        ciphertext = self.cipher.encrypt(plaintext)

        iv = getattr(self.cipher, 'iv', None) if hasattr(self.cipher, 'iv') else None

        mac_data = ciphertext + aad
        if iv:
            mac_data += iv

        hmac = HMAC(self.mac_key, self.hash_algorithm)
        tag = hmac.compute(mac_data)

        return ciphertext, tag, iv

    def decrypt(self, ciphertext: bytes, tag: bytes, aad: bytes = b"",
                iv: Optional[bytes] = None) -> bytes:

        mac_data = ciphertext + aad
        if iv:
            mac_data += iv

        hmac = HMAC(self.mac_key, self.hash_algorithm)
        computed_tag = hmac.compute(mac_data)

        if computed_tag != tag:
            raise AuthenticationError("Ошибка аутентификации: несоответствие MAC")

        if iv and hasattr(self.cipher, 'iv'):
            if self.encryption_mode == 'ctr':
                from cryptocore.modes.ctr import CTRCipher
                cipher = CTRCipher(self.enc_key, iv)
            elif self.encryption_mode == 'cbc':
                from cryptocore.modes.cbc import CBCCipher
                cipher = CBCCipher(self.enc_key, iv)
            elif self.encryption_mode == 'cfb':
                from cryptocore.modes.cfb import CFBCipher
                cipher = CFBCipher(self.enc_key, iv)
            elif self.encryption_mode == 'ofb':
                from cryptocore.modes.ofb import OFBCipher
                cipher = OFBCipher(self.enc_key, iv)
            else:
                cipher = self.cipher
        else:
            cipher = self.cipher

        plaintext = cipher.decrypt(ciphertext)
        return plaintext


class AuthenticationError(Exception):
    pass


def derive_keys_from_master(master_key: bytes) -> Tuple[bytes, bytes]:

    if len(master_key) < 16:
        raise ValueError("Мастер-ключ должен быть минимум 16 байт")

    if len(master_key) >= 32:
        return master_key[:16], master_key[16:32]
    else:
        enc_key = master_key[:16]

        import hashlib
        mac_key = hashlib.sha256(master_key + b"MAC").digest()[:16]

        return enc_key, mac_key