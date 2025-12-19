import struct
import os
from typing import Tuple, Optional
from Crypto.Cipher import AES
from cryptocore.csprng import generate_random_bytes


class GCMError(Exception):
    pass


class AuthenticationError(GCMError):
    pass


class GCM:
    _POLY = 0xE1

    def __init__(self, key: bytes, nonce: Optional[bytes] = None):
        self._validate_key(key)
        self.key = key
        self.aes = AES.new(key, AES.MODE_ECB)

        if nonce is None:
            self.nonce = generate_random_bytes(12)
        else:
            if len(nonce) != 12:
                raise ValueError("Nonce должен быть 12 байт для GCM")
            self.nonce = nonce

        self.H = self._bytes_to_int(self.aes.encrypt(b'\x00' * 16))

    def _validate_key(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Ключ должен быть 16, 24 или 32 байт для AES")
        if len(key) != 16:
            raise ValueError("В данной реализации поддерживается только AES-128 (16 байт)")

    def _bytes_to_int(self, data: bytes) -> int:
        return int.from_bytes(data, byteorder='big')

    def _int_to_bytes(self, value: int, length: int = 16) -> bytes:

        return value.to_bytes(length, byteorder='big')

    def _gf_mult(self, x: int, y: int) -> int:

        z = 0
        v = x

        for i in range(127, -1, -1):
            if (y >> i) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ (self._POLY << 120)
            else:
                v = v >> 1

        return z

    def _ghash(self, aad: bytes, ciphertext: bytes) -> int:
        y = 0

        aad_len = len(aad)
        if aad_len > 0:

            if aad_len % 16 != 0:
                aad += b'\x00' * (16 - (aad_len % 16))

            for i in range(0, len(aad), 16):
                block = aad[i:i + 16]
                x = self._bytes_to_int(block)
                y ^= x
                y = self._gf_mult(y, self.H)


        ct_len = len(ciphertext)
        if ct_len > 0:

            if ct_len % 16 != 0:
                ciphertext += b'\x00' * (16 - (ct_len % 16))

            for i in range(0, len(ciphertext), 16):
                block = ciphertext[i:i + 16]
                x = self._bytes_to_int(block)
                y ^= x
                y = self._gf_mult(y, self.H)


        len_aad = aad_len * 8
        len_ct = ct_len * 8

        len_block = (len_aad << 64) | len_ct
        y ^= len_block
        y = self._gf_mult(y, self.H)

        return y

    def _compute_initial_counter(self) -> bytes:
        if len(self.nonce) == 12:

            return self.nonce + b'\x00\x00\x00\x01'
        else:

            raise ValueError("Поддерживаются только 12-байтовые nonce")

    def _inc_32(self, counter: bytes) -> bytes:

        counter_int = self._bytes_to_int(counter)

        counter_int = (counter_int + 1) & 0xFFFFFFFF

        high_part = self._bytes_to_int(counter[:12]) << 32
        new_counter = high_part | counter_int
        return self._int_to_bytes(new_counter)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:

        j0 = self._compute_initial_counter()


        auth_key = self.aes.encrypt(j0)

        counter = self._inc_32(j0)

        # Шифрование в режиме CTR
        ciphertext = bytearray()
        current_counter = counter

        for i in range(0, len(plaintext), 16):
            keystream = self.aes.encrypt(current_counter)
            block = plaintext[i:i + 16]
            encrypted_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            ciphertext.extend(encrypted_block)
            current_counter = self._inc_32(current_counter)

        ciphertext = bytes(ciphertext)


        ghash = self._ghash(aad, ciphertext)
        tag_int = ghash ^ self._bytes_to_int(auth_key)
        tag = self._int_to_bytes(tag_int, 16)

        return self.nonce + ciphertext + tag

    def decrypt(self, data: bytes, aad: bytes = b"") -> bytes:

        if len(data) < 28:  # 12 (nonce) + 16 (tag)
            raise ValueError("Данные слишком короткие для формата GCM")


        nonce = data[:12]
        ciphertext_with_tag = data[12:]

        if len(ciphertext_with_tag) < 16:
            raise ValueError("Данные не содержат полный тег аутентификации")

        ciphertext = ciphertext_with_tag[:-16]
        received_tag = ciphertext_with_tag[-16:]


        self.nonce = nonce


        j0 = self._compute_initial_counter()
        auth_key = self.aes.encrypt(j0)
        ghash = self._ghash(aad, ciphertext)
        computed_tag_int = ghash ^ self._bytes_to_int(auth_key)
        computed_tag = self._int_to_bytes(computed_tag_int, 16)


        if computed_tag != received_tag:
            raise AuthenticationError("Ошибка аутентификации")


        counter = self._inc_32(j0)
        plaintext = bytearray()
        current_counter = counter

        for i in range(0, len(ciphertext), 16):
            keystream = self.aes.encrypt(current_counter)
            block = ciphertext[i:i + 16]
            decrypted_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            plaintext.extend(decrypted_block)
            current_counter = self._inc_32(current_counter)

        return bytes(plaintext)


def gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:

    gcm = GCM(key)
    return gcm.encrypt(plaintext, aad)


def gcm_decrypt(key: bytes, data: bytes, aad: bytes = b"") -> bytes:

    gcm = GCM(key, data[:12])
    return gcm.decrypt(data, aad)