from Crypto.Cipher import AES
import os
from cryptocore.csprng import generate_random_bytes

class CTRCipher:
    def __init__(self, key: bytes, iv: bytes = None):
        self._validate_key(key)
        self.key = key
        self.block_size = 16

        if iv is None:
            self.iv = generate_random_bytes(16)
        else:
            if len(iv) != 16:
                raise ValueError("IV must be 16 bytes")
            self.iv = iv

    def _validate_key(self, key):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes for AES-128")

    def _increment_counter(self, counter: bytes) -> bytes:
        counter_int = int.from_bytes(counter, byteorder='big')
        counter_int = (counter_int + 1) & ((1 << 128) - 1)
        return counter_int.to_bytes(16, byteorder='big')

    def _split_into_blocks(self, data: bytes) -> list:
        return [data[i:i + self.block_size] for i in range(0, len(data), self.block_size)]

    def encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        blocks = self._split_into_blocks(data)

        encrypted_blocks = []
        counter = self.iv

        for block in blocks:
            keystream = cipher.encrypt(counter)
            encrypted_block = bytes(a ^ b for a, b in zip(block, keystream))
            encrypted_blocks.append(encrypted_block)
            counter = self._increment_counter(counter)

        return b''.join(encrypted_blocks)

    def decrypt(self, data: bytes) -> bytes:
        return self.encrypt(data)