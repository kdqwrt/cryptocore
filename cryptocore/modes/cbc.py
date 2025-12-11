from Crypto.Cipher import AES
import os
from cryptocore.csprng import generate_random_bytes


class CBCCipher:
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

    def _pad_data(self, data: bytes) -> bytes:

        if len(data) % self.block_size == 0:
            return data + bytes([self.block_size] * self.block_size)
        padding_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([padding_len] * padding_len)

    def _unpad_data(self, data: bytes) -> bytes:

        if not data:
            return b''
        padding_len = data[-1]
        if padding_len < 1 or padding_len > self.block_size:
            raise ValueError("Invalid padding")
        if data[-padding_len:] != bytes([padding_len] * padding_len):
            raise ValueError("Invalid padding bytes")
        return data[:-padding_len]

    def _split_into_blocks(self, data: bytes) -> list:
        return [data[i:i + self.block_size] for i in range(0, len(data), self.block_size)]

    def encrypt(self, data: bytes) -> bytes:

        padded_data = self._pad_data(data)
        cipher = AES.new(self.key, AES.MODE_ECB)
        blocks = self._split_into_blocks(padded_data)

        encrypted_blocks = []
        previous_block = self.iv

        for block in blocks:
            xored_block = bytes(a ^ b for a, b in zip(block, previous_block))
            encrypted_block = cipher.encrypt(xored_block)
            encrypted_blocks.append(encrypted_block)
            previous_block = encrypted_block

        return b''.join(encrypted_blocks)

    def decrypt(self, data: bytes) -> bytes:

        if len(data) % self.block_size != 0:
            raise ValueError("Data length must be multiple of block size")

        cipher = AES.new(self.key, AES.MODE_ECB)
        blocks = self._split_into_blocks(data)

        decrypted_blocks = []
        previous_block = self.iv

        for block in blocks:
            decrypted_block = cipher.decrypt(block)
            plain_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
            decrypted_blocks.append(plain_block)
            previous_block = block

        padded_result = b''.join(decrypted_blocks)
        return self._unpad_data(padded_result)