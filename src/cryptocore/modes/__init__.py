from abc import ABC, abstractmethod
from Crypto.Cipher import AES
import os


class BlockCipherMode(ABC):
    def __init__(self, key: bytes, requires_padding: bool = False):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes for AES-128")
        self.key = key
        self.block_size = 16
        self.requires_padding = requires_padding

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        pass

    def _pad_data(self, data: bytes) -> bytes:

        if not self.requires_padding:
            return data

        if len(data) % self.block_size == 0:
            return data + bytes([self.block_size] * self.block_size)
        padding_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([padding_len] * padding_len)

    def _unpad_data(self, data: bytes) -> bytes:

        if not self.requires_padding or not data:
            return data

        padding_len = data[-1]
        if padding_len < 1 or padding_len > self.block_size:
            raise ValueError("Invalid padding")
        if data[-padding_len:] != bytes([padding_len] * padding_len):
            raise ValueError("Invalid padding bytes")
        return data[:-padding_len]

    def _generate_iv(self) -> bytes:

        return os.urandom(16)

    def _split_into_blocks(self, data: bytes) -> list:

        return [data[i:i + self.block_size] for i in range(0, len(data), self.block_size)]