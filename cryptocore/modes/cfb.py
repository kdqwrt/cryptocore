from Crypto.Cipher import AES
import os


class CFBCipher:
    def __init__(self, key: bytes, iv: bytes = None):
        self._validate_key(key)
        self.key = key
        self.block_size = 16

        if iv is None:
            self.iv = os.urandom(16)
        else:
            if len(iv) != 16:
                raise ValueError("IV must be 16 bytes")
            self.iv = iv

    def _validate_key(self, key):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes for AES-128")

    def _split_into_blocks(self, data: bytes) -> list:
        return [data[i:i + self.block_size] for i in range(0, len(data), self.block_size)]

    def encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        blocks = self._split_into_blocks(data)

        encrypted_blocks = []
        feedback = self.iv

        for block in blocks:
            encrypted_feedback = cipher.encrypt(feedback)
            encrypted_block = bytes(a ^ b for a, b in zip(block, encrypted_feedback))
            encrypted_blocks.append(encrypted_block)
            feedback = encrypted_block

        return b''.join(encrypted_blocks)

    def decrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        blocks = self._split_into_blocks(data)

        decrypted_blocks = []
        feedback = self.iv

        for block in blocks:
            encrypted_feedback = cipher.encrypt(feedback)
            decrypted_block = bytes(a ^ b for a, b in zip(block, encrypted_feedback))
            decrypted_blocks.append(decrypted_block)
            feedback = block

        return b''.join(decrypted_blocks)