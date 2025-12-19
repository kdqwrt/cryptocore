import struct


class SHA256:
    _INITIAL_HASH = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    )

    _K = (
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    )

    @staticmethod
    def _right_rotate(x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _sigma0(x: int) -> int:
        return SHA256._right_rotate(x, 7) ^ SHA256._right_rotate(x, 18) ^ (x >> 3)

    @staticmethod
    def _sigma1(x: int) -> int:
        return SHA256._right_rotate(x, 17) ^ SHA256._right_rotate(x, 19) ^ (x >> 10)

    @staticmethod
    def _capsigma0(x: int) -> int:
        return SHA256._right_rotate(x, 2) ^ SHA256._right_rotate(x, 13) ^ SHA256._right_rotate(x, 22)

    @staticmethod
    def _capsigma1(x: int) -> int:
        return SHA256._right_rotate(x, 6) ^ SHA256._right_rotate(x, 11) ^ SHA256._right_rotate(x, 25)

    @staticmethod
    def _ch(x: int, y: int, z: int) -> int:
        return (x & y) ^ (~x & z)

    @staticmethod
    def _maj(x: int, y: int, z: int) -> int:
        return (x & y) ^ (x & z) ^ (y & z)

    def __init__(self):
        self.h = list(self._INITIAL_HASH)
        self.buffer = bytearray()
        self.bit_length = 0
        self._finalized = False

    def _padding(self) -> bytes:
        ml_bits = self.bit_length
        padding = bytearray([0x80])
        current_bytes = (self.bit_length // 8) + 1
        zeros_needed = (64 - (current_bytes + 8) % 64) % 64
        padding.extend([0] * zeros_needed)
        padding.extend(struct.pack('>Q', ml_bits))

        return bytes(padding)

    def _process_block(self, block: bytes) -> None:
        if len(block) != 64:
            raise ValueError(f"Block must be 64 bytes, got {len(block)} bytes")

        w = [0] * 64

        for i in range(16):
            w[i] = struct.unpack('>I', block[i * 4:(i + 1) * 4])[0]

        for i in range(16, 64):
            s0 = self._sigma0(w[i - 15])
            s1 = self._sigma1(w[i - 2])
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = self.h

        # Главный цикл из 64 раундов
        for i in range(64):
            t1 = (h + self._capsigma1(e) + self._ch(e, f, g) + self._K[i] + w[i]) & 0xFFFFFFFF
            t2 = (self._capsigma0(a) + self._maj(a, b, c)) & 0xFFFFFFFF

            # Обновление рабочих переменных
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        #  Обновление промежуточного хэша
        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF

    def update(self, data: bytes) -> None:
        if self._finalized:
            raise RuntimeError("Hash has been finalized. Create a new instance.")

        # Добавляем данные в буфер
        self.buffer.extend(data)
        self.bit_length += len(data) * 8

        # Обрабатываем полные блоки по 64 байта
        while len(self.buffer) >= 64:
            block = bytes(self.buffer[:64])
            self._process_block(block)
            del self.buffer[:64]

    def digest(self) -> bytes:
        if not self._finalized:

            original_buffer = self.buffer.copy()

            # Добавляем padding
            padding = self._padding()
            self.buffer.extend(padding)

            while len(self.buffer) >= 64:
                block = bytes(self.buffer[:64])
                self._process_block(block)
                del self.buffer[:64]

            self._finalized = True

            self.buffer = original_buffer

        result = bytearray()
        for val in self.h:
            result.extend(struct.pack('>I', val))

        return bytes(result)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> 'SHA256':
        new = SHA256()
        new.h = self.h.copy()
        new.buffer = self.buffer.copy()
        new.bit_length = self.bit_length
        new._finalized = self._finalized
        return new


def sha256(data: bytes) -> str:
    hasher = SHA256()
    hasher.update(data)
    return hasher.hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    hasher = SHA256()
    hasher.update(data)
    return hasher.digest()