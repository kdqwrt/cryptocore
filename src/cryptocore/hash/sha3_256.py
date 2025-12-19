import struct


class SHA3_256:

    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ]


    RHO_OFFSETS = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]
    ]

    def __init__(self):
        self.state = [[0] * 5 for _ in range(5)]
        self.buffer = bytearray()
        self._finalized = False
        self.rate_bytes = 136
        self.output_bytes = 32

    @staticmethod
    def _rotl64(x: int, n: int) -> int:
        n %= 64
        return ((x << n) & 0xFFFFFFFFFFFFFFFF) | (x >> (64 - n))

    def _keccak_f1600(self):
        for round_num in range(24):
            C = [0] * 5
            D = [0] * 5

            for x in range(5):
                C[x] = (self.state[x][0] ^ self.state[x][1] ^
                        self.state[x][2] ^ self.state[x][3] ^ self.state[x][4])

            for x in range(5):
                D[x] = C[(x - 1) % 5] ^ self._rotl64(C[(x + 1) % 5], 1)

            for x in range(5):
                for y in range(5):
                    self.state[x][y] ^= D[x]

            B = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    # π: транспонирование матрицы
                    new_x = y
                    new_y = (2 * x + 3 * y) % 5
                    # ρ: циклический сдвиг
                    B[new_x][new_y] = self._rotl64(
                        self.state[x][y],
                        self.RHO_OFFSETS[x][y]
                    )

            # χ  шаг
            for x in range(5):
                for y in range(5):
                    self.state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])

            # ι  шаг
            self.state[0][0] ^= self.RC[round_num]

    def _absorb(self):
        rate_bytes = self.rate_bytes


        while len(self.buffer) >= rate_bytes:
            block = bytes(self.buffer[:rate_bytes])

            for i in range(0, rate_bytes, 8):
                chunk = block[i:i + 8]


                word = 0
                for j in range(len(chunk)):
                    word |= chunk[j] << (8 * j)

                word_index = i // 8
                x = word_index % 5
                y = word_index // 5

                # XOR с состоянием
                self.state[x][y] ^= word

            # Применяем перестановку Keccak-f
            self._keccak_f1600()

            del self.buffer[:rate_bytes]

    def update(self, data: bytes):
        if self._finalized:
            raise RuntimeError("Хеш уже завершен. Создайте новый экземпляр.")

        self.buffer.extend(data)
        self._absorb()

    def _pad(self):
        rate_bytes = self.rate_bytes
        buffer_len = len(self.buffer)
        bytes_needed = rate_bytes - (buffer_len % rate_bytes)

        padding = bytearray()

        if bytes_needed == 1:
            padding.append(0x86)
        else:
            padding.append(0x06)

            padding.extend([0] * (bytes_needed - 2))

            padding.append(0x80)

        return bytes(padding)

    def digest(self):
        if not self._finalized:
            padding = self._pad()
            self.buffer.extend(padding)

            self._absorb()

            result = bytearray()
            squeezed = 0

            while squeezed < self.output_bytes:
                for y in range(5):
                    for x in range(5):
                        if squeezed >= self.output_bytes:
                            break

                        word = self.state[x][y]

                        for i in range(8):
                            if squeezed >= self.output_bytes:
                                break
                            result.append((word >> (8 * i)) & 0xFF)
                            squeezed += 1

                if squeezed < self.output_bytes:
                    self._keccak_f1600()

            self._finalized = True
            return bytes(result)

        return bytes(self.output_bytes)

    def hexdigest(self):
        return self.digest().hex()

    def copy(self):
        new = SHA3_256()
        new.state = [row.copy() for row in self.state]
        new.buffer = self.buffer.copy()
        new._finalized = self._finalized
        return new


def sha3_256(data: bytes) -> str:

    hasher = SHA3_256()
    hasher.update(data)
    return hasher.hexdigest()


def sha3_256_bytes(data: bytes) -> bytes:
    hasher = SHA3_256()
    hasher.update(data)
    return hasher.digest()