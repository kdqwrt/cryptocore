from Crypto.Cipher import AES


def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    block_size = 16  # 128 бит


    if len(key) != 16:
        raise ValueError("Key must be 16 bytes (128 bits) for AES-128")


    cipher = AES.new(key, AES.MODE_ECB)


    blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        blocks.append(block)

    if blocks:
        last_block = blocks[-1]
        padding_needed = block_size - len(last_block)
    else:

        last_block = b''
        padding_needed = block_size
        blocks.append(last_block)

    if padding_needed > 0:
        blocks[-1] = last_block + bytes([padding_needed] * padding_needed)
    else:

        blocks.append(bytes([block_size] * block_size))


    encrypted_blocks = []
    for block in blocks:
        encrypted_block = cipher.encrypt(block)
        encrypted_blocks.append(encrypted_block)

    return b''.join(encrypted_blocks)


def decrypt_ecb(data: bytes, key: bytes) -> bytes:

    block_size = 16

    if len(key) != 16:
        raise ValueError("Key must be 16 bytes (128 bits) for AES-128")

    if len(data) % block_size != 0:
        raise ValueError("Encrypted data must be multiple of block size (16 bytes)")


    cipher = AES.new(key, AES.MODE_ECB)

    blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        blocks.append(block)

    decrypted_blocks = []
    for block in blocks:
        decrypted_block = cipher.decrypt(block)
        decrypted_blocks.append(decrypted_block)

    padded_data = b''.join(decrypted_blocks)

    if not padded_data:
        return b''

    padding_len = padded_data[-1]

    if padding_len < 1 or padding_len > block_size:
        raise ValueError("Invalid padding")


    expected_padding = bytes([padding_len] * padding_len)
    if padded_data[-padding_len:] != expected_padding:
        raise ValueError("Invalid padding bytes")


    return padded_data[:-padding_len]