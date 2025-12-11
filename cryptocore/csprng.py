import os

def generate_random_bytes(num_bytes: int) -> bytes:
    if num_bytes <= 0:
        raise ValueError("Number of bytes must be positive")
    try:
        return os.urandom(num_bytes)
    except Exception as e:
        raise OSError(f"Failed to generated random bytes: {str(e)}")

def generate_key() -> bytes:
    return generate_random_bytes(16)

def generate_iv() -> bytes:
    return generate_random_bytes(16)
