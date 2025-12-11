import os
from typing import Generator, Tuple


def read_file(filename: str) -> bytes:
    with open(filename, 'rb') as f:
        return f.read()


def read_file_chunks(filename: str, chunk_size: int = 8192) -> Generator[bytes, None, None]:
    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


def write_file(filename: str, data: bytes):
    directory = os.path.dirname(filename)
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(filename, 'wb') as f:
        f.write(data)


def read_file_with_iv(filename: str) -> Tuple[bytes, bytes]:
    data = read_file(filename)

    if len(data) < 16:
        raise ValueError("File is too short to contain IV (less than 16 bytes)")

    iv = data[:16]
    actual_data = data[16:]
    return iv, actual_data


def write_file_with_iv(filename: str, iv: bytes, data: bytes):
    write_file(filename, iv + data)


def get_file_size(filename: str) -> int:
    return os.path.getsize(filename)


def file_exists(filename: str) -> bool:
    return os.path.exists(filename) and os.path.isfile(filename)


def is_file_readable(filename: str) -> bool:
    return os.access(filename, os.R_OK)


def is_file_writable(filename: str) -> bool:
    if os.path.exists(filename):
        return os.access(filename, os.W_OK)
    else:
        # Проверяем доступность директории для записи
        directory = os.path.dirname(filename) or '.'
        return os.access(directory, os.W_OK)