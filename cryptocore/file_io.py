import os


def read_file(filename: str) -> bytes:
    with open(filename, 'rb') as f:
        return f.read()


def write_file(filename: str, data: bytes):
    os.makedirs(os.path.dirname(filename) if os.path.dirname(filename) else '.',
                exist_ok=True)
    with open(filename, 'wb') as f:
        f.write(data)


def read_file_with_iv(filename: str):
    data = read_file(filename)
    if len(data) < 16:
        raise ValueError("File is too short to contain IV (less than 16 bytes)")

    iv = data[:16]
    actual_data = data[16:]
    return iv, actual_data


def write_file_with_iv(filename: str, iv: bytes, data: bytes):
    write_file(filename, iv + data)