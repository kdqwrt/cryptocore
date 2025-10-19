import os


def read_file(file_path: str) -> bytes:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Файл не найден: {file_path}")

    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except IOError as e:
        raise Exception(f"Ошибка чтения файла: {str(e)}")


def write_file(file_path: str, data: bytes):
    try:

        directory = os.path.dirname(file_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        with open(file_path, 'wb') as f:
            f.write(data)
    except IOError as e:
        raise Exception(f"Ошибка записи файла: {str(e)}")