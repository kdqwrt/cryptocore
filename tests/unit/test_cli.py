import subprocess
import tempfile
import os
import sys


def test_derive_basic():

    result = subprocess.run(
        [sys.executable, '-m', 'cryptocore.cli', 'derive',
         '--password', 'test123',
         '--salt', 'a1b2c3d4e5f601234567890123456789',
         '--iterations', '1000',
         '--length', '32'],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0

    output = result.stdout.strip()
    key_hex, salt_hex = output.split()
    assert len(key_hex) == 64  # 32 байта в hex
    assert len(salt_hex) == 32  # 16 байт в hex


def test_derive_with_auto_salt():

    result = subprocess.run(
        [sys.executable, '-m', 'cryptocore.cli', 'derive',
         '--password', 'test123',
         '--iterations', '1000'],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    output = result.stdout.strip()
    key_hex, salt_hex = output.split()
    assert len(salt_hex) == 32  # Автогенерированная соль


def test_derive_with_output_file():

    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
        output_file = f.name

    try:
        result = subprocess.run(
            [sys.executable, '-m', 'cryptocore.cli', 'derive',
             '--password', 'test123',
             '--salt', 'a1b2c3d4e5f601234567890123456789',
             '--output', output_file],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert os.path.exists(output_file)
        assert os.path.getsize(output_file) == 32  # 32 байта ключа
    finally:
        if os.path.exists(output_file):
            os.unlink(output_file)


def test_rfc6070_via_cli():

    result = subprocess.run(
        [sys.executable, '-m', 'cryptocore.cli', 'derive',
         '--password', 'password',
         '--salt', '73616c74',  # "salt" в hex
         '--iterations', '1',
         '--length', '20'],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    key_hex = result.stdout.strip().split()[0]
    expected = '0c60c80f961f0e71f3a9b524af6012062fe037a6'
    assert key_hex == expected, f"Expected {expected}, got {key_hex}"