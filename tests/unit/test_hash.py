
import unittest
import tempfile
import os
import sys
import hashlib


sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


try:
    from cryptocore.hash.sha256 import SHA256
    from cryptocore.hash.sha3_256 import SHA3_256

    HAS_HASH = True
except ImportError:
    HAS_HASH = False
    print("Warning: Hash modules not found. Skipping hash tests.")


@unittest.skipIf(not HAS_HASH, "Hash modules not available")
class TestHashFunctions(unittest.TestCase):

    def test_sha256_nist_vectors(self):

        test_vectors = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ]

        for data, expected in test_vectors:
            with self.subTest(data=data):
                sha256 = SHA256()
                sha256.update(data)
                result = sha256.hexdigest()
                self.assertEqual(result.lower(), expected.lower())

    def test_sha3_256_nist_vectors(self):

        test_vectors = [
            (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        ]

        for data, expected in test_vectors:
            with self.subTest(data=data):
                sha3_256 = SHA3_256()
                sha3_256.update(data)
                result = sha3_256.hexdigest()
                self.assertEqual(result.lower(), expected.lower())

    def test_empty_input(self):

        # SHA-256
        sha256 = SHA256()
        sha256.update(b"")
        result1 = sha256.hexdigest()
        self.assertEqual(result1, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        # SHA3-256
        sha3_256 = SHA3_256()
        sha3_256.update(b"")
        result2 = sha3_256.hexdigest()
        self.assertEqual(result2, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")

    def test_compatibility_with_hashlib(self):

        test_data = b"Test data for compatibility check"

        # SHA-256
        sha256 = SHA256()
        sha256.update(test_data)
        our_sha256 = sha256.hexdigest()

        expected_sha256 = hashlib.sha256(test_data).hexdigest()
        self.assertEqual(our_sha256, expected_sha256)


        try:
            sha3_256 = SHA3_256()
            sha3_256.update(test_data)
            our_sha3_256 = sha3_256.hexdigest()

            expected_sha3_256 = hashlib.sha3_256(test_data).hexdigest()
            self.assertEqual(our_sha3_256, expected_sha3_256)
        except (ImportError, AttributeError):
            self.skipTest("hashlib.sha3_256 not available")

    def test_chunk_processing(self):

        # Создаем файл среднего размера
        file_size = 10 * 1024  # 10KB

        with tempfile.NamedTemporaryFile(delete=False, mode='wb', suffix='.bin') as f:
            # Пишем случайные данные
            written = 0
            while written < file_size:
                chunk = os.urandom(min(1024, file_size - written))
                f.write(chunk)
                written += len(chunk)
            temp_file = f.name

        try:

            hashlib_hash = hashlib.sha256()
            with open(temp_file, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    hashlib_hash.update(chunk)
            expected = hashlib_hash.hexdigest()

            # Вычисляем хеш нашей реализацией
            sha256 = SHA256()
            with open(temp_file, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sha256.update(chunk)
            our_hash = sha256.hexdigest()

            self.assertEqual(our_hash, expected)

        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_avalanche_effect(self):
        data1 = b"Hello, world!"
        data2 = b"Hello, world?"

        sha256_1 = SHA256()
        sha256_1.update(data1)
        hash1 = sha256_1.hexdigest()

        sha256_2 = SHA256()
        sha256_2.update(data2)
        hash2 = sha256_2.hexdigest()

        int1 = int(hash1, 16)
        int2 = int(hash2, 16)

        diff_bits = bin(int1 ^ int2).count('1')

        print(f"\nSHA-256 Avalanche effect test:")
        print(f"  Bits changed: {diff_bits}/256 ({diff_bits / 256:.1%})")

        self.assertGreater(diff_bits, 50)
        self.assertLess(diff_bits, 200)


def run_hash_tests():
    print("=" * 60)
    print("RUNNING HASH FUNCTION TESTS (SPRINT 4)")
    print("=" * 60)

    if not HAS_HASH:
        print("SKIPPING: Hash modules not found")
        print("Make sure you have created:")
        print("  src/cryptocore/hash/sha256.py")
        print("  src/cryptocore/hash/sha3_256.py")
        return False

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestHashFunctions)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 60)
    print("TEST SUMMARY:")
    print(f"  Tests run: {result.testsRun}")
    print(f"  Failures: {len(result.failures)}")
    print(f"  Errors: {len(result.errors)}")
    print(f"  Skipped: {len(result.skipped)}")
    print("=" * 60)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_hash_tests()
    sys.exit(0 if success else 1)