# cryptocore
**A file encryption and decryption tool using AES-128 in ECB mode.**
## Dependencies
- Python 3.8+
- pycryptodome 3.10+

## Build Instructions


## Usage Instructions
example of CLI command
python run.py -algorithm aes -mode ecb -encrypt -key @00112233445566778899aabbccddeeff -input test.txt -output encrypted.bin
python run.py -algorithm aes -mode ecb -decrypt -key @00112233445566778899aabbccddeeff -input encrypted.bin -output decrypted.txt
