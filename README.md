# cryptocore
**A file encryption and decryption tool using AES-128 in ECB mode.**
## Dependencies
- Python 3.8+
- pycryptodome 3.10+

## Build Instructions


## Usage Instructions
**example of CLI command:**

**ecb**
python run.py -algorithm aes -mode ecb -encrypt -key @00112233445566778899aabbccddeeff -input test.txt -output encrypted.bin
python run.py -algorithm aes -mode ecb -decrypt -key @00112233445566778899aabbccddeeff -input encrypted.bin -output decrypted.txt
**cbc**
python run.py --algorithm aes --mode cbc --encrypt --key @00112233445566778899aabbccddeeff --input test.txt --output test_cbc.bin
python run.py --algorithm aes --mode cbc --decrypt --key @00112233445566778899aabbccddeeff --input test_cbc.bin --output test_cbc_decrypted.txt
**cfb**
python run.py --algorithm aes --mode cfb --encrypt --key @00112233445566778899aabbccddeeff --input test.txt --output test_cfb.bin
python run.py --algorithm aes --mode cfb --decrypt --key @00112233445566778899aabbccddeeff --input test_cfb.bin --output test_cfb_decrypted.txt
**ofb**
python run.py --algorithm aes --mode ofb --encrypt --key @00112233445566778899aabbccddeeff --input test.txt --output test_ofb.bin
python run.py --algorithm aes --mode ofb --decrypt --key @00112233445566778899aabbccddeeff --input test_ofb.bin --output test_ofb_decrypted.txt
**ctr**
python run.py --algorithm aes --mode ctr --encrypt --key @00112233445566778899aabbccddeeff --input test.txt --output test_ctr.bin
python run.py --algorithm aes --mode ctr --decrypt --key @00112233445566778899aabbccddeeff --input test_ctr.bin --output test_ctr_decrypted.txt
