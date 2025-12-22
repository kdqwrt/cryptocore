from cryptocore.csprng import generate_random_bytes

total_size = 10_000_000  # 10 MB
output_file = 'nist_test_data.bin'

bytes_written = 0
with open(output_file, 'wb') as f:
    while bytes_written < total_size:
        chunk_size = min(4096, total_size - bytes_written)
        random_chunk = generate_random_bytes(chunk_size)
        f.write(random_chunk)
        bytes_written += len(random_chunk)

print(f"Generated {bytes_written} bytes for NIST testing in '{output_file}'")