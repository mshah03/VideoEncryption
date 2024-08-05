import time
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import struct
import subprocess
import hashlib

# Create socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('192.168.11.85', 9999))  # Use the server's IP address

# Receive key and IV from server
key_iv = client_socket.recv(48)
key = key_iv[:32]
iv = key_iv[32:]
backend = default_backend()

buffer = b''

# Start ffplay as a subprocess
ffplay_process = subprocess.Popen(['ffplay','-autoexit', '-'], stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

payload_size = struct.calcsize('Q')

decryption_latencies = []

try:
    while True:
        # Receive chunk ID
        chunk_id_bytes = client_socket.recv(payload_size)
        if not chunk_id_bytes:
            break
        chunk_id = struct.unpack('Q', chunk_id_bytes)[0]

        # Receive hash size
        hash_size_bytes = client_socket.recv(payload_size)
        hash_size = struct.unpack('Q', hash_size_bytes)[0]

        # Receive original chunk hash
        original_chunk_hash = client_socket.recv(hash_size)

        # Receive message size
        message_size_bytes = client_socket.recv(payload_size)
        if not message_size_bytes:
            break
        message_size = struct.unpack('Q', message_size_bytes)[0]

        if message_size == 0:
            print("End of stream")
            break

        # Read the encrypted chunk based on the received size
        while len(buffer) < message_size:
            encrypted_chunk = client_socket.recv(min(1024, message_size - len(buffer)))
            if not encrypted_chunk:
                break
            buffer += encrypted_chunk

        if len(buffer) < message_size:
            print(f"Incomplete chunk received for chunk ID: {chunk_id}")
            break

        encrypted_data = buffer[:message_size]
        buffer = buffer[message_size:]

        start_time = time.time()  # Start time for latency measurement

        # Decrypt chunk
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_chunk = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad the decrypted chunk
        try:
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_chunk = unpadder.update(decrypted_chunk) + unpadder.finalize()
        except ValueError as e:
            print(f"Unpadding error: {e}")
            break

        end_time = time.time()  # End time for latency measurement
        decryption_latencies.append(end_time - start_time)

        # Verify the hash of the decrypted chunk
        decrypted_chunk_hash = hashlib.sha256(decrypted_chunk).digest()
        if decrypted_chunk_hash != original_chunk_hash:
            print(f"Data mismatch for chunk ID: {chunk_id}")
        else:
            print(f"Data integrity verified for chunk ID: {chunk_id}")

        # Write decrypted data to ffplay
        try:
            ffplay_process.stdin.write(decrypted_chunk)
        except Exception as e:
            print(f"Error writing to ffplay: {e}")
            break

except Exception as e:
    print(f"Error: {e}")

finally:
    client_socket.close()
    ffplay_process.stdin.close()
    ffplay_process.wait()

# Save decryption latencies to a file
with open('decryption_latencies.txt', 'w') as f:
    for latency in decryption_latencies:
        f.write(f"{latency}\n")
