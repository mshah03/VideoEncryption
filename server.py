import socket
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import struct
import hashlib
import time

# AES encryption setup
key = os.urandom(32)  # AES-256 key
iv = os.urandom(16)  # Initialization vector
backend = default_backend()

# Create socket
ip_addr = '192.168.11.85'
port_no = 9999
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((ip_addr, port_no))  # Use your local network IP
server_socket.listen(5)
print(f"Server listening on {ip_addr}: {port_no}")
conn, addr = server_socket.accept()
print(f"Connection from: {addr}")

# Send key and IV to client (this must be done securely in a real application)
conn.sendall(key + iv)

# Use ffmpeg to read and stream video file with +faststart
ffmpeg_process = subprocess.Popen(
    ['ffmpeg', '-i', '/home/stuti/Downloads/input.mp4', '-f', 'mpegts', '-'],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

chunk_id = 0
transmission_latencies = []
encryption_latencies = []

while True:
    chunk = ffmpeg_process.stdout.read(1024)
    if not chunk:
        break

    # Calculate hash of the original chunk
    original_chunk_hash = hashlib.sha256(chunk).digest()

    # Pad the chunk
    padder = padding.PKCS7(128).padder()
    padded_chunk = padder.update(chunk) + padder.finalize()

    # Encrypt the chunk
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    start_time = time.time()
    encrypted_chunk = encryptor.update(padded_chunk) + encryptor.finalize()
    encryption_latency = time.time() - start_time
    encryption_latencies.append(encryption_latency)

    # Create a message with chunk ID, hash, and encrypted data
    chunk_id_bytes = struct.pack('Q', chunk_id)
    hash_size = struct.pack('Q', len(original_chunk_hash))
    message_size = struct.pack('Q', len(encrypted_chunk))
    conn.sendall(chunk_id_bytes + hash_size + original_chunk_hash + message_size + encrypted_chunk)

    print(f"Sent chunk ID: {chunk_id}, Size: {len(encrypted_chunk)}, Encryption Latency: {encryption_latency:.6f} seconds")
    chunk_id += 1

# Send end-of-stream marker
end_marker = b'END'
conn.sendall(struct.pack('Q', chunk_id) + struct.pack('Q', len(end_marker)) + end_marker)

conn.close()
server_socket.close()

stdout, stderr = ffmpeg_process.communicate()

if ffmpeg_process.returncode != 0:
    print("ffmpeg error occured")
    print(stderr.decode())

# Save encryption latencies to file
with open('encryption_latencies.txt', 'w') as f:
    for latency in encryption_latencies:
        f.write(f"{latency}\n")

# Save transmission latencies to file
with open('transmission_latencies.txt', 'w') as f:
    for latency in transmission_latencies:
        f.write(f"{latency}\n")
