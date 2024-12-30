import hashlib
import time
import json
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Lightwave Communication Class
class LightwaveCommunication:
    def __init__(self, host="127.0.0.1", port=65432):
        self.host = host
        self.port = port

    def receive(self):
        """Listens for incoming data over a socket connection."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.host, self.port))
                s.listen()
                print(f"Receiver is listening on {self.host}:{self.port}...")
                conn, addr = s.accept()
                with conn:
                    print(f"Connected by {addr}")
                    data = conn.recv(1024)
                    return data
        except Exception as e:
            print(f"Error in receiving data: {e}")
            return None

# Cryptography Class
class Cryptography:
    def __init__(self):
        # Generate RSA keys
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def get_public_key(self):
        """Returns the public key in PEM format."""
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def decrypt(self, ciphertext):
        """Decrypts data using the private key."""
        try:
            plaintext = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None

# Blockchain Classes
class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculates the hash of the block."""
        block_string = f"{self.index}{self.previous_hash}{self.timestamp}{json.dumps(self.transactions)}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty):
        """Mines the block by finding a hash that satisfies the difficulty."""
        while not self.hash.startswith('0' * difficulty):
            self.nonce += 1
            self.hash = self.calculate_hash()

class Blockchain:
    def __init__(self, difficulty=3):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty

    def create_genesis_block(self):
        """Creates the first block in the chain."""
        return Block(0, "0", time.time(), ["Genesis Block"])

    def get_latest_block(self):
        """Returns the most recent block."""
        return self.chain[-1]

    def add_block(self, transactions):
        """Adds a new block to the chain after mining."""
        new_block = Block(len(self.chain), self.get_latest_block().hash, time.time(), transactions)
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

# Main Integration Code
if __name__ == "__main__":
    try:
        # Initialize components
        blockchain = Blockchain()
        comm = LightwaveCommunication()
        crypto = Cryptography()

        # Display the public key (for sender usage)
        public_key = crypto.get_public_key()
        print("Public Key (PEM):")
        print(public_key.decode())

        # Receive encrypted data
        print("Waiting for encrypted data...")
        encrypted_data = comm.receive()
        if not encrypted_data:
            print("No data received. Exiting...")
            exit(1)

        print(f"Encrypted Data Received: {encrypted_data}")

        # Decrypt the received data
        decrypted_data = crypto.decrypt(encrypted_data)
        if decrypted_data is None:
            print("Failed to decrypt the data. Exiting...")
            exit(1)

        # Add the decrypted data to the blockchain
        blockchain.add_block([decrypted_data.decode()])
        print("Decrypted Data added to Blockchain.")

        # Display the blockchain
        for block in blockchain.chain:
            print(f"Block {block.index}:")
            print(f"  Transactions: {block.transactions}")
            print(f"  Hash: {block.hash}")

    except Exception as e:
        print(f"An error occurred: {e}")

