import hashlib
import time
import json
import socket
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class LightwaveCommunication:
    def __init__(self, host="127.0.0.1", port=65432):
        self.host = host
        self.port = port

    def receive(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            conn, addr = s.accept()
            with conn:
                data = conn.recv(1024 * 1024)  # Receive larger files
                return data

class Cryptography:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def get_public_key(self):
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def decrypt(self, ciphertext):
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def decrypt_file(self, encrypted_file_data, chunk_size=256):  # Decrypt file chunks
        decrypted_data = b""
        for i in range(0, len(encrypted_file_data), chunk_size):
            chunk = encrypted_file_data[i:i + chunk_size]
            decrypted_data += self.decrypt(chunk)
        return decrypted_data

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return {"index": 0, "previous_hash": "0", "transactions": ["Genesis Block"], "hash": "0"}

    def add_block(self, transactions):
        previous_block = self.chain[-1]
        block = {
            "index": len(self.chain),
            "previous_hash": previous_block["hash"],
            "transactions": transactions,
            "hash": hashlib.sha256(json.dumps(transactions).encode()).hexdigest()
        }
        self.chain.append(block)

# GUI for Server
class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Server - Blockchain Receiver")
        self.root.configure(bg="#f0f4f8")

        self.crypto = Cryptography()
        self.comm = LightwaveCommunication()
        self.blockchain = Blockchain()

        # Display Public Key
        tk.Label(root, text="Public Key:", font=("Helvetica", 12), bg="#f0f4f8", fg="#333333").pack(pady=5)
        self.public_key_text = tk.Text(root, height=5, width=50, bg="#ffffff", fg="#333333", font=("Courier", 10))
        self.public_key_text.pack(pady=5)
        self.public_key_text.insert(tk.END, self.crypto.get_public_key().decode())
        self.public_key_text.config(state=tk.DISABLED)

        # Log of received messages
        tk.Label(root, text="Received Messages:", font=("Helvetica", 12), bg="#f0f4f8", fg="#333333").pack(pady=5)
        self.log = tk.Listbox(root, height=10, width=50, bg="#e8f4fc", fg="#003366", font=("Arial", 10))
        self.log.pack(pady=5)

        # Blockchain updates
        tk.Label(root, text="Blockchain:", font=("Helvetica", 12), bg="#f0f4f8", fg="#333333").pack(pady=5)
        self.blockchain_log = tk.Listbox(root, height=10, width=50, bg="#e8f4fc", fg="#003366", font=("Arial", 10))
        self.blockchain_log.pack(pady=5)

        # Save File Button
        self.save_file_button = tk.Button(root, text="Save Received File", command=self.save_file, bg="#ff9800", fg="#ffffff", font=("Helvetica", 12), relief="flat")
        self.save_file_button.pack(pady=10)

        # Start button
        self.start_button = tk.Button(root, text="Start Listening", command=self.start_listening, bg="#4caf50", fg="#ffffff", font=("Helvetica", 12), relief="flat")
        self.start_button.pack(pady=10)

        self.received_file_data = None

    def start_listening(self):
        self.start_button.config(state=tk.DISABLED)
        self.listen_for_messages()

    def listen_for_messages(self):
        encrypted_data = self.comm.receive()
        if encrypted_data:
            try:
                decrypted_data = self.crypto.decrypt_file(encrypted_data)
                self.log.insert(tk.END, "Message/File received.")

                # Check if it's a file (binary data)
                if decrypted_data.startswith(b"\x89PNG") or b"JFIF" in decrypted_data:
                    self.received_file_data = decrypted_data
                    self.log.insert(tk.END, "Received a file. Ready to save.")
                else:
                    self.log.insert(tk.END, f"Message: {decrypted_data.decode(errors='ignore')}")

                self.blockchain.add_block([decrypted_data])
                self.blockchain_log.insert(tk.END, json.dumps(self.blockchain.chain[-1], indent=2))
            except Exception as e:
                self.log.insert(tk.END, f"Decryption failed: {e}")
        self.root.after(100, self.listen_for_messages)  # Continuous listening

    def save_file(self):
        if self.received_file_data:
            file_path = filedialog.asksaveasfilename(defaultextension="*.*", title="Save File")
            if file_path:
                with open(file_path, "wb") as file:
                    file.write(self.received_file_data)
                self.log.insert(tk.END, f"File saved to {file_path}")
                self.received_file_data = None
        else:
            self.log.insert(tk.END, "No file to save.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()
