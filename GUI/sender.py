import socket
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class LightwaveCommunication:
    def __init__(self, host="127.0.0.1", port=65432):
        self.host = host
        self.port = port

    def send(self, data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(data)

class Cryptography:
    def __init__(self, public_key_pem):
        self.public_key = serialization.load_pem_public_key(public_key_pem)

    def encrypt(self, plaintext):
        return self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def encrypt_file(self, file_data, chunk_size=190):  # Adjust chunk size to fit RSA encryption
        encrypted_data = b""
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i:i + chunk_size]
            encrypted_data += self.encrypt(chunk)
        return encrypted_data

# GUI for Sender
class SenderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sender - Blockchain Messenger")
        self.root.configure(bg="#f9f9fb")

        self.crypto = None
        self.comm = LightwaveCommunication()

        # Public Key Input
        tk.Label(root, text="Receiver Public Key:", font=("Helvetica", 12), bg="#f9f9fb", fg="#333333").pack(pady=5)
        self.public_key_entry = tk.Text(root, height=5, width=50, bg="#ffffff", fg="#333333", font=("Courier", 10))
        self.public_key_entry.pack(pady=5)

        # Message Input
        tk.Label(root, text="Message:", font=("Helvetica", 12), bg="#f9f9fb", fg="#333333").pack(pady=5)
        self.message_entry = tk.Entry(root, width=50, font=("Arial", 10))
        self.message_entry.pack(pady=5)

        # File Selection
        tk.Label(root, text="Select File/Photo:", font=("Helvetica", 12), bg="#f9f9fb", fg="#333333").pack(pady=5)
        self.file_path = tk.StringVar()
        self.file_entry = tk.Entry(root, textvariable=self.file_path, width=50, font=("Arial", 10))
        self.file_entry.pack(pady=5)
        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file, bg="#1e88e5", fg="#ffffff", font=("Helvetica", 12), relief="flat")
        self.browse_button.pack(pady=5)

        # Log of Sent Messages
        tk.Label(root, text="Sent Messages:", font=("Helvetica", 12), bg="#f9f9fb", fg="#333333").pack(pady=5)
        self.log = tk.Listbox(root, height=10, width=50, bg="#e3f2fd", fg="#003366", font=("Arial", 10))
        self.log.pack(pady=5)

        # Buttons
        self.set_key_button = tk.Button(root, text="Set Public Key", command=self.set_public_key, bg="#1e88e5", fg="#ffffff", font=("Helvetica", 12), relief="flat")
        self.set_key_button.pack(pady=5)

        self.send_button = tk.Button(root, text="Send Message", command=self.send_message, state=tk.DISABLED, bg="#4caf50", fg="#ffffff", font=("Helvetica", 12), relief="flat")
        self.send_button.pack(pady=5)

        self.send_file_button = tk.Button(root, text="Send File/Photo", command=self.send_file, state=tk.DISABLED, bg="#ff9800", fg="#ffffff", font=("Helvetica", 12), relief="flat")
        self.send_file_button.pack(pady=5)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_path.set(file_path)

    def set_public_key(self):
        try:
            public_key_pem = self.public_key_entry.get("1.0", tk.END).strip().encode()
            self.crypto = Cryptography(public_key_pem)
            self.public_key_entry.config(state=tk.DISABLED)
            self.set_key_button.config(state=tk.DISABLED)
            self.send_button.config(state=tk.NORMAL)
            self.send_file_button.config(state=tk.NORMAL)
            self.log.insert(tk.END, "Public Key set successfully!")
        except Exception as e:
            self.log.insert(tk.END, f"Failed to set Public Key: {e}")

    def send_message(self):
        try:
            message = self.message_entry.get().encode()
            encrypted_message = self.crypto.encrypt(message)
            self.comm.send(encrypted_message)
            self.log.insert(tk.END, f"Message sent: {message.decode()}")
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            self.log.insert(tk.END, f"Failed to send message: {e}")

    def send_file(self):
        try:
            file_path = self.file_path.get()
            if not file_path:
                self.log.insert(tk.END, "No file selected.")
                return

            with open(file_path, "rb") as file:
                file_data = file.read()
                encrypted_file_data = self.crypto.encrypt_file(file_data)
                self.comm.send(encrypted_file_data)

            self.log.insert(tk.END, f"File sent: {file_path}")
            self.file_path.set("")
        except Exception as e:
            self.log.insert(tk.END, f"Failed to send file: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SenderGUI(root)
    root.mainloop()
