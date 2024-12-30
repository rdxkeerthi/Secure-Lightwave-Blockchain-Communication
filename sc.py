# Sender Script
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class SenderLightwaveCommunication:
    def __init__(self, host="127.0.0.1", port=65432):
        self.host = host
        self.port = port

    def send(self, data):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
                s.sendall(data)
                print(f"Data sent to {self.host}:{self.port}")
        except Exception as e:
            print(f"Error in sending data: {e}")

class SenderCryptography:
    def __init__(self, public_key_pem):
        self.public_key = serialization.load_pem_public_key(public_key_pem)

    def encrypt(self, plaintext):
        try:
            ciphertext = self.public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return ciphertext
        except Exception as e:
            print(f"Encryption failed: {e}")
            return None

if __name__ == "__main__":
    # Sender setup
    comm = SenderLightwaveCommunication()

    # Load receiver's public key (copy from receiver output)
    public_key_pem = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Iq6J+fUTXGqmq88haKJ
bageMFMC24upzSqUmqXGiKE76QM9GPdFJtTSk/SyL6bPpvYeNKCfJSQ/vt2aIrud
6sIkxZSLGI9rwJLPRabM2Qc0kKC7fpv4YqcqbZySGrYmPPbxQItw+6Spl8DAXFjZ
KnT8qDk5kjZlZESblTE050m7BYNDTWisd1FvYCaqbx0S2pHuGlT7cVn9iJDSE5aO
amd+oDqNH/nb62A2mUu//4LNr8WIYcBMzFKP5Ib6Pz6IFEK+21a6IYCIINazNZ/W
yc/4CLn2rt32P73SrpD34CTjUxkrVRjMz15nnqb5CeV1uo5Wx9uPNBO8ORAE5Ycu
BwIDAQAB
-----END PUBLIC KEY-----"""

    crypto = SenderCryptography(public_key_pem)

    # Prepare data to send
    plaintext_data = b"Hi! This is a test message."
    encrypted_data = crypto.encrypt(plaintext_data)
    if encrypted_data:
        print(f"Encrypted Data: {encrypted_data}")

        # Send encrypted data
        comm.send(encrypted_data)
