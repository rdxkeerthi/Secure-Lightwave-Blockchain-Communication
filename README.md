# Secure Lightwave Blockchain Communication System

## Objective:

To develop a secure communication system using blockchain for data authentication and transaction monitoring while leveraging lightwave (e.g., laser or optical) communication to transmit data between nodes.

## Key Components:

1. **Blockchain Layer:**
    - A decentralized network to manage transactions and verify data integrity.
    - Each node in the blockchain will store a record of all transactions and communications.
    - Smart contracts for automated transaction validation.

2. **Lightwave Communication Layer:**
    - Data transmission using lightwaves (e.g., infrared or visible laser communication).
    - High-speed and secure point-to-point data transfer.
    - Error correction mechanisms to ensure reliable communication.

3. **Cryptography Layer:**
    - Advanced encryption algorithms (e.g., AES-256, RSA) to encrypt data before transmission.
    - Digital signatures for authentication of data sources.
    - Public and private keys managed via blockchain for added security.

## How to Run the Code 

**For GUI**
1. Clone the repository.
2. Install the required packages using pip: `pip install -r requirements.txt`
3. `cd GUI`
4. Run the Server file first `python3 server.py`
5. Copy the Pem Key from the Server 
6. Then run the Client file `python3 sender.py`
7. Paste the Pem Key in the Box at the Sender GUI



# Next Update 

### To send this Encrypted Data Through LightWave To Test any loss in the Dataset 