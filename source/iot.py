import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from config import BLOCK_SIZE, CHALLENGE_INDICES
from utils import xor_bytes

class IoTEntity:
    """Base class for encryption utilities."""
    def __init__(self, vault):
        self.vault = vault
        self.session_key = None

    def encrypt(self, key, plaintext):
        cipher = AES.new(key, AES.MODE_ECB) 
        return cipher.encrypt(pad(plaintext, BLOCK_SIZE))

    def decrypt(self, key, ciphertext):
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    
class IoTServer(IoTEntity):
    def __init__(self, vault):
        super().__init__(vault)
        self.active_challenges = {} # Store r1 and C1 per session

    def receive_M1_generate_M2(self, device_id, session_id):
        """
        Process the initial connection request (M1) and generate the first server challenge (M2).
        The method performs the following steps:
        1.  Receives M1, which consists of the Device ID and Session ID
        2.  Verifies the validity of the Device ID
        3.  Generates a random challenge C1 (a set of indices for the vault)
        4.  Generates a random nonce r1
        5.  Stores C1 and r1 in memory to verify the device's response later
        6.  Returns M2 = {C1, r1}
        """
        print(f"[Server] Received M1: Device={device_id}, Session={session_id}")
        
        # Mock verification logic for simulation
        if device_id != "DEV_001":
            raise Exception("Invalid Device ID")

        # Generate Challenge C1 and Nonce r1
        c1 = [secrets.randbelow(self.vault.n) for _ in range(CHALLENGE_INDICES)]
        r1 = secrets.token_bytes(16) 
        
        # Store context for verification later
        self.active_challenges[session_id] = {'c1': c1, 'r1': r1}
        
        return {'c1': c1, 'r1': r1}

    def receive_M3_generate_M4(self, session_id, m3_encrypted):
        """
        Process the Device's response (M3), verify its identity, and generate the Server's response (M4).
        The method performs the following steps:
        1.  Derives key k1 using the challenge indices C1 stored from the previous step
        2.  Decrypts M3 to retrieve the Device's proof (r1), session component (t1), and the Device's challenge (C2, r2)
        3.  Verifies that the received r1 matches the r1 originally sent by the Server
        4.  Derives key k2 from the Device's challenge indices C2
        5.  Generates a random session component t2 and computes the final Session Key (t = t1 XOR t2)
        6.  Encrypts the response payload (r2 || t2) using the key (k2 XOR t1) to create M4
        """
        context = self.active_challenges.get(session_id)
        if not context:
            raise Exception("Session not found")

        # Derive k1 and decrypt M3
        k1 = self.vault.get_derived_key(context['c1'])
        decrypted = self.decrypt(k1, m3_encrypted)
        
        # Parse M3: r1 (16B) | t1 (16B) | r2 (16B) | C2 (Rest)
        rec_r1 = decrypted[:16]
        t1 = decrypted[16:32]
        r2 = decrypted[32:48]
        c2 = list(decrypted[48:]) 

        # Verify Device Identity
        if rec_r1 != context['r1']:
            raise Exception("Server Verification Failed: r1 mismatch")

        # Process Device Challenge (C2)
        k2 = self.vault.get_derived_key(c2)
        t2 = secrets.token_bytes(16)
        
        # Establish Session Key
        self.session_key = xor_bytes(t1, t2)
        
        # Encrypt M4 (Key = k2 XOR t1)
        enc_key = xor_bytes(k2, t1)
        payload = r2 + t2
        m4 = self.encrypt(enc_key, payload)
        
        return m4

class IoTDevice(IoTEntity):
    def generate_M1(self, device_id, session_id):
        """
        Generate the initial connection request M1.
        M1 contains the unique Device ID and Session ID in plaintext because it contains 
        no sensitive security parameters (keys or vaults).
        """
        self.device_id = device_id
        self.session_id = session_id
        print(f"[Device] Generating Connection Request (M1)")
        return {'device_id': device_id, 'session_id': session_id}
    
    def process_M2_generate_M3(self, m2_data):
        """
        Process the Server's Challenge (M2) and generate the Device's Response (M3).
        The method performs the following steps:
        1.  Extracts the Server's challenge indices (C1) and random nonce (r1).
        2.  Derives the temporary encryption key k1 by XORing vault keys at indices C1.
        3.  Generates a random session component (t1).
        4.  Generates a new challenge for the Server (C2) and a random nonce (r2).
        5.  Encrypts the payload (r1 || t1 || r2 || C2) using k1 to create M3.
        """
        c1 = m2_data['c1']
        r1 = m2_data['r1']
        k1 = self.vault.get_derived_key(c1)
        
        # Generate random number t1 for session key generation
        self.t1 = secrets.token_bytes(16)
        
        c2 = [secrets.randbelow(self.vault.n) for _ in range(CHALLENGE_INDICES)]
        self.r2 = secrets.token_bytes(16)
        self.c2 = c2
        payload = r1 + self.t1 + self.r2 + bytes(c2)
        
        return self.encrypt(k1, payload)

    def process_M4(self, m4_encrypted):
        """
        Process the Server's Response (M4), verify its identity, and derive the Session Key.
        The method performs the following steps:
        1.  Derives key k2 using the challenge indices C2 sent in the previous step.
        2.  Calculates the decryption key (k2 XOR t1).
        3.  Decrypts M4 to retrieve the Server's verification (r2) and session component (t2).
        4.  Verifies that received r2 matches the r2 originally generated by the Device.
        5.  Derives the final Session Key (t = t1 XOR t2).
        """
        k2 = self.vault.get_derived_key(self.c2)
        dec_key = xor_bytes(k2, self.t1)
        decrypted = self.decrypt(dec_key, m4_encrypted)
        
        rec_r2 = decrypted[:16]
        t2 = decrypted[16:]

        # If rec_r2 matches our self.r2, the Server correctly derived k2, so it has the Vault.
        if rec_r2 != self.r2: 
            raise Exception("Device Verification Failed: r2 mismatch")
        
        self.session_key = xor_bytes(self.t1, t2)
        print(f"[Device] Session established. Key: {self.session_key.hex()[:10]}...")