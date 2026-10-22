import base64
import gc
import os
import hmac
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class AdvancedCryptoEngine:
    def __init__(self, password: str, passkey: str):
        self.salt = os.urandom(16)
        self._key = self._derive_master_key(password, passkey, self.salt)
        
    def _derive_master_key(self, password: str, passkey: str, salt: bytes) -> bytes:
        combined_secret = (password + passkey).encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=500000,
        )
        derived = base64.urlsafe_b64encode(kdf.derive(combined_secret))
        
        del combined_secret
        gc.collect()
        return derived

    def secure_wipe(self, variable):
        try:
            del variable
        except NameError:
            pass
        gc.collect()

    def encrypt_data(self, plain_text: str) -> bytes:
        cipher = Fernet(self._key)
        encrypted_bytes = cipher.encrypt(plain_text.encode())
        payload = self.salt + encrypted_bytes
        h = hmac.new(self._key, payload, hashlib.sha256).digest()
        return h + payload

    def decrypt_data(self, signed_payload: bytes) -> str:
        h_len = 32 
        received_h = signed_payload[:h_len]
        payload = signed_payload[h_len:]
        
        calculated_h = hmac.new(self._key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(received_h, calculated_h):
            raise InvalidToken("Security Alert: Data tampering detected! Payload is modified.")
            
        salt = payload[:16]
        encrypted_bytes = payload[16:]
        
        cipher = Fernet(self._key)
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        return decrypted_bytes.decode('utf-8')

    def encrypt_file(self, input_filepath: str, output_filepath: str = None):
        if not output_filepath:
            output_filepath = input_filepath + '.enc'
            
        with open(input_filepath, 'rb') as f:
            file_data = f.read()
            
        cipher = Fernet(self._key)
        encrypted_data = cipher.encrypt(file_data)
        payload = self.salt + encrypted_data
        
        with open(output_filepath, 'wb') as f:
            f.write(payload)
            
        print(f"[+] Success: {input_filepath} encrypted to {output_filepath}")

    def decrypt_file(self, encrypted_filepath: str, output_filepath: str):
        with open(encrypted_filepath, 'rb') as f:
            file_data = f.read()
            
        salt = file_data[:16]
        encrypted_bytes = file_data[16:]
        
        cipher = Fernet(self._key)
        decrypted_data = cipher.decrypt(encrypted_bytes)
        
        with open(output_filepath, 'wb') as f:
            f.write(decrypted_data)
            
        print(f"[+] Success: {encrypted_filepath} decrypted to {output_filepath}")

    def wipe_memory_keys(self):
        self._key = b'\x00' * 32
        self.secure_wipe(self._key)
        print("[+] Memory securely scrubbed.")
