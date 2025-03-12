import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordManager:
    def __init__(self, master_password):
        """Initialize the password manager with a master password"""
        self.key = self._generate_key(master_password)
        self.cipher = Fernet(self.key)
        self.storage_file = "passwords.enc"
        self.passwords = {}
        
        # Load existing passwords if file exists
        if os.path.exists(self.storage_file):
            self.load_passwords()
    
    def _generate_key(self, master_password):
        """Generate encryption key from master password"""
        salt = b'secure_salt_value'  # In a real app, this should be stored securely
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key
    
    def add_password(self, website, username, password):
        """Add or update a password entry"""
        self.passwords[website] = {
            'username': username,
            'password': password
        }
        self.save_passwords()
        
    def get_password(self, website):
        """Retrieve a password entry"""
        if website in self.passwords:
            return self.passwords[website]
        return None
    
    def delete_password(self, website):
        """Delete a password entry"""
        if website in self.passwords:
            del self.passwords[website]
            self.save_passwords()
            return True
        return False
    
    def get_all_websites(self):
        """Return all stored website names"""
        return list(self.passwords.keys())
    
    def save_passwords(self):
        """Encrypt and save passwords to file"""
        encrypted_data = self.cipher.encrypt(json.dumps(self.passwords).encode())
        with open(self.storage_file, 'wb') as file:
            file.write(encrypted_data)
    
    def load_passwords(self):
        """Decrypt and load passwords from file"""
        try:
            with open(self.storage_file, 'rb') as file:
                encrypted_data = file.read()
            decrypted_data = self.cipher.decrypt(encrypted_data)
            self.passwords = json.loads(decrypted_data)
        except Exception as e:
            print(f"Error loading passwords: {e}")
            self.passwords = {}
            
    def verify_master_password(self, master_password):
        """Verify if the provided master password is correct"""
        test_key = self._generate_key(master_password)
        return test_key == self.key