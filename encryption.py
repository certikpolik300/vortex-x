import os
import struct
import hashlib
import hmac
import zlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import json
import time
import qrcode
from cryptogamax import gamax  # Importing the GamaX library

class ECDH:
    @staticmethod
    def generate_keypair():
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def derive_shared_key(private_key, peer_public_key):
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA3_512(),
            length=64,
            salt=None,
            info=b'EMProto Key Exchange',
            backend=default_backend()
        ).derive(shared_secret)
        return derived_key

    @staticmethod
    def generate_verification_code(public_key1, public_key2):
        combined_keys = public_key1.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ) + public_key2.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        hash_obj = hashlib.sha3_512(combined_keys).hexdigest()
        short_code = int(hash_obj[:10], 16)
        qr = qrcode.QRCode()
        qr.add_data(hash_obj)
        qr_code = qr.make_image(fill='black', back_color='white')
        return short_code, qr_code

class AESCTR:
    @staticmethod
    def encrypt(key, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv, ciphertext

    @staticmethod
    def decrypt(key, iv, ciphertext):
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

class RSA:
    @staticmethod
    def generate_keypair():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def encrypt(public_key, data):
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA3_512()),
                algorithm=hashes.SHA3_512(),
                label=None
            )
        )

    @staticmethod
    def decrypt(private_key, ciphertext):
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA3_512()),
                algorithm=hashes.SHA3_512(),
                label=None
            )
        )

class MessageEncryption:
    @staticmethod
    def encrypt(auth_key, message):
        salt = os.urandom(8)
        session_id = os.urandom(8)
        seq_number = struct.pack("Q", int.from_bytes(os.urandom(8), 'big') % (2**32))
        timestamp = struct.pack("Q", int.from_bytes(os.urandom(8), 'big'))
        payload = salt + session_id + seq_number + timestamp + message.encode()

        msg_key = hashlib.sha3_512(payload).digest()[:32]

        # Use GamaX for encryption
        gamax_cipher = gamax(auth_key)
        encrypted_data, mac, nonce = gamax_cipher.encrypt(payload)

        return msg_key + nonce + mac + encrypted_data

    @staticmethod
    def decrypt(auth_key, encrypted_message):
        msg_key = encrypted_message[:32]
        nonce = encrypted_message[32:64]
        mac = encrypted_message[64:96]
        ciphertext = encrypted_message[96:]

        gamax_cipher = gamax(auth_key)
        decrypted_payload = gamax_cipher.decrypt(ciphertext, mac, nonce)

        message = decrypted_payload[32:].decode()

        return message

class FileEncryption:
    @staticmethod
    def encrypt(auth_key, file_path):
        with open(file_path, 'rb') as f:
            file_data = f.read()

        salt = os.urandom(8)
        session_id = os.urandom(8)
        seq_number = struct.pack("Q", int.from_bytes(os.urandom(8), 'big') % (2**32))
        timestamp = struct.pack("Q", int.from_bytes(os.urandom(8), 'big'))
        payload = salt + session_id + seq_number + timestamp + file_data

        msg_key = hashlib.sha3_512(payload).digest()[:32]
        aes_key = hashlib.sha3_512(auth_key + msg_key).digest()  # Derive AES key only for file encryption

        iv, ciphertext = AESCTR.encrypt(aes_key, payload)

        return msg_key + iv + ciphertext

    @staticmethod
    def decrypt(auth_key, encrypted_data, output_path):
        msg_key = encrypted_data[:32]
        iv = encrypted_data[32:48]
        ciphertext = encrypted_data[48:]

        aes_key = hashlib.sha3_512(auth_key + msg_key).digest()
        decrypted_payload = AESCTR.decrypt(aes_key, iv, ciphertext)

        with open(output_path, 'wb') as f:
            f.write(decrypted_payload[32:])

class SecurityUtils:
    @staticmethod
    def verify_message_integrity(auth_key, decrypted_message, expected_msg_key):
        calculated_msg_key = hashlib.sha3_512(auth_key + decrypted_message.encode()).digest()[:32]
        return hmac.compare_digest(calculated_msg_key, expected_msg_key)

class SecureKeyStorage:
    def __init__(self, storage_path):
        self.storage_path = storage_path
        self.keys = self.load_keys()

    def load_keys(self):
        if os.path.exists(self.storage_path):
            with open(self.storage_path, 'r') as f:
                return json.load(f)
        else:
            return {}

    def save_keys(self):
        with open(self.storage_path, 'w') as f:
            json.dump(self.keys, f)

    def generate_new_key(self):
        new_key = gamax().generate_strong_key()  # Use GamaX for key generation
        key_id = hashlib.sha256(new_key).hexdigest()
        self.keys[key_id] = {
            'key': new_key.hex(),
            'timestamp': time.time()
        }
        self.save_keys()
        return key_id, new_key

    def get_key(self, key_id):
        key_data = self.keys.get(key_id)
        if key_data:
            return bytes.fromhex(key_data['key'])
        else:
            return None

    def rotate_keys(self, rotation_interval):
        current_time = time.time()
        for key_id in list(self.keys.keys()):
            if current_time - self.keys[key_id]['timestamp'] > rotation_interval:
                del self.keys[key_id]
                self.generate_new_key()

        self.save_keys()
