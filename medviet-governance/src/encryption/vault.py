# src/encryption/vault.py
import os
import base64
import json

import pandas as pd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SimpleVault:
    """
    Envelope encryption pattern (thay thế AWS KMS cho local dev).

    Architecture:
        Master Key (KEK) → encrypts → Data Key (DEK) → encrypts → Data

    QUAN TRỌNG: Trong production, KEK phải lưu trong HSM/KMS, không phải file.
    """

    def __init__(self, master_key_path: str = ".vault_key"):
        self.master_key_path = master_key_path
        self.kek = self._load_or_create_kek()

    def _load_or_create_kek(self) -> bytes:
        """Load KEK từ file nếu tồn tại, ngược lại generate và lưu."""
        if os.path.exists(self.master_key_path):
            with open(self.master_key_path, "rb") as f:
                return base64.b64decode(f.read())
        else:
            kek = os.urandom(32)  # 256-bit key
            with open(self.master_key_path, "wb") as f:
                f.write(base64.b64encode(kek))
            return kek

    def generate_dek(self) -> tuple[bytes, bytes]:
        """Generate Data Encryption Key mới. Trả về (plaintext_dek, encrypted_dek)."""
        plaintext_dek = os.urandom(32)

        aesgcm = AESGCM(self.kek)
        nonce = os.urandom(12)
        encrypted_dek = nonce + aesgcm.encrypt(nonce, plaintext_dek, None)

        return plaintext_dek, encrypted_dek

    def decrypt_dek(self, encrypted_dek: bytes) -> bytes:
        """Decrypt encrypted DEK bằng KEK. Trả về plaintext DEK."""
        nonce = encrypted_dek[:12]
        ciphertext = encrypted_dek[12:]
        aesgcm = AESGCM(self.kek)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def encrypt_data(self, plaintext: str) -> dict:
        """
        Envelope encryption:
        1. Generate DEK mới
        2. Encrypt data bằng plaintext DEK (AES-256-GCM)
        3. Xóa plaintext DEK khỏi memory
        4. Trả về dict {encrypted_dek, ciphertext, algorithm}
        """
        plaintext_dek, encrypted_dek = self.generate_dek()

        aesgcm = AESGCM(plaintext_dek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

        del plaintext_dek

        return {
            "encrypted_dek": base64.b64encode(encrypted_dek).decode(),
            "ciphertext": base64.b64encode(nonce + ciphertext).decode(),
            "algorithm": "AES-256-GCM"
        }

    def decrypt_data(self, encrypted_payload: dict) -> str:
        """
        Decrypt từ envelope encryption payload:
        1. Decrypt DEK bằng KEK
        2. Decrypt data bằng DEK
        3. Trả về plaintext string
        """
        encrypted_dek = base64.b64decode(encrypted_payload["encrypted_dek"])
        ciphertext_with_nonce = base64.b64decode(encrypted_payload["ciphertext"])

        plaintext_dek = self.decrypt_dek(encrypted_dek)
        nonce = ciphertext_with_nonce[:12]
        ciphertext = ciphertext_with_nonce[12:]

        aesgcm = AESGCM(plaintext_dek)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        del plaintext_dek

        return plaintext.decode()

    def encrypt_column(self, df: pd.DataFrame, column: str) -> pd.DataFrame:
        """Encrypt một cột trong DataFrame, thay bằng JSON string của encrypted payload."""
        df = df.copy()
        df[column] = df[column].apply(
            lambda x: json.dumps(self.encrypt_data(str(x)))
        )
        return df
