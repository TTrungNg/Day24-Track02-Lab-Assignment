# src/pii/anonymizer.py
import random
import hashlib

import pandas as pd
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from faker import Faker

from .detector import build_vietnamese_analyzer, detect_pii

fake = Faker("vi_VN")


def _fake_cccd() -> str:
    # Bắt đầu bằng 1-9 để không bị pandas strip leading zero khi đọc CSV
    return str(random.randint(1, 9)) + "".join([str(random.randint(0, 9)) for _ in range(11)])


def _fake_phone() -> str:
    prefix = random.choice(["03", "05", "07", "08", "09"])
    return prefix + "".join([str(random.randint(0, 9)) for _ in range(8)])


class MedVietAnonymizer:

    def __init__(self):
        self.analyzer = build_vietnamese_analyzer()
        self.anonymizer = AnonymizerEngine()

    def anonymize_text(self, text: str, strategy: str = "replace") -> str:
        """Anonymize text với chiến lược được chọn (replace / mask / hash)."""
        results = detect_pii(text, self.analyzer)
        if not results:
            return text

        if strategy == "replace":
            operators = {
                "PERSON": OperatorConfig("replace", {"new_value": fake.name()}),
                "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": fake.email()}),
                "VN_CCCD": OperatorConfig("replace", {"new_value": _fake_cccd()}),
                "VN_PHONE": OperatorConfig("replace", {"new_value": _fake_phone()}),
            }
        elif strategy == "mask":
            operators = {
                "PERSON": OperatorConfig("mask", {
                    "masking_char": "*", "chars_to_mask": 6, "from_end": False
                }),
                "EMAIL_ADDRESS": OperatorConfig("mask", {
                    "masking_char": "*", "chars_to_mask": 5, "from_end": False
                }),
                "VN_CCCD": OperatorConfig("mask", {
                    "masking_char": "*", "chars_to_mask": 8, "from_end": False
                }),
                "VN_PHONE": OperatorConfig("mask", {
                    "masking_char": "*", "chars_to_mask": 6, "from_end": False
                }),
            }
        elif strategy == "hash":
            operators = {
                "PERSON": OperatorConfig("hash", {"hash_type": "sha256"}),
                "EMAIL_ADDRESS": OperatorConfig("hash", {"hash_type": "sha256"}),
                "VN_CCCD": OperatorConfig("hash", {"hash_type": "sha256"}),
                "VN_PHONE": OperatorConfig("hash", {"hash_type": "sha256"}),
            }
        else:
            operators = {}

        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators
        )
        return anonymized.text

    def anonymize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Anonymize toàn bộ DataFrame.
        - ho_ten, dia_chi, email: qua anonymize_text()
        - cccd, so_dien_thoai: replace trực tiếp bằng fake data
        - bac_si_phu_trach: replace bằng fake name
        - benh, ket_qua_xet_nghiem, patient_id, ngay_sinh, ngay_kham: GIỮ NGUYÊN
        """
        df_anon = df.copy()

        df_anon["ho_ten"] = df_anon["ho_ten"].apply(
            lambda x: self.anonymize_text(str(x), strategy="replace")
        )
        df_anon["dia_chi"] = df_anon["dia_chi"].apply(
            lambda x: self.anonymize_text(str(x), strategy="replace")
        )
        df_anon["email"] = df_anon["email"].apply(
            lambda x: self.anonymize_text(str(x), strategy="replace")
        )
        df_anon["cccd"] = [_fake_cccd() for _ in range(len(df_anon))]
        df_anon["so_dien_thoai"] = [_fake_phone() for _ in range(len(df_anon))]

        # Đảm bảo các cột số được lưu dưới dạng string với đúng format
        df_anon["cccd"] = df_anon["cccd"].astype(str)
        df_anon["so_dien_thoai"] = df_anon["so_dien_thoai"].astype(str)
        df_anon["bac_si_phu_trach"] = [fake.name() for _ in range(len(df_anon))]

        return df_anon

    def _normalize_value(self, col: str, value: str) -> str:
        """Zero-pad phone và CCCD nếu pandas đã strip leading zero khi đọc CSV."""
        if col == "so_dien_thoai":
            # SĐT VN luôn 10 chữ số; pandas có thể đọc thành 9 chữ số
            digits = value.strip()
            if digits.isdigit() and len(digits) == 9:
                return "0" + digits
        if col == "cccd":
            # CCCD 12 chữ số; pandas có thể strip leading zero → 11 chữ số
            digits = value.strip()
            if digits.isdigit() and len(digits) == 11:
                return "0" + digits
        return value

    def calculate_detection_rate(self,
                                  original_df: pd.DataFrame,
                                  pii_columns: list) -> float:
        """Tính % cell PII được detect thành công. Mục tiêu: > 95%."""
        total = 0
        detected = 0

        for col in pii_columns:
            for raw_value in original_df[col].astype(str):
                value = self._normalize_value(col, raw_value)
                total += 1
                results = detect_pii(value, self.analyzer)
                if len(results) > 0:
                    detected += 1

        return detected / total if total > 0 else 0.0
