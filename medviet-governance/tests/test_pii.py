# tests/test_pii.py
import pytest
import pandas as pd
from src.pii.anonymizer import MedVietAnonymizer


@pytest.fixture(scope="module")
def anonymizer():
    return MedVietAnonymizer()


@pytest.fixture(scope="module")
def sample_df():
    return pd.read_csv("data/raw/patients_raw.csv").head(50)


class TestPIIDetection:

    def test_cccd_detected(self, anonymizer):
        text = "Bệnh nhân Nguyen Van A, CCCD: 012345678901"
        results = anonymizer.analyzer.analyze(
            text=text, language="vi", entities=["VN_CCCD"]
        )
        assert len(results) >= 1

    def test_phone_detected(self, anonymizer):
        text = "Liên hệ: 0912345678"
        results = anonymizer.analyzer.analyze(
            text=text, language="vi", entities=["VN_PHONE"]
        )
        assert len(results) >= 1

    def test_email_detected(self, anonymizer):
        text = "Email: nguyenvana@gmail.com"
        results = anonymizer.analyzer.analyze(
            text=text, language="vi", entities=["EMAIL_ADDRESS"]
        )
        assert len(results) >= 1

    def test_detection_rate_above_95_percent(self, anonymizer, sample_df):
        """Pipeline phải đạt >95% detection rate trên các cột PII."""
        pii_columns = ["ho_ten", "cccd", "so_dien_thoai", "email"]
        rate = anonymizer.calculate_detection_rate(sample_df, pii_columns)
        print(f"\nDetection rate: {rate:.2%}")
        assert rate >= 0.95, f"Detection rate {rate:.2%} < 95%"


class TestAnonymization:

    def test_pii_not_in_output(self, anonymizer, sample_df):
        """Sau anonymization, không còn CCCD gốc trong cột cccd của output."""
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        anon_cccd_values = df_anon["cccd"].astype(str).tolist()
        for original_cccd in sample_df["cccd"]:
            assert str(original_cccd) not in anon_cccd_values, (
                f"Original CCCD '{original_cccd}' vẫn còn trong anonymized data!"
            )

    def test_non_pii_columns_unchanged(self, anonymizer, sample_df):
        """Cột benh và ket_qua_xet_nghiem phải giữ nguyên sau anonymization."""
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        assert df_anon["benh"].equals(sample_df["benh"]), \
            "Cột 'benh' bị thay đổi!"
        assert df_anon["ket_qua_xet_nghiem"].equals(sample_df["ket_qua_xet_nghiem"]), \
            "Cột 'ket_qua_xet_nghiem' bị thay đổi!"

    def test_patient_id_unchanged(self, anonymizer, sample_df):
        """patient_id phải giữ nguyên (pseudonym đã đủ an toàn)."""
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        assert df_anon["patient_id"].equals(sample_df["patient_id"])

    def test_anonymized_cccd_format(self, anonymizer, sample_df):
        """CCCD sau anonymization phải có đúng 12 ký tự số."""
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        for cccd in df_anon["cccd"].astype(str):
            assert len(cccd) == 12 and cccd.isdigit(), \
                f"CCCD anonymized không hợp lệ: '{cccd}'"

    def test_anonymized_phone_format(self, anonymizer, sample_df):
        """SĐT sau anonymization phải bắt đầu bằng 0[3|5|7|8|9]."""
        import re
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        pattern = re.compile(r"^0[35789]\d{8}$")
        for phone in df_anon["so_dien_thoai"].astype(str):
            assert pattern.match(phone), \
                f"SĐT anonymized không hợp lệ: '{phone}'"
