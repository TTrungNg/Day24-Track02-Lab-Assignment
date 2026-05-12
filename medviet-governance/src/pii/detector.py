# src/pii/detector.py
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider


# Tên người Việt Nam: 2-4 từ, mỗi từ bắt đầu bằng chữ hoa (có dấu)
_VN_NAME_REGEX = (
    r"(?<!\w)"
    r"[A-ZÁÀẢÃẠĂẮẰẲẴẶÂẤẦẨẪẬĐÉÈẺẼẸÊẾỀỂỄỆÍÌỈĨỊÓÒỎÕỌÔỐỒỔỖỘƠỚỜỞỠỢÚÙỦŨỤƯỨỪỬỮỰÝỲỶỸỴ]"
    r"[a-záàảãạăắằẳẵặâấầẩẫậđéèẻẽẹêếềểễệíìỉĩịóòỏõọôốồổỗộơớờởỡợúùủũụưứừửữựýỳỷỹỵ]+"
    r"(?:\s"
    r"[A-ZÁÀẢÃẠĂẮẰẲẴẶÂẤẦẨẪẬĐÉÈẺẼẸÊẾỀỂỄỆÍÌỈĨỊÓÒỎÕỌÔỐỒỔỖỘƠỚỜỞỠỢÚÙỦŨỤƯỨỪỬỮỰÝỲỶỸỴ]"
    r"[a-záàảãạăắằẳẵặâấầẩẫậđéèẻẽẹêếềểễệíìỉĩịóòỏõọôốồổỗộơớờởỡợúùủũụưứừửữựýỳỷỹỵ]+"
    r"){1,3}"
    r"(?!\w)"
)


def build_vietnamese_analyzer() -> AnalyzerEngine:
    """
    Xây dựng AnalyzerEngine với custom recognizers cho PII tiếng Việt.

    Pattern recognizers (không cần NLP model):
    - VN_CCCD  : 12 chữ số liên tiếp
    - VN_PHONE : 0[3|5|7|8|9] + 8 chữ số
    - EMAIL_ADDRESS: regex chuẩn
    - PERSON   : tên Việt Nam 2-4 từ viết hoa đầu
    """

    # TASK 2.2.1 — CCCD: 11-12 chữ số (11 khi leading-zero bị pandas strip)
    cccd_recognizer = PatternRecognizer(
        supported_entity="VN_CCCD",
        supported_language="vi",
        patterns=[Pattern(name="cccd_pattern", regex=r"\b\d{11,12}\b", score=0.9)],
        context=["cccd", "căn cước", "chứng minh", "cmnd"]
    )

    # TASK 2.2.2 — SĐT VN: 0[3|5|7|8|9] + 8 chữ số
    phone_recognizer = PatternRecognizer(
        supported_entity="VN_PHONE",
        supported_language="vi",
        patterns=[Pattern(name="vn_phone", regex=r"\b0[35789]\d{8}\b", score=0.85)],
        context=["điện thoại", "sdt", "phone", "liên hệ"]
    )

    # Email recognizer (vi)
    email_recognizer = PatternRecognizer(
        supported_entity="EMAIL_ADDRESS",
        supported_language="vi",
        patterns=[Pattern(
            name="email_pattern",
            regex=r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            score=0.9
        )],
        context=["email", "mail", "thư điện tử"]
    )

    # PERSON recognizer — tên người Việt Nam dạng "Nguyễn Văn A"
    person_recognizer = PatternRecognizer(
        supported_entity="PERSON",
        supported_language="vi",
        patterns=[Pattern(name="vn_person", regex=_VN_NAME_REGEX, score=0.75)],
        context=["bệnh nhân", "bác sĩ", "họ tên", "tên"]
    )

    # TASK 2.2.3 — NLP engine: dùng en_core_web_lg (sẵn có trong hệ thống)
    # vi_core_news_lg không có trên PyPI; pattern recognizers thay thế NER.
    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "vi", "model_name": "en_core_web_lg"}]
    })
    nlp_engine = provider.create_engine()

    # TASK 2.2.4 — Khởi tạo engine và đăng ký các recognizers
    analyzer = AnalyzerEngine(
        nlp_engine=nlp_engine,
        supported_languages=["vi"],
    )
    analyzer.registry.add_recognizer(cccd_recognizer)
    analyzer.registry.add_recognizer(phone_recognizer)
    analyzer.registry.add_recognizer(email_recognizer)
    analyzer.registry.add_recognizer(person_recognizer)

    return analyzer


def detect_pii(text: str, analyzer: AnalyzerEngine) -> list:
    """Detect PII trong text tiếng Việt, trả về list RecognizerResult."""
    results = analyzer.analyze(
        text=text,
        language="vi",
        entities=["PERSON", "EMAIL_ADDRESS", "VN_CCCD", "VN_PHONE"]
    )
    return results
