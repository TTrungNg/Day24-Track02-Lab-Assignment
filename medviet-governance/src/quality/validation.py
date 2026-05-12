# src/quality/validation.py
import pandas as pd


def validate_anonymized_data(filepath: str, original_filepath: str = "data/raw/patients_raw.csv") -> dict:
    """
    Validate anonymized data thủ công (không dùng Great Expectations để tránh phụ thuộc version).
    Trả về dict: {"success": bool, "failed_checks": list, "stats": dict}
    """
    df = pd.read_csv(filepath)
    original_df = pd.read_csv(original_filepath)

    results = {
        "success": True,
        "failed_checks": [],
        "stats": {
            "total_rows": len(df),
            "columns": list(df.columns)
        }
    }

    # Check 1: CCCD trong file anonymized không được trùng với CCCD gốc
    original_cccd_set = set(original_df["cccd"].astype(str))
    leaked = df["cccd"].astype(str).isin(original_cccd_set)
    if leaked.any():
        results["success"] = False
        results["failed_checks"].append(
            f"Original CCCD found in anonymized data: {leaked.sum()} rows"
        )

    # Check 2: Không có null trong các cột quan trọng
    important_cols = ["patient_id", "benh", "ket_qua_xet_nghiem"]
    for col in important_cols:
        if col in df.columns and df[col].isnull().any():
            results["success"] = False
            results["failed_checks"].append(f"Null values found in column: {col}")

    # Check 3: Số rows phải bằng original
    if len(df) != len(original_df):
        results["success"] = False
        results["failed_checks"].append(
            f"Row count mismatch: anonymized={len(df)}, original={len(original_df)}"
        )

    # Check 4: Cột benh và ket_qua_xet_nghiem phải giữ nguyên
    if not df["benh"].equals(original_df["benh"]):
        results["success"] = False
        results["failed_checks"].append("Column 'benh' was modified (should be unchanged)")

    if not df["ket_qua_xet_nghiem"].equals(original_df["ket_qua_xet_nghiem"]):
        results["success"] = False
        results["failed_checks"].append(
            "Column 'ket_qua_xet_nghiem' was modified (should be unchanged)"
        )

    # Check 5: cccd phải có đúng 12 ký tự
    wrong_len = df["cccd"].astype(str).str.len() != 12
    if wrong_len.any():
        results["success"] = False
        results["failed_checks"].append(
            f"CCCD length != 12 in {wrong_len.sum()} rows"
        )

    # Check 6: email phải chứa @
    if "email" in df.columns:
        invalid_email = ~df["email"].astype(str).str.contains("@", na=False)
        if invalid_email.any():
            results["success"] = False
            results["failed_checks"].append(
                f"Invalid email format in {invalid_email.sum()} rows"
            )

    return results


def build_patient_expectation_suite():
    """
    Tạo expectation suite bằng Great Expectations.
    Chỉ gọi khi great_expectations đã được cài và context đã init.
    """
    try:
        import great_expectations as gx
    except ImportError:
        raise ImportError("Cài great_expectations trước: pip install great-expectations")

    context = gx.get_context()

    try:
        suite = context.add_expectation_suite("patient_data_suite")
    except Exception:
        suite = context.get_expectation_suite("patient_data_suite")

    df = pd.read_csv("data/raw/patients_raw.csv")
    validator = context.sources.pandas_default.read_dataframe(df)

    # 1. patient_id không được null
    validator.expect_column_values_to_not_be_null("patient_id")

    # 2. cccd phải có đúng 12 ký tự
    validator.expect_column_value_lengths_to_equal(column="cccd", value=12)

    # 3. ket_qua_xet_nghiem trong khoảng [0, 50]
    validator.expect_column_values_to_be_between(
        column="ket_qua_xet_nghiem", min_value=0, max_value=50
    )

    # 4. benh phải thuộc danh sách hợp lệ
    valid_conditions = ["Tiểu đường", "Huyết áp cao", "Tim mạch", "Khỏe mạnh"]
    validator.expect_column_values_to_be_in_set(column="benh", value_set=valid_conditions)

    # 5. email phải match regex pattern cơ bản
    validator.expect_column_values_to_match_regex(
        column="email",
        regex=r"[^@\s]+@[^@\s]+\.[^@\s]+"
    )

    # 6. patient_id phải unique
    validator.expect_column_values_to_be_unique(column="patient_id")

    validator.save_expectation_suite()
    return suite
