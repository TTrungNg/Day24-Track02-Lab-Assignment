# src/api/main.py
import pandas as pd
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse

from src.access.rbac import get_current_user, require_permission
from src.pii.anonymizer import MedVietAnonymizer

app = FastAPI(title="MedViet Data API", version="1.0.0")
anonymizer = MedVietAnonymizer()

RAW_DATA_PATH = "data/raw/patients_raw.csv"


@app.get("/health")
async def health():
    return {"status": "ok", "service": "MedViet Data API"}


@app.get("/api/patients/raw")
@require_permission(resource="patient_data", action="read")
async def get_raw_patients(
    current_user: dict = Depends(get_current_user)
):
    """Trả về 10 records đầu từ raw data — chỉ admin được phép."""
    df = pd.read_csv(RAW_DATA_PATH)
    return df.head(10).to_dict(orient="records")


@app.get("/api/patients/anonymized")
@require_permission(resource="training_data", action="read")
async def get_anonymized_patients(
    current_user: dict = Depends(get_current_user)
):
    """Trả về anonymized data — ml_engineer và admin được phép."""
    df = pd.read_csv(RAW_DATA_PATH)
    df_anon = anonymizer.anonymize_dataframe(df)
    return df_anon.head(10).to_dict(orient="records")


@app.get("/api/metrics/aggregated")
@require_permission(resource="aggregated_metrics", action="read")
async def get_aggregated_metrics(
    current_user: dict = Depends(get_current_user)
):
    """Trả về aggregated metrics không có PII — data_analyst, ml_engineer, admin."""
    df = pd.read_csv(RAW_DATA_PATH)
    disease_counts = (
        df.groupby("benh")
        .size()
        .reset_index(name="so_benh_nhan")
        .to_dict(orient="records")
    )
    avg_result = round(df["ket_qua_xet_nghiem"].mean(), 2)
    return {
        "disease_counts": disease_counts,
        "avg_ket_qua_xet_nghiem": avg_result,
        "total_patients": len(df),
    }


@app.delete("/api/patients/{patient_id}")
@require_permission(resource="patient_data", action="delete")
async def delete_patient(
    patient_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Xóa bệnh nhân — chỉ admin được phép, các role khác nhận 403."""
    return {
        "status": "deleted",
        "patient_id": patient_id,
        "deleted_by": current_user["username"],
    }
