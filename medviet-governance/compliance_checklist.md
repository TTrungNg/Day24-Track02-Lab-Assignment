# NĐ13/2023 Compliance Checklist — MedViet AI Platform

## A. Data Localization
- [ ] Tất cả patient data lưu trên servers đặt tại Việt Nam
- [ ] Backup cũng phải ở trong lãnh thổ VN
- [ ] Log việc transfer data ra ngoài nếu có

## B. Explicit Consent
- [ ] Thu thập consent trước khi dùng data cho AI training
- [ ] Có mechanism để user rút consent (Right to Erasure)
- [ ] Lưu consent record với timestamp

## C. Breach Notification (72h)
- [ ] Có incident response plan
- [ ] Alert tự động khi phát hiện breach
- [ ] Quy trình báo cáo đến cơ quan có thẩm quyền trong 72h

## D. DPO Appointment
- [ ] Đã bổ nhiệm Data Protection Officer
- [ ] DPO có thể liên hệ tại: dpo@medviet.vn

## E. Technical Controls (mapping từ requirements)

| NĐ13 Requirement | Technical Control | Status | Owner |
|-----------------|-------------------|--------|-------|
| Data minimization | PII anonymization pipeline (Presidio) | ✅ Done | AI Team |
| Access control | RBAC (Casbin) + ABAC (OPA) | ✅ Done | Platform Team |
| Encryption | AES-256-GCM at rest (SimpleVault), TLS 1.3 in transit | ✅ Done | Infra Team |
| Audit logging | Structured API access logs + ELK Stack | ⬜ Todo | Platform Team |
| Breach detection | Anomaly monitoring (Prometheus + Alertmanager) | ⬜ Todo | Security Team |

## F. Technical Solutions cho các mục còn Todo

### Audit Logging
**Mục tiêu:** Ghi lại mọi thao tác truy cập dữ liệu theo yêu cầu NĐ13/2023 Điều 26.

**Giải pháp kỹ thuật:**
- Thêm FastAPI middleware ghi structured log mỗi request: `{timestamp, user_id, role, action, resource, ip_address, status_code}`
- Dùng **structlog** (Python) để format JSON log
- Gửi log vào **ELK Stack** (Elasticsearch + Logstash + Kibana) hoặc **Loki + Grafana**
- Retention policy: lưu tối thiểu 24 tháng theo quy định
- Log phải immutable (ghi vào append-only storage, không cho sửa/xóa)

```python
# Ví dụ middleware audit log
@app.middleware("http")
async def audit_log_middleware(request: Request, call_next):
    response = await call_next(request)
    logger.info("api_access", 
        user=request.headers.get("X-User"),
        path=request.url.path,
        method=request.method,
        status=response.status_code,
        timestamp=datetime.utcnow().isoformat()
    )
    return response
```

### Breach Detection
**Mục tiêu:** Phát hiện và cảnh báo sự cố trong vòng 72h theo NĐ13/2023 Điều 27.

**Giải pháp kỹ thuật:**
- Deploy **Prometheus** để thu thập metrics từ FastAPI (dùng `prometheus-fastapi-instrumentator`)
- Tạo **Alertmanager** rules cho các anomaly:
  - Hơn 50 lần xác thực thất bại trong 1 phút → alert "Brute Force Attempt"
  - Tải xuống > 1000 records trong 1 phút → alert "Data Exfiltration"
  - API latency tăng đột biến → alert "System Anomaly"
- Kết nối alert với **PagerDuty** hoặc **Slack webhook** để notify on-call team
- Runbook incident response: trong 1h đầu phải xác nhận và isolate, trong 24h phải đánh giá phạm vi, trong 72h phải báo cáo lên Bộ TT&TT

```yaml
# Ví dụ Prometheus alert rule
groups:
  - name: medviet_security
    rules:
      - alert: BruteForceAttempt
        expr: rate(http_requests_total{status="401"}[1m]) > 50
        for: 1m
        annotations:
          summary: "Possible brute force attack detected"
```
