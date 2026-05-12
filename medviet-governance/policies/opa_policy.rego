package medviet.data_access

import future.keywords.if
import future.keywords.in

# Default: deny all
default allow := false

# Admin được phép tất cả actions
allow if {
    input.user.role == "admin"
}

# ML Engineer được đọc/ghi training data và model artifacts
allow if {
    input.user.role == "ml_engineer"
    input.resource in {"training_data", "model_artifacts"}
    input.action in {"read", "write"}
}

# ML Engineer được đọc aggregated metrics
allow if {
    input.user.role == "ml_engineer"
    input.resource == "aggregated_metrics"
    input.action == "read"
}

# ML Engineer KHÔNG được delete production data (explicit deny override)
deny if {
    input.user.role == "ml_engineer"
    input.resource == "production_data"
    input.action == "delete"
}

# Data Analyst chỉ được đọc aggregated metrics và ghi reports
allow if {
    input.user.role == "data_analyst"
    input.resource == "aggregated_metrics"
    input.action == "read"
}

allow if {
    input.user.role == "data_analyst"
    input.resource == "reports"
    input.action in {"read", "write"}
}

# Intern chỉ được access sandbox data
allow if {
    input.user.role == "intern"
    input.resource == "sandbox_data"
    input.action in {"read", "write"}
}

# Không ai được export restricted data ra ngoài VN servers
deny if {
    input.data_classification == "restricted"
    input.destination_country != "VN"
}

# Final decision: allow nếu có allow rule khớp VÀ không có deny rule khớp
final_allow := true if {
    allow
    not deny
}
