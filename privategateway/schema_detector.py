from __future__ import annotations


SENSITIVE_FIELD_TYPES = {
    "customer_name": "PERSON",
    "name": "PERSON",
    "email": "EMAIL",
    "phone": "PHONE",
    "customer_id": "CUSTOMER_ID",
    "loan_no": "LOAN_NO",
    "employee_id": "EMPLOYEE_ID",
    "account_no": "ACCOUNT_NO",
    "address": "ADDRESS",
    "id_card": "ID_CARD",
    "passport": "PASSPORT",
    "api_key": "SECRET",
    "password": "SECRET",
    "connection_string": "SECRET",
}


def sensitive_type_for_column(column: str) -> str | None:
    normalized = column.strip().lower().replace(" ", "_")
    return SENSITIVE_FIELD_TYPES.get(normalized)
