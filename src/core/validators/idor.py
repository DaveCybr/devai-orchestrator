"""IDOR validator — horizontal, vertical, mass assignment."""
from __future__ import annotations

SENSITIVE_FIELDS = [
    "email", "phone", "address", "ssn", "credit_card", "password",
    "role", "is_admin", "is_verified", "balance", "salary", "private",
]


def validate(url: str, first_response: str = "", second_response: str = "", user_a_id: str = "", user_b_id: str = "", **kwargs) -> dict:
    if not first_response or not second_response:
        return {"confirmed": False, "type": "unconfirmed", "evidence": "Need two responses to compare"}

    # 1. Horizontal IDOR — identical structure, different data
    if first_response == second_response:
        # If both responses are identical but supposed to be different users
        if user_a_id != user_b_id:
            return {"confirmed": False, "type": "shared_resource", "evidence": "Both users see identical data (shared/public?)"}

    # 2. User B data leaked in User A's session
    if user_b_id and user_b_id in second_response and len(second_response) > 50:
        return {"confirmed": True, "type": "horizontal", "evidence": f"User B's data ({user_b_id}) accessible from User A"}

    # 3. Vertical IDOR — admin data accessible to regular user
    for field in SENSITIVE_FIELDS:
        if field in second_response.lower() and field not in first_response.lower():
            return {"confirmed": True, "type": "vertical", "evidence": f"Sensitive field '{field}' in response"}

    # 4. Mass assignment — extra fields accepted
    if "is_admin" in url.lower() or "role" in url.lower():
        return {"confirmed": True, "type": "mass_assignment", "evidence": "Privilege field accepted"}

    return {"confirmed": False, "type": "unconfirmed", "evidence": "No IDOR indicators found"}
