"""
Lab 11 — Optional enrichment: Human-in-the-Loop Design
  (Không chấm — tham khảo. Tóm tắt nộp do scripts/grade.py tự sinh,
   không viết report/*.md tay.)
  - Confidence Router
  - 3 HITL decision points
"""
from dataclasses import dataclass
import math


# ============================================================
# Optional enrichment: ConfidenceRouter (không chấm)
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        if not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("confidence must be a finite value between 0 and 1")
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision("escalate", confidence, f"High-risk action: {action_type}", "high", True)
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision("auto_send", confidence, "High confidence", "low", False)
        if confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision("queue_review", confidence, "Medium confidence — needs review", "normal", True)
        return RoutingDecision("escalate", confidence, "Low confidence — escalating", "high", True)


# ============================================================
# Optional enrichment: 3 HITL decision points (không chấm)
# Không bắt buộc điền. Tóm tắt bài nộp: chạy scripts/grade.py
# (tự sinh lab_report.md) — không viết report tay.
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
# - approval_path: What approve/reject/timeout decision is recorded?
# - audit_fields: Which correlation ID, intent and proposed action/diff are logged?
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "Approve money transfer",
        "trigger": "A proposed transfer_money action, at any confidence score",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Verified customer, source account, payee, amount, currency and risk signals",
        "example": "Transfer 50 million VND to a newly added beneficiary",
        "approval_path": "Hold execution; record reviewer approval for this exact action. Reject or timeout cancels it.",
        "audit_fields": "request_id, customer_id, intent, proposed action/diff, reviewer_id, decision, timestamp",
    },
    {
        "id": 2,
        "name": "Review an uncertain banking response",
        "trigger": "Response confidence is at least 0.7 and below 0.9",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Customer question, cited product policy, draft answer and uncertainty",
        "example": "Loan eligibility depends on an ambiguous employment history",
        "approval_path": "Queue the draft; reviewer approves or corrects it. Rejection or timeout escalates without sending.",
        "audit_fields": "request_id, intent, confidence, redacted context, draft diff, reviewer_id, decision, timestamp",
    },
    {
        "id": 3,
        "name": "Approve account closure or identity change",
        "trigger": "close_account or update_personal_info is proposed, regardless of confidence",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Verified identity, requested field changes, before/after diff and outstanding obligations",
        "example": "Close a savings account or replace the customer's registered contact details",
        "approval_path": "Hold changes until a reviewer approves the exact diff; reject or timeout leaves the account unchanged.",
        "audit_fields": "request_id, intent, redacted action diff, verification reference, reviewer_id, decision, timestamp",
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
