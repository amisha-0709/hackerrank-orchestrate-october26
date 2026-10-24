import unittest
from datetime import datetime, timezone

import main


T = datetime(2026, 9, 1, tzinfo=timezone.utc)


def fact(resource_id, system, record):
    return {"resource_id": resource_id, "system_id": system, "record": record,
            "collection": "synthetic_test", "time": T, "file_captured": T,
            "evidence_id": "test_evidence"}


def request(text="Please delete my account."):
    return {"case_id": "synthetic", "email": "person@example.com", "request_text": text,
            "audit_at": "2026-09-02T00:00:00Z"}


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.identities = {"user_1": {"user1", "personexamplecom"}}

    def test_explicit_non_deletion_is_not_applicable(self):
        status, steps = main.audit(request("Do not delete my account; export my data."), [], self.identities)
        self.assertEqual((status, steps), ("NOT_APPLICABLE", []))

    def test_present_account_is_a_finding_then_delete_then_verify(self):
        status, steps = main.audit(request(), [fact("account_1", "account_service", {
            "resource_id": "account_1", "email": "person@example.com"})], self.identities)
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual([item["phase"] for item in steps], ["FINDING", "REMEDIATION", "VERIFICATION"])
        self.assertEqual([item["operation"] for item in steps], [
            "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"])

    def test_later_evidence_is_not_used_at_an_earlier_cutoff(self):
        later = fact("account_1", "account_service", {"resource_id": "account_1", "email": "person@example.com"})
        later["time"] = later["file_captured"] = datetime(2026, 9, 3, tzinfo=timezone.utc)
        status, _ = main.audit(request(), [later], self.identities)
        self.assertEqual(status, "COMPLETE")

    def test_retained_security_record_and_absent_account_are_compliant(self):
        absent = fact("account_1", "account_service", {"resource_id": "account_1", "raw": "rows=0 lookup_key=person@example.com"})
        retained = fact("audit_record_1", "security_service", {"resource_id": "audit_record_1", "subject_reference": "user_1"})
        status, steps = main.audit(request(), [absent, retained], self.identities)
        self.assertEqual(status, "COMPLETE")
        self.assertEqual([item["operation"] for item in steps], ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT"])

    def test_data_flow_is_disabled_before_dependent_record_is_deleted(self):
        flow = fact("data_flow_1", "integration_service", {"resource_id": "data_flow_1", "email": "person@example.com", "enabled": True})
        search = fact("search_1", "search_service", {"resource_id": "search_1", "email": "person@example.com"})
        status, steps = main.audit(request(), [flow, search], self.identities)
        self.assertEqual(status, "INCOMPLETE")
        remediation = [item["operation"] for item in steps if item["phase"] == "REMEDIATION"]
        self.assertEqual(remediation, ["DISABLE_DATA_FLOW", "DELETE_RECORD"])


if __name__ == "__main__":
    unittest.main()
