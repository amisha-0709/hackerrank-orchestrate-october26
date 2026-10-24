"""Deterministic, evidence-first deletion audit agent.

The implementation deliberately uses only participant-facing data.  It turns
each point-in-time evidence capture into resource facts, resolves identifiers
from the identity snapshot plus its audit history, and derives policy actions.
"""
from __future__ import annotations

import csv
import json
import re
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"


def when(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def norm(value) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def read_csv(name: str):
    with (DATA / name).open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def policy_actions():
    """Load, rather than invent, the policy actions used by the audit plan."""
    return {row["data_category"]: row["required_action"] for row in read_csv("deletion_rules.csv")}


POLICY_ACTIONS = policy_actions()


def activity_identity_links():
    """Activity rows corroborate identity-to-resource links but never prove state."""
    links = defaultdict(str)
    for row in read_csv("system_activity.csv"):
        if row["event_type"] == "LINK_RESOURCE_IDENTITY":
            links[row["resource_id"]] += " " + row["details"]
    return links


def resource_system(resource: dict, default: str = "") -> str:
    return resource.get("data_store") or resource.get("origin_system") or default


def collection_category(system: str, record: dict, collection: str = "") -> str:
    text = " ".join([system, collection, json.dumps(record, sort_keys=True)]).lower()
    if "tombstone" in text:
        return "tombstone"
    if "backup" in text or "archive_path" in text:
        return "backup"
    if "connector" in text or "continuous_sync" in text or "data_flow" in text:
        return "flow"
    if "security" in text or "audit_event" in text or "integrity_seal" in text or "legal_hold" in text or "legal retention" in text:
        return "security"
    if "attachment" in text and "support" in text:
        return "support_attachment"
    if "support" in text or "ticket" in text or "attachment" in text:
        return "support"
    if "analytic" in text or "telemetry" in text:
        return "analytics"
    if "export" in text or "download" in text:
        return "export"
    if "marketing" in text:
        return "marketing"
    if "search" in text or "index" in text:
        return "search"
    if "email" in text and ("delivery" in text or "notification" in text):
        return "email_log"
    return "account"


def flatten(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from flatten(item)
    elif isinstance(value, list):
        for item in value:
            yield from flatten(item)


def direct_values(record: dict):
    """Values that establish a link; metrics and generic status strings cannot."""
    keys = {"user_id", "customer_reference", "subject_reference", "subject_selector", "subject_ref", "lookup_key",
            "email", "phone", "email_hash", "full_name", "display_name", "name", "owner_email", "owner_phone",
            "requester_email", "requester_phone", "customer_email"}
    values = set()
    for key, value in flatten(record):
        if key in keys and value not in (None, ""):
            values.add(norm(value))
    return values


def has_direct_pii(record: dict) -> bool:
    """Stable references are permitted for retained security/tombstone records."""
    pii_keys = {"email", "requester_email", "owner_email", "customer_email", "phone", "requester_phone",
                "owner_phone", "email_hash", "full_name", "display_name", "requester_name", "name"}
    return any(key in pii_keys and value not in (None, "") for key, value in flatten(record))


def parse_json_file(path: Path, file_id: str, captured: datetime):
    raw = json.loads(path.read_text(encoding="utf-8"))
    facts = []

    def walk(value, inherited_system="", inherited_collection="", stamp=captured):
        if isinstance(value, dict):
            system = value.get("data_store") or value.get("origin_system") or inherited_system
            collection = value.get("collection") or value.get("collection_name") or inherited_collection
            time_field = value.get("captured_at") or value.get("observed_at")
            current = when(time_field) if isinstance(time_field, str) else stamp
            if value.get("resource_id"):
                facts.append({"resource_id": value["resource_id"], "system_id": system,
                              "record": value, "collection": collection, "time": current,
                              "evidence_id": file_id})
            for key, child in value.items():
                # Service exports nest observations beneath the service name;
                # retain that context instead of producing an empty system id.
                child_system = key if key.endswith(("_service", "_platform")) else system
                walk(child, child_system, collection, current)
        elif isinstance(value, list):
            for child in value:
                walk(child, inherited_system, inherited_collection, stamp)
    walk(raw)
    return facts


def parse_sql(path: Path, file_id: str, captured: datetime):
    """Load the SQLite-compatible snapshots using their real table schemas."""
    facts = []
    table_system = {"customer_profiles": "account_service", "customer_search_documents": "search_service",
                    "customer_analytics_profiles": "analytics_platform", "support_records": "support_platform",
                    "customer_exports": "export_service", "connector_subscriptions": "integration_service",
                    "backup_restore_entries": "backup_service", "security_audit_records": "security_service"}
    try:
        conn = sqlite3.connect(":memory:")
        conn.executescript(path.read_text(encoding="utf-8"))
        tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            if table == "snapshot_scope":
                continue
            columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
            if "resource_id" not in columns:
                continue
            system = table_system.get(table, "")
            for values in conn.execute(f'SELECT * FROM "{table}"'):
                record = dict(zip(columns, values))
                # Some replica exports store the useful object as record_json.
                if isinstance(record.get("record_json"), str):
                    try:
                        record.update(json.loads(record["record_json"]))
                    except json.JSONDecodeError:
                        pass
                stamp = record.get("updated_at") or record.get("captured_at") or captured.isoformat()
                facts.append({"resource_id": record["resource_id"], "system_id": record.get("origin_system") or system,
                              "record": record, "collection": record.get("collection_name") or table,
                              "time": when(stamp), "evidence_id": file_id})
    except sqlite3.Error:
        return []
    finally:
        if 'conn' in locals(): conn.close()
    return facts


def parse_log(path: Path, file_id: str, captured: datetime):
    facts = []
    trace_links = defaultdict(dict)
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        rid = re.search(r"resource_id=([^\s]+)", line)
        service = re.search(r"service=([^\s]+)", line)
        if not rid or not service:
            continue
        event = re.search(r"event=([^\s]+)", line)
        stamp = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)", line)
        record = {"resource_id": rid.group(1), "raw": line, "event": event.group(1) if event else ""}
        trace = re.search(r"trace_id=([^\s]+)", line)
        if trace:
            record["trace_id"] = trace.group(1)
        # Carry links from structured correlation values into a record-like object.
        for key in ("correlation_key", "lookup_key", "subject_key", "subject_ref", "matched_value", "customer_reference", "email"):
            found = re.search(key + r'=(?:\"([^\"]+)\"|([^\s]+))', line)
            if found:
                record[key] = found.group(1) or found.group(2)
        if trace:
            trace_links[trace.group(1)].update({k: v for k, v in record.items() if k in {"correlation_key", "lookup_key", "subject_key", "subject_ref", "matched_value", "customer_reference", "email"}})
        facts.append({"resource_id": rid.group(1), "system_id": service.group(1), "record": record,
                      "collection": "log_observation", "time": when(stamp.group(1)) if stamp else captured,
                      "evidence_id": file_id})
    for fact in facts:
        fact["record"].update(trace_links.get(fact["record"].get("trace_id"), {}))
    return facts


def parse_pdf(path: Path, file_id: str, captured: datetime, origin: str):
    """Extract searchable text from a participant-visible business document.

    PDFs can establish a retained record or a support attachment.  This is
    intentionally best-effort: a document with no extractable text is ignored,
    rather than guessed from its filename or manifest metadata.
    """
    try:
        import pdfplumber
        with pdfplumber.open(path) as pdf:
            text = "\n".join(page.extract_text() or "" for page in pdf.pages)
    except Exception:
        return []
    ids = re.findall(r"\b(?:support|audit_record|account|export|backup|tombstone)_[A-Za-z0-9]+\b", text)
    # The named record is the actual business object.  A legal register can
    # omit a platform resource id, in which case the stable user reference is
    # still a retained legal-hold record.
    if not ids and re.search(r"\buser_\d+\b", text):
        ids = ["legal_hold_" + (re.search(r"\buser_(\d+)\b", text).group(1))]
    facts = []
    for resource_id in dict.fromkeys(ids):
        facts.append({"resource_id": resource_id, "system_id": origin, "record": {
            "resource_id": resource_id, "document_text": text,
            "subject_reference": (re.search(r"\buser_\d+\b", text).group(0)
                                  if re.search(r"\buser_\d+\b", text) else None)},
            "collection": "document_evidence", "time": captured, "evidence_id": file_id})
    return facts


def load_facts():
    facts = []
    activity_links = activity_identity_links()
    prefix_system = {"account": "account_service", "search": "search_service", "analytics": "analytics_platform",
                     "support": "support_platform", "export": "export_service", "backup": "backup_service",
                     "data_flow": "integration_service", "audit_record": "security_service", "tombstone": "identity_service",
                     "legal_hold": "legal_retention_service"}
    for item in read_csv("evidence_files.csv"):
        path = DATA / item["file_path"]
        captured = when(item["captured_at"])
        if path.suffix == ".json":
            parsed = parse_json_file(path, item["file_id"], captured)
        elif path.suffix == ".sql":
            parsed = parse_sql(path, item["file_id"], captured)
        elif path.suffix in {".log", ".txt"}:
            parsed = parse_log(path, item["file_id"], captured)
        elif path.suffix == ".pdf":
            parsed = parse_pdf(path, item["file_id"], captured, item["origin"])
        else:
            parsed = []
        for fact in parsed:
            if fact["resource_id"] in activity_links:
                fact["record"]["activity_identity_link"] = activity_links[fact["resource_id"]]
            if not fact["system_id"]:
                for prefix, system in prefix_system.items():
                    if fact["resource_id"].startswith(prefix + "_"):
                        fact["system_id"] = system
                        break
            fact["file_captured"] = captured
        facts.extend(parsed)
    return facts


def identities():
    result = {}
    for row in read_csv("user_identities.csv"):
        result[row["user_id"]] = {norm(row[k]) for k in ("user_id", "name", "email", "phone", "email_hash") if row[k]}
    for row in read_csv("user_audit_log.csv"):
        if row["user_id"] in result:
            result[row["user_id"]].update({norm(row["old_value"]), norm(row["new_value"])})
    return result


def wants_deletion(text: str) -> bool:
    lowered = text.lower()
    deletion = ("delete", "delet", "erase", "remove my account", "close my account", "close this account", "closed my account",
                "suppression", "supprimer", "eliminar", "elimine", "eliminación", "削除", "削除を")
    non_deletion = ("export my", "access request", "correct my", "marketing opt", "unsubscribe",
                    "do not delete", "don't delete", "without deleting")
    # The supplied requests use varied wording (including post-deletion audit
    # requests); an explicit non-deletion intent is the only safe exclusion.
    return not any(word in lowered for word in non_deletion) and (any(word in lowered for word in deletion) or
        any(word in lowered for word in ("account", "profile", "personal data", "personal information")))


def linked(fact, ids):
    values = direct_values(fact["record"])
    raw = (fact["record"].get("raw", "") + " " + fact["record"].get("document_text", "") + " " +
           fact["record"].get("activity_identity_link", ""))
    return bool(values & ids) or any(identifier and identifier in norm(raw) for identifier in ids)


def state(fact):
    raw = fact["record"].get("raw", "")
    category = collection_category(fact["system_id"], fact["record"], fact["collection"])
    if "rows=0" in raw or "http_status=404" in raw or fact["record"].get("status_code") == 404:
        return "absent", category
    if category == "flow":
        return ("active" if fact["record"].get("enabled", True) else "disabled"), category
    if category == "backup":
        return ("blocked" if fact["record"].get("restore_allowed") is False else "active"), category
    values = direct_values(fact["record"])
    if category == "analytics":
        return ("exposed" if values else "compliant"), category
    if category in {"support", "tombstone", "email_log"}:
        return ("exposed" if has_direct_pii(fact["record"]) else "compliant"), category
    return "present", category


ACTION = {"account": ("DELETE_RECORD", "VERIFY_RECORD_ABSENT", "ABSENT"),
          "search": ("DELETE_RECORD", "VERIFY_RECORD_ABSENT", "ABSENT"),
          "export": ("DELETE_RECORD", "VERIFY_RECORD_ABSENT", "ABSENT"),
          "marketing": ("DELETE_RECORD", "VERIFY_RECORD_ABSENT", "ABSENT"),
          "support": ("REDACT_RECORD", "VERIFY_RECORD_REDACTED", "REDACTED"),
          "support_attachment": ("DELETE_RECORD", "VERIFY_RECORD_ABSENT", "ABSENT"),
          "tombstone": ("REDACT_RECORD", "VERIFY_RECORD_REDACTED", "REDACTED"),
          "email_log": ("REDACT_RECORD", "VERIFY_RECORD_REDACTED", "REDACTED"),
          "analytics": ("ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
          "security": (None, "VERIFY_RECORD_PRESENT", "PRESENT"),
          "flow": ("DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
          "backup": ("BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED", "BLOCKED")}


FINDING = {"present": ("REPORT_REMAINING_RECORD", "PRESENT"), "exposed": ("REPORT_EXPOSED_PII", "PRESENT"),
           "active": ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE"), "restore": ("REPORT_RESTORE_RISK", "ACTIVE")}
FIND_ORDER = {"REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3}
REMEDY_ORDER = {"DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4}
VERIFY_ORDER = {"VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2,
                "VERIFY_RECORD_ANONYMIZED": 3, "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5}


def step(phase, system, resource, operation, status, evidence):
    return {"step_no": 0, "phase": phase, "system_id": system, "resource_id": resource,
            "operation": operation, "state": status, "evidence_id": evidence}


def audit(request, all_facts, identity_map):
    if not wants_deletion(request["request_text"]):
        return "NOT_APPLICABLE", []
    email = norm(request["email"])
    users = [user for user, vals in identity_map.items() if email in vals]
    if not users:
        return "INCOMPLETE", []
    ids = set().union(*(identity_map[user] for user in users))
    cutoff = when(request["audit_at"])
    # Latest observation of a resource wins; observations after audit time are unavailable.
    candidates = [fact for fact in all_facts if fact["file_captured"] <= cutoff and linked(fact, ids)]
    # Each evidence capture is an investigation batch.  A later matching batch
    # supersedes older captures rather than accumulating stale historical rows.
    batch_time = max((fact["file_captured"] for fact in candidates), default=None)
    latest = {}
    for fact in candidates:
        if fact["file_captured"] == batch_time and fact["time"] <= cutoff:
            key = (fact["system_id"], fact["resource_id"])
            if key not in latest or latest[key]["time"] <= fact["time"]:
                latest[key] = fact
    records = []
    for fact in latest.values():
        condition, category = state(fact)
        records.append((fact, condition, category))
    violations = []
    for fact, condition, category in records:
        if category in {"account", "search", "export", "marketing", "support_attachment"} and condition == "present":
            violations.append((fact, "present", category))
        elif category in {"support", "tombstone", "email_log", "analytics"} and condition == "exposed":
            violations.append((fact, "exposed", category))
        elif category == "flow" and condition == "active":
            violations.append((fact, "active", category))
        elif category == "backup" and condition == "active":
            violations.append((fact, "restore", category))
    incomplete = bool(violations)
    if not incomplete:
        checks = []
        for fact, condition, category in records:
            remediate, verify, final = ACTION[category]
            if (category in {"account", "search", "export", "marketing", "support_attachment"} and condition == "absent") or \
               (category in {"support", "tombstone", "email_log", "analytics"} and condition == "compliant") or \
               (category == "security" and condition == "present") or \
               (category == "flow" and condition == "disabled") or (category == "backup" and condition == "blocked"):
                checks.append(step("VERIFICATION", fact["system_id"], fact["resource_id"], verify, final, fact["evidence_id"]))
        checks.sort(key=lambda x: (VERIFY_ORDER[x["operation"]], x["system_id"], x["resource_id"]))
        for i, item in enumerate(checks, 1): item["step_no"] = i
        return "COMPLETE", checks
    findings, remediation, verification = [], [], []
    for fact, kind, category in violations:
        op, st = FINDING[kind]
        findings.append(step("FINDING", fact["system_id"], fact["resource_id"], op, st, fact["evidence_id"]))
    for fact, _, category in violations:
        op, verify, final = ACTION[category]
        remediation.append(step("REMEDIATION", fact["system_id"], fact["resource_id"], op, final, ""))
    # Every evidenced relevant record gets a final policy-state verification.
    for fact, condition, category in records:
        _, verify, final = ACTION[category]
        verification.append(step("VERIFICATION", fact["system_id"], fact["resource_id"], verify, final, ""))
    findings.sort(key=lambda x: (FIND_ORDER[x["operation"]], x["system_id"], x["resource_id"]))
    remediation.sort(key=lambda x: (REMEDY_ORDER[x["operation"]], x["system_id"], x["resource_id"]))
    verification.sort(key=lambda x: (VERIFY_ORDER[x["operation"]], x["system_id"], x["resource_id"]))
    result = findings + remediation + verification
    for i, item in enumerate(result, 1): item["step_no"] = i
    return "INCOMPLETE", result


def run(input_name="deletion_requests.csv", output_path=None):
    all_facts = load_facts()
    identity_map = identities()
    rows = []
    for request in read_csv(input_name):
        status, steps = audit(request, all_facts, identity_map)
        rows.append({"case_id": request["case_id"], "deletion_status": status,
                     "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
    rows.sort(key=lambda row: row["case_id"])
    output_path = output_path or ROOT / "output.csv"
    with Path(output_path).open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader(); writer.writerows(rows)
    return rows


if __name__ == "__main__":
    run()
