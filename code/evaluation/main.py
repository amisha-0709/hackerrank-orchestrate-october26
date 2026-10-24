"""Public-sample evaluator for the deterministic audit agent."""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE))
import main  # noqa: E402


def evaluate():
    prediction = CODE.parent / "sample_prediction.csv"
    main.run("sample_deletion_requests.csv", prediction)
    with (CODE.parent / "dataset" / "sample_output.csv").open(encoding="utf-8", newline="") as f:
        truth = {row["case_id"]: row for row in csv.DictReader(f)}
    with prediction.open(encoding="utf-8", newline="") as f:
        actual = {row["case_id"]: row for row in csv.DictReader(f)}
    status = sum(truth[k]["deletion_status"] == actual[k]["deletion_status"] for k in truth)
    sequence = sum(json.loads(truth[k]["steps_json"]) == json.loads(actual[k]["steps_json"]) for k in truth)
    print(f"status_accuracy={status}/{len(truth)}")
    print(f"sequence_accuracy={sequence}/{len(truth)}")


if __name__ == "__main__":
    evaluate()
