# Public-sample evaluation

Run date: 2026-10-25. Evaluation was performed only against the participant-visible 32-row sample output.

| Metric | Result |
| --- | --- |
| Case-level deletion-status accuracy | 16 / 32 (50.00%) |
| Exact step-sequence accuracy | 1 / 32 (3.13%) |
| Step-level / field-level accuracy | Not claimed: this run does not include an approved scorer for partial step matches. |

The evaluator is `evaluation/main.py`; run it from the repository root with `python code/evaluation/main.py`.

## Additional evaluation cases

1. A non-deletion request containing an explicit “do not delete” instruction must return `NOT_APPLICABLE` and `[]`.
2. A retained security event with a stable subject reference but no direct identifier must produce `VERIFY_RECORD_PRESENT`, not a deletion action.
3. An enabled connector linked through a historical email must produce an active-flow finding before remediation of any downstream record.

## Failures found and improvements made

The first implementation accumulated observations from older evidence captures, causing stale records to be reported as currently present. The current implementation groups each audit around the latest matching point-in-time evidence batch at or before the audit time and lets a later observation of the same resource supersede an earlier one. It also extracts searchable text from the supplied PDFs and preserves service context from nested service-export JSON.

The public score remains incomplete. All four PDFs have extractable text and are now parsed, but the eleven supplied screenshots require OCR that is not available in this runtime. Anonymized records can also no longer be linked by their own fields. Therefore this report deliberately records the measured score and does not claim hidden-test performance.
