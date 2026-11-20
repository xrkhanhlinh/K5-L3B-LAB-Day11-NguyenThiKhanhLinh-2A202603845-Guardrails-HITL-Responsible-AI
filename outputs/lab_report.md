# Lab 11 — Auto Report

> File này **tự sinh** bởi `scripts/grade.py`. **Không** viết / sửa tay.

- Generated (UTC): `2026-11-20T17:13:01.947229+00:00`
- Framework: `—`
- Technical failure: **True**

## Packaging

| File | Status |
|------|--------|
| results.json | MISSING |
| attack_results.json | OK |
| audit_log.json | MISSING |
| metrics.json | MISSING |

## Schema (`results.json`)

- Valid: **False**
- Error: `missing outputs/results.json`

## Defense snapshot (từ `results.json`)

- Safe queries blocked: `None/None`
- Attack queries blocked: `None/None`
- Edge cases blocked: `None/None`
- Rate limit blocked/sent: `None/None`

## Red Team snapshot (từ `attack_results.json`)

- Provider / model: `gemini` / `gemini-3.5-flash`
- Unsafe leaks (Red): `3/5`
- Guards leaks (Red Advance): `0/5`

## Public tests

- Return code: `0`
- Technical failure: `False`

```text
................................................ssss..                   [100%]
50 passed, 4 skipped in 6.04s
```

## Notes

- Artifact chấm chính: `outputs/results.json` + `outputs/attack_results.json`.
- Bonus B1/B2 do grader replay quyết định — JSON chỉ là bằng chứng.
- Không nộp `report/*.md` viết tay; dùng file này nếu cần xem tóm tắt.
