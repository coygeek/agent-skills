# Behavior Validator Report Schema

Use this JSON shape when the orchestrator needs machine-readable behavior validation output.

```json
{
  "overall_behavior": "satisfies_contract",
  "overall_confidence": 0.9,
  "target": {
    "type": "web app",
    "access": "http://localhost:3000"
  },
  "checks": [
    {
      "contract_clause": "User task 1",
      "status": "pass",
      "severity": "P2",
      "evidence": "Created an invoice, refreshed the page, and saw it remain in the invoice list.",
      "reproduction_steps": [
        "Open /invoices",
        "Click Create",
        "Submit valid invoice fields",
        "Refresh /invoices"
      ],
      "confidence": 0.9
    }
  ],
  "anti_cheat_probes": [
    {
      "probe": "Changed fixture amount and refreshed dashboard",
      "result": "Dashboard total updated from 120 to 180"
    }
  ],
  "blockers": []
}
```

Allowed `overall_behavior` values:

- `satisfies_contract`
- `violates_contract`
- `blocked`

Allowed check `status` values:

- `pass`
- `fail`
- `blocked`
- `out_of_scope`

Use `fail` for observable contract violations, including static or fake behavior. Use `blocked` only when runtime access or required test inputs are unavailable.
