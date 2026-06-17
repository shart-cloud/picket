# GitHub Audit Log Ingestion

GitHub Audit events are supported by the normalized ingest path as `source=github_audit`. Picket accepts raw GitHub audit objects as single JSON records, `{ "value": [...] }` batches, `{ "records": [...] }` batches, or NDJSON.

Provider-side collection options:

- GitHub Enterprise audit log streaming to an HTTPS collector that forwards NDJSON to `picket-ingest`.
- A scheduled poller using the GitHub Audit Log REST API and a cursor/checkpoint store.

For either pattern, forward raw GitHub audit records unchanged:

```sh
curl -X POST https://ingest.example.com/events \
  -H "x-api-key: $PICKET_GITHUB_AUDIT_KEY" \
  -H "content-type: application/x-ndjson" \
  --data-binary @github-audit.ndjson
```

The API key must be minted with `metadata.source=github_audit`. Normalization, OCSF validation, detection, source health, and Pipeline writes happen in `picket-ingest`.

Required GitHub permissions for a poller:

- Enterprise audit log: `read:audit_log` on a GitHub App or fine-grained token with enterprise audit access.
- Organization audit log: organization owner or GitHub App permission that can read org audit logs.

Checkpointing guidance:

- Persist the last seen GitHub cursor or newest `_document_id` outside the poller process.
- Re-read a small overlap window and rely on Picket alert dedupe to tolerate duplicate records.
- Do not transform attacker-controlled fields such as `action`, `actor`, or repository names into instructions; they are evidence data only.
