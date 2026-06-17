# Microsoft 365 Management Activity Ingestion

Microsoft 365 Management Activity events are supported by the normalized ingest path as `source=m365_management`. Picket accepts raw Management Activity API content rows as single JSON records, `{ "value": [...] }` batches, `{ "records": [...] }` batches, or NDJSON.

Provider-side collection pattern:

1. Register an Entra ID application with permissions for the Office 365 Management Activity API.
2. Subscribe to the content types you need, typically `Audit.Exchange`, `Audit.SharePoint`, `Audit.AzureActiveDirectory`, and `Audit.General`.
3. Poll available content blobs on a schedule.
4. Forward each raw record unchanged to `picket-ingest` with an API key minted as `metadata.source=m365_management`.

Example forward:

```sh
curl -X POST https://ingest.example.com/events \
  -H "x-api-key: $PICKET_M365_MANAGEMENT_KEY" \
  -H "content-type: application/json" \
  --data '{"value":[{"CreationTime":"2026-05-28T13:45:12Z","Operation":"New-InboxRule","Workload":"Exchange","ResultStatus":"Succeeded","UserId":"alice@example.com"}]}'
```

Picket currently ships default M365 rules for:

- Exchange inbox forwarding rule creation or modification.
- Audit logging bypass / admin audit configuration changes.

Operational notes:

- Keep API credentials in the poller platform's secret manager, not Terraform state.
- Use a durable checkpoint keyed by content URI or event `Id`.
- Reprocess overlap is acceptable; Picket alert dedupe is designed to tolerate repeated events.
