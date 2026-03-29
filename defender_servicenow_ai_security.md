# AI Security for Microsoft Defender Recommendations and Vulnerabilities

This guide gives practical Azure Resource Graph (ARG) queries and an integration pattern to push prioritized security findings into ServiceNow.

## 1) Scope and Architecture

- **Source systems**: Defender for Cloud recommendations and vulnerability findings.
- **Query layer**: Azure Resource Graph (ARG) for cross-subscription search and filtering.
- **Automation layer**: Logic App / Function App / Automation runbook to run ARG queries on schedule.
- **ITSM layer**: ServiceNow Table API to create/update incidents or vulnerability records.

Suggested flow:

1. Run ARG query every 1-4 hours.
2. Normalize records into a common schema (`findingId`, `severity`, `resourceId`, `resourceType`, `resourceCriticality`, `serviceOwner`, `environmentClass`, `dueDate`).
3. Deduplicate by stable key (`recommendationId + resourceId` or CVE + resource).
4. Upsert into ServiceNow.
5. Write back ServiceNow ticket number as external reference tag (optional).


### 1.1 Required Tags and Environment Classification

Require these Azure resource tags before automation is enabled:

- `service_owner` (email, group alias, or owning team identifier)
- `environment` (normalized to `dev`, `prd`, `quality`)
- `application` (service/application name)

Normalization rules:

- Map `prod`, `production` -> `prd`
- Map `qa`, `uat`, `test`, `quality` -> `quality`
- Map `dev`, `development`, `sandbox` -> `dev`
- If tag missing/invalid, set `environmentClass=unknown` and force human triage.

## 2) Defender for Cloud Recommendation Query (ARG)

Use this query to get active high/medium recommendations and key metadata.

```kusto
securityresources
| where type =~ 'microsoft.security/assessments'
| extend assessmentKey = name
| extend statusCode = tostring(properties.status.code)
| extend statusCause = tostring(properties.status.cause)
| extend severity = tostring(properties.metadata.severity)
| extend recommendationName = tostring(properties.displayName)
| extend description = tostring(properties.metadata.description)
| extend remediation = tostring(properties.metadata.remediationDescription)
| where statusCode == 'Unhealthy'
| where severity in~ ('High', 'Medium')
| project
    assessmentKey,
    recommendationName,
    severity,
    statusCode,
    statusCause,
    description,
    remediation,
    resourceDetails = properties.resourceDetails,
    id,
    subscriptionId,
    tenantId,
    timeGenerated = todatetime(properties.status.firstEvaluationDate)
| order by severity desc, recommendationName asc
```

## 3) Defender Vulnerability Findings Query (ARG)

Use this query pattern to extract sub-assessment vulnerability data (including CVE data where present).

```kusto
securityresources
| where type =~ 'microsoft.security/assessments/subassessments'
| extend parentAssessment = extract('.*assessments/(.+?)/.*', 1, id)
| extend statusCode = tostring(properties.status.code)
| extend severity = tostring(properties.status.severity)
| extend displayName = tostring(properties.displayName)
| extend description = tostring(properties.description)
| extend remediation = tostring(properties.remediation)
| extend resourceId = tostring(properties.resourceDetails.id)
| extend cve = tostring(properties.id)
| where statusCode == 'Unhealthy'
| where severity in~ ('High', 'Medium')
| project
    parentAssessment,
    cve,
    displayName,
    description,
    remediation,
    severity,
    statusCode,
    resourceId,
    id,
    subscriptionId,
    tenantId,
    timeGenerated = todatetime(properties.timeGenerated)
| order by severity desc, timeGenerated desc
```

## 4) Prioritization Model Before ServiceNow Ingestion

Recommended score:

- `Critical` = 100
- `High` = 80
- `Medium` = 50
- Add `+10` for internet-exposed assets.
- Add `+10` for production-tagged resources.
- Add `+10` if exploit is known/active (if available from enrichment feed).

Map score to ticket priority:

- 90+ → P1
- 70-89 → P2
- 40-69 → P3
- <40 → P4

## 5) ServiceNow Integration Design

### Option A: Incident-based workflow (fast start)

- Target table: `incident`
- Use for operational triage and SOC/SecOps routing.

Suggested field mapping:

- `short_description` = `[Defender][High] <Recommendation/Vuln name>`
- `description` = full details + remediation + portal link + resource ID
- `category` = `security`
- `subcategory` = `vulnerability`
- `urgency` / `impact` derived from priority model
- `assignment_group` from resource tags/business owner map
- `u_service_owner` = `service_owner` tag value
- `u_environment_class` = normalized `dev` / `prd` / `quality`
- `correlation_id` = deterministic external key for upsert

### Option B: Vulnerability Response workflow (recommended at scale)

- Target tables: `sn_vul_vulnerable_item`, `sn_vul_entry` (via supported APIs/integration pattern).
- Better for CVE lifecycle tracking, exception handling, and SLA reporting.

## 6) Upsert Pattern (Pseudo)

```text
for each finding in arg_results:
  owner = tags.service_owner
  env = normalize_environment(tags.environment)   # dev|prd|quality|unknown
  key = sha256(findingType + '|' + recommendationOrCve + '|' + resourceId)
  lookup ServiceNow by correlation_id = key
  if exists and state not in Closed/Resolved:
      update (severity, assignment_group, u_service_owner, u_environment_class, remediation_plan, due_date, last_seen)
  else if not exists:
      create new record with correlation_id = key, u_service_owner = owner, u_environment_class = env
  if finding no longer present for N runs and closure_validator_passed:
      auto-resolve with resolution_notes = 'No longer detected in Defender', close_code='Automated Remediation Verified'
```

## 7) Remediation Ownership and SLA by Environment

Use service owner and environment classification to drive remediation timelines:

- `prd` + Critical/High: owner acknowledgement within 4 hours, remediation target 24-72 hours.
- `quality` + Critical/High: owner acknowledgement within 1 business day, remediation target 3-7 days.
- `dev` + Critical/High: owner acknowledgement within 2 business days, remediation target 7-14 days.

ServiceNow automation actions:

- On ticket **create**: set `u_service_owner`, `u_environment_class`, assignment group, and due date SLA.
- During **remediation**: require owner updates in work notes and track `u_remediation_status`.
- On **closure**: verify owner sign-off (`u_owner_validated=true`) for `prd` and `quality` before closure state transition.

## 8) Governance and Security Controls

- Use managed identity for Azure-side query execution.
- Store ServiceNow credentials in Key Vault (or OAuth client credentials).
- Restrict integration principal to least privilege in ServiceNow tables.
- Log every create/update call with request/response code and correlation key.
- Add dead-letter handling for API failures and retry with backoff.

## 9) Operational ARG Query Tips

- Scope by management group or explicit subscription list for performance.
- Use time filters where supported to reduce payload.
- Cap result set per run and page through results for large environments.
- Track query execution time and record count for capacity tuning.

## 10) Minimum Viable Runbook

1. Schedule every 2 hours.
2. Execute both ARG queries.
3. Normalize + priority score.
4. Upsert to ServiceNow with correlation key.
5. Post summary to Teams/Slack:
   - New P1/P2 findings
   - Aging findings over SLA
   - Integration failures

---

If you want, this can be converted next into:

- A production Logic App workflow JSON,
- A Python Azure Function implementation,
- Or a ServiceNow Import Set transform map design.

## 11) AI Agent Validation for Ticket Open and Closure

Add an AI decision layer before creating and closing ServiceNow records so false positives and noisy reopen/close cycles are reduced.

### 11.1 Open-Ticket Validation Agent

Run this check before creating/updating a ticket:

1. Collect context for each finding:
   - ARG record fields (severity, recommendation/CVE, resource ID, first seen, last seen).
   - Resource business context (`service_owner` tag, normalized `environmentClass` = dev/prd/quality, internet exposure).
   - Change context (recent deployments/maintenance windows).
   - Existing ServiceNow records by `correlation_id`.
2. Ask the AI agent to produce:
   - `open_decision`: `open_now` or `suppress` (suppression stricter for `prd`/`quality`).
   - `confidence`: 0-100.
   - `reason_code`: one of `policy_violation`, `active_exposure`, `duplicate`, `accepted_risk`, `likely_false_positive`, `insufficient_context`.
   - `explanation`: short analyst-readable rationale.
3. Enforce policy guardrails:
   - If severity is Critical/High and confidence >= 70, force ticket open.
   - Never suppress if asset is production + internet-exposed unless an active exception exists.
   - If confidence < 60, route to human triage queue.

### 11.2 Closure Validation Agent

Run this check before auto-resolving a ticket:

1. Require absence across multiple runs (for example, 3 consecutive query cycles).
2. Validate closure evidence:
   - Finding no longer present in ARG.
   - No related active sibling findings on the same resource (same recommendation/CVE family).
   - No recent reopen history in last N days (for example, 14).
3. Ask AI agent to produce:
   - `close_decision`: `close_now`, `keep_open`, or `needs_human_review`.
   - `confidence`: 0-100.
   - `closure_summary`: concise rationale for audit history.
4. Guardrails:
   - Critical findings in `prd` or `quality` require owner sign-off plus either human approval or very high confidence (for example >= 90).
   - If evidence is incomplete, do not close automatically.

### 11.3 Suggested Prompt Contract

Use strict JSON output so automation can parse the response deterministically.

```json
{
  "decision_type": "open_validation",
  "open_decision": "open_now",
  "confidence": 87,
  "reason_code": "active_exposure",
  "explanation": "High severity vulnerability on internet-exposed production asset with no approved risk exception.",
  "recommended_priority": "P1",
  "required_human_approval": false
}
```

For closure:

```json
{
  "decision_type": "closure_validation",
  "close_decision": "close_now",
  "confidence": 92,
  "closure_summary": "Finding absent in 3 consecutive scans and no sibling active findings detected.",
  "required_human_approval": false
}
```

### 11.4 ServiceNow Field Integration

Store AI validation outputs on ticket create/update:

- `u_ai_decision_type`
- `u_ai_decision`
- `u_ai_confidence`
- `u_ai_reason_code`
- `u_ai_explanation`
- `u_ai_last_validated_at`
- `u_ai_requires_human_approval`
- `u_service_owner`
- `u_environment_class`
- `u_owner_validated`

Use these fields to drive assignment:

- `required_human_approval = true` -> assign to security triage group.
- high confidence + clear reason -> normal automation path.

### 11.5 Control, Audit, and Safety Requirements

- Keep a full audit trail of model input hash, output JSON, and policy rule outcome.
- Do not allow free-form model output to directly call ServiceNow APIs; only policy engine can execute state changes.
- Implement allow-list reason codes and JSON schema validation before processing.
- Add monthly review of suppression decisions for drift and missed detections.
- Measure precision/recall on sampled tickets and tune confidence thresholds.


## 12) Enhancing the Workflow with OpenAI

You can operationalize the AI validation layer with OpenAI models to improve decision quality, consistency, and auditability.

### 12.1 Recommended OpenAI Decision Architecture

- **Policy Engine (deterministic)**: hard guardrails for severity, environment, and compliance.
- **OpenAI Decision Service (probabilistic)**: risk interpretation, duplicate/noise analysis, and closure reasoning.
- **Execution Layer**: ServiceNow API calls only after policy checks pass.

Control principle: OpenAI proposes a decision, policy engine approves/rejects execution.

### 12.2 Structured Output Contract (Required)

Use strict JSON schema validation for all model outputs before any state transition.

Required fields:

- `decision_type`: `open_validation` | `remediation_validation` | `closure_validation`
- `decision`: `open_now` | `suppress` | `keep_open` | `close_now` | `needs_human_review`
- `confidence`: integer 0-100
- `reason_code`: controlled vocabulary
- `explanation`: short text for analysts
- `policy_flags`: array of triggered policy checks
- `requires_human_approval`: boolean

If JSON validation fails, route the record to human triage and do not modify ticket state.

### 12.3 OpenAI Prompting Pattern

Use a layered prompt style:

1. **System instruction**: apply SOC policy and return only schema-compliant JSON.
2. **Developer instruction**: enumerate non-negotiable guardrails (for example, no suppression for internet-exposed `prd` without approved exception).
3. **User payload**: finding details, service owner tags, environment class, ticket history, remediation history.

Recommended prompt constraints:

- Keep explanations concise and auditable.
- Force reason codes from an allow-list.
- Require explicit uncertainty handling (`needs_human_review`) when evidence is incomplete.

### 12.4 Example OpenAI Request/Response Flow (Pseudo)

```text
for each normalized_finding:
  candidate = build_ai_payload(finding, tags, ticket_history, remediation_events)
  ai_output = call_openai(candidate, response_format=json_schema)

  if not valid_schema(ai_output):
      route_to_human("invalid_ai_output")
      continue

  policy_result = evaluate_policy(ai_output, finding, environmentClass, serviceOwner)

  if policy_result.allowed:
      upsert_servicenow(ai_output, finding)
  else:
      route_to_human(policy_result.reason)

  write_audit_log(input_hash, ai_output, policy_result, timestamp)
```

### 12.5 Model Safety and Data Handling

- Minimize sensitive data in prompts (no secrets, tokens, or unnecessary PII).
- Prefer pseudonymous identifiers for users/hosts when possible.
- Apply retention controls for prompts/responses according to policy.
- Log request IDs and trace IDs for incident forensics.

### 12.6 OpenAI-Powered Remediation Validation

During remediation, use OpenAI to validate quality of fix evidence before closure:

- Parse work notes/change records for remediation completeness.
- Check that fix evidence maps to the finding cause (not just symptom).
- Flag weak evidence for human review.
- Suggest missing remediation steps for service owner follow-up.

Suggested additional ServiceNow fields:

- `u_ai_remediation_quality` (high/medium/low)
- `u_ai_missing_evidence`
- `u_ai_recommended_next_action`

### 12.7 KPI Framework for OpenAI Effectiveness

Track effectiveness monthly:

- Precision of `open_now` decisions.
- False suppression rate by environment (`dev`, `quality`, `prd`).
- Reopen rate after `close_now`.
- Mean time to remediate (MTTR) improvement by service owner.
- Human override rate on AI decisions.

Use KPI drift to tune prompts, thresholds, and policy rules.


## 13) Resource-Based Ticket Raising Rules

Raise tickets based on **resource context**, not only finding severity. Combine severity with resource criticality, exposure, and environment to determine whether to create P1/P2/P3/P4 tickets.

### 13.1 Required Resource Attributes

For each finding, enrich these resource attributes before ticket decision:

- `resourceType` (VM, SQL, Storage, Key Vault, AKS, App Service, etc.)
- `resourceCriticality` (`tier0`, `tier1`, `tier2`, `tier3`)
- `environmentClass` (`prd`, `quality`, `dev`)
- `internetExposed` (true/false)
- `containsSensitiveData` (true/false)
- `serviceOwner` and `businessOwner`

If `resourceCriticality` is missing, default to `tier2` and require human review for `High`/`Critical` findings.

### 13.2 Ticket Raising Matrix (Severity x Resource)

Use this deterministic matrix as minimum enforcement:

- `Critical` + (`tier0` or `tier1`) -> always open **P1**.
- `High` + `prd` + internet-exposed -> open **P1/P2** (policy decides urgency).
- `High` + (`tier0` or `containsSensitiveData=true`) -> open **P2** minimum.
- `Medium` + `prd` + (`tier0`/`tier1`) -> open **P2/P3**.
- `Medium` + `dev` + non-exposed `tier3` -> allow suppress/human review path.
- `Low` + `dev` + non-exposed -> backlog or suppress based on policy.

Never suppress findings on `tier0` production resources without approved risk exception.

### 13.3 Resource-Type Priority Overrides

Apply overrides for sensitive platform services:

- `Microsoft.KeyVault/vaults`: secrets exposure/misconfig -> increase priority by 1 level.
- `Microsoft.Sql/servers` or managed databases with public access -> increase priority by 1 level.
- `Microsoft.Storage/storageAccounts` with anonymous/public exposure -> increase priority by 1 level.
- `Microsoft.ContainerService/managedClusters` with control-plane risk -> force human approval before suppression.

### 13.4 ServiceNow Mapping for Resource-Aware Tickets

When creating/updating tickets, include:

- `cmdb_ci` mapped from `resourceId`
- `u_resource_id`
- `u_resource_type`
- `u_resource_criticality`
- `u_internet_exposed`
- `u_contains_sensitive_data`
- `u_business_owner`

Set assignment routing using `u_resource_criticality` + `u_service_owner`.

### 13.5 Resource-Aware Open Decision (Pseudo)

```text
riskScore = severityScore
riskScore += criticalityWeight(resourceCriticality)
riskScore += internetExposureWeight(internetExposed)
riskScore += dataSensitivityWeight(containsSensitiveData)
riskScore += resourceTypeOverride(resourceType)

if environmentClass == 'prd' and resourceCriticality in ('tier0','tier1') and severity in ('Critical','High'):
    force_open = true

if riskScore >= openThreshold or force_open:
    create_or_update_ticket(priority_from_score(riskScore))
else:
    send_to_ai_or_human_review()
```

### 13.6 Closure Rules by Resource Criticality

Before closure, enforce stricter criteria for critical resources:

- `tier0`/`tier1` in `prd`: require owner validation + AI confidence + policy approval.
- `tier2`/`tier3`: allow automation with confidence threshold and scan absence checks.
- Any resource with sensitive data: require evidence attachment or change ticket reference.

### 13.7 Suggested ARG Enrichment Fields

During normalization, extract resource metadata and tags:

- `resourceType = tostring(type)` from related resource context.
- `serviceOwner = tostring(tags.service_owner)`.
- `environmentClass = normalize(tags.environment)`.
- `resourceCriticality = tostring(tags.criticality)`.
- `businessOwner = tostring(tags.business_owner)`.
- `containsSensitiveData = tobool(tags.contains_sensitive_data)`.

This enrichment ensures ticket creation reflects true business and technical impact.


## 14) Integrating Azure AI Foundry for Security Activity Orchestration

Use Azure AI Foundry as the control plane to orchestrate AI activities for ticket open, remediation validation, and closure decisions.

### 14.1 Foundry-Centric Architecture

- **Activity Source**: Defender findings from ARG (recommendations + vulnerabilities).
- **Orchestrator**: Logic App / Function App invokes AI Foundry workflow.
- **AI Layer**: Foundry project endpoint (model + prompt flow + safety policies).
- **Policy Engine**: deterministic rule service that validates AI outputs.
- **Execution**: ServiceNow Table API updates only after policy approval.

This keeps model calls centralized while preserving deterministic governance.

### 14.2 AI Foundry Activities to Implement

Define these activities in Foundry:

1. `open_ticket_validation`
   - Input: finding, resource context, ownership tags, prior incidents.
   - Output: open/suppress decision, confidence, reason code.
2. `remediation_quality_validation`
   - Input: work notes, change ticket refs, latest scan evidence.
   - Output: remediation quality score, missing evidence list.
3. `closure_validation`
   - Input: last N scan states, sibling findings, owner sign-off status.
   - Output: close/keep-open/human-review decision.

### 14.3 Foundry Prompt Flow Design

Build a prompt flow with these nodes:

- **Input Normalizer Node**: converts ARG + ServiceNow payload into canonical schema.
- **Policy Context Node**: injects environment (`dev`/`quality`/`prd`), resource criticality, exception state.
- **Model Decision Node**: calls deployed model in Foundry.
- **Schema Validator Node**: enforces strict JSON schema.
- **Risk Scoring Node**: computes blended score from finding + model output.
- **Decision Output Node**: emits approved action proposal.

If schema validation fails, emit `needs_human_review` automatically.

### 14.4 Example Activity Contract (Foundry)

```json
{
  "activity": "open_ticket_validation",
  "input": {
    "finding_id": "<id>",
    "severity": "High",
    "resource_id": "<azure_resource_id>",
    "resource_type": "Microsoft.Compute/virtualMachines",
    "resource_criticality": "tier1",
    "environment_class": "prd",
    "service_owner": "secops-app-team"
  },
  "output": {
    "decision": "open_now",
    "confidence": 91,
    "reason_code": "active_exposure",
    "requires_human_approval": false,
    "recommended_priority": "P1"
  }
}
```

### 14.5 Observability and Activity Telemetry

Capture per activity run:

- `activity_name`, `activity_version`
- `model_deployment`, `prompt_version`
- `input_hash`, `output_hash`
- `schema_validation_status`
- `policy_decision` and `policy_reason`
- latency and error classification

Write telemetry to Log Analytics/Application Insights and keep correlation with `correlation_id` in ServiceNow.

### 14.6 Human-in-the-Loop with Foundry

For high-risk actions, enforce approvals:

- `prd` + (`tier0`/`tier1`) + Critical/High -> mandatory human approval.
- suppression decisions on internet-exposed assets -> mandatory human approval.
- unresolved schema/policy conflicts -> manual triage queue.

Store reviewer identity and approval timestamp on the ServiceNow record.

### 14.7 Foundry + ServiceNow Execution Guardrails

- Never allow direct model output to call ServiceNow APIs.
- Only policy-approved actions can invoke create/update/close operations.
- Validate idempotency via `correlation_id` before writes.
- Use retry with backoff for transient Foundry/API failures.
- Send failed activities to dead-letter queue for replay.

### 14.8 Deployment and Lifecycle Management

- Version prompts and flows (`v1`, `v1.1`, etc.) with controlled rollout.
- Run A/B evaluation between prompt versions on sampled findings.
- Define rollback path to previous activity version.
- Review monthly drift metrics (precision, false suppressions, reopen rates).

### 14.9 Minimum Activity Pipeline (Reference)

1. Scheduled ARG pull.
2. Resource/tag enrichment.
3. Call Foundry `open_ticket_validation`.
4. Evaluate deterministic policy.
5. Upsert ServiceNow ticket.
6. During remediation, call `remediation_quality_validation`.
7. Before closure, call `closure_validation`.
8. Emit telemetry and KPI dashboard updates.

This pattern gives a governed, observable AI-activity backbone for Defender-to-ServiceNow operations.
