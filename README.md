# Defender to ServiceNow AI Automation

This repository contains documentation and starter templates for integrating Microsoft Defender findings with ServiceNow using Azure Logic Apps and Azure OpenAI.

## Repository Contents

- `defender_servicenow_ai_security.md`
  - Full implementation guide.
  - ARG query patterns for recommendations and vulnerabilities.
  - Normalization, prioritization, AI validation, and policy guardrails.
  - ServiceNow integration guidance and lifecycle flow (create/remediate/close).

- `logicapp_defender_servicenow_template.json`
  - ARM template for deploying a Logic App workflow.
  - Includes recurrence trigger, feed selection, ARG query branch, Azure OpenAI validation, and ServiceNow branching actions.

- `logicapp_defender_servicenow_template.parameters.sample.json`
  - Sample deployment parameters file.
  - Update with environment-specific values before deployment.

---

## End-to-End Flow

1. Logic App recurrence trigger starts run.
2. Workflow asks which feed is needed (`recommendations`, `vulnerabilities`, or `both`).
3. ARG query fetches findings from Defender.
4. Azure OpenAI validates and returns decision (`create`, `remediate`, `close`, `needs_human_review`).
5. Policy checks are applied.
6. ServiceNow ticket action executes (create/update/close) or route to human review.

---

## Deployment Quick Start

### Prerequisites

- Azure subscription with permissions for Logic App deployment.
- Access to Microsoft Defender for Cloud data.
- Azure OpenAI resource + deployed model.
- ServiceNow integration account with API permissions.
- Optional Teams connector if interactive feed prompt is enabled.

### Configure parameters

Copy and edit sample parameter file values:

- `subscriptionId`
- `resourceGroupName`
- `tenantId`
- `azureOpenAiEndpoint`
- `azureOpenAiDeployment`
- `serviceNowInstance`
- `serviceNowUser`
- `serviceNowPassword`

### Validate template

```bash
az deployment group validate \
  --resource-group <resource-group> \
  --template-file logicapp_defender_servicenow_template.json \
  --parameters @logicapp_defender_servicenow_template.parameters.sample.json
```

### Deploy template

```bash
az deployment group create \
  --resource-group <resource-group> \
  --template-file logicapp_defender_servicenow_template.json \
  --parameters @logicapp_defender_servicenow_template.parameters.sample.json
```

---

## Important Notes

- Replace placeholder values/endpoints before production use:
  - Teams connector `$connections`
  - ServiceNow `SYS_ID_PLACEHOLDER` lookup logic
  - remediation and human-review webhook endpoints
- Prefer Key Vault references for secrets.
- Add policy-engine validation between AI decision and ServiceNow state changes.
- Enable diagnostic logging and auditing for compliance.

For detailed architecture, controls, and blueprint, see `defender_servicenow_ai_security.md`.
