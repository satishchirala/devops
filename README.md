# Azure Logic App: Monthly Vulnerability Report to SOC + ServiceNow

This repository contains a starter workflow for an Azure Logic App that:

1. Runs automatically in the **first week of every month** (days 1-7).
2. Queries Microsoft Defender for Cloud vulnerability assessments across your subscription.
3. Filters only `High` and `Critical` findings.
4. Segregates findings into:
   - **OS-level vulnerabilities**
   - **Application-level vulnerabilities**
5. Resolves notification recipient from the resource **Service Owner tag email**.
6. Sends an email report and opens a ServiceNow incident assigned to your SOC assignment group.

## Files

- `logic-app/workflow.json` – Logic App workflow definition (Consumption-style JSON).

## Architecture

- **Trigger**: Monthly recurrence in week 1 (`monthDays: 1..7`, 08:00 UTC)
- **Data source**: Defender for Cloud REST API (`Microsoft.Security/assessments`)
- **Processing**:
  - Parse JSON
  - Filter High/Critical
  - Split into OS-level and Application-level findings
  - Resolve recipient from `ServiceOwnerEmail` / `serviceOwnerEmail` / `ServiceOwner` tag
- **Actions**:
  - Office 365: Send email to Service Owner (fallback to SOC mailbox)
  - ServiceNow: Create incident in SOC assignment group

## Classification Logic

Current segregation is based on `properties.displayName` keyword matching:

- **OS-level** keywords: `os`, `operating system`, `kernel`
- **Application-level** keywords: `application`, `software`, `package`, `library`

> Tune these keywords using your real Defender assessment names for better accuracy.

## Service Owner Email Tag Logic

The workflow uses the first matched High/Critical finding and tries these tag keys in order:

1. `ServiceOwnerEmail`
2. `serviceOwnerEmail`
3. `ServiceOwner`
4. Fallback: `socMailTo` parameter

## Prerequisites

1. Azure subscription with Microsoft Defender for Cloud enabled.
2. Logic App with **System Assigned Managed Identity** enabled.
3. RBAC on subscription for managed identity:
   - `Security Reader` (minimum for reading Defender findings)
4. Office 365 connection (or SMTP equivalent) for email.
5. ServiceNow connector connection.
6. ServiceNow fields ready:
   - assignment group `sys_id` (SOC group)
   - impact / urgency defaults

## Deployment Steps

1. Create a Logic App (Consumption or Standard).
2. Open **Code View** and paste `logic-app/workflow.json` into your workflow definition.
3. Update these parameters:
   - `subscriptionId`
   - `socMailTo` (fallback mailbox)
   - `serviceNowAssignmentGroup`
   - `serviceNowCategory`
4. Authenticate connectors:
   - Office 365 (`Send an email (V2)`)
   - ServiceNow (`Create Record` / incident API)
5. Save and run a manual test.

## Report Output

The email and ServiceNow ticket include:

- Resolved service owner email (from tag/fallback)
- Total High/Critical finding count
- OS-level finding count + HTML table
- Application-level finding count + HTML table

## Important Notes

- Schedule currently uses **UTC 08:00 on days 1-7 each month** to satisfy first-week automation.
- If you need strict “first Monday” scheduling, add a weekday condition action.
- For multi-subscription estates, iterate subscriptions via Management Group APIs or deploy one workflow per subscription.

