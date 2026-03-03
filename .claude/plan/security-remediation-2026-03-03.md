# Implementation Plan: Security Audit Remediation

**Source Audit:** `.claude/plan/security-audit-2026-03-02.md`
**Date:** 2026-03-03
**Task Type:** Backend + Infrastructure (CDK + Node.js + Python)

---

## Overview

This plan implements fixes for the 41 findings from the 2026-03-02 security audit across 4 tiers. Each step includes the exact file, line range, and code change. No architectural redesign — all fixes are surgical, defense-in-depth improvements.

**Estimated changes:** ~30 files touched, ~400 lines added/modified, 0 new files.

---

## Tier 1 — Block Deployment (4 fixes, highest priority)

### Step 1.1: C1 — Refuse to start OpenClaw when STS scoping fails

**File:** `bridge/agentcore-contract.js:535-540`
**Current:** Falls back to `{ ...process.env }` spreading full credentials.
**Fix:** Hard-fail — throw error preventing OpenClaw launch with unscoped credentials.

```javascript
// BEFORE (line 535-540):
const openclawEnv = scopedCredsAvailable
  ? scopedCreds.buildOpenClawEnv({ credDir: SCOPED_CREDS_DIR, baseEnv: process.env })
  : { ...process.env, OPENCLAW_SKIP_CRON: "1" };

// AFTER:
if (!scopedCredsAvailable) {
  console.error("[contract] CRITICAL: Scoped credentials failed — refusing to start OpenClaw with full execution role credentials.");
  // Build a safe env that strips ALL AWS credential sources
  // OpenClaw will have zero AWS access — tools will fail gracefully
  const safeEnv = scopedCreds.buildOpenClawEnv({
    credDir: null,  // no credential files
    baseEnv: process.env,
  });
  // Set a flag so contract server knows OpenClaw has no AWS access
  safeEnv.OPENCLAW_SKIP_CRON = "1";
  safeEnv.OPENCLAW_NO_AWS = "1";
}
const openclawEnv = scopedCredsAvailable
  ? scopedCreds.buildOpenClawEnv({ credDir: SCOPED_CREDS_DIR, baseEnv: process.env })
  : safeEnv;
```

**Also update** `bridge/scoped-credentials.js` `buildOpenClawEnv()` to handle `credDir: null` — return env with all AWS credential vars stripped but no `credential_process` config.

**Test:** `bridge/scoped-credentials.test.js` — add test for `buildOpenClawEnv({ credDir: null })`.

---

### Step 1.2: C3 — Add session name condition to STS self-assume trust policy

**File:** `stacks/agentcore_stack.py:149-154`
**Current:** Trust policy has no conditions on self-assume.
**Fix:** Require `scoped-*` session name prefix.

```python
# BEFORE (line 149-154):
self.execution_role.assume_role_policy.add_statements(
    iam.PolicyStatement(
        actions=["sts:AssumeRole"],
        principals=[iam.ArnPrincipal(execution_role_arn_str)],
    )
)

# AFTER:
self.execution_role.assume_role_policy.add_statements(
    iam.PolicyStatement(
        actions=["sts:AssumeRole"],
        principals=[iam.ArnPrincipal(execution_role_arn_str)],
        conditions={
            "StringLike": {
                "sts:RoleSessionName": "scoped-*"
            }
        },
    )
)
```

**Verify:** `bridge/scoped-credentials.js` already uses `RoleSessionName: "scoped-..."` — confirm exact prefix match.

**Test:** `cdk synth` — verify no cdk-nag regressions. Existing `scoped-credentials.test.js` covers the STS call.

---

### Step 1.3: H2 — Add `exec` and `read` to OpenClaw tool deny list

**File:** `bridge/agentcore-contract.js:304-314`
**Current:** Deny list: `["write", "edit", "apply_patch", "browser", "canvas", "cron", "gateway"]`
**Fix:** Add `"exec"` and `"read"` to deny list.

```javascript
// BEFORE (line 306-314):
deny: [
  "write",
  "edit",
  "apply_patch",
  "browser",
  "canvas",
  "cron",
  "gateway",
],

// AFTER:
deny: [
  "write",
  "edit",
  "apply_patch",
  "exec",       // Prevents arbitrary shell execution — blocks /proc reads
  "read",       // Prevents local file reads — use s3-user-files skill instead
  "browser",
  "canvas",
  "cron",
  "gateway",
],
```

**Risk:** Verify OpenClaw skills (s3-user-files, eventbridge-cron) don't use `exec` or `read` tools internally. They use `child_process.spawn` via the lightweight agent, NOT OpenClaw's built-in `exec` tool — so this is safe.

**Test:** Manual — start a session, verify `exec` and `read` tools are not available in the OpenClaw tool list.

---

### Step 1.4: C2 — Add DNS resolution check on redirect targets

**File:** `bridge/lightweight-agent.js:508-521`
**Current:** Redirect only calls `validateUrlSafety()` (hostname pattern), not `validateResolvedIps()` (DNS resolution).
**Fix:** Add `validateResolvedIps()` call on redirect targets.

```javascript
// BEFORE (line 508-521):
if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
  const redirectUrl = new URL(res.headers.location, url).href;
  const redirectError = validateUrlSafety(redirectUrl);
  if (redirectError) {
    resolve(`Error: Redirect blocked — ${redirectError}`);
    return;
  }
  res.resume();
  resolve(executeWebFetch(redirectUrl, depth + 1));
  return;
}

// AFTER:
if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
  const redirectUrl = new URL(res.headers.location, url).href;
  const redirectError = validateUrlSafety(redirectUrl);
  if (redirectError) {
    res.resume();
    resolve(`Error: Redirect blocked — ${redirectError}`);
    return;
  }
  const redirectParsed = new URL(redirectUrl);
  res.resume();
  validateResolvedIps(redirectParsed.hostname).then(ipError => {
    if (ipError) {
      resolve(`Error: Redirect blocked — ${ipError}`);
      return;
    }
    resolve(executeWebFetch(redirectUrl, depth + 1));
  });
  return;
}
```

**Also:** Add `res.resume()` before the existing `redirectError` resolve (it's missing — causes socket hang).

**Test:** `bridge/lightweight-agent.test.js` — add test case for redirect to internal IP.

---

## Tier 2 — Next Deploy Cycle (6 fixes)

### Step 2.1: H1 — Scope Secrets Manager to only needed secrets

**File:** `stacks/agentcore_stack.py:102-113`
**Current:** `resources=["arn:aws:secretsmanager:...:secret:openclaw/*"]`
**Fix:** Restrict to the 2 secrets the container actually needs.

```python
# AFTER:
resources=[
    f"arn:aws:secretsmanager:{region}:{account}:secret:openclaw/gateway-token-*",
    f"arn:aws:secretsmanager:{region}:{account}:secret:openclaw/cognito-password-secret-*",
],
```

**Note:** The `-*` suffix is required because Secrets Manager appends a random suffix to the ARN.

**Test:** `cdk synth` + verify bridge startup still fetches both secrets successfully.

---

### Step 2.2: C4 — Scope CloudWatch PutMetricData with namespace condition

**File:** `stacks/agentcore_stack.py:157-169`
**Current:** Single statement with `logs:*`, `cloudwatch:PutMetricData`, `xray:*` all on `Resource: *`.
**Fix:** Split into separate statements with conditions.

```python
# AFTER — split into 3 statements:
# 1. CloudWatch Logs — scoped to /openclaw/ prefix
self.execution_role.add_to_policy(
    iam.PolicyStatement(
        actions=[
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
        ],
        resources=[
            f"arn:aws:logs:{region}:{account}:log-group:/openclaw/*",
            f"arn:aws:logs:{region}:{account}:log-group:/openclaw/*:*",
        ],
    )
)

# 2. CloudWatch Metrics — namespace condition
self.execution_role.add_to_policy(
    iam.PolicyStatement(
        actions=["cloudwatch:PutMetricData"],
        resources=["*"],
        conditions={
            "StringEquals": {
                "cloudwatch:namespace": [
                    "OpenClaw/AgentCore",
                    "OpenClaw/TokenUsage",
                ]
            }
        },
    )
)

# 3. X-Ray — required Resource: *
self.execution_role.add_to_policy(
    iam.PolicyStatement(
        actions=[
            "xray:PutTraceSegments",
            "xray:PutTelemetryRecords",
        ],
        resources=["*"],
    )
)
```

**Test:** `cdk synth` — verify no cdk-nag regressions.

---

### Step 2.3: M1 — Scope DynamoDB session policy per-user

**File:** `bridge/scoped-credentials.js:136-147`
**Current:** Full access to `openclaw-identity` table.
**Fix:** Add `dynamodb:LeadingKeys` condition restricting to user's own PK prefix.

```javascript
// AFTER — add condition to DynamoDB statement:
{
  Sid: "DynamoDBIdentity",
  Effect: "Allow",
  Action: [
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:UpdateItem",
    "dynamodb:DeleteItem",
    "dynamodb:Query",
  ],
  Resource: dynamoResources,
  Condition: {
    "ForAllValues:StringLike": {
      "dynamodb:LeadingKeys": [
        `USER#${actorId}`,
        `CRON#*`,  // Cron records are under user's PK
      ]
    }
  },
},
```

**Risk:** Must verify all DynamoDB operations use the user's PK. The cron skill writes `USER#{userId}` / `CRON#{scheduleId}` pairs — this condition covers it.

**Note:** `actorId` must be passed through to `createScopedCredentials()` and `buildSessionPolicy()`. Currently `namespace` (underscore format) is passed; need to also pass `actorId` (colon format) for DynamoDB key matching.

**Test:** `bridge/scoped-credentials.test.js` — add test verifying DynamoDB condition in generated policy.

---

### Step 2.4: M2 — Bind proxy to 127.0.0.1 instead of 0.0.0.0

**File:** `bridge/agentcore-proxy.js:1564`
**Current:** `server.listen(PORT, "0.0.0.0", () => {`
**Fix:** Bind to loopback only.

```javascript
// AFTER:
server.listen(PORT, "127.0.0.1", () => {
  console.log(`[proxy] Bedrock proxy adapter listening on http://127.0.0.1:${PORT} (model: ${MODEL_ID})`);
```

**Risk:** Low. Both OpenClaw and lightweight-agent connect to `http://localhost:${PORT}` — loopback binding is correct.

**Test:** `bridge/proxy-identity.test.js` still passes (tests connect to localhost).

---

### Step 2.5: H9 — Move Slack url_verification after signature validation

**File:** `lambda/router/index.py:1165-1177`
**Current:** `url_verification` echoed before HMAC check.
**Fix:** Move signature validation before the url_verification handler, or add an env flag.

```python
# AFTER (Option A — env flag, recommended):
elif path.endswith("/webhook/slack"):
    # Slack url_verification — only during initial setup
    try:
        event_data = json.loads(body) if isinstance(body, str) else body
        if event_data.get("type") == "url_verification":
            if os.environ.get("SLACK_VERIFIED") == "true":
                logger.warning("Slack url_verification rejected — already verified")
                return {"statusCode": 403, "body": "Already verified"}
            # Validate challenge format before echoing
            challenge = event_data.get("challenge", "")
            if not re.match(r'^[a-zA-Z0-9_\-\.]{1,100}$', challenge):
                return {"statusCode": 400, "body": "Invalid challenge format"}
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"challenge": challenge}),
            }
    except (json.JSONDecodeError, TypeError):
        pass

    # Validate Slack request signature before processing
    if not validate_slack_webhook(headers, body):
        ...
```

**CDK change:** Add `SLACK_VERIFIED` env var to Router Lambda (default: empty, set to `"true"` after Slack setup).

**Test:** `lambda/router/` — add test for rejected url_verification when `SLACK_VERIFIED=true`.

---

### Step 2.6: H10 — Cap AgentCore response body read size

**File:** `lambda/router/index.py:424-425` and `lambda/cron/index.py:209-239`
**Current:** `body.read().decode("utf-8")` — unbounded.
**Fix:** Limit to 500KB.

```python
# AFTER (router/index.py):
MAX_RESPONSE_BYTES = 500_000  # 500 KB
if hasattr(body, "read"):
    body_bytes = body.read(MAX_RESPONSE_BYTES + 1)
    body_text = body_bytes.decode("utf-8", errors="replace")
    if len(body_bytes) > MAX_RESPONSE_BYTES:
        logger.warning("AgentCore response truncated at %d bytes", MAX_RESPONSE_BYTES)
        body_text = body_text[:MAX_RESPONSE_BYTES]
else:
    body_text = str(body)[:MAX_RESPONSE_BYTES]
```

Apply same pattern in `lambda/cron/index.py`.

**Test:** Unit test with oversized mock response body.

---

## Tier 3 — Short-Term Backlog (11 fixes)

### Step 3.1: H4 — Remove sensitive fields from /health endpoint

**File:** `bridge/agentcore-proxy.js:1340-1354`
**Fix:** Remove `last_identity`, `s3_bucket` from response. Keep diagnostic fields that don't leak PII.

```javascript
// Remove these lines:
s3_bucket: process.env.S3_USER_FILES_BUCKET || "not configured",
last_identity: lastIdentityDiag,
```

---

### Step 3.2: H5 — Restrict security group egress to HTTPS only

**File:** `stacks/agentcore_stack.py:57-63`
**Fix:**
```python
allow_all_outbound=False,
# Then add:
self.agent_sg.add_egress_rule(
    peer=ec2.Peer.any_ipv4(),
    connection=ec2.Port.tcp(443),
    description="HTTPS to VPC endpoints and internet (web_fetch/web_search)",
)
```

---

### Step 3.3: H6 — DynamoDB tables with CMK encryption

**Files:** `stacks/router_stack.py:55-69`, `stacks/token_monitoring_stack.py:40-54`
**Fix:** Add `encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED` and `encryption_key=` to both tables.
**CDK:** Pass `cmk_arn` to both stacks from `app.py` (may already be available via cross-stack ref).

---

### Step 3.4: H7 — SNS alarm topic encryption

**File:** `stacks/observability_stack.py:35-41`
**Fix:** Add `master_key=` to SNS topic.
**Note:** Requires KMS key policy to grant SNS service `kms:GenerateDataKey` and `kms:Decrypt`.

---

### Step 3.5: H11 — Schedule name length cap

**File:** `bridge/skills/eventbridge-cron/common.js:105-107`
**Fix:**
```javascript
function buildScheduleName(userId, scheduleId) {
  const name = `openclaw-${userId}-${scheduleId}`;
  if (name.length > 64) {
    // Truncate userId portion to fit, keeping scheduleId intact
    const prefix = `openclaw-`;
    const suffix = `-${scheduleId}`;
    const maxUserIdLen = 64 - prefix.length - suffix.length;
    return `${prefix}${userId.slice(0, maxUserIdLen)}${suffix}`;
  }
  return name;
}
```

---

### Step 3.6: H12 — Add validateEnv() to list.js

**File:** `bridge/skills/eventbridge-cron/list.js`
**Fix:** Add `validateEnv` to import and call it at line 14 (after `validateUserId`).

```javascript
const {
  validateUserId,
  validateEnv,  // ADD
  listCronRecords,
  extractChannelInfo,
} = require("./common");

async function main() {
  const userId = process.argv[2];
  validateUserId(userId);
  validateEnv();  // ADD
```

---

### Step 3.7: M5 — Credential directory permissions

**File:** `bridge/scoped-credentials.js:244`
**Fix:**
```javascript
fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
```

---

### Step 3.8: M6 — Cron Lambda ownership verification

**File:** `lambda/cron/index.py:437-481`
**Fix:** After extracting `userId` and `scheduleId` from EventBridge payload, query DynamoDB to verify a `CRON#` record exists for that user before proceeding.

```python
# Verify schedule ownership
cron_record = identity_table.get_item(
    Key={"PK": f"USER#{user_id}", "SK": f"CRON#{schedule_id}"}
).get("Item")
if not cron_record:
    logger.error("Schedule %s not owned by user %s — skipping", schedule_id, user_id)
    return {"statusCode": 403, "body": "Schedule ownership verification failed"}
```

---

### Step 3.9: M7 — URL scheme allowlist in markdown-to-HTML

**File:** `lambda/router/index.py:586-587`
**Fix:**
```python
# BEFORE:
text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)

# AFTER:
def _safe_link(m):
    text_part, url_part = m.group(1), m.group(2)
    if re.match(r'^(https?://|tg://|mailto:)', url_part):
        return f'<a href="{url_part}">{text_part}</a>'
    return m.group(0)  # leave non-http links as plain text

text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", _safe_link, text)
```

**Test:** `lambda/router/test_markdown_html.py` — add tests for `javascript:` and `data:` URI rejection.

---

### Step 3.10: M14 — Minimum cron interval enforcement

**File:** `bridge/skills/eventbridge-cron/common.js:65-76`
**Fix:** After `validateExpression()` passes the format check, parse cron fields and reject intervals under 5 minutes.

```javascript
function validateExpression(expression) {
  const cronRegex = /^cron\(.+\)$/;
  const rateRegex = /^rate\(\d+\s+(minute|minutes|hour|hours|day|days)\)$/;

  if (!cronRegex.test(expression) && !rateRegex.test(expression)) {
    console.error(`Error: Invalid expression...`);
    process.exit(1);
  }

  // Enforce minimum 5-minute interval
  const rateMatch = expression.match(/^rate\((\d+)\s+(minute|minutes)\)$/);
  if (rateMatch && parseInt(rateMatch[1], 10) < 5) {
    console.error("Error: Minimum rate interval is 5 minutes.");
    process.exit(1);
  }

  const cronMatch = expression.match(/^cron\(([^\s]+)\s/);
  if (cronMatch && cronMatch[1] === "*") {
    console.error("Error: Cron expressions with every-minute (* in minutes field) are not allowed. Minimum interval is 5 minutes.");
    process.exit(1);
  }
}
```

---

### Step 3.11: H3 — Remove Cognito secret from proxy env (stretch goal)

**File:** `bridge/agentcore-contract.js:509`
**Fix:** Write `COGNITO_PASSWORD_SECRET` to a file in `/tmp/` with `0o600` perms, have proxy read it at startup.
**Risk:** Medium — requires proxy code change to read from file instead of env. Consider for later iteration if `exec`/`read` deny (Step 1.3) sufficiently mitigates the risk.

---

## Tier 4 — Medium-Term Hardening (remaining M and L findings)

These are lower-priority defense-in-depth improvements. Brief notes:

| # | Fix | File | Effort |
|---|-----|------|--------|
| M3 | Add `## SYSTEM` heading detection to fence-break sanitizer | `bridge/agentcore-proxy.js:529` | Small |
| M4 | Track credential expiry time, log warning if expired | `bridge/workspace-sync.js:47` | Small |
| M8 | Add 15-min TTL to `_token_cache` | `lambda/router/index.py:62` + `lambda/cron/index.py:47` | Small |
| M9 | Switch CloudTrail bucket to CMK | `stacks/security_stack.py:64` | Small CDK |
| M10 | Create `scripts/rotate-token.sh` or remove cdk-nag suppression | `stacks/security_stack.py:156` | Small |
| M11 | Change token monitoring table to `RemovalPolicy.RETAIN` | `stacks/token_monitoring_stack.py` | 1-line CDK |
| M12 | Enable API Gateway access logging | `stacks/router_stack.py:256` | Medium CDK |
| M13 | Add VPC endpoint policies scoped to execution role | `stacks/vpc_stack.py:96` | Medium CDK |
| L1 | Increase bind code length to 8 chars | `lambda/router/index.py:342` | Small |
| L2 | Cap `channel_user_id` length to 128 chars | `lambda/router/index.py:199` | Small |
| L3 | Reduce logged response body to 200 chars | `lambda/router/index.py:428` | Small |
| L4 | Hash `actor_id` before use as CloudWatch dimension | `lambda/token_metrics/index.py:202` | Small |
| L5 | Add S3 object size check (10MB max) before download | `bridge/workspace-sync.js:146` | Small |
| L6 | Sanitize `NODE_OPTIONS` — strip `--inspect` and `--require` | `bridge/lightweight-agent.js:269` | Small |
| L7 | Reject leading/trailing dots in S3 key sanitizer | `bridge/skills/s3-user-files/common.js:15` | Small |
| L8 | Add `MaxKeys: 1000` to ListObjectsV2 | `bridge/skills/s3-user-files/list.js:30` | 1-line |
| L9 | Enable S3 bucket versioning | `stacks/agentcore_stack.py:194` | 1-line CDK |
| L10 | Change VPC flow log group to `RemovalPolicy.RETAIN` | `stacks/vpc_stack.py:44` | 1-line CDK |

---

## AgentCore Native Features (Quick Wins)

These are additive, not blocking — implement alongside Tier 3.

### QW1: Link WorkloadIdentity to Runtime

**File:** `stacks/agentcore_stack.py` (CfnRuntime properties)
```python
workload_identity_details=agentcore.CfnRuntime.WorkloadIdentityDetailsProperty(
    workload_identity_arn=self.workload_identity.attr_workload_identity_arn,
),
```

### QW2: Add RequestHeaderConfiguration

**File:** `stacks/agentcore_stack.py` (CfnRuntime properties)
```python
request_header_configuration=agentcore.CfnRuntime.RequestHeaderConfigurationProperty(
    request_header_allowlist=[
        "x-bedrock-agentcore-runtime-session-id",
        "Authorization",
    ]
),
```

### QW3: Pass runtimeUserId in Lambda invocations

**Files:** `lambda/router/index.py`, `lambda/cron/index.py`
Add `runtimeUserId=actor_id` to `invoke_agent_runtime()` calls.

### QW4: Add distributed tracing

**Files:** `lambda/router/index.py`, `lambda/cron/index.py`
Generate W3C trace IDs and pass as `traceId`/`traceParent` to `invoke_agent_runtime()`.

---

## Execution Order

```
Phase 1 (Tier 1 — same commit):
  1.1 C1: STS fallback hard-fail          [bridge/agentcore-contract.js, bridge/scoped-credentials.js]
  1.2 C3: STS trust policy condition       [stacks/agentcore_stack.py]
  1.3 H2: exec/read deny list             [bridge/agentcore-contract.js]
  1.4 C2: DNS rebinding on redirects      [bridge/lightweight-agent.js]
  → Run: bridge tests + cdk synth
  → Commit: "fix(security): tier-1 critical security fixes"

Phase 2 (Tier 2 — same commit):
  2.1 H1: Scope secrets                   [stacks/agentcore_stack.py]
  2.2 C4: CloudWatch namespace condition  [stacks/agentcore_stack.py]
  2.3 M1: DynamoDB per-user scoping       [bridge/scoped-credentials.js]
  2.4 M2: Bind proxy to 127.0.0.1        [bridge/agentcore-proxy.js]
  2.5 H9: Slack url_verification          [lambda/router/index.py]
  2.6 H10: Response body size cap         [lambda/router/index.py, lambda/cron/index.py]
  → Run: bridge tests + lambda tests + cdk synth
  → Commit: "fix(security): tier-2 high-priority security fixes"

Phase 3 (Tier 3 — same commit):
  3.1-3.11: Short-term backlog fixes
  → Run: all tests + cdk synth
  → Commit: "fix(security): tier-3 defense-in-depth improvements"

Phase 4 (Tier 4 + Quick Wins — separate commits):
  4.x: Medium-term hardening (batch by domain: CDK, bridge, lambda)
  QW1-4: AgentCore native features
  → Run: all tests + cdk synth
  → Commit per batch
```

---

## Risks and Mitigation

| Risk | Mitigation |
|------|------------|
| C1 fix breaks OpenClaw entirely on STS failure | `buildOpenClawEnv({ credDir: null })` gives OpenClaw a clean env — it starts but tools fail gracefully. Users get lightweight agent only |
| C3 trust policy condition blocks existing sessions | New STS calls already use `scoped-*` prefix. Old sessions unaffected until next credential refresh (45 min cycle) |
| H2 deny list blocks legitimate user workflows | `exec` and `read` are not commonly used by chat assistants. Users have `s3-user-files` for file ops and `web_fetch`/`web_search` for web access |
| M2 proxy bind change breaks networking | Both OpenClaw and lightweight-agent connect via `localhost` — loopback binding is sufficient |
| H5 egress restriction blocks non-443 traffic | `web_fetch`/`web_search` use HTTPS (443) only. VPC endpoints use 443. No legitimate non-443 outbound traffic |
| CDK changes cause circular dependencies | All changes are additive (conditions, new statements) — no cross-stack reference changes |

---

## Key Files (Summary)

| File | Operation | Steps |
|------|-----------|-------|
| `bridge/agentcore-contract.js` | Modify | 1.1, 1.3 |
| `bridge/lightweight-agent.js` | Modify | 1.4 |
| `bridge/scoped-credentials.js` | Modify | 1.1, 2.3 |
| `bridge/agentcore-proxy.js` | Modify | 2.4, 3.1 |
| `stacks/agentcore_stack.py` | Modify | 1.2, 2.1, 2.2, 3.2 |
| `lambda/router/index.py` | Modify | 2.5, 2.6, 3.9 |
| `lambda/cron/index.py` | Modify | 2.6, 3.8 |
| `bridge/skills/eventbridge-cron/common.js` | Modify | 3.5, 3.10 |
| `bridge/skills/eventbridge-cron/list.js` | Modify | 3.6 |
| `stacks/router_stack.py` | Modify | 3.3 |
| `stacks/token_monitoring_stack.py` | Modify | 3.3 |
| `stacks/observability_stack.py` | Modify | 3.4 |
| Test files | Modify | Multiple — add security regression tests |

---

## SESSION_ID

- CODEX_SESSION: N/A (wrapper unavailable)
- GEMINI_SESSION: N/A (wrapper unavailable)
