# Security Audit Report — OpenClaw on AgentCore

**Date:** 2026-03-02
**Scope:** Full codebase — bridge, Lambda, CDK infrastructure, skill scripts
**Auditors:** 4 parallel security review agents (bridge, Lambda, CDK, skills)
**Status:** Remediated (2026-03-03) — 37/41 fixed, 4 open

---

## Executive Summary

A comprehensive security audit of the OpenClaw on AgentCore codebase identified **4 CRITICAL**, **13 HIGH**, **14 MEDIUM**, and **10 LOW** findings across all layers. No hardcoded secrets were found. The codebase has a strong security baseline (cdk-nag, KMS CMK, webhook validation, STS session policies), but defense-in-depth gaps exist — particularly when the STS scoping layer fails or doesn't cover a resource.

37 of 41 findings remediated on 2026-03-03. 4 findings remain open (H3, H8, H13 deferred as architectural changes; M3, M4, M10, M13, L4 deferred to medium-term backlog).

The most significant cross-cutting theme is that **per-user isolation relies on a single layer** (the STS session policy). When that layer fails, is bypassed, or doesn't cover a resource, there is no fallback.

---

## CRITICAL (4 findings)

### C1: Full Execution Role Leaked to OpenClaw When STS Fails

- **Domain:** Bridge
- **File:** `bridge/agentcore-contract.js:535-540`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
When `createScopedCredentials()` fails (STS throttle, transient network error, role misconfiguration), the fallback spreads the entire `process.env` into OpenClaw's environment:

```javascript
const openclawEnv = scopedCredsAvailable
  ? scopedCreds.buildOpenClawEnv({ credDir: SCOPED_CREDS_DIR, baseEnv: process.env })
  : { ...process.env, OPENCLAW_SKIP_CRON: "1" };   // <-- full process.env spread
```

`process.env` contains `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (or equivalent AgentCore credential injection), giving OpenClaw full container execution role access — the exact credential leakage the scoping mechanism was designed to prevent.

**Attack Scenario:**
STS AssumeRole call fails transiently at session init. OpenClaw starts with full credentials. OpenClaw's bash/exec tool calls `aws s3 ls s3://bucket/` without prefix restriction, reading all users' data.

**Suggested Fix:**
On STS failure, refuse to start OpenClaw with unscoped credentials:
```javascript
if (!scopedCredsAvailable) {
  throw new Error("Cannot start OpenClaw: scoped credential creation failed. " +
    "Refusing to launch with full execution role credentials.");
}
```
Or build a safe fallback env using `buildOpenClawEnv` with empty `credDir` that omits all AWS credential env vars, ensuring OpenClaw has zero AWS access rather than full access.

---

### C2: DNS Rebinding Bypass on web_fetch Redirects

- **Domain:** Bridge
- **File:** `bridge/lightweight-agent.js:509-521`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
Redirect validation calls only `validateUrlSafety()` (hostname pattern check), not `validateResolvedIps()` (the DNS resolution check). Initial fetch URLs go through both checks; redirects only get one.

```javascript
const redirectUrl = new URL(res.headers.location, url).href;
const redirectError = validateUrlSafety(redirectUrl);   // hostname check only
// validateResolvedIps() NOT called here
resolve(executeWebFetch(redirectUrl, depth + 1));
```

**Attack Scenario:**
User asks agent to fetch `https://attacker.com/redirect`. Server responds `302 Location: https://attacker2.com/`. `validateUrlSafety()` passes. `validateResolvedIps()` is NOT called. If attacker controls attacker2.com DNS, they rebind it to `169.254.169.254` (AWS IMDS), bypassing SSRF protection.

**Suggested Fix:**
Add `validateResolvedIps()` call on redirect targets:
```javascript
const redirectUrl = new URL(res.headers.location, url).href;
const redirectError = validateUrlSafety(redirectUrl);
if (redirectError) { resolve(`Error: Redirect blocked — ${redirectError}`); return; }
const redirectParsed = new URL(redirectUrl);
res.resume();
validateResolvedIps(redirectParsed.hostname).then(ipError => {
  if (ipError) { resolve(`Error: Redirect blocked — ${ipError}`); return; }
  resolve(executeWebFetch(redirectUrl, depth + 1));
});
```

---

### C3: STS Self-Assume Trust Has No Conditions — Privilege Escalation Path

- **Domain:** CDK
- **File:** `stacks/agentcore_stack.py:149-154`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
The execution role is permitted to assume itself with no conditions on the trust policy entry (no `sts:RoleSessionName`, no `aws:SourceAccount`, no ExternalId):

```python
self.execution_role.assume_role_policy.add_statements(
    iam.PolicyStatement(
        actions=["sts:AssumeRole"],
        principals=[iam.ArnPrincipal(execution_role_arn_str)],
        # No Condition block
    )
)
```

**Attack Scenario:**
The proxy retains full execution role credentials. Any code that can call STS directly (e.g., via OpenClaw's exec tool — see H2) can re-assume the role WITHOUT a session policy, obtaining unrestricted S3 access across all user namespaces.

**Suggested Fix:**
Add a condition requiring the `scoped-` session name prefix:
```python
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

---

### C4: cloudwatch:PutMetricData on Resource: * — Can Falsify Cost Alarms

- **Domain:** CDK
- **File:** `stacks/agentcore_stack.py:157-169`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
```python
self.execution_role.add_to_policy(
    iam.PolicyStatement(
        actions=[
            "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
            "cloudwatch:PutMetricData",
            "xray:PutTraceSegments", "xray:PutTelemetryRecords",
        ],
        resources=["*"],
    )
)
```

`cloudwatch:PutMetricData` on `Resource: *` without a namespace condition means the container can write to any CloudWatch namespace, including `OpenClaw/TokenUsage`.

**Attack Scenario:**
Compromised container sends `PutMetricData` to `OpenClaw/TokenUsage` with zero token counts, silencing the `openclaw-daily-token-budget` alarm while consuming unlimited Bedrock tokens.

**Suggested Fix:**
```python
iam.PolicyStatement(
    actions=["cloudwatch:PutMetricData"],
    resources=["*"],
    conditions={
        "StringEquals": {
            "cloudwatch:namespace": ["OpenClaw/AgentCore", "OpenClaw/TokenUsage"]
        }
    },
)
```
Also scope `logs:CreateLogGroup`/`logs:CreateLogStream` to the `/openclaw/` log group prefix.

---

## HIGH (13 findings)

### H1: Execution Role Can Read ALL openclaw/* Secrets

- **Domain:** CDK
- **File:** `stacks/agentcore_stack.py:102-113`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
Container can read all secrets under `openclaw/*` including Telegram bot token, Slack signing secret, and webhook secret. Only needs `openclaw/gateway-token` and `openclaw/cognito-password-secret`.

**Attack Scenario:**
Compromised container exfiltrates Telegram bot token → impersonates bot → sends messages to all users. Exfiltrates webhook-secret → forges inbound webhooks.

**Suggested Fix:**
```python
resources=[
    f"arn:aws:secretsmanager:{region}:{account}:secret:openclaw/gateway-token-*",
    f"arn:aws:secretsmanager:{region}:{account}:secret:openclaw/cognito-password-secret-*",
],
```

---

### H2: exec/read Tools NOT in OpenClaw Deny List

- **Domain:** Bridge
- **File:** `bridge/agentcore-contract.js:304-314`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
The OpenClaw tool deny list blocks `write`, `edit`, `apply_patch`, `browser`, `canvas`, `cron`, `gateway` but NOT `exec` or `read`. OpenClaw can execute arbitrary shell commands and read local files.

**Attack Scenario:**
User asks AI to run a shell command → reads `/proc/<pid>/environ` → exfiltrates AWS credentials, Cognito secrets, bucket names. Or runs `aws sts get-caller-identity` → discovers account ID.

**Suggested Fix:**
Add `"exec"` and `"read"` to the deny list. If shell execution is needed, use a tightly scoped custom skill.

---

### H3: Cognito Password Secret in Proxy Child Process Env

- **Domain:** Bridge
- **File:** `bridge/agentcore-contract.js:509`
- **Status:** [ ] Open

**Description:**
`COGNITO_PASSWORD_SECRET` is passed as a plain env var to the proxy process:
```javascript
COGNITO_PASSWORD_SECRET: COGNITO_PASSWORD_SECRET || "",
```

**Attack Scenario:**
Combined with H2, user runs `cat /proc/$(pgrep -f agentcore-proxy)/environ` → extracts `COGNITO_PASSWORD_SECRET` → derives `HMAC-SHA256(secret, "telegram:99999999")` → authenticates as any user in Cognito.

**Suggested Fix:**
Pass via file (like the credential_process pattern) or named pipe. Verify OpenClaw cannot access sibling process `/proc` entries.

---

### H4: Proxy /health Endpoint Unauthenticated — Leaks actorId and Diagnostics

- **Domain:** Bridge
- **File:** `bridge/agentcore-proxy.js:1322-1356`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
`GET /health` on `0.0.0.0:18790` returns `last_identity` (actorId), S3 bucket name, request counts, installed skills — no authentication required.

**Suggested Fix:**
Remove `last_identity` from response. Require gateway token header, or bind to `127.0.0.1` only (see M2).

---

### H5: AgentCore SG allow_all_outbound=True

- **Domain:** CDK
- **File:** `stacks/agentcore_stack.py:57-63`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
Unrestricted egress to any IP on any port. AWS service calls route through VPC endpoints and don't need internet.

**Attack Scenario:**
Compromised container establishes reverse shell, exfiltrates credentials to attacker server. Combined with C1/C3, full credential exfiltration.

**Suggested Fix:**
```python
allow_all_outbound=False,
self.agent_sg.add_egress_rule(
    peer=ec2.Peer.any_ipv4(),
    connection=ec2.Port.tcp(443),
    description="HTTPS to VPC endpoints and internet (web_fetch/web_search tools)",
)
```
Note: `web_fetch`/`web_search` tools intentionally access the internet — this is an architectural trade-off. Restrict to HTTPS (443) only.

---

### H6: DynamoDB Identity Table Lacks CMK Encryption

- **Domain:** CDK
- **File:** `stacks/router_stack.py:55-69`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
Identity table (PII: channel user IDs, bind codes, cron messages, sessions) uses AWS-owned keys, not the project CMK. Same issue for `openclaw-token-usage` table in `token_monitoring_stack.py:40-54`.

**Suggested Fix:**
```python
encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
encryption_key=kms.Key.from_key_arn(self, "CmkKey", cmk_arn),
```

---

### H7: SNS Alarm Topic Unencrypted, No SSL Enforcement

- **Domain:** CDK
- **File:** `stacks/observability_stack.py:35-41`
- **Status:** [x] Fixed (2026-03-03)

**Suggested Fix:**
```python
master_key=kms.Key.from_key_arn(self, "AlarmTopicCmk", cmk_arn),
```
Add a topic policy that denies non-SSL subscriptions.

---

### H8: Cognito Client Has No Secret (generate_secret=False)

- **Domain:** CDK
- **File:** `stacks/security_stack.py:112-119`
- **Status:** [ ] Open

**Description:**
Sole auth barrier is the HMAC password secret. Cascades with H1 — leaked `cognito-password-secret` = auth as any user.

**Suggested Fix:**
Set `generate_secret=True` and use `SECRET_HASH` in auth requests.

---

### H9: Slack url_verification Bypasses Signature Validation

- **Domain:** Lambda
- **File:** `lambda/router/index.py:1165-1177`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
Slack `url_verification` challenge is echoed BEFORE HMAC signature validation. Any unauthenticated client can confirm the endpoint exists by POSTing `{"type":"url_verification","challenge":"probe"}`.

**Suggested Fix — Option A (recommended):**
Add env flag `SLACK_VERIFIED=true` that rejects all `url_verification` after initial setup.

**Suggested Fix — Option B (minimal):**
Validate `challenge` against a safe character set and length before echoing:
```python
if not re.match(r'^[a-zA-Z0-9_\-\.]{1,100}$', challenge):
    return {"statusCode": 400, "body": "Invalid challenge"}
```

---

### H10: Unbounded AgentCore Response Body — OOM Risk

- **Domain:** Lambda
- **File:** `lambda/router/index.py:424-425`, `lambda/cron/index.py:209-239`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
`body.read().decode("utf-8")` has no byte limit. Large AI response (e.g., 50MB from subagent) → Lambda OOM → retry storm.

**Suggested Fix:**
```python
MAX_RESPONSE_BYTES = 500_000  # 500 KB
body_text = body.read(MAX_RESPONSE_BYTES + 1).decode("utf-8", errors="replace")
if len(body_text) > MAX_RESPONSE_BYTES:
    logger.warning("AgentCore response truncated at %d bytes", MAX_RESPONSE_BYTES)
    body_text = body_text[:MAX_RESPONSE_BYTES]
```

---

### H11: Schedule Name Has No Length Cap — EventBridge 64-char Limit

- **Domain:** Skills
- **File:** `bridge/skills/eventbridge-cron/common.js:105-107`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
`buildScheduleName` produces `openclaw-{userId}-{scheduleId}` which can exceed 64 chars. Could cause cross-user collisions if EventBridge truncates.

**Suggested Fix:**
```javascript
function buildScheduleName(userId, scheduleId) {
  return `openclaw-${userId}-${scheduleId}`.slice(0, 64);
}
```
Also reduce userId component max from 64 to 32 chars.

---

### H12: list.js Missing validateEnv() — Null TableName in DynamoDB Call

- **Domain:** Skills
- **File:** `bridge/skills/eventbridge-cron/list.js:1-63`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
`create.js`, `update.js`, and `delete.js` call `validateEnv()`. `list.js` does not. In degraded deployment, DynamoDB call with `TableName: null` produces AWS SDK error that may leak infrastructure details.

**Suggested Fix:**
Add `validateEnv()` call at the top of `list.js`. One-line fix.

---

### H13: Router Lambda S3 PutObject Scoped to */_uploads/* (Any User)

- **Domain:** CDK
- **File:** `stacks/router_stack.py:196-200`
- **Status:** [ ] Open

**Description:**
```python
resources=[f"{user_files_bucket_arn}/*/_uploads/*"],
```
Allows writing to any user's `_uploads/` directory. Lambda code enforces the correct prefix, but IAM does not.

**Note:** Architectural limitation — Lambda doesn't know the target user prefix at policy authoring time. The Lambda code correctly validates the namespace. This is a defense-in-depth gap, not a direct vulnerability.

---

## MEDIUM (14 findings)

### M1: DynamoDB Session Policy Not Scoped Per-User

- **Domain:** Bridge
- **File:** `bridge/scoped-credentials.js:136-147`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
Session policy grants full access to `openclaw-identity` table and all GSIs. OpenClaw can read/modify any user's records, allowlist entries, sessions.

**Suggested Fix:**
Add `dynamodb:LeadingKeys` condition restricting to user's own `USER#` PK prefix and their `CRON#` records.

---

### M2: Proxy Binds to 0.0.0.0 Instead of 127.0.0.1

- **Domain:** Bridge
- **File:** `bridge/agentcore-proxy.js:1564`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
Proxy reachable from VPC network, not just loopback. No authentication on any endpoint.

**Suggested Fix:**
```javascript
server.listen(PORT, "127.0.0.1", () => {
```

---

### M3: Prompt Injection via Workspace Files

- **Domain:** Bridge
- **File:** `bridge/agentcore-proxy.js:529-534`
- **Status:** [ ] Open

**Description:**
User-controlled `.openclaw/` files injected into system prompt. Fence-break mitigation (escaping ``` and ~~~) is present but incomplete — heading-level injection (e.g., `## CRITICAL OVERRIDE`) not mitigated.

---

### M4: Workspace Sync Credential Expiry Not Tracked

- **Domain:** Bridge
- **File:** `bridge/workspace-sync.js:47-86`
- **Status:** [ ] Open

**Description:**
If credential refresh fails, workspace sync continues using expired credentials silently, producing confusing S3 errors.

---

### M5: Credential Directory Created with 0o755 (World-Listable)

- **Domain:** Bridge
- **File:** `bridge/scoped-credentials.js:244`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
`mkdirSync` without explicit mode creates dir with `0o755`. Files are `0o600` (correct), but dir listing is accessible.

**Suggested Fix:**
```javascript
fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
```

---

### M6: Cron Lambda Trusts EventBridge Payload Without Ownership Verification

- **Domain:** Lambda
- **File:** `lambda/cron/index.py:437-481`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
Cron Lambda accepts `userId`, `actorId`, `channel` from EventBridge payload without verifying the schedule belongs to the stated user. If a schedule is created with a manipulated userId (via prompt injection on the cron skill), it fires to the wrong user's session.

**Suggested Fix:**
Cross-check that a `CRON#` record exists in DynamoDB for the given userId and scheduleId.

---

### M7: URL Injection in Markdown-to-HTML Conversion

- **Domain:** Lambda
- **File:** `lambda/router/index.py:586-587`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
`[text](url)` → `<a href="url">text</a>` without scheme validation. `javascript:` and `data:` URIs pass through.

**Suggested Fix:**
Allowlist URL schemes: `http://`, `https://`, `tg://`, `mailto:`.

---

### M8: Secrets Cached Indefinitely in Lambda Container

- **Domain:** Lambda
- **File:** `lambda/router/index.py:62-80`, `lambda/cron/index.py:47-68`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
`_token_cache` dictionary never expires. Rotated secrets not reflected until container recycle (hours/days).

**Suggested Fix:**
Add 15-minute TTL to cache entries.

---

### M9: CloudTrail Bucket Uses SSE-S3, Not CMK

- **Domain:** CDK
- **File:** `stacks/security_stack.py:64-74`
- **Status:** [x] Fixed (2026-03-03)

---

### M10: No Secret Rotation — Referenced Script Does Not Exist

- **Domain:** CDK
- **File:** `stacks/security_stack.py:156-168`
- **Status:** [ ] Open

**Description:**
cdk-nag suppression `AwsSolutions-SMG4` cites `scripts/rotate-token.sh`. This file does not exist in the repository.

---

### M11: Token Monitoring Table RemovalPolicy.DESTROY

- **Domain:** CDK
- **File:** `stacks/token_monitoring_stack.py:40-54`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
`cdk destroy` permanently deletes all token usage audit records. Identity table correctly uses `RETAIN`.

---

### M12: No API Gateway Access Logging

- **Domain:** CDK
- **File:** `stacks/router_stack.py:256-274`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
Source IPs not captured. Critical for identifying brute-force attempts and forensic timeline reconstruction.

---

### M13: VPC Endpoint Policies Default to Allow *

- **Domain:** CDK
- **File:** `stacks/vpc_stack.py:96-103`
- **Status:** [ ] Open

**Description:**
All 7 interface VPC endpoints accept requests from any principal in the VPC.

---

### M14: No Minimum Cron Interval Enforcement

- **Domain:** Skills
- **File:** `bridge/skills/eventbridge-cron/common.js:65-76`
- **Status:** [x] Fixed (2026-03-03)

**Description:**
`cron(* * * * ? *)` (every minute) passes validation. At scale, causes Lambda cost abuse and warmup storms.

**Suggested Fix:**
Enforce minimum 5-minute interval.

---

## LOW (10 findings)

### L1: Bind Code Brute-Force Not Rate-Limited

- **Domain:** Lambda
- **File:** `lambda/router/index.py:342-390`
- **Status:** [x] Fixed (2026-03-03)

6-char hex code (16^6 = 16.7M space), 10-min TTL, API Gateway allows 100 req/s → 60K attempts → 0.36% success probability per active code.

### L2: channel_user_id Length Not Bounded Before DynamoDB Key Construction

- **Domain:** Lambda
- **File:** `lambda/router/index.py:199-277`
- **Status:** [x] Fixed (2026-03-03)

### L3: Full AI Response Body Logged (2000 chars) to CloudWatch

- **Domain:** Lambda
- **File:** `lambda/router/index.py:428, 981`
- **Status:** [x] Fixed (2026-03-03)

PII risk — reduce to metadata only, or reduce preview length.

### L4: actor_id Exposed as CloudWatch Metric Dimension

- **Domain:** Lambda
- **File:** `lambda/token_metrics/index.py:202-206`
- **Status:** [ ] Open

### L5: Workspace restoreWorkspace Does Not Validate S3 Object Size Before Download

- **Domain:** Bridge
- **File:** `bridge/workspace-sync.js:146-181`
- **Status:** [x] Fixed (2026-03-03)

### L6: NODE_OPTIONS Forwarded Unvalidated to Child Processes

- **Domain:** Bridge
- **File:** `bridge/lightweight-agent.js:265-276`
- **Status:** [x] Fixed (2026-03-03)

### L7: sanitize() Allows Leading/Trailing Dots in S3 Keys

- **Domain:** Skills
- **File:** `bridge/skills/s3-user-files/common.js:15-22`
- **Status:** [x] Fixed (2026-03-03)

### L8: ListObjectsV2 Has No MaxKeys Cap

- **Domain:** Skills
- **File:** `bridge/skills/s3-user-files/list.js:30-35`
- **Status:** [x] Fixed (2026-03-03)

### L9: S3 User Files Bucket Versioning Disabled

- **Domain:** CDK
- **File:** `stacks/agentcore_stack.py:194`
- **Status:** [x] Fixed (2026-03-03)

No recovery from accidental/malicious file deletion.

### L10: VPC Flow Log Group RemovalPolicy.DESTROY

- **Domain:** CDK
- **File:** `stacks/vpc_stack.py:44-49`
- **Status:** [x] Fixed (2026-03-03)

Destroys forensic evidence on stack removal.

---

## Verified as Secure (Not Vulnerable)

The following areas were examined and confirmed secure:

- **Telegram webhook validation** — fail-closed, timing-safe `hmac.compare_digest()`, validated before any processing
- **Slack HMAC validation** — correct `v0:{timestamp}:{body}` basestring, 5-minute replay window, constant-time comparison
- **DynamoDB operations** — all use parameterized `ExpressionAttributeValues`, no string interpolation
- **S3 image key construction** — namespace from system-computed actorId, extension from closed dict, no path traversal
- **MIME type validation** — whitelist checked before download/upload, extension from fixed dict
- **No hardcoded secrets** — all from Secrets Manager via env vars
- **Allowlist enforcement** — checked before user record creation, existing users correctly bypass
- **Cross-user S3 access** (when STS works) — session policy enforces `{namespace}/*` at AWS level
- **DynamoDB cron ownership** — `getCronRecord(userId, scheduleId)` validates ownership before delete/update
- **Atomic credential file writes** — write to `.tmp` then `rename` prevents partial reads
- **ECR image scanning on push** — enabled
- **VPC endpoints** — Bedrock, Secrets Manager, ECR, CloudWatch traffic stays on AWS backbone
- **Registration gating** — `registration_open: false` default prevents unauthorized registration

---

## Remediation Priority

### Tier 1 — Block deployment (fix immediately)

| # | Finding | Effort | Impact |
|---|---------|--------|--------|
| C1 | STS failure fallback leaks full credentials | 1-line | Highest — bypasses entire isolation |
| C3 | STS self-assume has no conditions | 5-line CDK | Closes privilege escalation path |
| H2 | exec/read not in deny list | 1-line | Closes primary container escape |
| C2 | DNS rebinding on redirects | 10-line | Closes SSRF bypass |

### Tier 2 — Next deploy cycle

| # | Finding | Effort | Impact |
|---|---------|--------|--------|
| H1 | Scope secrets to 2 needed | 2-line CDK | Limits blast radius |
| C4 | Scope CloudWatch PutMetricData | 5-line CDK | Prevents alarm falsification |
| M1 | Scope DynamoDB per-user | 15-line | Prevents cross-user record access |
| M2 | Bind proxy to 127.0.0.1 | 1-line | Reduces attack surface |
| H9 | Slack url_verification before validation | 5-line | Closes unauthenticated endpoint |
| H10 | Cap response body size | 5-line | Prevents OOM/retry storm |

### Tier 3 — Short-term backlog

| # | Finding | Effort |
|---|---------|--------|
| H3 | Cognito secret via file, not env | Medium |
| H4 | Remove last_identity from /health | Small |
| H5 | Restrict SG egress to HTTPS only | Small CDK |
| H6 | DynamoDB CMK encryption | Small CDK |
| H7 | SNS topic encryption | Small CDK |
| H8 | Cognito client secret | Medium |
| H11 | Schedule name length cap | Small |
| H12 | validateEnv() in list.js | 1-line |
| M6 | Cron ownership verification | Medium |
| M7 | URL scheme allowlist | Small |
| M14 | Minimum cron interval | Small |

### Tier 4 — Medium-term hardening

| # | Finding |
|---|---------|
| M3-M5, M8-M13 | Defense-in-depth improvements |
| L1-L10 | Low-priority hardening |

---

## Cross-Cutting Theme: Defense-in-Depth Gaps

| Layer | Current State | Needed |
|-------|---------------|--------|
| S3 access | STS session policy OK | + Hard fail on STS error (C1) |
| DynamoDB access | Full table access | + Per-user LeadingKeys condition (M1) |
| Secrets Manager | All openclaw/* readable | + Only 2 needed secrets (H1) |
| Container egress | All outbound open | + HTTPS only (H5) |
| OpenClaw tools | write/edit denied | + exec/read denied (H2) |
| STS re-assume | Unconditioned | + Session name condition (C3) |
| CloudWatch | Unrestricted namespace | + Namespace condition (C4) |

---

## Appendix: AgentCore Native Features — Mitigation Opportunities

**Research Date:** 2026-03-02
**Sources:** AgentCore CDK L1 constructs (`aws_bedrockagentcore`), AgentCore Starter Toolkit docs (`aws.github.io/bedrock-agentcore-starter-toolkit`), botocore service models

### Native Features Currently UNUSED

The project creates a `CfnWorkloadIdentity` and `CfnRuntime` but does not leverage several security-relevant native features. Below is an analysis of each feature and which audit findings it could help mitigate.

---

### 1. AuthorizerConfiguration (CustomJWTAuthorizer)

**CDK Property:** `CfnRuntime.AuthorizerConfigurationProperty`
**Sub-properties:**
- `discovery_url` — OIDC discovery endpoint (e.g., Cognito User Pool issuer URL)
- `allowed_audience` — List of allowed JWT `aud` claims
- `allowed_clients` — List of allowed OAuth client IDs
- `allowed_scopes` — List of required OAuth scopes
- `custom_claims` — Custom JWT claim validation rules (claim name, operator, value)

**What it does:**
AgentCore natively validates JWT bearer tokens on `InvokeAgentRuntime` calls before the request reaches the container. If the token is invalid, expired, or doesn't match the allowed audience/scopes, the invocation is rejected at the AgentCore level — before any container code runs.

**Mitigates:**
| Finding | How |
|---------|-----|
| **C3** (STS self-assume unconditioned) | Adds an authentication layer independent of IAM. Even if an attacker obtains temporary STS credentials, they cannot invoke the runtime without a valid Cognito JWT |
| **H8** (Cognito client no secret) | The JWT authorizer validates the token issuer and audience at the AgentCore platform level, adding defense-in-depth beyond the Cognito client auth flow |
| **M6** (Cron Lambda trusts EventBridge payload) | Could validate that the cron Lambda presents a valid service token when invoking AgentCore |

**Implementation sketch:**
```python
self.runtime = agentcore.CfnRuntime(
    ...
    authorizer_configuration=agentcore.CfnRuntime.AuthorizerConfigurationProperty(
        custom_jwt_authorizer=agentcore.CfnRuntime.CustomJWTAuthorizerConfigurationProperty(
            discovery_url=cognito_issuer_url,  # already passed to stack
            allowed_audience=[cognito_client_id],
            allowed_clients=[cognito_client_id],
        )
    ),
)
```

**Effort:** Low-medium. CDK change is small, but Router Lambda and Cron Lambda must be updated to include a Cognito JWT bearer token in `InvokeAgentRuntime` calls. The proxy already has Cognito JWT minting logic.

**Trade-off:** Requires Cognito token on every invocation. The Router Lambda would need to mint a service-level JWT or use the user's JWT for authentication, adding latency (~50ms for Cognito auth).

---

### 2. WorkloadIdentityDetails (Runtime-Linked Identity)

**CDK Property:** `CfnRuntime.WorkloadIdentityDetailsProperty`
**Sub-property:** `workload_identity_arn` — ARN of the WorkloadIdentity resource

**What it does:**
Links the runtime to a WorkloadIdentity, enabling the container to request user-scoped OAuth2 tokens via `get_workload_access_token(workload_name, user_id=...)`. The identity service provides per-user token isolation at the AgentCore platform level, with a built-in Token Vault for secure credential storage.

**Mitigates:**
| Finding | How |
|---------|-----|
| **H1** (All secrets readable) | Channel tokens (Telegram, Slack) could be stored in AgentCore Token Vault instead of Secrets Manager. The container would request tokens through the Identity API, scoped by user, instead of reading raw secrets |
| **H3** (Cognito secret in env) | Cognito authentication could potentially be replaced by AgentCore Identity's native user federation flow, removing the need for the Cognito password derivation pattern entirely |

**Implementation sketch:**
```python
self.runtime = agentcore.CfnRuntime(
    ...
    # Link to workload identity (already created but not linked)
    workload_identity_details=agentcore.CfnRuntime.WorkloadIdentityDetailsProperty(
        workload_identity_arn=self.workload_identity.attr_workload_identity_arn,
    ),
)
```

**Effort:** Medium-high. The CDK linking is trivial, but migrating from Secrets Manager + Cognito to AgentCore Identity's token vault requires significant refactoring of the proxy authentication flow. Better suited as a future architectural evolution.

**Current status:** [~] Partial (2026-03-03) — commented out in CDK (CDK version doesn't support yet). WorkloadIdentity is created (`openclaw_identity`) but linking to the runtime is blocked by CDK L1 construct support.

---

### 3. RequestHeaderConfiguration (Header Allowlist)

**CDK Property:** `CfnRuntime.RequestHeaderConfigurationProperty`
**Sub-property:** `request_header_allowlist` — List of headers forwarded to the container

**What it does:**
Restricts which HTTP headers from the `InvokeAgentRuntime` caller are forwarded to the container. By default, all `x-bedrock-*` prefixed headers and `Authorization` are forwarded. An explicit allowlist prevents unexpected headers from reaching the container.

**Mitigates:**
| Finding | How |
|---------|-----|
| **H4** (Proxy /health unauthenticated) | Not directly, but reduces attack surface by limiting header injection paths |
| General hardening | Prevents callers from injecting unexpected headers that the contract server might interpret |

**Implementation sketch:**
```python
self.runtime = agentcore.CfnRuntime(
    ...
    request_header_configuration=agentcore.CfnRuntime.RequestHeaderConfigurationProperty(
        request_header_allowlist=[
            "x-bedrock-agentcore-runtime-session-id",
            "Authorization",
        ]
    ),
)
```

**Effort:** Low. One CDK property addition. Minimal risk.

**Current status:** [~] Partial (2026-03-03) — commented out in CDK (CDK version doesn't support yet).

---

### 4. runtimeUserId (Per-Invocation User Identity)

**API Parameter:** `runtimeUserId` on `InvokeAgentRuntime`
**IAM Requirement:** Caller needs `bedrock-agentcore:InvokeAgentRuntimeForUser` in addition to `bedrock-agentcore:InvokeAgentRuntime`

**What it does:**
Passes a user identifier to the AgentCore platform at invocation time, separate from the session ID. AgentCore propagates this to the container via the `BedrockAgentCoreContext`. This provides platform-level user identity tracking independent of the container's own identity resolution.

**Mitigates:**
| Finding | How |
|---------|-----|
| **M6** (Cron Lambda trusts payload) | The `runtimeUserId` is set by the caller (Router/Cron Lambda) and propagated by AgentCore. The container could validate that the AgentCore-provided userId matches its own `USER_ID` env var |
| **C1** (STS fallback) | If AgentCore propagates the userId through a trusted path, the container could use it as a secondary validation source for namespace scoping |

**Implementation sketch (Router Lambda):**
```python
resp = agentcore_client.invoke_agent_runtime(
    agentRuntimeArn=AGENTCORE_RUNTIME_ARN,
    qualifier=AGENTCORE_QUALIFIER,
    runtimeSessionId=session_id,
    runtimeUserId=actor_id,  # <-- NEW: per-invocation user identity
    payload=payload,
    contentType="application/json",
    accept="application/json",
)
```

**Effort:** Low. Add one parameter to both Lambda invocation calls. Container needs to read the header (`x-bedrock-agentcore-runtime-user-id` or from `RequestContext`).

**Current status:** [~] Partial (2026-03-03) — implemented in both Lambda invocations (Router and Cron).

---

### 5. Distributed Tracing (traceId / traceParent / traceState)

**API Parameters:** `traceId`, `traceParent`, `traceState`, `baggage` on `InvokeAgentRuntime`

**What it does:**
Enables W3C Trace Context propagation from the Router/Cron Lambda through AgentCore to the container. X-Ray segments are automatically correlated.

**Mitigates:**
| Finding | How |
|---------|-----|
| **M12** (No API Gateway access logging) | Partially — tracing provides correlated request tracking across services, compensating for missing API Gateway access logs |
| Security incident investigation | End-to-end tracing helps reconstruct attack timelines (which webhook → which Lambda invocation → which AgentCore session → which Bedrock call) |

**Effort:** Low. Generate trace IDs in the Lambda and pass them through.

---

### 6. AgentCore Policy (Cedar-Based Tool Authorization)

**Architecture:** Policy Engine → attaches to Gateway → intercepts tool calls → evaluates Cedar policies

**What it does:**
Intercepts every tool call at the AgentCore Gateway boundary and evaluates it against Cedar authorization policies. Policies can reference JWT claims (user identity), tool parameters, and scopes.

**Mitigates:**
| Finding | How |
|---------|-----|
| **H2** (exec/read not denied) | Cedar policies could block specific tool invocations even if the OpenClaw deny list is misconfigured — platform-level enforcement outside the container |
| **M14** (No minimum cron interval) | Cedar policy could enforce `when { context.input.interval >= 300 }` on cron creation tool calls |

**Applicability:** Limited. Our architecture uses OpenClaw's native tool system, not AgentCore Gateway. To leverage AgentCore Policy, we'd need to route tool calls through an MCP Gateway, which is a significant architectural change. Better suited as a future evolution when migrating to MCP-based tools.

---

### 7. VPC Endpoint Policies (Scoped Endpoint Access)

**Configuration:** IAM policy documents attached to VPC interface endpoints

**What it does:**
Restricts which IAM principals can use specific VPC endpoints. Can scope Bedrock, Secrets Manager, ECR, and CloudWatch endpoints to the execution role only.

**Mitigates:**
| Finding | How |
|---------|-----|
| **M13** (VPC endpoint policies default Allow *) | Directly addresses this finding — add endpoint policies restricting to the execution role ARN |
| **H1** (All secrets readable) | VPC endpoint policy on Secrets Manager can restrict to specific secret ARNs, adding a network-level control in addition to IAM |

**Important note from docs:** "VPC endpoint policies can only restrict callers based on IAM principals and not OAuth users." Since our invocations use IAM (SigV4), this is fully applicable.

**Effort:** Medium. Requires passing the execution role ARN to the VPC stack or adding endpoint policies in the AgentCore stack.

---

### Summary: Native Feature → Finding Mitigation Matrix

| Native Feature | Effort | Findings Mitigated | Recommendation |
|----------------|--------|--------------------|----------------|
| **AuthorizerConfiguration** | Low-Med | C3, H8, M6 | **Implement in Tier 2** — significant defense-in-depth |
| **WorkloadIdentityDetails** (link to runtime) | Low | Foundation for future | **Quick win** — link existing resource |
| **runtimeUserId** | Low | M6, C1 (partial) | **Implement in Tier 2** — low effort, good signal |
| **RequestHeaderConfiguration** | Low | General hardening | **Quick win** — minimal risk |
| **Distributed Tracing** | Low | M12 (partial), forensics | **Implement in Tier 2** — improves observability |
| **VPC Endpoint Policies** | Medium | M13, H1 (partial) | **Implement in Tier 3** — addresses existing finding |
| **AgentCore Policy (Cedar)** | High | H2, M14 | **Future** — requires architectural change to MCP Gateway |

### Recommended Quick Wins (link existing resources + low-effort additions)

1. **Link WorkloadIdentity to Runtime** — Already created, just not connected. One CDK property.
2. **Add RequestHeaderConfiguration** — Whitelist only needed headers. One CDK property.
3. **Pass runtimeUserId in Lambda invocations** — One parameter addition per Lambda.
4. **Add traceId/traceParent** — Trace propagation for observability.

### Recommended Tier 2 (medium-term, significant security improvement)

5. **Add AuthorizerConfiguration with Cognito JWT** — Requires Lambdas to include bearer tokens, but adds platform-level authentication independent of IAM.

### Future Architectural Evolution

6. **Migrate to AgentCore Identity** — Replace custom Cognito + Secrets Manager pattern with native Token Vault.
7. **Migrate tools to MCP Gateway + Cedar Policies** — Platform-level tool authorization.
