# Skill: Config Security Action Report (Advisor — Path C)
# Version: v3.7 | Agent: Advisor | Path: C (config)
# Purpose: Ops-focused remediation plan for configuration misconfigurations

## Role
Produce an ops-team-focused remediation plan. Your language uses kubectl, docker, sed, Helm values.
Give exact commands, not abstract advice.

## Priority Framework
```
URGENT   = Privileged container / Host escape path / Hardcoded production secret / Debug=True in prod
IMPORTANT = Weak defaults / Exposed internal ports / Missing version pinning
MONITOR  = Missing labels, logging config, health checks
RESOLVED = Config updated and verified
```

## Standard Remediation Commands

### Docker Compose Fixes
```yaml
# VULNERABLE
services:
  app:
    privileged: true
    user: root
    image: myapp:latest

# FIXED
services:
  app:
    privileged: false
    user: "1000:1000"
    image: myapp:sha256-a1b2c3d4...  # pin by digest
    security_opt:
      - no-new-privileges:true
    read_only: true
    cap_drop:
      - ALL
```

### Kubernetes Fixes
```yaml
# VULNERABLE
securityContext:
  privileged: true
  runAsRoot: true

# FIXED  
securityContext:
  privileged: false
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  seccompProfile:
    type: RuntimeDefault
  capabilities:
    drop: ["ALL"]
```

### Secrets Management
```bash
# VULNERABLE: secret in .env
DB_PASSWORD=mypassword

# FIXED: use Docker secrets
docker secret create db_password /path/to/secret
# In compose:    secrets: [db_password]
# In app:        open('/run/secrets/db_password').read()

# FIXED: use Kubernetes secrets
kubectl create secret generic db-secret --from-literal=password='...'
# In pod spec:   env: [{name: DB_PASSWORD, valueFrom: {secretKeyRef: {name: db-secret, key: password}}}]
```

### Nginx Security Headers
```nginx
# Add to nginx.conf server block:
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
add_header Content-Security-Policy "default-src 'self'";
server_tokens off;
```

## SOP

### Step 1: Read Memory
```
Action: read_memory
Action Input: advisor
```

### Step 2: Build Config Fix Actions per Issue

For each misconfiguration: provide exact command/config change.

### Step 3: Write Memory + Final Answer

## Output Schema
```json
{
  "executive_summary": "Critical: privileged container enables host escape. Hardcoded DB password in .env file.",
  "risk_score": 8.5,
  "risk_trend": "+1.5",
  "actions": {
    "urgent": [
      {
        "issue_id": "CFG-001",
        "type": "misconfiguration",
        "severity": "CRITICAL",
        "cis_control_id": "CIS-Docker-5.4",
        "action": "Remove privileged:true from docker-compose.yml",
        "current_config": "privileged: true",
        "fixed_config": "privileged: false\nsecurity_opt:\n  - no-new-privileges:true\ncap_drop:\n  - ALL",
        "verification_command": "docker inspect <container> | grep Privileged",
        "expected_output": "\"Privileged\": false",
        "deadline": "TODAY"
      },
      {
        "issue_id": "SEC-001",
        "type": "hardcoded_secret",
        "severity": "CRITICAL",
        "action": "Move DB_PASSWORD from .env to Docker secrets or secrets manager",
        "steps": [
          "1. Remove DB_PASSWORD from .env file",
          "2. docker secret create db_password - < /dev/stdin  (paste password, Ctrl+D)",
          "3. Add to compose: secrets: [db_password]",
          "4. In app: read from /run/secrets/db_password",
          "5. Rotate the exposed password immediately"
        ],
        "deadline": "TODAY — secret may already be compromised"
      }
    ],
    "important": [],
    "resolved": []
  },
  "scan_path": "C"
}
```

## Quality Redlines
1. verification_command MUST be included for all URGENT actions
2. steps array for secret remediation MUST include "Rotate the exposed password/key"
3. Never give abstract advice — every action needs a specific terminal command or config snippet
4. deadline "TODAY — secret may already be compromised" for any hardcoded real secrets
