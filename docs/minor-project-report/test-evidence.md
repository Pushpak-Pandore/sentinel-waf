# Sentinel WAF — Automated Security Testing & Verification Evidence

> **Project Title:** SENTINEL WAF — WEB APPLICATION FIREWALL  
> **Student Author:** Pushpak Pandore  
> **Program:** Cyber Security Internship  
> **Organization:** Internzvalley  
> **Verification Date:** 10 October 2026  
> **Test Suite Status:** 17 / 17 Tests Passed (100% Pass Rate)

---

## 1. Automated Unit & Integration Test Results (Vitest)

Command Executed:
```powershell
cd "p:\Internvalley intership\server"
npm test
```

### Execution Output:
```text
 > sentinel-waf-server@1.0.0 test
 > vitest run

 RUN  v2.1.9 P:/Internvalley intership/server

 ✓ tests/wafEngine.test.ts (17 tests) 274ms

 Test Files  1 passed (1)
      Tests  17 passed (17)
   Start at  22:00:15
   Duration  1.70s
```

### Detailed Test Cases Breakdown:

| Test ID | Capability / Module | Scenario | Expected Result | Observed Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | IP Evaluator | Normalize IPv4, IPv6, and IPv6-mapped addresses | `192.168.1.50`, `IPv4`, `IPv6` recognized | Correct normalization | `PASS` |
| **TC-02** | IP Evaluator | CIDR Subnet boundary matching (`192.168.1.0/24`) | Match `192.168.1.25`, reject `10.0.0.5` | Precise CIDR boundary match | `PASS` |
| **TC-03** | Regex Engine | Execution of safe regex patterns without ReDoS | `union select` regex matches safely | Safe execution | `PASS` |
| **TC-04** | WAF Pipeline | SQL Injection payload fixture (`1' UNION SELECT...`) | Request intercepted with 403 Forbidden | Blocked, Category SQLI | `PASS` |
| **TC-05** | WAF Pipeline | XSS payload fixture (`<script>alert(1)</script>`) | Request intercepted with 403 Forbidden | Blocked, Category XSS | `PASS` |
| **TC-06** | WAF Pipeline | Path Traversal / LFI payload (`../../etc/passwd`) | Request intercepted with 403 Forbidden | Blocked, Category LFI | `PASS` |
| **TC-07** | Proxy Engine | Permitted benign GET request (`/proxy/api/data`) | Upstream response 200 OK | Request forwarded | `PASS` |
| **TC-08** | Proxy Engine | Intercept malicious SQLi GET at proxy perimeter | Response 403 with Sentinel header | Intercepted at perimeter | `PASS` |
| **TC-09** | Proxy Engine | Intercept malicious XSS POST at proxy perimeter | Response 403 with error payload | Intercepted at perimeter | `PASS` |
| **TC-10** | Auth Control | Unauthenticated request to administrative API | Response 401 Unauthorized | Access denied | `PASS` |
| **TC-11** | Auth Control | Admin login with seeded credentials | Token generated, role ADMIN verified | Authenticated successfully | `PASS` |
| **TC-12** | CRS v4 & Anomaly | OWASP CRS v4 cumulative anomaly scoring | Total score calculated, inbound threshold | Cumulative score verified | `PASS` |
| **TC-13** | Shadow Mode | Candidate policy evaluation in shadow mode | Projected decision logged without blocking | Shadow decision logged | `PASS` |
| **TC-14** | HTTPS TLS | TLS certificate loader & dev fallback generation | Key/Cert pair initialized securely | Loaded TLS configuration | `PASS` |
| **TC-15** | GeoIP Engine | Public vs Loopback/Private IP lookup | `127.0.0.1` -> LOCAL, `8.8.8.8` -> US | GeoIP enrichment verified | `PASS` |
| **TC-16** | ML Anomaly | ML HTTP Anomaly Detector shadow mode scoring | Anomaly score computed without blocking | Score calculated in shadow | `PASS` |
| **TC-17** | PDF Generator | One-click Executive Security Audit PDF generation | Valid `%PDF` binary buffer generated | PDF streamed with headers | `PASS` |

---

## 2. Static Code Analysis & Production Build Verification

### Backend Type Check (`npx tsc`):
```powershell
cd "p:\Internvalley intership\server"
npx tsc
# Result: 0 errors
```

### Frontend Production Build (`tsc && vite build`):
```powershell
cd "p:\Internvalley intership\client"
npm run build
# Result: 2396 modules transformed, built in 5.89s with 0 errors
```
