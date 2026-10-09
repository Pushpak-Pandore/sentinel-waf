# SENTINEL WAF - Advanced Web Application Firewall & Threat Monitoring Platform

![Sentinel WAF Banner](client/public/shield.svg)

**Sentinel WAF** is an enterprise-grade Web Application Firewall and Threat Intelligence Platform engineered in Node.js, Express, TypeScript, React, Vite, and Prisma ORM.

It operates as an inline reverse proxy that intercepts inbound HTTP/HTTPS traffic, normalizes request parameters, checks IP access policies, applies rate-limiting rules, executes signature detection rules (SQLi, XSS, CSRF, LFI, Bot activity, Command Injection), enforces configurable operating modes (`PREVENTION`, `DETECTION`, `DISABLED`), and exposes real-time security analytics through an administrative console.

---

## 🏛️ Architecture Overview

```
                          +-----------------------------------+
                          |     Client / Attacker Request     |
                          +-----------------------------------+
                                            |
                                            v
                          +-----------------------------------+
                          |      SENTINEL WAF ENGINE          |
                          |     (Port 5000 / proxy route)     |
                          +-----------------------------------+
                                            |
         +----------------------------------+----------------------------------+
         |                                  |                                  |
         v                                  v                                  v
+------------------+              +------------------+              +------------------+
| 1. IP Access     |              | 2. Rate Limiting |              | 3. Signature     |
|    (IPv4 / IPv6  |              |    (Sliding      |              |    Matcher       |
|    CIDR Subnet)  |              |     Window 429)  |              |    (SQLi, XSS)   |
+------------------+              +------------------+              +------------------+
         |                                  |                                  |
         +----------------------------------+----------------------------------+
                                            |
                                            v
                          +-----------------------------------+
                          |   Enforcement Mode Resolution     |
                          | (PREVENTION / DETECTION / DISABLE)|
                          +-----------------------------------+
                                            |
                     +----------------------+----------------------+
                     | (If Allowed/Log)                            | (If Blocked)
                     v                                             v
        +--------------------------+                  +--------------------------+
        |   Upstream Proxy Target  |                  | HTTP 403 Forbidden       |
        | (Local App - Port 5001)  |                  | (Correlation ID & Log)   |
        +--------------------------+                  +--------------------------+
                     |                                             |
                     +----------------------+----------------------+
                                            |
                                            v
                          +-----------------------------------+
                          | PostgreSQL / SQLite Database Log  |
                          |   & SSE Real-time Dashboard Stream|
                          +-----------------------------------+
```

---

## 🚀 Quick Start (Local Setup)

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher
- **PowerShell** (for Windows execution)

### 1. Install Dependencies & Build Environment

Open a PowerShell terminal in the repository root directory (`p:\Internvalley intership`):

```powershell
# Install root orchestration scripts
npm install

# Install server dependencies and build Prisma database
cd server
npm install
npx prisma db push
npm run seed
cd ..

# Install client dependencies
cd client
npm install
cd ..
```

---

## 🏃 Running Sentinel WAF

Execute the following commands in separate PowerShell terminals (or tabs):

### Terminal 1: Start Backend Server & Mock Target App
```powershell
cd server
npm run dev
```
*The WAF proxy runs on `http://localhost:5000` and the test target application runs on `http://localhost:5001`.*

### Terminal 2: Start Administrative React Dashboard
```powershell
cd client
npm run dev
```
*Open `http://localhost:3000` in your web browser.*

---

## 🔑 Default Credentials

- **Administrator**: `admin@sentinel.local` / `AdminPass123!`
- **Analyst (Read-only)**: `analyst@sentinel.local` / `AnalystPass123!`

---

## 🧪 Testing Security Interception & Test Fixtures

You can test threat interception using `curl` or PowerShell `Invoke-WebRequest`:

### 1. Legitimate Request (Passed Through WAF)
```powershell
curl http://localhost:5000/proxy/api/data
```
*Returns HTTP 200 OK with `X-Sentinel-WAF: Active` header.*

### 2. SQL Injection Attack Attempt (Blocked by WAF)
```powershell
curl "http://localhost:5000/proxy/api/search?q=1'%20UNION%20SELECT%20username,password%20FROM%20users--"
```
*Returns HTTP 403 Forbidden with Sentinel Correlation ID and SQLi threat log.*

### 3. Cross-Site Scripting (XSS) Attack Attempt (Blocked)
```powershell
curl -X POST http://localhost:5000/proxy/api/comments -H "Content-Type: application/json" -d '{"comment":"<script>alert(1)</script>"}'
```
*Returns HTTP 403 Forbidden.*

### 4. Path Traversal Attempt (Blocked)
```powershell
curl "http://localhost:5000/proxy/api/download?file=../../../../etc/passwd"
```
*Returns HTTP 403 Forbidden.*

---

## 🧪 Running Automated Test Suite

Execute the vitest test suite covering unit & integration checks:

```powershell
cd server
npm test
```

---

## 🐳 Docker Deployment

To launch the full stack (PostgreSQL + Backend + Frontend) using Docker Compose:

```bash
docker-compose up --build
```

---

## 📄 License & Security Rationale

Developed as an original cybersecurity engineering project.

*Note: Custom Web Application Firewalls provide essential defense-in-depth perimeter filtering, but do not replace secure application coding standards (parameterized SQL queries, contextual output encoding, robust identity management, and network-level DDoS mitigation).*
