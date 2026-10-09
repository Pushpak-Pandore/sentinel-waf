# Sentinel WAF — Minor Project Report Deliverables

> **Student Author:** Pushpak Pandore  
> **Program:** Cyber Security Internship  
> **Organization:** Internzvalley  
> **Submission Date:** 10 October 2026  

---

## Deliverables Directory Structure

- **`MR-Pushpak Pandore.pdf`**: Final formatted Academic Minor Project Report (PDF Format).
- **`MR-Pushpak Pandore.docx`**: Editable Microsoft Word Project Report Source (DOCX Format).
- **`test-evidence.md`**: Complete automated test verification suite output and build evidence.
- **`screenshots/`**: High-resolution screenshots captured from the live running Sentinel WAF application.
  - `login_page.png` — Authentication portal.
  - `overview_dashboard.png` — Security overview dashboard.
  - `attack_analytics.png` — Attack analytics, GeoIP threat map, ML shadow telemetry & PDF report export.
  - `waf_rules.png` — OWASP CRS v4 and custom rule management.
  - `security_events.png` — Real-time security event telemetry log.
  - `request_inspector.png` — Request simulation & testing suite.
  - `virtual_patches.png` — Active virtual patches & false-positive exceptions.
  - `system_health.png` — System status & telemetry health monitor.
- **`diagrams/`**: Logical system architecture and request processing workflow diagrams.

---

## How to Regenerate or Update the Report

To regenerate both the DOCX and PDF deliverables programmatically:

```powershell
# Navigate to server directory
cd "p:\Internvalley intership\server"

# Run the report builder script
node generateReport.js
```
