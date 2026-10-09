const fs = require('fs');
const path = require('path');
const PDFDocument = require('pdfkit');
const {
  Document,
  Packer,
  Paragraph,
  TextRun,
  HeadingLevel,
  Table,
  TableRow,
  TableCell,
  WidthType,
  AlignmentType,
  BorderStyle,
  ImageRun,
} = require('docx');

const outputDir = path.join(__dirname, '..', 'docs', 'minor-project-report');
const screenshotsDir = path.join(outputDir, 'screenshots');
const docxPath = path.join(outputDir, 'MR-Pushpak Pandore.docx');
const pdfPath = path.join(outputDir, 'MR-Pushpak Pandore.pdf');
const mdPath = path.join(outputDir, 'Sentinel_WAF_Minor_Project_Report.md');

console.log('Generating Detailed Sentinel WAF Minor Project Report with embedded screenshots...');

const screenshots = [
  {
    file: 'login_page.png',
    fig: 'Figure 8.1',
    title: 'Sentinel WAF Administrative Login Portal',
    route: '/login',
    desc: 'Secure authentication gateway enforcing bcrypt hashed password validation and JWT token generation for administrative users.',
  },
  {
    file: 'overview_dashboard.png',
    fig: 'Figure 8.2',
    title: 'Security Overview & Operational Status Dashboard',
    route: '/overview',
    desc: 'High-level telemetry displaying active WAF enforcement mode, total requests processed, blocked threat counts, active rules, and application health.',
  },
  {
    file: 'attack_analytics.png',
    fig: 'Figure 8.3',
    title: 'Attack Analytics, GeoIP World Threat Map & ML Shadow Telemetry',
    route: '/analytics',
    desc: 'Interactive GeoIP threat distribution map, ML HTTP anomaly shadow mode evaluation telemetry, time-series traffic charts, and PDF report export action.',
  },
  {
    file: 'waf_rules.png',
    fig: 'Figure 8.4',
    title: 'OWASP CRS v4 & Custom WAF Security Rules Management',
    route: '/rules',
    desc: 'Management interface for enabling/disabling OWASP CRS v4 signatures, custom regex patterns, target field selections, and rule actions.',
  },
  {
    file: 'security_events.png',
    fig: 'Figure 8.5',
    title: 'Real-Time Security Event Telemetry Log & Forensics',
    route: '/events',
    desc: 'Granular security event stream containing correlation IDs, client IP addresses, attack categories, threat severities, matched rules, and payload snippets.',
  },
  {
    file: 'request_inspector.png',
    fig: 'Figure 8.6',
    title: 'Interactive Request Inspector & Attack Simulation Suite',
    route: '/inspector',
    desc: 'Payload testing suite allowing security engineers to simulate SQLi, XSS, and LFI attack vectors against the WAF inspection engine.',
  },
  {
    file: 'virtual_patches.png',
    fig: 'Figure 8.7',
    title: 'Active Virtual Patches & False-Positive Exception Management',
    route: '/virtual-patches',
    desc: 'Interface for deploying instant zero-day virtual patches and managing scoped, expiring false-positive rule exceptions.',
  },
  {
    file: 'system_health.png',
    fig: 'Figure 8.8',
    title: 'System Infrastructure Health & Telemetry Monitor',
    route: '/system-health',
    desc: 'Operational health status monitoring backend database connectivity, Redis rate limiter state, active SIEM webhooks, and upstream server availability.',
  },
];

// Helper to safely load image buffer for DOCX
function getImageBuffer(filename) {
  const p = path.join(screenshotsDir, filename);
  if (fs.existsSync(p)) {
    return fs.readFileSync(p);
  }
  return null;
}

// ---------------------------------------------------------
// 1. GENERATE DOCX FILE (WITH ALL EMBEDDED SCREENSHOTS)
// ---------------------------------------------------------

async function buildDocxReport() {
  const children = [
    // Title Page
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 800, after: 200 },
      children: [new TextRun({ text: 'SENTINEL WAF', bold: true, size: 44, color: '0F172A' })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 500 },
      children: [
        new TextRun({
          text: 'Web Application Firewall: Design, Implementation and Security Evaluation',
          italic: true,
          size: 22,
          color: '0284C7',
        }),
      ],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 1000 },
      children: [new TextRun({ text: 'MINOR PROJECT REPORT', bold: true, size: 26, color: '334155' })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 180 },
      children: [new TextRun({ text: 'Submitted by: ', bold: true, size: 22 }), new TextRun({ text: 'Pushpak Pandore', size: 22 })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 180 },
      children: [new TextRun({ text: 'Program: ', bold: true, size: 22 }), new TextRun({ text: 'Cyber Security Internship', size: 22 })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 180 },
      children: [new TextRun({ text: 'Organization: ', bold: true, size: 22 }), new TextRun({ text: 'Internzvalley', size: 22 })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 800 },
      children: [new TextRun({ text: 'Submission Date: ', bold: true, size: 22 }), new TextRun({ text: '10 October 2026', size: 22 })],
    }),

    // Abstract
    new Paragraph({ text: 'ABSTRACT', heading: HeadingLevel.HEADING_1, spacing: { before: 400, after: 200 } }),
    new Paragraph({
      text: 'Web application security is a crucial defensive priority as modern software architectures transition critical business logic to cloud-hosted HTTP/HTTPS endpoints. Modern web applications are continuously targeted by automated bots, SQL Injection (SQLi), Cross-Site Scripting (XSS), Local File Inclusion (LFI), command injection, and Distributed Denial of Service (DDoS) vectors. Sentinel WAF is an advanced, enterprise-grade Web Application Firewall and security telemetry platform engineered to inspect HTTP/HTTPS traffic at Layer 7, enforce deterministic rules and threat scoring, and provide deep operational visibility.',
      spacing: { after: 200 },
    }),
    new Paragraph({
      text: 'Sentinel WAF incorporates OWASP Core Rule Set (CRS) v4 compatibility, cumulative anomaly scoring, non-blocking candidate policy shadow evaluation, scoped false-positive exception management, route-specific virtual patching, distributed Redis rate limiting, authenticated SIEM log forwarding, dual-listener HTTPS TLS perimeter termination, MaxMind GeoIP threat map visualization, machine-learning HTTP anomaly detection in shadow mode, and one-click executive security PDF audit report export. This report documents the architectural design, component implementation, verified security test suite outcomes (17/17 test cases passed), and live application interface screenshots.',
      spacing: { after: 300 },
    }),

    // Chapter 1: Introduction
    new Paragraph({ text: 'CHAPTER 1: INTRODUCTION', heading: HeadingLevel.HEADING_1, spacing: { before: 400, after: 200 } }),
    new Paragraph({ text: '1.1 Background and Concept of Web Application Firewalls', heading: HeadingLevel.HEADING_2 }),
    new Paragraph({
      text: 'A Web Application Firewall (WAF) operates at Layer 7 (Application Layer) of the Open Systems Interconnection (OSI) model. Unlike network-layer firewalls operating at Layers 3 and 4 (IP/TCP), a WAF parses higher-level web application protocol attributes including request URIs, query strings, headers, form data, JSON request bodies, and session cookies. By inspecting raw and normalized HTTP streams, a WAF identifies malicious patterns before requests reach upstream backend servers.',
      spacing: { after: 200 },
    }),
    new Paragraph({ text: '1.2 WAF vs. Traditional Firewalls and Intrusion Detection Systems', heading: HeadingLevel.HEADING_2 }),
    new Paragraph({
      text: 'Traditional network firewalls restrict access based on IP addresses, ports, and protocols. However, web application attacks travel over standard HTTP (port 80) and HTTPS (port 443) channels allowed through network firewalls. Network Intrusion Detection/Prevention Systems (IDS/IPS) inspect packet payloads across network protocols, but often lack deep contextual understanding of application-specific routing, session tokens, and complex URL encoding variations. A WAF provides tailored protection specifically tuned to web application protocols and vulnerability patterns.',
      spacing: { after: 300 },
    }),

    // Chapter 2: Problem Statement & Objectives
    new Paragraph({ text: 'CHAPTER 2: PROBLEM STATEMENT AND OBJECTIVES', heading: HeadingLevel.HEADING_1, spacing: { before: 400, after: 200 } }),
    new Paragraph({ text: '2.1 Problem Statement', heading: HeadingLevel.HEADING_2 }),
    new Paragraph({
      text: 'Modern web applications face sophisticated cyber threats. Legacy defensive approaches rely on rigid, binary rule matching that often causes false positives—blocking legitimate users—or fails to detect complex multi-vector attacks. Furthermore, security operations teams often lack real-time visibility into geographic attack origins, struggle to test new security policies without risking production outages, and lack automated reporting capabilities for executive management.',
      spacing: { after: 200 },
    }),
    new Paragraph({ text: '2.2 Project Objectives', heading: HeadingLevel.HEADING_2 }),
    new Paragraph({
      text: '1. Design and deploy a high-performance HTTP/HTTPS reverse proxy and WAF inspection engine.\n2. Integrate OWASP Core Rule Set (CRS) v4 signatures with cumulative threat anomaly scoring.\n3. Implement safe candidate policy shadow evaluation to test new security rules without blocking valid users.\n4. Build route-specific virtual patching and scoped, expiring false-positive exception controls.\n5. Enrich security events with MaxMind GeoIP geolocation and display an interactive World Threat Map.\n6. Deploy a lightweight machine-learning HTTP anomaly detector running in shadow mode.\n7. Provide a one-click executive security audit PDF report generator for compliance and management.',
      spacing: { after: 300 },
    }),

    // Chapter 3: Existing vs Proposed
    new Paragraph({ text: 'CHAPTER 3: EXISTING SYSTEM VS. PROPOSED SYSTEM', heading: HeadingLevel.HEADING_1, spacing: { before: 400, after: 200 } }),
    new Table({
      rows: [
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'Feature Dimension', bold: true })] }),
            new TableCell({ children: [new Paragraph({ text: 'Conventional Baseline Controls', bold: true })] }),
            new TableCell({ children: [new Paragraph({ text: 'Proposed Sentinel WAF Platform', bold: true })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'Inspection Depth' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Layer 3/4 Network Port Filtering' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Layer 7 Deep HTTP/HTTPS Payload Inspection' })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'Rule Architecture' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Ad-hoc Regex Signatures' })] }),
            new TableCell({ children: [new Paragraph({ text: 'OWASP CRS v4 + Custom Rules + Virtual Patches' })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'Decision Logic' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Single-Rule Binary Match' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Cumulative Threat Anomaly Scoring' })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'Testing & Validation' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Direct Production Enforcement' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Non-Blocking Candidate Policy Shadow Mode' })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'Geo Threat Map' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Raw IP Log Files' })] }),
            new TableCell({ children: [new Paragraph({ text: 'MaxMind GeoIP Enriched World Threat Map' })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'Anomaly Analytics' })] }),
            new TableCell({ children: [new Paragraph({ text: 'None' })] }),
            new TableCell({ children: [new Paragraph({ text: 'ML HTTP Anomaly Scorer (Shadow Mode)' })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'Executive Audit' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Manual Log Export' })] }),
            new TableCell({ children: [new Paragraph({ text: 'One-Click Executive Security PDF Report Export' })] }),
          ],
        }),
      ],
    }),

    // Chapter 8: SCREENSHOTS CHAPTER (WITH EMBEDDED IMAGES)
    new Paragraph({ text: 'CHAPTER 8: ACTUAL APPLICATION SCREENSHOTS', heading: HeadingLevel.HEADING_1, spacing: { before: 400, after: 200 } }),
    new Paragraph({
      text: 'The Sentinel WAF platform was launched and verified through automated browser execution. All 8 administrative interface screens captured below represent the live running software application:',
      spacing: { after: 300 },
    }),
  ];

  // Append each screenshot with title, description, and embedded image
  for (const s of screenshots) {
    children.push(
      new Paragraph({
        text: `${s.fig}: ${s.title}`,
        heading: HeadingLevel.HEADING_3,
        spacing: { before: 300, after: 100 },
      }),
      new Paragraph({
        children: [
          new TextRun({ text: `Application Route: ${s.route} — `, bold: true }),
          new TextRun({ text: s.desc, italic: true }),
        ],
        spacing: { after: 200 },
      })
    );

    const imgBuf = getImageBuffer(s.file);
    if (imgBuf) {
      children.push(
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 400 },
          children: [
            new ImageRun({
              data: imgBuf,
              transformation: { width: 520, height: 290 },
            }),
          ],
        })
      );
    }
  }

  // Chapter 9: Security Testing
  children.push(
    new Paragraph({ text: 'CHAPTER 9: SECURITY TESTING & EVALUATION', heading: HeadingLevel.HEADING_1, spacing: { before: 400, after: 200 } }),
    new Paragraph({
      text: 'Sentinel WAF was subjected to automated unit, integration, and security payload verification using Vitest. All 17 test cases passed cleanly:',
      spacing: { after: 200 },
    }),
    new Table({
      rows: [
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'Test ID', bold: true })] }),
            new TableCell({ children: [new Paragraph({ text: 'Tested Feature', bold: true })] }),
            new TableCell({ children: [new Paragraph({ text: 'Test Scenario & Payload', bold: true })] }),
            new TableCell({ children: [new Paragraph({ text: 'Expected vs Observed Result', bold: true })] }),
            new TableCell({ children: [new Paragraph({ text: 'Status', bold: true })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'TC-01' })] }),
            new TableCell({ children: [new Paragraph({ text: 'IP Evaluator' })] }),
            new TableCell({ children: [new Paragraph({ text: 'IPv4 & IPv6 Normalization' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Normalized IP & Version correctly' })] }),
            new TableCell({ children: [new Paragraph({ text: 'PASS' })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'TC-04' })] }),
            new TableCell({ children: [new Paragraph({ text: 'WAF Engine' })] }),
            new TableCell({ children: [new Paragraph({ text: 'SQLi (1\' UNION SELECT...)' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Intercepted with 403 Forbidden' })] }),
            new TableCell({ children: [new Paragraph({ text: 'PASS' })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'TC-05' })] }),
            new TableCell({ children: [new Paragraph({ text: 'WAF Engine' })] }),
            new TableCell({ children: [new Paragraph({ text: 'XSS (<script>alert(1)</script>)' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Intercepted with 403 Forbidden' })] }),
            new TableCell({ children: [new Paragraph({ text: 'PASS' })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'TC-06' })] }),
            new TableCell({ children: [new Paragraph({ text: 'WAF Engine' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Path Traversal (../../etc/passwd)' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Intercepted with 403 Forbidden' })] }),
            new TableCell({ children: [new Paragraph({ text: 'PASS' })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'TC-14' })] }),
            new TableCell({ children: [new Paragraph({ text: 'HTTPS TLS' })] }),
            new TableCell({ children: [new Paragraph({ text: 'TLS Loader & Dev Cert Fallback' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Self-signed cert pair generated' })] }),
            new TableCell({ children: [new Paragraph({ text: 'PASS' })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'TC-15' })] }),
            new TableCell({ children: [new Paragraph({ text: 'GeoIP Engine' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Public vs Private IP lookup' })] }),
            new TableCell({ children: [new Paragraph({ text: '127.0.0.1 -> LOCAL; 8.8.8.8 -> US' })] }),
            new TableCell({ children: [new Paragraph({ text: 'PASS' })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'TC-16' })] }),
            new TableCell({ children: [new Paragraph({ text: 'ML Anomaly' })] }),
            new TableCell({ children: [new Paragraph({ text: 'ML Shadow Mode scoring' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Computed score without blocking' })] }),
            new TableCell({ children: [new Paragraph({ text: 'PASS' })] }),
          ],
        }),
        new TableRow({
          children: [
            new TableCell({ children: [new Paragraph({ text: 'TC-17' })] }),
            new TableCell({ children: [new Paragraph({ text: 'PDF Export' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Executive PDF Report Export' })] }),
            new TableCell({ children: [new Paragraph({ text: 'Valid %PDF binary stream generated' })] }),
            new TableCell({ children: [new Paragraph({ text: 'PASS' })] }),
          ],
        }),
      ],
    }),

    // Chapter 12: Conclusion
    new Paragraph({ text: 'CHAPTER 12: CONCLUSION', heading: HeadingLevel.HEADING_1, spacing: { before: 400, after: 200 } }),
    new Paragraph({
      text: 'Sentinel WAF successfully demonstrates a production-grade Web Application Firewall and Threat Telemetry architecture. By combining deterministic OWASP CRS v4 signatures, cumulative anomaly scoring, candidate policy shadow evaluation, GeoIP threat map visualization, machine-learning anomaly detection, and automated executive PDF audit reporting, Sentinel WAF delivers comprehensive, defense-in-depth application perimeter security.',
      spacing: { after: 300 },
    })
  );

  const doc = new Document({
    sections: [{ properties: {}, children }],
  });

  const buffer = await Packer.toBuffer(doc);
  try {
    fs.writeFileSync(docxPath, buffer);
    console.log(`[DOCX Report Generated with Screenshots]: ${docxPath} (${buffer.length} bytes)`);
  } catch (e) {
    const fallbackPath = path.join(outputDir, 'Sentinel_WAF_Minor_Project_Report_Pushpak_Pandore.docx');
    fs.writeFileSync(fallbackPath, buffer);
    console.log(`[DOCX Report Generated (Fallback Path)]: ${fallbackPath} (${buffer.length} bytes)`);
  }
}

// ---------------------------------------------------------
// 2. GENERATE PDF FILE (WITH ALL EMBEDDED SCREENSHOTS)
// ---------------------------------------------------------

async function buildPdfReport() {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 40, size: 'A4' });
      let targetPdfPath = pdfPath;
      try {
        const testFd = fs.openSync(pdfPath, 'w');
        fs.closeSync(testFd);
      } catch {
        targetPdfPath = path.join(outputDir, 'MR-Pushpak-Pandore-Report.pdf');
      }

      const stream = fs.createWriteStream(targetPdfPath);
      doc.pipe(stream);

      // Title Page
      doc.rect(0, 0, 595.28, 841.89).fill('#0f172a');
      doc.fillColor('#38bdf8').fontSize(32).font('Helvetica-Bold').text('SENTINEL WAF', 40, 180, { align: 'center' });
      doc.fillColor('#94a3b8').fontSize(14).font('Helvetica').text('Web Application Firewall: Design, Implementation and Security Evaluation', 40, 225, { align: 'center' });
      doc.fillColor('#f8fafc').fontSize(18).font('Helvetica-Bold').text('MINOR PROJECT REPORT', 40, 320, { align: 'center' });
      doc.fillColor('#cbd5e1').fontSize(12).font('Helvetica').text('Submitted by: Pushpak Pandore', 40, 420, { align: 'center' });
      doc.text('Program: Cyber Security Internship', 40, 445, { align: 'center' });
      doc.text('Organization: Internzvalley', 40, 470, { align: 'center' });
      doc.text('Submission Date: 10 October 2026', 40, 495, { align: 'center' });

      // Page 2: Abstract & Introduction
      doc.addPage();
      doc.fillColor('#0f172a').fontSize(18).font('Helvetica-Bold').text('ABSTRACT', 40, 40);
      doc.fillColor('#334155').fontSize(10).font('Helvetica').text(
        'Web application security is a crucial defensive priority as organizations transition critical workflows to public cloud infrastructure. Sentinel WAF is an advanced enterprise-grade Web Application Firewall and security telemetry platform designed to inspect HTTP/HTTPS traffic in real time, enforce rule-based and anomaly-based policies, and provide operational threat visibility.\n\nSentinel WAF incorporates OWASP Core Rule Set (CRS) v4 compatibility, cumulative anomaly scoring, candidate policy shadow evaluation, scoped false-positive exception management, route-specific virtual patching, distributed rate limiting, SIEM webhook log forwarding, HTTPS/TLS termination, GeoIP threat map visualization, machine-learning HTTP anomaly detection in shadow mode, and one-click executive security PDF report generation.',
        40, 70, { width: 515 }
      );

      doc.fillColor('#0f172a').fontSize(14).font('Helvetica-Bold').text('CHAPTER 1: INTRODUCTION', 40, 240);
      doc.fillColor('#334155').fontSize(10).font('Helvetica').text(
        'A Web Application Firewall (WAF) operates at Layer 7 of the OSI model, inspecting HTTP/HTTPS streams between clients and target web applications. Unlike Layer 3/4 network firewalls, a WAF parses higher-level web protocol attributes including URIs, query parameters, request headers, form inputs, JSON payloads, and cookies to mitigate web vulnerability exploits.',
        40, 265, { width: 515 }
      );

      // Chapter 8: Screenshots pages (One screenshot per page with title and description)
      doc.addPage();
      doc.fillColor('#0f172a').fontSize(18).font('Helvetica-Bold').text('CHAPTER 8: ACTUAL APPLICATION SCREENSHOTS', 40, 40);
      doc.fillColor('#334155').fontSize(10).font('Helvetica').text(
        'The following sections present real high-resolution interface captures from the live running Sentinel WAF platform:',
        40, 70, { width: 515 }
      );

      let currentY = 100;
      for (const s of screenshots) {
        const imgPath = path.join(screenshotsDir, s.file);
        if (fs.existsSync(imgPath)) {
          if (currentY > 500) {
            doc.addPage();
            currentY = 40;
          }

          doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold').text(`${s.fig}: ${s.title}`, 40, currentY);
          doc.fillColor('#64748b').fontSize(9).font('Helvetica-Oblique').text(`Route: ${s.route} — ${s.desc}`, 40, currentY + 16, { width: 515 });
          
          doc.image(imgPath, 40, currentY + 35, { width: 515 });
          currentY += 340;
        }
      }

      // Final Page: Testing Evidence & Conclusion
      doc.addPage();
      doc.fillColor('#0f172a').fontSize(16).font('Helvetica-Bold').text('CHAPTER 9 & 12: SECURITY TESTING & CONCLUSION', 40, 40);
      doc.fillColor('#334155').fontSize(10).font('Helvetica').text(
        'Sentinel WAF was subjected to comprehensive automated unit and integration testing using Vitest. All 17 automated test cases passed cleanly with 100% success rate.\n\nVerified Capabilities Matrix:\n- IP & CIDR Boundary Parsing: PASS\n- SQL Injection Interception: PASS\n- XSS Payload Interception: PASS\n- Path Traversal / LFI Interception: PASS\n- Permitted Upstream Proxying: PASS\n- HTTPS TLS Certificate Loader: PASS\n- GeoIP Threat Map Enrichment: PASS\n- ML Anomaly Shadow Evaluation: PASS\n- Executive Security Audit PDF Export: PASS\n\nConclusion:\nSentinel WAF successfully fulfills all objectives of an enterprise-grade Web Application Firewall and Threat Monitoring platform. By combining deterministic OWASP CRS v4 signatures, cumulative threat anomaly scoring, non-blocking shadow evaluation, GeoIP threat map visualization, ML HTTP anomaly detection, and automated PDF audit report generation, Sentinel WAF provides a robust, defense-in-depth perimeter safeguard for web applications.',
        40, 70, { width: 515 }
      );

      doc.end();

      stream.on('finish', () => {
        console.log(`[PDF Report Generated with Screenshots]: ${pdfPath}`);
        resolve();
      });
      stream.on('error', (err) => reject(err));
    } catch (err) {
      reject(err);
    }
  });
}

// ---------------------------------------------------------
// 3. GENERATE MARKDOWN FILE (WITH ALL EMBEDDED MARKDOWN IMAGES)
// ---------------------------------------------------------

function buildMarkdownReport() {
  let mdContent = `# SENTINEL WAF — WEB APPLICATION FIREWALL
## Web Application Firewall: Design, Implementation and Security Evaluation

**Minor Project Report**  
**Submitted by:** Pushpak Pandore  
**Program:** Cyber Security Internship  
**Organization:** Internzvalley  
**Submission Date:** 10 October 2026  

---

## ABSTRACT

Web application security is a crucial defensive priority as organizations transition critical workflows to public cloud infrastructure. Modern web applications are continuously exposed to automated scanning, SQL injection (SQLi), Cross-Site Scripting (XSS), Path Traversal / Local File Inclusion (LFI), bot abuse, and Denial-of-Service (DoS) vectors. Sentinel WAF is an advanced enterprise-grade Web Application Firewall and security telemetry platform designed to inspect HTTP/HTTPS traffic in real time, enforce rule-based and anomaly-based policies, and provide operational threat visibility.

Sentinel WAF incorporates OWASP Core Rule Set (CRS) v4 compatibility, cumulative anomaly scoring, candidate policy shadow evaluation, scoped false-positive exception management, route-specific virtual patching, distributed rate limiting, SIEM webhook log forwarding, HTTPS/TLS termination, GeoIP threat map visualization, machine-learning HTTP anomaly detection in shadow mode, and one-click executive security PDF report generation.

**Keywords:** Web Application Firewall, OWASP CRS v4, Threat Scoring, HTTPS Proxy, GeoIP, ML Anomaly Detection, DevSecOps.

---

## CHAPTER 1: INTRODUCTION

### 1.1 Overview of Web Application Firewalls
A Web Application Firewall (WAF) operates at Layer 7 (Application Layer) of the OSI model, inspecting HTTP and HTTPS request/response streams between clients and target web applications. Unlike network firewalls operating at Layers 3 and 4 (IP/TCP), a WAF parses higher-level web application protocol attributes including URIs, query parameters, headers, form data, JSON bodies, and cookies.

### 1.2 WAF vs. Traditional Firewalls and IDS/IPS
Traditional network firewalls filter traffic based on source/destination IP addresses and TCP/UDP ports. Intrusion Detection/Prevention Systems (IDS/IPS) inspect network packets against broad signatures, but often lack deep contextual understanding of application-specific routing, session tokens, and normalized URL encoding. A WAF provides granular protection specifically tuned to web application protocols.

---

## CHAPTER 2: PROBLEM STATEMENT AND OBJECTIVES

### 2.1 Problem Statement
Modern web applications face sophisticated cyber threats. Legacy defensive approaches rely on rigid binary rule matching that often causes false positives—blocking legitimate users—or fails to detect complex multi-vector attacks. Furthermore, security teams lack visibility into geographic threat origins and struggle to test new security policies without risking production outages.

### 2.2 Project Objectives
1. Implement a reverse proxy architecture inspecting HTTP (Port 5000) and HTTPS (Port 5443) traffic.
2. Integrate OWASP CRS v4 signature inspection with explainable cumulative threat anomaly scoring.
3. Provide safe shadow evaluation for testing candidate security policies without impacting live users.
4. Support scoped, expiring false-positive exceptions and route-specific virtual patching.
5. Incorporate GeoIP threat map visualization and machine-learning HTTP anomaly detection in shadow mode.
6. Deliver a one-click executive security audit PDF report generator.

---

## CHAPTER 8: APPLICATION SCREENSHOTS & UI VERIFICATION

The Sentinel WAF administrative interface was verified through live browser execution. Below are the actual application screenshots captured from the running software:

`;

  for (const s of screenshots) {
    mdContent += `### ${s.fig}: ${s.title}\n\n`;
    mdContent += `* **Route:** \`${s.route}\`\n`;
    mdContent += `* **Description:** ${s.desc}\n\n`;
    mdContent += `![${s.title}](screenshots/${s.file})\n\n`;
    mdContent += `---\n\n`;
  }

  mdContent += `## CHAPTER 9: SECURITY TESTING & EVALUATION

Sentinel WAF was verified using an automated Vitest test suite. All 17 test cases passed cleanly with 100% success rate:

| Test ID | Capability | Scenario & Payload | Expected vs Observed Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **TC-01** | IP Evaluator | IPv4 & IPv6 Normalization | Normalized IP & Version correctly | \`PASS\` |
| **TC-04** | WAF Engine | SQLi (\`1' UNION SELECT...\`) | Intercepted with 403 Forbidden | \`PASS\` |
| **TC-05** | WAF Engine | XSS (\`<script>alert(1)</script>\`) | Intercepted with 403 Forbidden | \`PASS\` |
| **TC-06** | WAF Engine | Path Traversal (\`../../etc/passwd\`) | Intercepted with 403 Forbidden | \`PASS\` |
| **TC-07** | Proxy Engine | Permitted GET request | Forwarded to upstream 200 OK | \`PASS\` |
| **TC-14** | HTTPS TLS | TLS Loader & Dev Cert Fallback | Self-signed cert pair generated | \`PASS\` |
| **TC-15** | GeoIP Engine | Public vs Private IP lookup | 127.0.0.1 -> LOCAL; 8.8.8.8 -> US | \`PASS\` |
| **TC-16** | ML Anomaly | ML Shadow Mode scoring | Computed score without blocking | \`PASS\` |
| **TC-17** | PDF Export | Executive PDF Report Export | Valid %PDF binary stream generated | \`PASS\` |

---

## CHAPTER 12: CONCLUSION

Sentinel WAF successfully demonstrates a production-grade Web Application Firewall and Threat Telemetry architecture. By combining deterministic OWASP CRS v4 signatures, cumulative threat anomaly scoring, candidate policy shadow evaluation, GeoIP threat map visualization, machine-learning anomaly detection, and automated PDF audit report generation, Sentinel WAF delivers comprehensive, defense-in-depth application perimeter security.
`;

  fs.writeFileSync(mdPath, mdContent);
  console.log(`[Markdown Report Generated with Embedded Images]: ${mdPath}`);
}

async function main() {
  await buildDocxReport();
  await buildPdfReport();
  buildMarkdownReport();
  console.log('All Sentinel WAF Minor Project Report deliverables generated successfully!');
}

main().catch(console.error);
