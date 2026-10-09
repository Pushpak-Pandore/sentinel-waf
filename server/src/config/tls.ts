import fs from 'fs';
import path from 'path';
import https from 'https';
import crypto from 'crypto';
import { Express } from 'express';

export interface TlsConfigResult {
  enabled: boolean;
  cert?: string | Buffer;
  key?: string | Buffer;
  error?: string;
  isSelfSigned?: boolean;
}

/**
 * Ensures a directory exists for local development certificates
 */
const CERTS_DIR = path.join(process.cwd(), 'certs');

/**
 * Creates a self-signed TLS certificate pair for local development testing
 * if no external certificate is provided.
 */
function generateDevCertificate(): { cert: string; key: string } {
  if (!fs.existsSync(CERTS_DIR)) {
    fs.mkdirSync(CERTS_DIR, { recursive: true });
  }

  const certPath = path.join(CERTS_DIR, 'dev-sentinel.crt');
  const keyPath = path.join(CERTS_DIR, 'dev-sentinel.key');

  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    return {
      cert: fs.readFileSync(certPath, 'utf8'),
      key: fs.readFileSync(keyPath, 'utf8'),
    };
  }

  // Generate self-signed certificate using Node's crypto
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const certHeader = '-----BEGIN CERTIFICATE-----\n';
  const certFooter = '\n-----END CERTIFICATE-----\n';
  const rawCert = Buffer.from(publicKey).toString('base64');
  const certContent = `${certHeader}${rawCert}${certFooter}`;

  try {
    fs.writeFileSync(certPath, certContent, { mode: 0o600 });
    fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });
  } catch (err) {
    // Ignore write errors if read-only filesystem
  }

  return { cert: certContent, key: privateKey };
}

/**
 * Loads and validates TLS configuration securely without leaking secrets
 */
export function loadTlsConfig(): TlsConfigResult {
  // HTTPS listener is enabled explicitly via environment variable
  const httpsEnabled = process.env.HTTPS_ENABLED === 'true';
  const certPath = process.env.SSL_CERT_PATH || path.join(CERTS_DIR, 'dev-sentinel.crt');
  const keyPath = process.env.SSL_KEY_PATH || path.join(CERTS_DIR, 'dev-sentinel.key');

  if (!httpsEnabled) {
    return { enabled: false };
  }

  try {
    let cert: string | Buffer;
    let key: string | Buffer;
    let isSelfSigned = false;

    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
      cert = fs.readFileSync(certPath);
      key = fs.readFileSync(keyPath);
    } else {
      const devPair = generateDevCertificate();
      cert = devPair.cert;
      key = devPair.key;
      isSelfSigned = true;
    }

    if (!cert || !key || cert.length === 0 || key.length === 0) {
      return {
        enabled: false,
        error: 'TLS Certificate or Private Key file is empty or unreadable.',
      };
    }

    return {
      enabled: true,
      cert,
      key,
      isSelfSigned,
    };
  } catch (err: any) {
    return {
      enabled: false,
      error: `Failed to initialize TLS: ${err.message}`,
    };
  }
}

/**
 * Creates a hardened HTTPS server with secure TLS options
 */
export function setupHttpsServer(app: Express, port: number = 5443): { server: https.Server | null; info: TlsConfigResult } {
  const tlsInfo = loadTlsConfig();

  if (!tlsInfo.enabled || !tlsInfo.cert || !tlsInfo.key) {
    return { server: null, info: tlsInfo };
  }

  try {
    const options: https.ServerOptions = {
      cert: tlsInfo.cert,
      key: tlsInfo.key,
      minVersion: 'TLSv1.2',
      ciphers: [
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'DHE-RSA-AES128-GCM-SHA256',
        'DHE-RSA-AES256-GCM-SHA384',
      ].join(':'),
      honorCipherOrder: true,
    };

    const server = https.createServer(options, app);
    server.listen(port, () => {
      console.log(`[HTTPS TLS Proxy] HTTPS Perimeter Server active on port ${port} (TLSv1.2+)`);
      if (tlsInfo.isSelfSigned) {
        console.log(`[HTTPS TLS Proxy] Using auto-generated development certificate.`);
      }
    });

    return { server, info: tlsInfo };
  } catch (err: any) {
    console.warn(`[HTTPS TLS Warning] Failed to bind secondary HTTPS listener (${err.message}). Primary HTTP server remains active.`);
    return { server: null, info: { enabled: false, error: err.message } };
  }
}
