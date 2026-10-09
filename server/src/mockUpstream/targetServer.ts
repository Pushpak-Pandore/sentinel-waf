import express from 'express';

export function createMockUpstreamServer(port: number = 5001) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Upstream status header
  app.use((req, res, next) => {
    res.setHeader('X-Upstream-Server', 'Sentinel-Mock-Target-v1');
    next();
  });

  app.get('/', (req, res) => {
    res.json({
      status: 'UPSTREAM_OK',
      message: 'Welcome to the Protected Sample Web Application.',
      path: req.path,
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/data', (req, res) => {
    res.json({
      success: true,
      message: 'Sample protected resource retrieved successfully.',
      items: [
        { id: 1, name: 'Prod-Database-01', status: 'Active' },
        { id: 2, name: 'Web-Server-Cluster-A', status: 'Healthy' }
      ]
    });
  });

  // Search Endpoint (SQLi Test Target)
  app.get('/api/search', (req, res) => {
    const q = req.query.q || '';
    res.json({
      query: q,
      resultsCount: 2,
      results: [
        { id: 101, title: `Search result for '${q}'` }
      ]
    });
  });

  // Comments Endpoint (XSS Test Target)
  app.post('/api/comments', (req, res) => {
    const comment = req.body.comment || '';
    res.json({
      success: true,
      message: 'Comment posted successfully.',
      storedComment: comment
    });
  });

  // Download Endpoint (LFI/Path Traversal Target)
  app.get('/api/download', (req, res) => {
    const file = req.query.file || 'report.pdf';
    res.json({
      success: true,
      fileName: file,
      content: `[Mock File Content for ${file}]`
    });
  });

  // Auth Endpoint
  app.post('/api/login', (req, res) => {
    const { username, password } = req.body || {};
    if (username === 'admin' && password === 'admin123') {
      res.json({ success: true, token: 'mock-upstream-jwt-token-777' });
    } else {
      res.status(401).json({ success: false, error: 'Invalid upstream credentials' });
    }
  });

  const server = app.listen(port, () => {
    console.log(`[Mock Upstream App] Listening on http://localhost:${port}`);
  });

  server.on('error', (err: any) => {
    if (err.code === 'EADDRINUSE') {
      console.log(`[Mock Upstream App] Port ${port} is already in use. Reusing existing upstream instance.`);
    } else {
      console.error('[Mock Upstream App Error]:', err);
    }
  });

  return server;
}

if (require.main === module) {
  const port = parseInt(process.env.UPSTREAM_PORT || '5001', 10);
  createMockUpstreamServer(port);
}
