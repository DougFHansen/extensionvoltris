#!/usr/bin/env node
/**
 * Local fixture server for the end-to-end suite.
 *
 * Serves pages on 127.0.0.1 so the tests exercise the real browser pipeline
 * without touching any external host. `.test` names are resolved through a
 * local proxy rule so a host-based block can be observed end to end.
 */
import { createServer } from 'node:http';

const PORT = Number(process.env.FIXTURE_PORT ?? 4319);

const PAGES = {
  '/': `<!doctype html><html><head><title>Fixture home</title></head>
<body><h1>Fixture</h1><a id="clean" href="/clean.html">clean</a>
<a id="lookalike" href="https://paypal.com.secure-login.test/">lookalike</a></body></html>`,

  '/clean.html': `<!doctype html><html><head><title>Clean fixture page</title></head>
<body><h1>Legitimate banking page</h1>
<form action="/login"><input type="password" name="password" placeholder="Password"><input type="text" name="user"></form>
<img src="http://127.0.0.1:${PORT}/pixel.gif" width="1" height="1"></body></html>`,

  '/banking.html': `<!doctype html><html><head><title>Banking</title></head>
<body><h1>Sign in</h1>
<form><label>Account</label><input type="text" name="username">
<label>Password</label><input type="password" name="password"></form></body></html>`,

  '/fake-update.html': `<!doctype html><html><head><title>Critical browser update required</title>
<meta name="description" content="Your Chrome browser is out of date. Update your browser now."></head>
<body><h1>Your Chrome browser needs an update</h1>
<p>Click here to install the latest version of your browser.</p>
<a href="/browser-update-installer.exe" id="dl">Install now</a></body></html>`,

  '/fake-virus.html': `<!doctype html><html><head><title>Security warning</title></head>
<body><h1>Warning</h1><p>Your computer is infected!</p><p>42 viruses and 3 malware threats were found on your device.</p>
<p>Start a security scan of your system immediately to remove them.</p></body></html>`,
};

const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://127.0.0.1:${PORT}`);

  if (url.pathname === '/health') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok');
    return;
  }

  if (url.pathname === '/pixel.gif') {
    res.writeHead(200, { 'content-type': 'image/gif' });
    res.end(Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'));
    return;
  }

  const page = PAGES[url.pathname];
  if (page) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(page);
    return;
  }

  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end('not found');
});

server.listen(PORT, '127.0.0.1', () => {
  process.stdout.write(`fixture server listening on http://127.0.0.1:${PORT}\n`);
});
