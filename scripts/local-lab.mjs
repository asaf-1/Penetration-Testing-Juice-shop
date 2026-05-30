import { createServer } from 'node:http';
import { createHmac } from 'node:crypto';

const port = Number(process.env.PORT ?? 3000);

// Simple in-memory user store for the lab. Keys are email addresses.
const users = new Map();
let nextUserId = 100;

// Collect request body as a string.
function readBody(request) {
  return new Promise((resolve) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    request.on('error', () => resolve(''));
  });
}

// Produce a minimal signed JWT for the lab (HS256 with a fixed lab secret).
const LAB_SECRET = 'lab-secret-do-not-use-in-production';

function makeJwt(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = createHmac('sha256', LAB_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

const server = createServer((request, response) => {
  handleRequest(request, response).catch((error) => {
    console.error('Request handler error:', error);
    if (!response.headersSent) {
      response.writeHead(500, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ message: 'Internal server error' }));
    }
  });
});

async function handleRequest(request, response) {
  const url = new URL(request.url ?? '/', `http://${request.headers.host ?? 'localhost'}`);

  if (url.pathname === '/health') {
    sendJson(response, 200, { ok: true });
    return;
  }

  // --- User registration ---
  if (url.pathname === '/api/Users' && request.method === 'POST') {
    const raw = await readBody(request);
    let data = {};
    try {
      data = JSON.parse(raw);
    } catch {
      /* ignore */
    }
    const { email, password } = data;
    if (!email || !password) {
      sendJson(response, 400, { message: 'email and password are required' });
      return;
    }
    if (users.has(email)) {
      sendJson(response, 409, { message: 'email already registered' });
      return;
    }
    const id = nextUserId++;
    users.set(email, { id, email, password });
    sendJson(response, 201, { status: 'success', data: { id, email } });
    return;
  }

  // --- User list (protected) ---
  if (url.pathname === '/api/Users' && request.method === 'GET') {
    const auth = request.headers['authorization'] ?? '';
    if (!auth.startsWith('Bearer ')) {
      sendJson(response, 401, { message: 'Unauthorized' });
      return;
    }
    // Return a limited public view — no passwords.
    const list = Array.from(users.values()).map(({ id, email }) => ({ id, email }));
    sendJson(response, 200, { status: 'success', data: list });
    return;
  }

  // --- Login ---
  if (url.pathname === '/rest/user/login' && request.method === 'POST') {
    const raw = await readBody(request);
    let data = {};
    try {
      data = JSON.parse(raw);
    } catch {
      /* ignore */
    }
    const { email, password } = data;
    const user = users.get(email ?? '');
    if (!user || user.password !== password) {
      sendJson(response, 401, { message: 'Invalid email or password' });
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({
      data: { id: user.id, email: user.email, role: 'customer' },
      iat: now,
      exp: now + 3600
    });
    sendJson(response, 200, { authentication: { token, bid: user.id } });
    return;
  }

  // --- Basket (protected, IDOR simulation) ---
  if (/^\/rest\/basket\/\d+$/.test(url.pathname)) {
    const auth = request.headers['authorization'] ?? '';
    if (!auth.startsWith('Bearer ')) {
      sendJson(response, 401, { message: 'Unauthorized' });
      return;
    }
    const basketId = Number(url.pathname.split('/').pop());
    // Each basket belongs to a different user to simulate IDOR.
    sendJson(response, 200, { status: 'success', data: { id: basketId, UserId: basketId } });
    return;
  }

  // --- Other protected API endpoints ---
  if (url.pathname === '/api/BasketItems' || url.pathname === '/api/Complaints') {
    sendJson(response, 401, { message: 'Unauthorized' });
    return;
  }

  if (url.pathname === '/rest/admin/application-configuration') {
    sendJson(response, 401, { message: 'Unauthorized' });
    return;
  }

  if (url.pathname === '/rest/user/whoami') {
    sendJson(response, 200, { user: {} });
    return;
  }

  // --- FTP files: block non-allowlisted extensions ---
  if (url.pathname.startsWith('/ftp/') && url.pathname !== '/ftp/') {
    const file = url.pathname.slice(5); // strip /ftp/
    const allowed = /\.(md|txt|pdf)$/i.test(file);
    if (!allowed) {
      sendJson(response, 403, { message: 'Only .md, .txt, and .pdf files may be downloaded' });
      return;
    }
    sendJson(response, 404, { message: 'File not found' });
    return;
  }

  if (url.pathname === '/rest/products/search') {
    const query = url.searchParams.get('q') ?? '';

    if (query.includes("'")) {
      sendJson(response, 500, {
        error: 'SQLITE_ERROR: near "\'": syntax error',
        detail: 'Simulated lab error for safe input-handling automation.'
      });
      return;
    }

    sendJson(response, 200, {
      status: 'success',
      data: [
        { id: 1, name: 'Apple Juice', price: 1.99 },
        { id: 2, name: 'Orange Juice', price: 2.49 }
      ],
      query
    });
    return;
  }

  if (url.pathname === '/ftp') {
    sendHtml(
      response,
      200,
      `<!doctype html>
<html lang="en">
  <head><title>File Listing</title></head>
  <body>
    <h1>Index of /ftp</h1>
    <ul>
      <li><a href="/ftp/acquisitions.md">acquisitions.md</a></li>
      <li><a href="/ftp/legal.md">legal.md</a></li>
      <li><a href="/ftp/incident-report.txt">incident-report.txt</a></li>
    </ul>
  </body>
</html>`
    );
    return;
  }

  if (url.pathname === '/security.txt') {
    response.writeHead(200, {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store'
    });
    response.end('Contact: security@example.test\nPolicy: local lab only\n');
    return;
  }

  if (url.pathname !== '/') {
    sendHtml(
      response,
      404,
      `<!doctype html>
<html lang="en">
  <head><title>Not Found</title></head>
  <body><h1>Not Found</h1></body>
</html>`
    );
    return;
  }

  sendHtml(response, 200, appHtml());
}

server.listen(port, () => {
  console.log(`Local lab target listening at http://localhost:${port}`);
});

process.on('SIGINT', close);
process.on('SIGTERM', close);

function close() {
  server.close(() => process.exit(0));
}

function sendJson(response, status, payload) {
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store'
  });
  response.end(`${JSON.stringify(payload, null, 2)}\n`);
}

function sendHtml(response, status, html) {
  response.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'set-cookie': 'lab_session=demo; Path=/; SameSite=Lax'
  });
  response.end(html);
}

function appHtml() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Local Security Lab</title>
    <style>
      :root {
        color-scheme: light;
        font-family: Arial, Helvetica, sans-serif;
        background: #f4f6f8;
        color: #1f2933;
      }

      body {
        margin: 0;
      }

      header {
        background: #0f172a;
        color: #ffffff;
        padding: 18px 28px;
      }

      nav {
        display: flex;
        gap: 16px;
        margin-top: 12px;
      }

      nav a {
        color: #dbeafe;
        text-decoration: none;
      }

      main {
        max-width: 960px;
        margin: 0 auto;
        padding: 32px 24px;
      }

      section {
        background: #ffffff;
        border: 1px solid #d9e2ec;
        border-radius: 8px;
        padding: 24px;
      }

      label {
        display: block;
        font-weight: 700;
        margin-top: 14px;
      }

      input {
        box-sizing: border-box;
        display: block;
        width: min(420px, 100%);
        margin-top: 6px;
        padding: 10px 12px;
        border: 1px solid #bcccdc;
        border-radius: 6px;
      }

      button {
        margin-top: 18px;
        padding: 10px 16px;
        border: 0;
        border-radius: 6px;
        background: #2563eb;
        color: #ffffff;
        cursor: pointer;
      }

      .notice {
        margin-top: 16px;
        color: #b42318;
        font-weight: 700;
      }

      .products {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 16px;
        margin-top: 18px;
      }

      .product {
        border: 1px solid #d9e2ec;
        border-radius: 8px;
        padding: 16px;
      }
    </style>
  </head>
  <body>
    <header>
      <h1>Local Security Lab</h1>
      <nav aria-label="Primary">
        <a href="#/">Home</a>
        <a href="#/search?q=apple">Search</a>
        <a href="#/login">Login</a>
        <a href="#/basket">Basket</a>
        <a href="#/administration">Administration</a>
      </nav>
    </header>
    <main id="app"></main>
    <script>
      const app = document.getElementById('app');

      window.addEventListener('hashchange', render);
      render();

      function render() {
        const hash = location.hash || '#/';
        const [route, queryString = ''] = hash.slice(1).split('?');
        const params = new URLSearchParams(queryString);

        if (route === '/login') {
          app.innerHTML = loginTemplate();
          document.getElementById('login-form').addEventListener('submit', (event) => {
            event.preventDefault();
            document.getElementById('login-message').textContent = 'Invalid email or password.';
          });
          return;
        }

        if (route === '/search') {
          const query = params.get('q') || '';
          app.innerHTML = searchTemplate(query);
          return;
        }

        if (route === '/basket') {
          app.innerHTML = guardedTemplate('Basket', 'Please log in to view your basket.');
          return;
        }

        if (route === '/administration') {
          app.innerHTML = guardedTemplate('Administration', 'Please log in. Administration requires authorization.');
          return;
        }

        if (route === '/profile') {
          app.innerHTML = guardedTemplate('Profile', 'Please log in to view your profile.');
          return;
        }

        if (route === '/order-history') {
          app.innerHTML = guardedTemplate('Order History', 'Please log in to view your order history.');
          return;
        }

        app.innerHTML = homeTemplate();
      }

      function homeTemplate() {
        return '<section><h2>Products</h2><p>Use this local lab for safe Playwright automation practice.</p><div class="products"><article class="product"><h3>Apple Juice</h3><p>$1.99</p></article><article class="product"><h3>Orange Juice</h3><p>$2.49</p></article></div></section>';
      }

      function loginTemplate() {
        return '<section><h2>Login</h2><form id="login-form"><label for="email">Email</label><input id="email" name="email" type="email" placeholder="Email"><label for="password">Password</label><input id="password" name="password" type="password" placeholder="Password"><button id="loginButton" type="submit">Log in</button><div id="login-message" class="notice" role="status"></div></form></section>';
      }

      function searchTemplate(query) {
        return '<section><h2>Search</h2><p>Search results for: <strong>' + escapeHtml(query) + '</strong></p><div class="products"><article class="product"><h3>Apple Juice</h3><p>Matches demo query.</p></article></div></section>';
      }

      function guardedTemplate(title, message) {
        return '<section><h2>' + escapeHtml(title) + '</h2><p class="notice">' + escapeHtml(message) + '</p></section>';
      }

      function escapeHtml(value) {
        return value.replace(/[&<>"']/g, (character) => {
          return {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
          }[character];
        });
      }
    </script>
  </body>
</html>`;
}
