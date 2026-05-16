import { createServer } from 'node:http';

const port = Number(process.env.PORT ?? 3000);

const server = createServer((request, response) => {
  const url = new URL(request.url ?? '/', `http://${request.headers.host ?? 'localhost'}`);

  if (url.pathname === '/health') {
    sendJson(response, 200, { ok: true });
    return;
  }

  if (url.pathname === '/rest/products/search') {
    const query = url.searchParams.get('q') ?? '';

    if (query.includes("'")) {
      sendJson(response, 500, {
        error: "SQLITE_ERROR: near \"'\": syntax error",
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
});

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
