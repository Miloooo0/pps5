const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');

const app = express();
const PORT = process.env.PORT || 3001;

// ─── Eliminar header X-Powered-By ───────────────────────────────────────────
app.disable('x-powered-by');

// ─── Cabeceras de seguridad HTTP ─────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc:           ["'self'"],
        scriptSrc:            ["'self'"],
        styleSrc:             ["'self'", "'unsafe-inline'"],
        imgSrc:               ["'self'", 'data:'],
        formAction:           ["'self'"],
        frameAncestors:       ["'none'"],
      },
    },
    frameguard:               { action: 'deny' },
    noSniff:                  true,
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy:  { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
  })
);

// Permissions-Policy (no incluido en helmet por defecto)
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// ─── Parsers ─────────────────────────────────────────────────────────────────
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// ─── Protección CSRF ─────────────────────────────────────────────────────────
// getSessionIdentifier: como la app no tiene sesiones reales,
// usamos la IP del cliente como identificador de sesión mínimo.
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret:             () => process.env.CSRF_SECRET || 'csrf-secret-dev-only',
  getSessionIdentifier:  (req) => req.ip || 'anonymous',
  cookieName:            'x-csrf-token',
  cookieOptions: {
    sameSite: 'strict',
    secure:   process.env.NODE_ENV === 'production',
    httpOnly: true,
    path:     '/',
  },
  // El token se envía en el cuerpo como _csrf (campo hidden)
  getCsrfTokenFromRequest: (req) => req.body?._csrf,
});

app.use(doubleCsrfProtection);

// ─── "Base de datos" en memoria ──────────────────────────────────────────────
const tickets = [
  { id: 1, title: 'Error al iniciar sesión',  description: 'No puedo acceder con mi usuario' },
  { id: 2, title: 'Fallo en el panel',        description: 'El dashboard carga lentamente' },
];
const comments = [];

// ─── Helper: escape HTML para prevenir XSS en salidas reflectivas ────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ════════════════════════════════════════════════════════════════════════════
// RUTAS
// ════════════════════════════════════════════════════════════════════════════

app.get('/', (req, res) => {
  const csrfToken = generateCsrfToken(req, res);
  res.send(`
    <html>
      <head><title>Mini Secure Tickets App</title></head>
      <body>
        <h1>Mini Secure Tickets App</h1>
        <p>Aplicación de ejemplo para prácticas DevSecOps.</p>
        <ul>
          <li><a href="/login">Login</a></li>
          <li><a href="/tickets">Ver tickets</a></li>
          <li><a href="/ticket/new">Crear ticket</a></li>
          <li><a href="/comments">Ver comentarios</a></li>
        </ul>

        <h2>Buscar tickets</h2>
        <form action="/search" method="GET">
          <input type="text" name="q" placeholder="Buscar..." />
          <button type="submit">Buscar</button>
        </form>

        <h2>Añadir comentario</h2>
        <form action="/comment" method="POST">
          <input type="hidden" name="_csrf" value="${csrfToken}" />
          <textarea name="comment" rows="4" cols="50" placeholder="Escribe un comentario"></textarea><br/>
          <button type="submit">Guardar comentario</button>
        </form>
      </body>
    </html>
  `);
});

app.get('/login', (req, res) => {
  const csrfToken = generateCsrfToken(req, res);
  res.send(`
    <html>
      <head><title>Login</title></head>
      <body>
        <h1>Login</h1>
        <form action="/login" method="POST">
          <input type="hidden" name="_csrf" value="${csrfToken}" />
          <label>Usuario: <input type="text" name="username" /></label><br/><br/>
          <label>Contraseña: <input type="password" name="password" /></label><br/><br/>
          <button type="submit">Entrar</button>
        </form>
        <p><a href="/">Volver</a></p>
      </body>
    </html>
  `);
});

app.post('/login', (req, res) => {
  const { username } = req.body;
  const safeUsername = escapeHtml(username || 'usuario');
  res.send(`
    <html>
      <head><title>Bienvenido</title></head>
      <body>
        <h1>Bienvenido, ${safeUsername}</h1>
        <p>Login simulado correctamente.</p>
        <p><a href="/">Ir al inicio</a></p>
      </body>
    </html>
  `);
});

app.get('/tickets', (req, res) => {
  const items = tickets
    .map(t => `<li><strong>${escapeHtml(t.title)}</strong><br/>${escapeHtml(t.description)}</li>`)
    .join('');
  res.send(`
    <html>
      <head><title>Tickets</title></head>
      <body>
        <h1>Listado de tickets</h1>
        <ul>${items}</ul>
        <p><a href="/">Volver</a></p>
      </body>
    </html>
  `);
});

app.get('/ticket/new', (req, res) => {
  const csrfToken = generateCsrfToken(req, res);
  res.send(`
    <html>
      <head><title>Nuevo ticket</title></head>
      <body>
        <h1>Crear ticket</h1>
        <form action="/ticket/new" method="POST">
          <input type="hidden" name="_csrf" value="${csrfToken}" />
          <label>Título: <input type="text" name="title" /></label><br/><br/>
          <label>Descripción:<br/>
            <textarea name="description" rows="4" cols="50"></textarea>
          </label><br/><br/>
          <button type="submit">Guardar ticket</button>
        </form>
        <p><a href="/">Volver</a></p>
      </body>
    </html>
  `);
});

app.post('/ticket/new', (req, res) => {
  const { title, description } = req.body;
  tickets.push({
    id:          tickets.length + 1,
    title:       title       || 'Sin título',
    description: description || 'Sin descripción',
  });
  res.send(`
    <html>
      <head><title>Ticket guardado</title></head>
      <body>
        <h1>Ticket guardado correctamente</h1>
        <p><a href="/tickets">Ver tickets</a></p>
      </body>
    </html>
  `);
});

app.get('/search', (req, res) => {
  const q = req.query.q || '';
  const safeQ = escapeHtml(q);
  const results = tickets.filter(t =>
    t.title.toLowerCase().includes(q.toLowerCase()) ||
    t.description.toLowerCase().includes(q.toLowerCase())
  );
  const items = results.length
    ? results.map(t => `<li><strong>${escapeHtml(t.title)}</strong><br/>${escapeHtml(t.description)}</li>`).join('')
    : '<li>No se encontraron resultados</li>';
  res.send(`
    <html>
      <head><title>Búsqueda</title></head>
      <body>
        <h1>Resultados de búsqueda para: ${safeQ}</h1>
        <ul>${items}</ul>
        <p><a href="/">Volver</a></p>
      </body>
    </html>
  `);
});

app.post('/comment', (req, res) => {
  const { comment } = req.body;
  comments.push(escapeHtml(comment || ''));
  res.send(`
    <html>
      <head><title>Comentario guardado</title></head>
      <body>
        <h1>Comentario guardado</h1>
        <p><a href="/comments">Ver comentarios</a></p>
      </body>
    </html>
  `);
});

app.get('/comments', (req, res) => {
  const items = comments.length
    ? comments.map(c => `<li>${c}</li>`).join('')
    : '<li>No hay comentarios todavía</li>';
  res.send(`
    <html>
      <head><title>Comentarios</title></head>
      <body>
        <h1>Comentarios</h1>
        <ul>${items}</ul>
        <p><a href="/">Volver</a></p>
      </body>
    </html>
  `);
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => console.log(`App running on http://localhost:${PORT}`));
}