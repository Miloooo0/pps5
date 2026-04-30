const request = require('supertest');
const app = require('../src/app');

// Helper: obtiene el token CSRF desde la cookie y el campo hidden del HTML
async function getCsrfToken(agent, path) {
  const res = await agent.get(path);
  // csrf-csrf guarda el token en la cookie 'x-csrf-token'
  const cookieHeader = res.headers['set-cookie'] || [];
  const csrfCookie = cookieHeader.find(c => c.startsWith('x-csrf-token'));
  // El token también aparece en el campo hidden _csrf del formulario
  const match = res.text.match(/name="_csrf"\s+value="([^"]+)"/);
  const bodyToken = match ? match[1] : null;
  return { csrfCookie, bodyToken };
}

describe('Mini Secure Tickets App', () => {

  // ─── Tests funcionales básicos ──────────────────────────────────────────
  test('GET / debe devolver 200', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toBe(200);
    expect(res.text).toContain('Mini Secure Tickets App');
  });

  test('GET /tickets debe devolver 200', async () => {
    const res = await request(app).get('/tickets');
    expect(res.statusCode).toBe(200);
    expect(res.text).toContain('Listado de tickets');
  });

  test('POST /ticket/new debe crear ticket con token CSRF válido', async () => {
    const agent = request.agent(app);
    const { csrfCookie, bodyToken } = await getCsrfToken(agent, '/ticket/new');

    const res = await agent
      .post('/ticket/new')
      .set('Cookie', csrfCookie)
      .type('form')
      .send({ title: 'Ticket de prueba', description: 'Descripción de prueba', _csrf: bodyToken });

    expect(res.statusCode).toBe(200);
    expect(res.text).toContain('Ticket guardado correctamente');
  });

  // ─── Tests de cabeceras de seguridad ────────────────────────────────────
  test('Las respuestas deben incluir Content-Security-Policy', async () => {
    const res = await request(app).get('/');
    expect(res.headers['content-security-policy']).toBeDefined();
  });

  test('Las respuestas deben incluir X-Frame-Options: DENY', async () => {
    const res = await request(app).get('/');
    expect(res.headers['x-frame-options']).toBe('DENY');
  });

  test('Las respuestas deben incluir X-Content-Type-Options: nosniff', async () => {
    const res = await request(app).get('/');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  test('Las respuestas NO deben incluir X-Powered-By', async () => {
    const res = await request(app).get('/');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  test('Las respuestas deben incluir Permissions-Policy', async () => {
    const res = await request(app).get('/');
    expect(res.headers['permissions-policy']).toBeDefined();
  });

  test('Las respuestas deben incluir Cross-Origin-Opener-Policy', async () => {
    const res = await request(app).get('/');
    expect(res.headers['cross-origin-opener-policy']).toBeDefined();
  });

  test('Las respuestas deben incluir Cross-Origin-Resource-Policy', async () => {
    const res = await request(app).get('/');
    expect(res.headers['cross-origin-resource-policy']).toBeDefined();
  });

  // ─── Tests de protección CSRF ────────────────────────────────────────────
  test('POST /ticket/new sin token CSRF debe devolver 403', async () => {
    const res = await request(app)
      .post('/ticket/new')
      .type('form')
      .send({ title: 'Sin token', description: 'Debe fallar' });
    expect(res.statusCode).toBe(403);
  });

  test('POST /login sin token CSRF debe devolver 403', async () => {
    const res = await request(app)
      .post('/login')
      .type('form')
      .send({ username: 'admin', password: '1234' });
    expect(res.statusCode).toBe(403);
  });

  test('POST /comment sin token CSRF debe devolver 403', async () => {
    const res = await request(app)
      .post('/comment')
      .type('form')
      .send({ comment: 'comentario sin csrf' });
    expect(res.statusCode).toBe(403);
  });

  // ─── Tests de prevención de XSS ──────────────────────────────────────────
  test('GET /search debe escapar el parámetro q para prevenir XSS', async () => {
    const xssPayload = '<script>alert(1)</script>';
    const res = await request(app).get(`/search?q=${encodeURIComponent(xssPayload)}`);
    expect(res.statusCode).toBe(200);
    expect(res.text).not.toContain('<script>alert(1)</script>');
    expect(res.text).toContain('&lt;script&gt;');
  });

  test('POST /login debe escapar el username para prevenir XSS', async () => {
    const agent = request.agent(app);
    const { csrfCookie, bodyToken } = await getCsrfToken(agent, '/login');

    const res = await agent
      .post('/login')
      .set('Cookie', csrfCookie)
      .type('form')
      .send({ username: '<script>alert(1)</script>', password: 'x', _csrf: bodyToken });

    expect(res.statusCode).toBe(200);
    expect(res.text).not.toContain('<script>alert(1)</script>');
    expect(res.text).toContain('&lt;script&gt;');
  });

  // ─── Tests: token CSRF presente en el HTML de los formularios ────────────
  test('GET / debe incluir campo _csrf en el formulario de comentarios', async () => {
    const res = await request(app).get('/');
    expect(res.text).toContain('name="_csrf"');
  });

  test('GET /login debe incluir campo _csrf en el formulario', async () => {
    const res = await request(app).get('/login');
    expect(res.text).toContain('name="_csrf"');
  });

  test('GET /ticket/new debe incluir campo _csrf en el formulario', async () => {
    const res = await request(app).get('/ticket/new');
    expect(res.text).toContain('name="_csrf"');
  });
});