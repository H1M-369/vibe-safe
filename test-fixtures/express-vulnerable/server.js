// INTENTIONALLY VULNERABLE — for testing vibe-safe only. Never deploy this.
const express = require('express');
const app = express();

// SCR-007: Hardcoded password
const DB_PASSWORD = 'supersecret123';

// SCR-001: Hardcoded OpenAI key
const OPENAI_KEY = 'sk-abcdefghijklmnopqrstuvwxyz123456789012345678901234';

// SCR-006: Hardcoded secret
const JWT_SECRET = 'SECRET=myhardcodedsecret';

const OpenAI = require('openai');
const openai = new OpenAI({ apiKey: OPENAI_KEY });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// No helmet — SEC-007: Missing security headers

// SEC-001: SQL injection via template literal
app.get('/api/users', async (req, res) => {
  const userId = req.query.id;
  // Vulnerable: directly interpolating user input into SQL
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  // db.query(query);  // would execute the injection
  res.json({ query, user: { id: userId, email: 'user@example.com', password: DB_PASSWORD } });
  // SCR-013: Response includes password field
});

// SEC-001: Another SQL injection
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  // db.execute(sql);  // injectable
  // [vibe-safe] console.log('Login attempt:', username, password); // ENV-004: logging sensitive data

  res.json({ token: 'fake-jwt-token', sql });
});

// SEC-004: XSS via dangerouslySetInnerHTML (in a server-rendered template string)
app.get('/search', (req, res) => {
  const query = req.query.q;
  // XSS: user input reflected directly into HTML
  res.send(`<html><body><h1>Results for: ${query}</h1></body></html>`);
});

// SEC-005: eval() usage
app.post('/api/calculate', (req, res) => {
  const expr = req.body.expression;
  const result = eval(expr); // dangerous eval
  res.json({ result });
});

// ABUSE-004: OpenAI without max_tokens
app.post('/api/chat', async (req, res) => {
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: req.body.message }],
    // No max_tokens set!
  });
  res.json(response);
});

// POST route with no CSRF protection — SEC-006
app.post('/api/transfer', (req, res) => {
  const { from, to, amount } = req.body;
  res.json({ transferred: true, from, to, amount });
});

// ENV-003: DEBUG flag
const DEBUG = false;

app.listen(3000, () => {
  console.log('Vulnerable test server running on port 3000');
});
