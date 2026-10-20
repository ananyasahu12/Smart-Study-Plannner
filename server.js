const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = __dirname;
const DATA_DIR = process.env.STUDYFLOW_DATA_DIR || path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'studyflow.json');
const PORT = Number(process.env.PORT) || 4173;
const COOKIE = 'studyflow_session';
let database = { users: [], planners: {}, sessions: [] };
let writeQueue = Promise.resolve();

async function loadDatabase() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try { database = JSON.parse(await fs.readFile(DB_FILE, 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; await persist(); }
  if (!Array.isArray(database.users)) database.users = [];
  if (!database.planners || typeof database.planners !== 'object') database.planners = {};
  if (!Array.isArray(database.sessions)) database.sessions = [];
  const activeSessions = database.sessions.filter(session => session.expiresAt > Date.now());
  if (activeSessions.length !== database.sessions.length) { database.sessions = activeSessions; await persist(); }
}
function persist() {
  writeQueue = writeQueue.then(async () => {
    const temp = `${DB_FILE}.tmp`;
    await fs.writeFile(temp, JSON.stringify(database, null, 2), { mode: 0o600 });
    await fs.rename(temp, DB_FILE);
  });
  return writeQueue;
}
function json(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function cookieOptions(maxAge) { return `${COOKIE}=${maxAge ? '' : 'deleted'}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge || 0}`; }
function getSession(req) {
  const header = req.headers.cookie || '';
  const token = header.split(';').map(s => s.trim()).find(s => s.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1);
  if (!token) return null;
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const session = database.sessions.find(item => item.tokenHash === hash && item.expiresAt > Date.now());
  const userId = session?.userId;
  const user = database.users.find(item => item.id === userId);
  return user ? { token, user } : null;
}
function publicUser(user) { return { id: user.id, name: user.name, email: user.email }; }
function plannerFor(userId) {
  if (!database.planners[userId]) database.planners[userId] = { subjects: [], tasks: [], preferences: { dailyMinutes: 120, remindersEnabled: false } };
  const planner = database.planners[userId];
  if (!Array.isArray(planner.subjects)) planner.subjects = [];
  if (!Array.isArray(planner.tasks)) planner.tasks = [];
  if (!planner.preferences) planner.preferences = { dailyMinutes: 120, remindersEnabled: false };
  return planner;
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 1024 * 1024) reject(new Error('Request body is too large.')); });
    req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch { reject(new Error('Request body must be valid JSON.')); } });
    req.on('error', reject);
  });
}
function cleanText(value, limit) { return typeof value === 'string' ? value.trim().slice(0, limit) : ''; }
function validDate(value) { return !value || (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(`${value}T00:00:00Z`))); }
function boundedNumber(value, fallback, min, max) { const n = Number(value); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback; }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (error, key) => error ? reject(error) : resolve({ salt, hash: key.toString('hex') })));
}
function verifyPassword(password, user) {
  return new Promise((resolve, reject) => crypto.scrypt(password, user.salt, 64, (error, key) => {
    if (error) return reject(error);
    const expected = Buffer.from(user.passwordHash, 'hex');
    resolve(expected.length === key.length && crypto.timingSafeEqual(expected, key));
  }));
}
async function sendSession(res, user) {
  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  database.sessions = database.sessions.filter(item => item.expiresAt > Date.now());
  database.sessions.push({ tokenHash, userId: user.id, expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 });
  await persist();
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; ${process.env.NODE_ENV === 'production' ? 'Secure; ' : ''}Max-Age=604800`);
  return publicUser(user);
}
async function requireUser(req, res) {
  const session = getSession(req);
  if (!session) { json(res, 401, { error: 'Sign in to use your study planner.' }); return null; }
  return session.user;
}
async function handleApi(req, res, url) {
  const pathname = url.pathname;
  if (pathname === '/api/health' && req.method === 'GET') return json(res, 200, { status: 'ok' });
  if (pathname === '/api/auth/register' && req.method === 'POST') {
    const body = await readBody(req), name = cleanText(body.name, 60), email = cleanText(body.email, 160).toLowerCase();
    if (name.length < 2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || typeof body.password !== 'string' || body.password.length < 8 || body.password.length > 200) return json(res, 400, { error: 'Enter your name, a valid email, and a password with at least 8 characters.' });
    if (database.users.some(user => user.email === email)) return json(res, 409, { error: 'An account with that email already exists.' });
    const credentials = await hashPassword(body.password);
    const user = { id: crypto.randomUUID(), name, email, ...credentials, createdAt: new Date().toISOString() };
    delete user.salt; user.salt = credentials.salt; user.passwordHash = credentials.hash; delete user.hash;
    database.users.push(user); plannerFor(user.id); await persist();
    return json(res, 201, { user: await sendSession(res, user) });
  }
  if (pathname === '/api/auth/login' && req.method === 'POST') {
    const body = await readBody(req), email = cleanText(body.email, 160).toLowerCase();
    const user = database.users.find(item => item.email === email);
    if (!user || !await verifyPassword(String(body.password || ''), user)) return json(res, 401, { error: 'Email or password is incorrect.' });
    return json(res, 200, { user: await sendSession(res, user) });
  }
  if (pathname === '/api/auth/logout' && req.method === 'POST') {
    const session = getSession(req); if (session) { const hash = crypto.createHash('sha256').update(session.token).digest('hex'); database.sessions = database.sessions.filter(item => item.tokenHash !== hash); await persist(); }
    res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; ${process.env.NODE_ENV === 'production' ? 'Secure; ' : ''}Max-Age=0`);
    return json(res, 200, { ok: true });
  }
  if (pathname === '/api/auth/session' && req.method === 'GET') {
    const session = getSession(req); return json(res, 200, { user: session ? publicUser(session.user) : null });
  }
  const user = await requireUser(req, res); if (!user) return;
  const planner = plannerFor(user.id);
  if (pathname === '/api/planner' && req.method === 'GET') return json(res, 200, { ...planner, user: publicUser(user) });
  if (pathname === '/api/coach/plan' && req.method === 'POST') {
    if (!process.env.OPENAI_API_KEY) return json(res, 503, { error: 'AI Coach is not configured yet. Add OPENAI_API_KEY to the server environment to enable it.' });
    const body = await readBody(req), question = cleanText(body.question, 500);
    const tasks = planner.tasks.filter(task => task.status !== 'completed').map(({ subject, topic, kind, dueDate, duration, difficulty, importance }) => ({ subject, topic, kind, dueDate: dueDate || null, duration, difficulty, importance }));
    const subjects = planner.subjects.map(item => item.name);
    const input = `Create a practical, encouraging study plan using this student's current subjects and unfinished tasks. Prioritize near deadlines and higher difficulty/importance. Keep it concise, break work into sessions within the daily time budget where possible, include short breaks, and give a clear first step. Do not invent deadlines. If there are no tasks, suggest how to start.\nDaily available minutes: ${planner.preferences.dailyMinutes}\nSubjects: ${JSON.stringify(subjects)}\nUnfinished tasks: ${JSON.stringify(tasks)}\nStudent request: ${question || 'Please organize my next study sessions.'}`;
    let response;
    try {
      response = await fetch('https://api.openai.com/v1/responses', { method: 'POST', headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ model: process.env.OPENAI_MODEL || 'gpt-6-astra', input, max_output_tokens: 800, store: false }), signal: AbortSignal.timeout(30000) });
    } catch (error) { console.error('AI Coach request failed:', error.message); return json(res, 502, { error: 'AI Coach could not connect. Please try again in a moment.' }); }
    const result = await response.json().catch(() => ({}));
    if (!response.ok) { console.error('AI Coach returned an error:', response.status, result.error?.message || ''); return json(res, 502, { error: 'AI Coach could not create a plan. Check the server API key and try again.' }); }
    const text = result.output_text || (result.output || []).flatMap(item => item.content || []).filter(item => item.type === 'output_text').map(item => item.text).join('\n');
    if (!text) return json(res, 502, { error: 'AI Coach returned an empty plan. Please try again.' });
    return json(res, 200, { plan: text });
  }
  if (pathname === '/api/preferences' && req.method === 'PUT') {
    const body = await readBody(req);
    planner.preferences = { dailyMinutes: boundedNumber(body.dailyMinutes, planner.preferences.dailyMinutes || 120, 15, 720), remindersEnabled: Boolean(body.remindersEnabled) };
    await persist(); return json(res, 200, { preferences: planner.preferences });
  }
  if (pathname === '/api/subjects' && req.method === 'POST') {
    const body = await readBody(req), name = cleanText(body.name, 40);
    if (name.length < 1) return json(res, 400, { error: 'A subject name is required.' });
    if (planner.subjects.some(s => s.name.toLowerCase() === name.toLowerCase())) return json(res, 409, { error: 'That subject already exists.' });
    const subject = { id: crypto.randomUUID(), name, createdAt: new Date().toISOString() };
    planner.subjects.push(subject); await persist(); return json(res, 201, { subject });
  }
  const subjectMatch = pathname.match(/^\/api\/subjects\/([\w-]+)$/);
  if (subjectMatch && ['PUT','DELETE'].includes(req.method)) {
    const subject = planner.subjects.find(s => s.id === subjectMatch[1]); if (!subject) return json(res, 404, { error: 'Subject not found.' });
    if (req.method === 'PUT') {
      const body = await readBody(req), name = cleanText(body.name, 40);
      if (!name) return json(res, 400, { error: 'A subject name is required.' });
      if (planner.subjects.some(s => s.id !== subject.id && s.name.toLowerCase() === name.toLowerCase())) return json(res, 409, { error: 'That subject already exists.' });
      const oldName = subject.name; subject.name = name; planner.tasks.forEach(t => { if (t.subjectId === subject.id) t.subject = name; else if (t.subject === oldName) t.subject = name; }); await persist(); return json(res, 200, { subject });
    }
    planner.subjects = planner.subjects.filter(s => s.id !== subject.id);
    planner.tasks.forEach(t => { if (t.subjectId === subject.id) { t.subjectId = null; t.subject = 'Unassigned'; } });
    await persist(); return json(res, 200, { ok: true });
  }
  if (pathname === '/api/tasks' && req.method === 'POST') {
    const body = await readBody(req), task = normalizeTask(body, planner, null);
    if (task.error) return json(res, 400, { error: task.error });
    planner.tasks.push(task.value); await persist(); return json(res, 201, { task: task.value });
  }
  const rescheduleMatch = pathname.match(/^\/api\/tasks\/([\w-]+)\/reschedule$/);
  if (rescheduleMatch && req.method === 'POST') {
    const task = planner.tasks.find(item => item.id === rescheduleMatch[1]);
    if (!task) return json(res, 404, { error: 'Task not found.' });
    const tomorrow = new Date(); tomorrow.setHours(0,0,0,0); tomorrow.setDate(tomorrow.getDate()+1);
    task.dueDate = tomorrow.toISOString().slice(0,10); task.status = 'pending'; task.missedAt = null; await persist();
    return json(res, 200, { task });
  }
  const taskMatch = pathname.match(/^\/api\/tasks\/([\w-]+)$/);
  if (taskMatch && ['PUT','PATCH','DELETE'].includes(req.method)) {
    const index = planner.tasks.findIndex(t => t.id === taskMatch[1]); if (index < 0) return json(res, 404, { error: 'Task not found.' });
    if (req.method === 'DELETE') { planner.tasks.splice(index, 1); await persist(); return json(res, 200, { ok: true }); }
    const body = await readBody(req), current = planner.tasks[index];
    if (req.method === 'PATCH') {
      if (!['pending','completed','missed'].includes(body.status)) return json(res, 400, { error: 'Choose pending, completed, or missed.' });
      current.status = body.status; current.completedAt = body.status === 'completed' ? (current.completedAt || new Date().toISOString()) : null; current.missedAt = body.status === 'missed' ? new Date().toISOString() : null; await persist(); return json(res, 200, { task: current });
    }
    const updated = normalizeTask(body, planner, current);
    if (updated.error) return json(res, 400, { error: updated.error });
    Object.assign(current, updated.value, { id: current.id, status: current.status, completedAt: current.completedAt, missedAt: current.missedAt, createdAt: current.createdAt });
    await persist(); return json(res, 200, { task: current });
  }
  if (pathname === '/api/planner/rescue' && req.method === 'POST') {
    const body = await readBody(req); const overdueTasks = planner.tasks.filter(t => t.status === 'missed' || (t.status !== 'completed' && t.dueDate && new Date(`${t.dueDate}T00:00:00`) < new Date(new Date().toDateString())));
    overdueTasks.sort((a,b) => taskScore(b)-taskScore(a));
    let date = new Date(); date.setHours(0,0,0,0); date.setDate(date.getDate()+1); let spent = 0; const daily = boundedNumber(body.dailyMinutes, planner.preferences.dailyMinutes || 120, 15, 720);
    for (const task of overdueTasks) { if (spent + task.duration > daily) { date.setDate(date.getDate()+1); spent = 0; } task.dueDate = date.toISOString().slice(0,10); task.status = 'pending'; task.missedAt = null; spent += task.duration; }
    await persist(); return json(res, 200, { rescheduled: overdueTasks.length, tasks: overdueTasks });
  }
  return json(res, 404, { error: 'API route not found.' });
}
function normalizeTask(body, planner, existing) {
  const topic = cleanText(body.topic, 100), subject = cleanText(body.subject, 40);
  if (!topic || !subject) return { error: 'A topic and subject are required.' };
  if (!validDate(body.dueDate)) return { error: 'Enter a valid deadline.' };
  const subjectItem = planner.subjects.find(s => s.id === body.subjectId) || planner.subjects.find(s => s.name.toLowerCase() === subject.toLowerCase());
  if (!subjectItem) return { error: 'Choose or create a subject first.' };
  let reminderAt = body.reminderAt ? new Date(body.reminderAt) : null;
  if (reminderAt && Number.isNaN(reminderAt.getTime())) return { error: 'Enter a valid reminder time.' };
  if (reminderAt && reminderAt.getTime() < Date.now() - 86400000) reminderAt = null;
  return { value: { id: existing?.id || crypto.randomUUID(), subjectId: subjectItem.id, subject: subjectItem.name, topic, kind: ['topic','assignment','exam'].includes(body.kind) ? body.kind : 'topic', dueDate: body.dueDate || '', duration: boundedNumber(body.duration,45,5,600), difficulty: boundedNumber(body.difficulty,3,1,5), importance: boundedNumber(body.importance,3,1,5), reminderAt: reminderAt?.toISOString() || '', status: existing?.status || 'pending', createdAt: existing?.createdAt || new Date().toISOString(), completedAt: existing?.completedAt || null, missedAt: existing?.missedAt || null } };
}
function taskScore(task) { const today = new Date(); today.setHours(0,0,0,0); let urgency = 1; if (task.dueDate) { const due = new Date(`${task.dueDate}T00:00:00`); const days = Math.round((due-today)/86400000); urgency = days <= 0 ? 5 : days <= 2 ? 4 : days <= 7 ? 3 : days <= 14 ? 2 : 1; } return urgency*.5 + task.difficulty*.3 + task.importance*.2; }
const MIME = { '.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.svg':'image/svg+xml' };
const server = http.createServer(async (req,res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (url.pathname.startsWith('/api/')) return await handleApi(req,res,url);
    const requested = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname.slice(1));
    const file = path.resolve(ROOT, requested);
    if (!file.startsWith(`${ROOT}${path.sep}`) && file !== path.join(ROOT,'index.html')) return json(res,403,{error:'Forbidden.'});
    const content = await fs.readFile(file); res.writeHead(200,{ 'Content-Type':MIME[path.extname(file)]||'application/octet-stream','Cache-Control':'no-cache' }); res.end(content);
  } catch(error) { console.error(error); json(res,error.message==='Request body must be valid JSON.'?400:500,{error:error.message||'Server error.'}); }
});
loadDatabase().then(()=>server.listen(PORT, '0.0.0.0', ()=>console.log(`StudyFlow running on port ${PORT}`))).catch(error=>{console.error(error);process.exitCode=1;});
