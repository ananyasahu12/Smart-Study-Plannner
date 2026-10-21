const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = __dirname;
const DATA_DIR = process.env.STUDYFLOW_DATA_DIR || path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'studyflow.json');
const PORT = Number(process.env.PORT) || 4173;
const COOKIE = 'studyflow_session';
const DEFAULT_PREFERENCES = { dailyMinutes: 120, weeklyGoalHours: 10, sessionMinutes: 50, breakMinutes: 10, preferredTime: 'Flexible', studyDays: [0,1,2,3,4,5,6], reminderLeadMinutes: 15, remindersEnabled: false };
let database = { users: [], planners: {}, sessions: [] };
let writeQueue = Promise.resolve();
let firebaseSigningKeys = { expiresAt: 0, keys: {} };

async function verifyFirebaseIdToken(token) {
  const projectId = process.env.FIREBASE_PROJECT_ID;
  if (!projectId) throw new Error('Google sign-in is not configured yet. Add the Firebase project settings to the server environment.');
  const pieces = typeof token === 'string' ? token.split('.') : [];
  if (pieces.length !== 3) throw new Error('Google sign-in returned an invalid credential. Please try again.');
  let header, claims;
  try { header = JSON.parse(Buffer.from(pieces[0], 'base64url').toString()); claims = JSON.parse(Buffer.from(pieces[1], 'base64url').toString()); }
  catch { throw new Error('Google sign-in returned an invalid credential. Please try again.'); }
  const now = Math.floor(Date.now() / 1000);
  if (header.alg !== 'RS256' || !header.kid || claims.aud !== projectId || claims.iss !== `https://securetoken.google.com/${projectId}` || !claims.sub || claims.sub.length > 128 || !Number.isFinite(claims.exp) || claims.exp <= now || !Number.isFinite(claims.iat) || claims.iat > now + 60 || !claims.email_verified || claims.firebase?.sign_in_provider !== 'google.com') throw new Error('The Google account could not be verified. Please sign in again with Google.');
  if (firebaseSigningKeys.expiresAt < Date.now() || !firebaseSigningKeys.keys[header.kid]) {
    const response = await fetch('https://www.googleapis.com/service_accounts/v1/metadata/x509/securetoken@system.gserviceaccount.com', { signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw new Error('Could not verify Google sign-in right now. Please try again.');
    const keys = await response.json();
    const maxAge = Number(response.headers.get('cache-control')?.match(/max-age=(\d+)/)?.[1] || 3600);
    firebaseSigningKeys = { keys, expiresAt: Date.now() + Math.min(maxAge, 3600) * 1000 };
  }
  const certificate = firebaseSigningKeys.keys[header.kid];
  const valid = certificate && crypto.verify('RSA-SHA256', Buffer.from(`${pieces[0]}.${pieces[1]}`), certificate, Buffer.from(pieces[2], 'base64url'));
  if (!valid) throw new Error('The Google account could not be verified. Please sign in again with Google.');
  const email = typeof claims.email === 'string' ? claims.email.trim().toLowerCase() : '';
  if (!email || !/^[^@\s]+@(gmail\.com|googlemail\.com)$/.test(email)) throw new Error('Please use a verified Gmail account to continue.');
  return { uid: claims.sub, email, name: cleanText(claims.name, 60) || email.split('@')[0] };
}

async function loadLocalSecrets() {
  try {
    const contents = await fs.readFile(path.join(ROOT, '.env'), 'utf8');
    for (const line of contents.split(/\r?\n/)) {
      const match = line.match(/^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
      if (!match || process.env[match[1]]) continue;
      const value = match[2].replace(/^(['"])(.*)\1$/, '$2');
      process.env[match[1]] = value;
    }
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
}

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
function publicUser(user) { return { id: user.id, name: user.name, email: user.email, year: user.year || '', program: user.program || '', branch: user.branch || '' }; }
function plannerFor(userId) {
  if (!database.planners[userId]) database.planners[userId] = { subjects: [], tasks: [], preferences: { ...DEFAULT_PREFERENCES } };
  const planner = database.planners[userId];
  if (!Array.isArray(planner.subjects)) planner.subjects = [];
  if (!Array.isArray(planner.tasks)) planner.tasks = [];
  planner.preferences = { ...DEFAULT_PREFERENCES, ...(planner.preferences || {}) };
  if (!Array.isArray(planner.preferences.studyDays)) planner.preferences.studyDays = [...DEFAULT_PREFERENCES.studyDays];
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
function normalizeAuthIdentifier(value) {
  const input = cleanText(value, 160).trim().toLowerCase();
  const gmail = /^[a-z0-9][a-z0-9._+-]{4,28}[a-z0-9]@(gmail\.com|googlemail\.com)$/.test(input) && !input.split('@')[0].includes('..');
  if (gmail) return input;
  if (!/^\+?[\d\s().-]+$/.test(input)) return '';
  const digits = input.replace(/\D/g, '');
  if (input.startsWith('+') && digits.length >= 8 && digits.length <= 15) return `+${digits}`;
  if (/^[6-9]\d{9}$/.test(digits)) return `+91${digits}`;
  return '';
}
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
  if (pathname === '/api/config' && req.method === 'GET') {
    const config = { apiKey: process.env.FIREBASE_API_KEY || '', authDomain: process.env.FIREBASE_AUTH_DOMAIN || '', projectId: process.env.FIREBASE_PROJECT_ID || '', appId: process.env.FIREBASE_APP_ID || '' };
    return json(res, 200, { firebase: config, configured: Object.values(config).every(Boolean) });
  }
  if (pathname === '/api/auth/register' || pathname === '/api/auth/login') return json(res, 410, { error: 'Password sign-in is turned off. Continue with your verified Google account.' });
  if (pathname === '/api/auth/google' && req.method === 'POST') {
    let identity;
    try { const body = await readBody(req); identity = await verifyFirebaseIdToken(body.idToken); }
    catch (error) { return json(res, error.message.startsWith('Google sign-in is not configured') ? 503 : 401, { error: error.message || 'Google sign-in failed. Please try again.' }); }
    let user = database.users.find(item => item.firebaseUid === identity.uid);
    if (!user) user = database.users.find(item => item.email?.toLowerCase() === identity.email);
    if (user) { user.email = identity.email; user.name = identity.name; user.firebaseUid = identity.uid; delete user.passwordHash; delete user.salt; }
    else { user = { id: crypto.randomUUID(), name: identity.name, email: identity.email, firebaseUid: identity.uid, createdAt: new Date().toISOString() }; database.users.push(user); }
    plannerFor(user.id); await persist();
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
  if (pathname === '/api/profile' && req.method === 'PUT') {
    const body = await readBody(req), name = cleanText(body.name, 60), year = cleanText(body.year, 30), program = cleanText(body.program, 40), branch = cleanText(body.branch, 60);
    const validYears = ['', 'Year 1', 'Year 2', 'Year 3', 'Year 4', 'Year 5', 'Year 6', 'Final year', 'Graduated', 'Other'];
    const validPrograms = ['', 'B.Tech', 'B.E.', 'M.Tech', 'M.E.', 'B.Sc.', 'M.Sc.', 'BCA', 'MCA', 'B.Com.', 'M.Com.', 'B.A.', 'M.A.', 'BBA', 'MBA', 'B.Des', 'M.Des', 'B.Arch', 'M.Arch', 'B.Pharm', 'M.Pharm', 'MBBS', 'MD', 'BDS', 'LLB', 'LLM', 'B.Ed', 'M.Ed', 'Diploma', 'PhD', 'Other'];
    if (name.length < 2 || !validYears.includes(year) || !validPrograms.includes(program) || branch.length > 60) return json(res, 400, { error: 'Enter a valid name, year, program, and branch.' });
    Object.assign(user, { name, year, program, branch }); await persist();
    return json(res, 200, { user: publicUser(user) });
  }
  const planner = plannerFor(user.id);
  if (pathname === '/api/planner' && req.method === 'GET') return json(res, 200, { ...planner, user: publicUser(user) });
  if (pathname === '/api/coach/plan' && req.method === 'POST') {
    const body = await readBody(req), question = cleanText(body.question, 500), key = process.env.GEMINI_API_KEY;
    if (!key) return json(res, 503, { error: 'Add your Gemini free-tier key to the local .env file as GEMINI_API_KEY, then restart the server.' });
    const tasks = planner.tasks.filter(task => task.status !== 'completed').map(({ subject, topic, kind, dueDate, duration, difficulty, importance }) => ({ subject, topic, kind, dueDate: dueDate || 'No deadline', duration, difficulty, importance }));
    const days = planner.preferences.studyDays.map(day => ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'][day]).join(', ');
    const input = `Make a personalized, realistic study plan based on this student's planner. Prioritize tasks using deadlines, difficulty and importance. Respect the daily and weekly study goals and available days, split long tasks into sessions, include the chosen break after each focus session, and state the first task to begin. Prefer the student's chosen time of day. Do not invent deadlines. Keep the answer clear and encouraging.\nDaily available minutes: ${planner.preferences.dailyMinutes}\nWeekly study goal: ${planner.preferences.weeklyGoalHours} hours\nFocus session: ${planner.preferences.sessionMinutes} minutes; break: ${planner.preferences.breakMinutes} minutes\nPreferred study time: ${planner.preferences.preferredTime}\nAvailable days: ${days}\nSubjects: ${JSON.stringify(planner.subjects.map(subject => subject.name))}\nUnfinished tasks: ${JSON.stringify(tasks)}\nStudent's question: ${question || 'Please help me organize my study time.'}`;
    let response;
    try {
      response = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent', { method: 'POST', headers: { 'x-goog-api-key': key, 'Content-Type': 'application/json' }, body: JSON.stringify({ systemInstruction: { parts: [{ text: 'You are a supportive study coach. Give specific, practical advice and a simple schedule.' }] }, contents: [{ role: 'user', parts: [{ text: input }] }], generationConfig: { maxOutputTokens: 800, temperature: 0.4 } }), signal: AbortSignal.timeout(30000) });
    } catch (error) { console.error('Gemini coach request failed:', error.message); return json(res, 502, { error: 'Could not reach Gemini. Check your connection and try again.' }); }
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      console.error(`Gemini coach returned status ${response.status}`);
      if (response.status === 429) return json(res, 429, { error: 'The Gemini free-tier limit was reached. Wait for the quota to reset before trying again.' });
      if (response.status === 401 || response.status === 403) return json(res, 502, { error: 'Gemini did not accept this API key. Check the server secret and try again.' });
      return json(res, 502, { error: 'Gemini could not create a plan. Please try again.' });
    }
    const text = (result.candidates || []).flatMap(candidate => candidate.content?.parts || []).map(part => part.text || '').join('\n').trim();
    if (!text) return json(res, 502, { error: 'The AI provider returned an empty plan. Please try again.' });
    return json(res, 200, { plan: text });
  }
  if (pathname === '/api/preferences' && req.method === 'PUT') {
    const body = await readBody(req);
    const allowedDays = [...new Set((Array.isArray(body.studyDays) ? body.studyDays : planner.preferences.studyDays).map(Number).filter(day => Number.isInteger(day) && day >= 0 && day <= 6))];
    planner.preferences = {
      dailyMinutes: boundedNumber(body.dailyMinutes, planner.preferences.dailyMinutes, 15, 720),
      weeklyGoalHours: boundedNumber(body.weeklyGoalHours, planner.preferences.weeklyGoalHours, 1, 60),
      sessionMinutes: [25,45,50,60,90].includes(Number(body.sessionMinutes)) ? Number(body.sessionMinutes) : planner.preferences.sessionMinutes,
      breakMinutes: [5,10,15,20].includes(Number(body.breakMinutes)) ? Number(body.breakMinutes) : planner.preferences.breakMinutes,
      preferredTime: ['Flexible','Morning','Afternoon','Evening','Night'].includes(body.preferredTime) ? body.preferredTime : planner.preferences.preferredTime,
      studyDays: allowedDays.length ? allowedDays : planner.preferences.studyDays,
      reminderLeadMinutes: [5,10,15,30,60].includes(Number(body.reminderLeadMinutes)) ? Number(body.reminderLeadMinutes) : planner.preferences.reminderLeadMinutes,
      remindersEnabled: Boolean(body.remindersEnabled)
    };
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
const MIME = { '.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.svg':'image/svg+xml','.png':'image/png' };
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
loadLocalSecrets().then(loadDatabase).then(()=>server.listen(PORT, '0.0.0.0', ()=>console.log(`Focus Forge running on port ${PORT}`))).catch(error=>{console.error(error);process.exitCode=1;});
