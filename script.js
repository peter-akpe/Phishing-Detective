/* ---------- helpers ---------- */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const BRANDS = { paypal:'paypal.com', microsoft:'microsoft.com', apple:'apple.com', amazon:'amazon.com',
  google:'google.com', netflix:'netflix.com', dhl:'dhl.com', fedex:'fedex.com', docusign:'docusign.com',
  linkedin:'linkedin.com', facebook:'facebook.com', chase:'chase.com', coinbase:'coinbase.com' };
const SHORTENERS = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|cutt\.ly|rb\.gy)$/i;
const RISKY_TLD = /\.(zip|mov|top|xyz|click|country|tk|ml|ga|cf|gq|work|support|icu|buzz|monster)$/i;
const FREE_HOST = /(freehosting|000webhost|weebly|wixsite|blogspot|github\.io|netlify\.app|pages\.dev|herokuapp)/i;
const PATH_WORDS = /(login|signin|verify|verification|secure|account|update|password|confirm|wallet|billing|recover)/gi;

const rootDomain = h => {
  const p = h.toLowerCase().split('.');
  if (p.length <= 2) return h.toLowerCase();
  const sld = ['co','com','org','net','gov','ac'];
  return sld.includes(p[p.length - 2]) && p[p.length - 1].length === 2 ? p.slice(-3).join('.') : p.slice(-2).join('.');
};
const parseUrl = u => { try { return new URL(/^https?:\/\//i.test(u) ? u : 'http://' + u); } catch { return null; } };
const cap = s => s[0].toUpperCase() + s.slice(1);

/* ---------- analysis engines: each returns {score, flags:[{title,detail,pts}]} ---------- */
function analyzeUrl(raw) {
  const flags = [], add = (pts, title, detail) => flags.push({ pts, title, detail });
  const u = parseUrl(raw.trim());
  if (!u || !u.hostname.includes('.')) return { score: 0, flags: [], invalid: true };
  const host = u.hostname.toLowerCase(), root = rootDomain(host);

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add(35, 'Raw IP address as host', 'Legitimate brands use domain names, not bare IPs.');
  if (/^xn--|\.xn--/.test(host)) add(30, 'Punycode domain', 'Can disguise lookalike foreign characters as normal letters.');
  if (raw.includes('@')) add(30, '"@" trick in URL', 'Everything before @ is ignored by the browser; the real host is after it.');

  for (const b in BRANDS) {
    const real = BRANDS[b];
    if (root === real) continue;
    const squashed = host.replace(/1/g, 'l').replace(/0/g, 'o').replace(/rn/g, 'm').replace(/5/g, 's');
    if (squashed.includes(b) || host.includes(b)) {
      const digits = /\d/.test(host.split('.')[0]) && squashed.includes(b) && !host.includes(b);
      add(digits ? 40 : 30, digits ? 'Misleading domain typosquatting' : `Imitates ${cap(b)}`,
        digits ? `The domain swaps a digit for a letter to impersonate ${cap(b)}.` : `${host} contains "${b}" but is not ${real}.`);
      break;
    }
  }
  if (host.split('.').length > 4) add(12, 'Excessive subdomains', `${host} buries the real domain among many labels.`);
  if (RISKY_TLD.test(host)) add(15, 'Risky top-level domain', 'This ending is heavily used for throwaway abuse domains.');
  if (SHORTENERS.test(host)) add(15, 'Shortened link', 'Hides the true destination behind a redirect.');
  if (FREE_HOST.test(host)) add(20, 'Free or unverified hosting', 'Banks and big brands do not host login pages on free hosts.');
  if (u.protocol === 'http:') add(8, 'Connection not encrypted (HTTP)', 'No TLS: anything typed can be read in transit.');
  const words = [...new Set((u.pathname + u.search).match(PATH_WORDS) || [])].map(w => w.toLowerCase());
  if (words.length) add(Math.min(25, 10 + words.length * 5), 'Credential-harvesting keywords in path', `Found: ${words.join(', ')}.`);
  if (/[?&](user|email|id|session)=/i.test(u.search) || /(alert|urgent|warning|suspend)/i.test(u.search))
    add(10, 'Coercive query parameters', 'Query string carries tracking or urgency cues to prompt action.');
  if (raw.length > 100) add(6, 'Unusually long URL', 'Long strings are often used to hide the real host.');
  return finish(flags);
}

function analyzeEmail(t) {
  const flags = [], add = (pts, title, detail) => flags.push({ pts, title, detail });
  const hdr = n => (t.match(new RegExp('^' + n + ':\\s*(.+)$', 'im')) || [])[1] || '';
  const dom = s => ((s.match(/@([a-z0-9.-]+\.[a-z]{2,})/i) || [])[1] || '').toLowerCase();
  const from = hdr('From'), fd = dom(from), rd = dom(hdr('Reply-To')), low = t.toLowerCase();

  if (fd && rd && rootDomain(fd) !== rootDomain(rd)) add(25, 'Reply-To points elsewhere', `Sent from ${fd} but replies go to ${rd}.`);
  const auth = t.match(/(spf|dkim|dmarc)\s*=\s*(fail|softfail)/gi);
  if (auth) add(30, 'Email authentication failed', [...new Set(auth.map(a => a.toLowerCase()))].join(', ') + '.');
  const shown = (from.match(/^"?([^"<]+)"?\s*</) || [])[1] || '';
  for (const b in BRANDS) if (fd && (shown + hdr('Subject')).toLowerCase().includes(b) && rootDomain(fd) !== BRANDS[b]) {
    add(30, `Claims to be ${cap(b)}`, `Sender domain is ${fd}, not ${BRANDS[b]}.`); break; }
  const rx = (re, pts, title, d) => { const m = low.match(re); if (m) add(pts, title, `${d} ${[...new Set(m)].slice(0, 4).join(', ')}.`); };
  rx(/\b(urgent|immediately|within \d+ hours|act now|final notice|account (?:will be )?(?:suspended|closed|locked)|verify your|unusual activity)\b/g, 22, 'Pressure and urgency', 'Phrases:');
  rx(/\b(password|card number|cvv|social security|ssn|bank account|security code|seed phrase)\b/g, 22, 'Requests sensitive data', 'Mentions:');
  rx(/\b(gift ?cards?|wire transfer|bitcoin|crypto|western union)\b/g, 20, 'Unusual payment method', 'Mentions:');
  rx(/\b(you(?:'ve| have) won|lottery|inheritance|claim your (?:prize|reward))\b/g, 15, 'Too-good-to-be-true offer', 'Phrases:');
  rx(/\b(legal action|arrest|lawsuit|penalt(?:y|ies))\b/g, 10, 'Threat of consequences', 'Phrases:');
  if (/dear (customer|user|client|member|account holder)|valued customer/i.test(t)) add(10, 'Generic greeting', 'Real providers usually address you by name.');
  if (/\.(exe|scr|bat|js|vbs|iso|lnk|msi|jar|hta|docm|xlsm|zip)\b/i.test(t)) add(20, 'Risky attachment type', 'Executable or macro-capable file types are a common malware route.');
  [...new Set(t.match(/https?:\/\/[^\s"'<>)]+/gi) || [])].slice(0, 6).forEach(l => {
    const r = analyzeUrl(l).flags.filter(f => f.pts >= 15)[0];
    if (r) add(Math.min(30, r.pts), 'Suspicious link: ' + r.title.toLowerCase(), l);
  });
  return finish(flags);
}
const finish = flags => ({ score: Math.min(100, flags.reduce((s, f) => s + f.pts, 0)), flags: flags.sort((a, b) => b.pts - a.pts) });
const level = s => s >= 60 ? 'bad' : s >= 30 ? 'sus' : 'safe';
const LABEL = { safe: 'Safe', sus: 'Suspicious', bad: 'High risk detected' };
const PROFILE = { safe: 'Low Threat Profile', sus: 'Elevated Threat Profile', bad: 'Severe Threat Profile' };
const WHY = {
  safe: 'No strong phishing indicators were found. Still, scammers can pass simple checks, so be careful with unexpected requests.',
  sus: 'Several warning signs add up. Not conclusive on its own, but treat it with caution until you verify it independently.',
  bad: 'Legitimate institutions never ask you to sign in or pay through links like this. Attackers copy trusted brand names to trick you into handing over passwords or codes.' };
const ACTIONS = {
  safe: ['If you were not expecting it, still verify with the sender.', 'Keep 2FA enabled on important accounts.'],
  sus: ['Do not click links or open attachments yet.', 'Contact the company using a number or site you already trust.', 'Report it if it seems off.'],
  bad: ['Do not enter passwords or personal information.', 'Close the page / delete the message immediately.', 'If you already clicked: change that password, enable 2FA and watch your accounts.', 'Report it to your email provider or IT team.'] };

/* ---------- report rendering ---------- */
function showReport(rec) {
  const lvl = level(rec.score), box = $('#report');
  box.hidden = false; box.dataset.lvl = lvl;
  $('#rId').textContent = rec.id;
  $('#rLabel').textContent = LABEL[lvl];
  $('#rTarget').textContent = rec.type === 'email' ? rec.specimen.replace(/\s+/g, ' ').slice(0, 160) : rec.specimen;
  $('#rScore').textContent = rec.score;
  $('#rProfile').textContent = PROFILE[lvl];
  $('#rWhy').textContent = WHY[lvl];
  const arc = $('#arc'); arc.setAttribute('class', 'arc');
  arc.style.strokeDashoffset = 326.7;
  requestAnimationFrame(() => requestAnimationFrame(() => arc.style.strokeDashoffset = 326.7 * (1 - rec.score / 100)));
  const ul = $('#rFlags'); ul.textContent = '';
  (rec.flags.length ? rec.flags : [{ title: 'No red flags found', detail: 'None of the rules matched.', pts: 0 }]).forEach(f => {
    const li = document.createElement('li');
    li.innerHTML = '<div><b></b><span></span></div>' + (f.pts ? '<em class="pts"></em>' : '');
    $('b', li).textContent = f.title; $('span', li).textContent = f.detail;
    if (f.pts) $('.pts', li).textContent = '+' + f.pts + ' pts';
    ul.appendChild(li);
  });
  const act = $('#rAct'); act.textContent = '';
  ACTIONS[lvl].forEach(a => { const li = document.createElement('li'); li.textContent = a; act.appendChild(li); });
  box.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ---------- history (localStorage, with safe fallback) ---------- */
let history = [];
try { history = JSON.parse(localStorage.getItem('pd-history') || '[]'); } catch { history = []; }
const save = () => { try { localStorage.setItem('pd-history', JSON.stringify(history.slice(0, 25))); } catch {} };

function renderHistory() {
  const body = $('#hBody'); body.textContent = '';
  $('#hEmpty').hidden = history.length > 0;
  history.forEach((h, i) => {
    const l = level(h.score), tr = document.createElement('tr');
    tr.innerHTML = '<td></td><td class="sp"></td><td></td><td></td><td><span class="v"></span></td><td><button>View</button></td>';
    const c = tr.children;
    c[0].textContent = h.type === 'email' ? '✉ Email' : '🔗 URL';
    c[1].textContent = h.specimen.replace(/\s+/g, ' ');
    c[2].textContent = new Date(h.time).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    c[3].textContent = h.score + ' / 100';
    c[4].firstChild.textContent = LABEL[l].replace(' detected', ''); c[4].firstChild.classList.add(l);
    $('button', tr).onclick = () => showReport(h);
    body.appendChild(tr);
  });
  const n = { safe: 0, sus: 0, bad: 0 }; history.forEach(h => n[level(h.score)]++);
  const max = Math.max(1, history.length);
  [['Safe', 'safe'], ['Sus', 'sus'], ['Bad', 'bad']].forEach(([id, k]) => {
    $('#c' + id).textContent = n[k]; $('#b' + id).style.width = (n[k] / max * 100) + '%';
  });
}

function run(type, specimen, result) {
  const rec = { id: 'URL-' + String(Math.floor(Math.random() * 9000) + 1000), type, specimen, time: Date.now(), ...result };
  if (type === 'email') rec.id = 'MAIL-' + rec.id.slice(4);
  history.unshift(rec); save(); renderHistory(); showReport(rec);
}

/* ---------- events ---------- */
function setTab(name) {
  $$('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === name));
  $('#pane-url').hidden = name !== 'url';
  $('#pane-email').hidden = name !== 'email';
}
$$('[data-tab]').forEach(el => el.addEventListener('click', () => setTab(el.dataset.tab)));
$$('#nav a').forEach(a => a.addEventListener('click', () => { $$('#nav a').forEach(x => x.classList.remove('on')); a.classList.add('on'); }));

const scanUrl = () => {
  const v = $('#urlIn').value.trim();
  const r = analyzeUrl(v);
  if (r.invalid) { $('#urlIn').focus(); $('#urlIn').setCustomValidity?.(''); alert('Enter a full link or domain, for example https://example.com'); return; }
  run('url', v, r);
};
$('#scanUrl').onclick = scanUrl;
$('#urlIn').addEventListener('keydown', e => e.key === 'Enter' && scanUrl());
$$('.chip').forEach(c => c.onclick = () => { $('#urlIn').value = c.dataset.url; scanUrl(); });

$('#scanMail').onclick = () => {
  const t = $('#mailIn').value;
  if (t.trim().length < 20) { $('#mailIn').focus(); return; }
  run('email', t, analyzeEmail(t));
};
$('#sampleMail').onclick = () => {
  $('#mailIn').value = `From: "PayPal Security" <service@paypa1-secure.top>
Reply-To: help@mailbox-recovery.xyz
Subject: Urgent: your account will be suspended
Authentication-Results: spf=fail; dkim=none; dmarc=fail

Dear customer,
Unusual activity was found. Verify your password and card number within 24 hours or your account will be closed.
http://198.51.100.7/login
https://bit.ly/3xYzAbc`;
};
$('#clearH').onclick = () => { history = []; save(); renderHistory(); $('#report').hidden = true; };

/* ---------- tips ---------- */
const RULES = [
  ['Inspect the Sender Address Closely', 'Look for swapped letters like rn for m, or a 1 for l. Check that the domain is exactly the real one.'],
  ['Beware of False Urgency', 'Phishing tries to rush you: "act immediately", "account deleted in 24 hours". Real services give reasonable notice.'],
  ['Never Email Passwords or 2FA Codes', 'No genuine bank or software provider asks for passwords, PINs or one-time codes by email or text.'],
  ['Hover Links Before Clicking', 'On desktop, hovering shows the true destination. If the text says paypal.com but the link goes elsewhere, it is fake.'],
  ['When in Doubt, Type the Address Manually', 'Ignore the buttons in the message. Open a new tab and go to the company\'s site yourself, or use its official app.']
];
RULES.forEach((r, i) => {
  const d = document.createElement('div'); d.className = 'card rule';
  d.innerHTML = '<b class="n"></b><h3></h3><p></p>';
  $('b', d).textContent = String(i + 1).padStart(2, '0'); $('h3', d).textContent = r[0]; $('p', d).textContent = r[1];
  $('#rules').appendChild(d);
});

renderHistory();