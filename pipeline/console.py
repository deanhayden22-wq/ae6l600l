#!/usr/bin/env python3
"""The ROM pipeline console: a local web page over the `rom` herdr session.

    rom console              # start it if needed and open http://127.0.0.1:47831/
    rom console --no-browser

One page, two views:
  * Status: the rom session, every item with its stage and outcome, what needs you,
    repo health (git, the last scripts/check.sh run, with a button to run it), and
    where the knowledge stands (verification registry, open holes, last correction).
  * Item tabs: the four panes (runner, reviewer, tracer, blind claude) live, each with
    its agent's state; gate and dialog answers as buttons; a text box per pane; the
    item's records (claim, pack, blind answers, settlement) one click away.

Loopback only. Every request must carry Host 127.0.0.1:<port>; every POST must carry
`X-Rom-Console: 1` and, if the browser sends one, this page's own Origin -- so no other
web page can drive the panes. The console answers what the panes ask, nothing more:
it never edits records, rom/ or definitions/, and never commits.
"""
import json
import os
import re
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run as R  # noqa: E402

PORT = int(os.environ.get('ROM_CONSOLE_PORT', '47831'))
PIDFILE = os.path.join(R.STATE, 'console.json')
RECORD_FILES = ['claim.md', 'pack.md', 'blind-claude.md', 'blind-codex.md', 'settle.md', 'item.json']
ROLES = ['runner', 'reviewer', 'tracer', 'blind_claude']
CHECK = {'running': False, 'started': None, 'finished': None, 'exit': None, 'tail': '', 'full': False}
_lock = threading.Lock()


# ------------------------------------------------------------------ state
def sh(cmd, cwd=R.REPO, timeout=20):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except Exception:
        return ''


def herdr_json(*args):
    p = subprocess.run(['herdr', '--session', R.SESSION, *args], capture_output=True, text=True,
                       env=R.herdr_env(), timeout=10)
    try:
        return json.loads(p.stdout)
    except Exception:
        return {}


def pane_text(pane, lines=140):
    p = subprocess.run(['herdr', '--session', R.SESSION, 'pane', 'read', pane, '--lines', str(lines)],
                       capture_output=True, text=True, env=R.herdr_env(), timeout=10)
    return p.stdout if p.returncode == 0 else ''


def runner_alive(slug):
    pat = f'run.py stages {slug}'
    for pid in os.listdir('/proc'):
        if pid.isdigit():
            try:
                if pat in open(f'/proc/{pid}/cmdline', 'rb').read().replace(b'\0', b' ').decode(errors='replace'):
                    return True
            except OSError:
                pass
    return False


def stage_of(slug, item):
    if item.get('done'):
        return 'done'
    if R.has_headings(R.rec(slug, 'settle.md'), R.SETTLE_HEADINGS + ['## Applied']):
        return 'apply'
    if os.path.exists(R.rec(slug, 'settle.md')):
        return 'critique' if item.get('need_critique', True) else 'gate'
    if R.has_headings(R.rec(slug, 'blind-claude.md'), R.BLIND_HEADINGS) and \
            R.has_headings(R.rec(slug, 'blind-codex.md'), R.BLIND_HEADINGS):
        return 'settle'
    return 'blind'


def parse_gate(text):
    """The runner's crucial prompt, if it is the last thing on its screen."""
    lines = [l for l in text.rstrip().split('\n') if l.strip()]
    tail = '\n'.join(lines[-4:])
    m = re.search(r'>>> YOUR ANSWER NEEDED: (.+?) ((?:\[[a-z]\][a-z]*/?)+):\s*$', tail.replace('\n', ''))
    if not m:
        return None
    choices = [re.sub(r'\[([a-z])\]', r'\1', c) for c in m.group(2).split('/') if c]
    return {'question': m.group(1).strip(), 'choices': choices}


def parse_dialog(text):
    """Numbered/arrow options of a dialog an agent is blocked on (the ❯ marks the cursor)."""
    lines = text.rstrip().split('\n')[-30:]
    cur = next((i for i in range(len(lines) - 1, -1, -1) if '❯' in lines[i]), None)
    if cur is None:
        return None
    indent = len(lines[cur]) - len(lines[cur].lstrip())

    def is_opt(l):
        s = l.strip()
        return s and not s.startswith(('│', '─', '╭', '╰', 'Enter', 'Esc')) and \
            abs((len(l) - len(l.lstrip())) - indent) <= 2
    lo = cur
    while lo - 1 >= 0 and is_opt(lines[lo - 1]):      # a blank line separates the question from the options
        lo -= 1
    hi = cur
    while hi + 1 < len(lines) and is_opt(lines[hi + 1]):
        hi += 1
    opts = [re.sub(r'^\s*❯?\s*', '', lines[i]).strip() for i in range(lo, hi + 1)]
    question = ' '.join(l.strip() for l in lines[max(0, lo - 8):lo] if l.strip())[-300:]
    return {'question': question, 'options': opts, 'cursor': cur - lo}


def items_state():
    out = []
    ws = herdr_json('workspace', 'list').get('result', {}).get('workspaces', []) if R.server_running() else []
    live_ws = {w['workspace_id'] for w in ws}
    agents = {a['pane_id']: a for a in herdr_json('agent', 'list').get('result', {}).get('agents', [])} if ws else {}
    if not os.path.isdir(R.RECORDS):
        return out
    for slug in sorted(os.listdir(R.RECORDS)):
        try:
            item = R.load_item(slug)
        except Exception:
            continue
        it = {'slug': slug, 'stage': stage_of(slug, item), 'rounds': item.get('rounds', 0),
              'created': item.get('created'), 'done': item.get('done'), 'addrs': item.get('addrs'),
              'claim_source': item.get('claim_source'), 'reviewer': item.get('reviewer'),
              'open': item.get('workspace') in live_ws, 'runner_alive': runner_alive(slug),
              'outcome': R.outcome(slug) if os.path.exists(R.rec(slug, 'settle.md')) else None,
              'files': [f for f in RECORD_FILES if os.path.exists(R.rec(slug, f))],
              'panes': {}, 'needs': []}
        if it['open']:
            for role in ROLES:
                pid = item['panes'].get(role)
                a = agents.get(pid, {})
                text = pane_text(pid)
                p = {'pane': pid, 'agent': a.get('name'), 'kind': a.get('agent'),
                     'status': a.get('agent_status'), 'text': text}
                if role == 'runner':
                    g = parse_gate(text)
                    if g:
                        p['gate'] = g
                        it['needs'].append({'role': role, 'crucial': True,
                                            'what': f'the runner asks: {g["question"]}'})
                elif p['status'] == 'blocked':
                    p['dialog'] = parse_dialog(text)
                    it['needs'].append({'role': role, 'crucial': False,
                                        'what': f'{a.get("name")} is waiting on a dialog'})
                it['panes'][role] = p
            if not it['runner_alive'] and not it['done']:
                it['needs'].append({'role': 'runner', 'crucial': False,
                                    'what': 'the runner is stopped: Resume it'})
        elif not it['done']:
            it['needs'].append({'role': 'runner', 'crucial': False,
                                'what': 'no workspace open: Open it to continue'})
        out.append(it)
    return out


def knowledge():
    k = {}
    try:
        j = json.load(open(os.path.join(R.REPO, 'docs', 'verification-status.json')))
        k['verification'] = {'generated': j.get('generated'), 'totals': j.get('totals')}
    except Exception:
        pass
    try:
        oh = open(os.path.join(R.REPO, 'docs', 'open-holes.md')).read()
        k['open_holes'] = [re.sub(r'\s+', ' ', m.group(1))[:140] for m in re.finditer(r'(?m)^## (\d+\..*)$', oh)
                           if '~~' not in m.group(1)]
    except Exception:
        pass
    plans = []
    pdir = os.path.join(R.REPO, 'docs', 'plans')
    for f in sorted(os.listdir(pdir)) if os.path.isdir(pdir) else []:
        if f.endswith('.md') and not f.endswith('.claims.md'):
            txt = open(os.path.join(pdir, f), encoding='utf-8', errors='replace').read()
            title = next((l[2:].strip() for l in txt.split('\n') if l.startswith('# ')), f)
            stage = re.search(r'\*\*Stage: ([^*]+)\*\*', txt)
            oq = re.search(r'(?ms)^## Open questions for the owner\n(.*?)^## ', txt)
            nq = len(re.findall(r'(?m)^\d+\. ', oq.group(1))) if oq else 0
            plans.append({'file': f'docs/plans/{f}', 'title': title, 'stage': stage.group(1).strip() if stage else '?',
                          'open_questions': nq})
    k['plans'] = plans
    try:
        co = open(os.path.join(R.REPO, 'docs', 'corrections.md')).read()
        last = re.findall(r'(?m)^## (\d+\..*)$', co)[-3:]
        k['corrections'] = [re.sub(r'\s+', ' ', x)[:160] for x in last]
    except Exception:
        pass
    return k


def repo_state():
    st = sh(['git', 'status', '-sb']).split('\n')
    head = st[0] if st else ''
    return {'branch': head.replace('## ', ''), 'dirty': [l for l in st[1:] if l.strip()][:30],
            'last_commit': sh(['git', 'log', '--oneline', '-1']).strip()}


def state():
    return {'session': {'name': R.SESSION, 'running': R.server_running()},
            'items': items_state(), 'repo': repo_state(), 'check': dict(CHECK),
            'knowledge': knowledge(), 'now': time.strftime('%H:%M:%S')}


# ------------------------------------------------------------------ actions
def item_of_pane(pane):
    for slug in os.listdir(R.RECORDS) if os.path.isdir(R.RECORDS) else []:
        try:
            if pane in R.load_item(slug).get('panes', {}).values():
                return slug
        except Exception:
            pass
    return None


ALLOWED_KEYS = {'up', 'down', 'left', 'right', 'enter', 'esc', 'tab', 'backspace', 'ctrl+c', 'ctrl+u',
                'y', 'n', '1', '2', '3', '4', '5', '6', '7', '8', '9'}


def act(path, body):
    if path == '/api/keys':
        pane, keys = body.get('pane'), body.get('keys', [])
        if not item_of_pane(pane) or not keys or any(k not in ALLOWED_KEYS for k in keys):
            return 400, {'error': 'unknown pane or key'}
        R.herdr('pane', 'send-keys', pane, *keys)
        return 200, {'ok': True}
    if path == '/api/text':
        pane, text = body.get('pane'), str(body.get('text', ''))
        if not item_of_pane(pane) or not text or len(text) > 4000:
            return 400, {'error': 'unknown pane or empty text'}
        R.herdr('pane', 'send-text', pane, text)
        if body.get('enter', True):
            R.herdr('pane', 'send-keys', pane, 'enter')
        return 200, {'ok': True}
    if path == '/api/runner':
        slug, action = body.get('slug'), body.get('action')
        if not slug or not os.path.exists(R.rec(slug, 'item.json')):
            return 400, {'error': 'unknown item'}
        item = R.load_item(slug)
        if action == 'stop':
            R.herdr('pane', 'send-keys', item['panes']['runner'], 'ctrl+c')
            return 200, {'ok': True}
        if action == 'resume':
            if runner_alive(slug):
                return 409, {'error': 'the runner is already running'}
            live = {w['workspace_id'] for w in herdr_json('workspace', 'list').get('result', {}).get('workspaces', [])}
            if item.get('workspace') in live:
                R.herdr('pane', 'run', item['panes']['runner'], f'python3 {os.path.join(HERE, "run.py")} stages {slug}')
                return 200, {'ok': True, 'output': 'runner restarted in its pane'}
            p = subprocess.run([sys.executable, os.path.join(HERE, 'run.py'), 'open', slug],
                               capture_output=True, text=True, cwd=R.REPO)
            return (200 if p.returncode == 0 else 500), {'output': p.stdout + p.stderr}
        return 400, {'error': 'unknown action'}
    if path == '/api/new':
        slug = str(body.get('slug', '')).strip()
        addrs = str(body.get('addrs', '')).replace(' ', '')
        if not re.match(r'^[a-z][a-z0-9-]{1,40}$', slug) or not re.match(r'^(0x[0-9A-Fa-f]+,?)+$', addrs):
            return 400, {'error': 'slug: lowercase-dashes; addrs: comma-separated 0x... values'}
        cmd = [sys.executable, os.path.join(HERE, 'run.py'), 'new', slug, '--addrs', addrs.strip(',')]
        if body.get('claim_file'):
            cmd += ['--claim-file', body['claim_file']] + (['--section', body['section']] if body.get('section') else [])
        elif body.get('claim_text'):
            cmd += ['--claim-text', body['claim_text']]
        else:
            return 400, {'error': 'a claim file (with optional section) or claim text is required'}
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=R.REPO, timeout=300)
        return (200 if p.returncode == 0 else 500), {'output': p.stdout + p.stderr}
    if path == '/api/check':
        with _lock:
            if CHECK['running']:
                return 409, {'error': 'a check is already running'}
            CHECK.update(running=True, started=time.strftime('%H:%M:%S'), finished=None, exit=None, tail='',
                         full=bool(body.get('full')))
        threading.Thread(target=_run_check, args=(bool(body.get('full')),), daemon=True).start()
        return 200, {'ok': True}
    return 404, {'error': 'no such action'}


def _run_check(full):
    p = subprocess.run(['bash', 'scripts/check.sh'] + (['--full'] if full else []), cwd=R.REPO,
                       capture_output=True, text=True)
    with _lock:
        CHECK.update(running=False, finished=time.strftime('%H:%M:%S'), exit=p.returncode,
                     tail='\n'.join((p.stdout + p.stderr).rstrip().split('\n')[-40:]))


# ------------------------------------------------------------------ server
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _host_ok(self):
        return self.headers.get('Host') in (f'127.0.0.1:{PORT}', f'localhost:{PORT}')

    def _send(self, code, body, ctype='application/json'):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {'error': 'host'})
        u = urlparse(self.path)
        if u.path == '/':
            return self._send(200, open(os.path.join(HERE, 'console.html'), 'rb').read(), 'text/html; charset=utf-8')
        if self.headers.get('X-Rom-Console') != '1':
            return self._send(403, {'error': 'header'})
        if u.path == '/api/state':
            return self._send(200, state())
        if u.path == '/api/file':
            q = parse_qs(u.query)
            slug, name = q.get('item', [''])[0], q.get('name', [''])[0]
            if name not in RECORD_FILES or not re.match(r'^[a-z][a-z0-9-]{1,40}$', slug) or \
                    not os.path.exists(R.rec(slug, name)):
                return self._send(404, {'error': 'no such record'})
            return self._send(200, {'name': name, 'text': open(R.rec(slug, name), encoding='utf-8',
                                                               errors='replace').read()})
        return self._send(404, {'error': 'not found'})

    def do_POST(self):
        if not self._host_ok() or self.headers.get('X-Rom-Console') != '1':
            return self._send(403, {'error': 'forbidden'})
        origin = self.headers.get('Origin')
        if origin and origin not in (f'http://127.0.0.1:{PORT}', f'http://localhost:{PORT}'):
            return self._send(403, {'error': 'origin'})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0)) or 0) or b'{}')
        except Exception:
            return self._send(400, {'error': 'bad json'})
        try:
            code, out = act(urlparse(self.path).path, body)
        except SystemExit as e:
            code, out = 500, {'error': str(e)}
        except Exception as e:
            code, out = 500, {'error': f'{type(e).__name__}: {e}'}
        return self._send(code, out)


def serve():
    srv = ThreadingHTTPServer(('127.0.0.1', PORT), H)
    os.makedirs(R.STATE, exist_ok=True)
    json.dump({'pid': os.getpid(), 'port': PORT}, open(PIDFILE, 'w'))
    srv.serve_forever()


def responding():
    import urllib.request
    try:
        req = urllib.request.Request(f'http://127.0.0.1:{PORT}/api/state', headers={'X-Rom-Console': '1'})
        urllib.request.urlopen(req, timeout=15).read()
        return True
    except Exception:
        return False


def start(open_browser=True):
    url = f'http://127.0.0.1:{PORT}/'
    if not responding():
        os.makedirs(R.STATE, exist_ok=True)
        subprocess.Popen([sys.executable, os.path.abspath(__file__), 'serve'], stdin=subprocess.DEVNULL,
                         stdout=open(os.path.join(R.STATE, 'console.log'), 'a'), stderr=subprocess.STDOUT,
                         start_new_session=True, cwd=R.REPO)
        for _ in range(60):
            time.sleep(0.25)
            if responding():
                break
        else:
            raise SystemExit(f'console did not start; see {os.path.join(R.STATE, "console.log")}')
        print(f'console started: {url}')
    else:
        print(f'console already running: {url}')
    if open_browser:
        webbrowser.open(url)
    return 0


if __name__ == '__main__':
    if sys.argv[1:] == ['serve']:
        serve()
    else:
        sys.exit(start(open_browser='--no-browser' not in sys.argv))
