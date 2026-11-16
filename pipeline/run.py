#!/usr/bin/env python3
"""AE5L600L verify pipeline (Track A of docs/pipeline-plan.md), driven through herdr.

    python3 pipeline/run.py new <slug> --addrs 0x0357C8,0xFFFF7904 \
        --claim-file docs/open-holes.md --section "## 9." [--reviewer codex] [--dry-run]
    python3 pipeline/run.py attach             # watch it / answer gates (Ctrl+b d to detach)
    python3 pipeline/run.py stages <slug>      # the runner itself; `new` starts it in its pane
    python3 pipeline/run.py status [<slug>]

Everything runs in its OWN herdr session, `rom` (socket ~/.config/herdr/sessions/rom/), started
headless on demand. The work session (`default`) is never touched. Run `new` from any terminal.
It builds:

  .pipeline/items/<slug>/              records (git-excluded): item.json, claim.md, pack.md,
                                       blind-*.md, settle.md
  ~/.local/state/ae5l-pipeline/<slug>/{claude,codex}/
                                       two blind workspaces OUTSIDE the repo: the ROM, the
                                       decoder, the definitions, the pack and BLIND.md. Outside,
                                       because Claude Code loads every parent CLAUDE.md, and the
                                       repo's is full of the claims being tested.

and, in the `rom` herdr session, a workspace `rom/<slug>` with four panes: runner | reviewer (Codex, cwd its blind
folder, workspace-write sandbox so it can write nowhere else) / tracer (Claude, main
checkout) | blind-claude (a fresh Claude in its blind folder).

Stages (each resumes from what is on disk):
  1 blind     both blind readers answer from bytes, without the claim or each other
  2 settle    the tracer compares claim vs both answers, hand-decodes every contradiction
  3 critique  the reviewer re-decodes the settlement (Pass N); up to 3 fix rounds
  4 gate      the owner: accept / fix round / stop
  5 apply     the tracer writes the corrections entry and doc edits, runs scripts/check.sh;
              the owner is asked before anything is committed
Nothing here flashes, edits rom/ or definitions/, or pushes.
"""
import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
AGENT_FILES = os.path.join(HERE, 'agent-files')
RECORDS = os.path.join(REPO, '.pipeline', 'items')
STATE = os.path.join(os.path.expanduser('~'), '.local', 'state', 'ae5l-pipeline')
CLAUDE_MODEL = 'claude-opus-5-5'
SESSION = 'rom'                     # a herdr session of its own, apart from the work session
SERVER_LOG = os.path.join(os.path.expanduser('~'), '.local', 'state', 'ae5l-pipeline', 'herdr-server.log')
# The rom session's own herdr config (HERDR_CONFIG_PATH), so nothing here changes the work session's.
ROM_CONFIG = os.path.join(os.path.expanduser('~'), '.config', 'herdr', 'sessions', SESSION, 'config.toml')
ROM_CONFIG_TEXT = '''# herdr config for the AE5L600L "rom" session only (written by pipeline/run.py).
onboarding = false

# The runner drives agents with no client attached; give them a real terminal, not 80x24.
[server]
headless_cols = 220
headless_rows = 64
'''
MAX_ROUNDS = 3
BLIND_HEADINGS = ['## Mechanism', '## Addresses', '## Inputs and outputs',
                  '## Inert or gated in this calibration', '## Statements', '## Not established']
SETTLE_HEADINGS = ['## Outcome', '## Claim statements', '## Blind disagreements', '## Hand decodes',
                   '## Draft corrections entry', '## Files to change', '## Objections']
BLIND_FILES = ['scripts/sh2e_disasm.py', 'scripts/desc_types.py', 'scripts/defs.py',
               'definitions/32BITBASE.xml', 'definitions/AE5L600L 2013 USDM Impreza WRX MT.xml']

sys.path.insert(0, os.path.join(REPO, 'scripts'))
sys.path.insert(0, os.path.join(REPO, 'scripts', 'mapping'))


# ------------------------------------------------------------------ helpers
def say(msg):
    print(msg, flush=True)


def rec(slug, *parts):
    return os.path.join(RECORDS, slug, *parts)


def blind_dir(slug, who):
    return os.path.join(STATE, slug, who)


def load_item(slug):
    return json.load(open(rec(slug, 'item.json')))


def save_item(slug, item):
    json.dump(item, open(rec(slug, 'item.json'), 'w'), indent=2)


def has_headings(path, heads):
    if not os.path.exists(path):
        return False
    txt = open(path, encoding='utf-8', errors='replace').read()
    return all(re.search(r'(?m)^' + re.escape(h) + r'\s*$', txt) for h in heads)


def agent_name(role, slug):
    base = re.sub(r'[^a-z0-9_-]', '-', f'{role}-{slug}'.lower())
    return base[:32] if base[0].isalpha() else ('a' + base)[:32]


def herdr_env():
    os.makedirs(os.path.dirname(ROM_CONFIG), exist_ok=True)
    if not os.path.exists(ROM_CONFIG):
        open(ROM_CONFIG, 'w').write(ROM_CONFIG_TEXT)
    return {**os.environ, 'HERDR_CONFIG_PATH': ROM_CONFIG}


def herdr(*args, check=True):
    p = subprocess.run(['herdr', '--session', SESSION, *args], capture_output=True, text=True, env=herdr_env())
    if check and p.returncode != 0:
        raise SystemExit(f'herdr {" ".join(args)} failed: {p.stderr.strip() or p.stdout.strip()}')
    try:
        return json.loads(p.stdout) if p.stdout.strip() else {}
    except json.JSONDecodeError:
        return {'raw': p.stdout}


def server_running():
    p = subprocess.run(['herdr', '--session', SESSION, 'status'], capture_output=True, text=True)
    m = re.search(r'server:\s*\n\s*status:\s*(\S+)', p.stdout)
    return bool(m and m.group(1) == 'running')


def ensure_server():
    """Start the `rom` session's server headless if it is not running. Never touches `default`."""
    if server_running():
        return
    os.makedirs(os.path.dirname(SERVER_LOG), exist_ok=True)
    subprocess.Popen(['herdr', '--session', SESSION, 'server'], stdin=subprocess.DEVNULL, env=herdr_env(),
                     stdout=open(SERVER_LOG, 'a'), stderr=subprocess.STDOUT, start_new_session=True)
    for _ in range(40):
        time.sleep(0.25)
        if server_running():
            say(f'started the herdr session "{SESSION}" (headless; log {SERVER_LOG})')
            return
    raise SystemExit(f'could not start herdr session "{SESSION}"; see {SERVER_LOG}')


def agent_status(name):
    r = herdr('agent', 'get', name, check=False)
    res = r.get('result', {})
    a = res.get('agent', res)
    return a.get('agent_status') or a.get('status')


def ask(question, choices):
    """Owner gate in the runner pane. Never times out, never defaults."""
    keys = '/'.join(f'[{c[0]}]{c[1:]}' for c in choices)
    while True:
        a = input(f'\n>>> YOUR ANSWER NEEDED: {question} {keys}: ').strip().lower()
        for c in choices:
            if a and c.startswith(a):
                return c


def wait_for(name, path, heads, what):
    """Wait until `path` has `heads` and agent `name` is no longer working."""
    say(f'   waiting on {name}: {what}')
    blocked_said = False
    while True:
        st = agent_status(name)
        if st == 'blocked' and not blocked_said:
            say(f'   {name} is BLOCKED on a dialog -- answer it in its pane')
            blocked_said = True
        if st != 'blocked':
            blocked_said = False
        if has_headings(path, heads) and st in ('idle', 'done', None):
            return True
        if st is None and not has_headings(path, heads):
            say(f'   {name} exited before writing {os.path.basename(path)}; restarting it')
            return False
        time.sleep(5)


# ------------------------------------------------------------------ setup
def extract_claim(path, section):
    txt = open(os.path.join(REPO, path), encoding='utf-8').read()
    if not section:
        return txt
    lines = txt.split('\n')
    start = next((i for i, l in enumerate(lines) if l.startswith(section)), None)
    if start is None:
        raise SystemExit(f'section {section!r} not found in {path}')
    level = len(section) - len(section.lstrip('#'))
    end = next((i for i in range(start + 1, len(lines))
                if re.match(r'^#{1,%d} ' % level, lines[i])), len(lines))
    return '\n'.join(lines[start:end]).strip() + '\n'


def current_rom():
    revs = sorted(p for p in os.listdir(os.path.join(REPO, 'rom')) if p.startswith('AE5L600L 20g rev 20.19'))
    return os.path.join('rom', revs[-1])


def build_pack(rom_rel, addrs):
    import claim_audit as C
    import struct
    R = C.Rom(os.path.join(REPO, rom_rel))
    text, _ = R.pack(addrs)
    stock = open(os.path.join(REPO, 'rom', 'ae5l600l.bin'), 'rb').read()
    cur = R.rom
    raw = ['', 'RAW BYTES AT THE ROM ADDRESSES OF INTEREST (8 bytes; stock -> as flashed)']
    for a in addrs:
        if a >= 0x100000:
            continue
        s, c = stock[a:a + 8], cur[a:a + 8]
        al = a & ~3
        fs = struct.unpack('>f', stock[al:al + 4])[0]
        fc = struct.unpack('>f', cur[al:al + 4])[0]
        raw.append(f'- 0x{a:06X}: stock {s.hex(" ")}  current {c.hex(" ")}'
                   f'{"  (DIFFERS)" if s != c else ""}   as float32 @0x{al:06X}: stock {fs:g}, current {fc:g}')
    note = ('\nNOTE: an address below 0xA0000 is described above as "code" only because of where it\n'
            'is. Literal pools sit inside code; check the bytes and how the code reads them.\n')
    return text.replace('\n\nFUNCTION', '\n' + '\n'.join(raw) + '\n' + note + '\nFUNCTION', 1)


def make_blind_dir(slug, who, rom_rel, pack):
    d = blind_dir(slug, who)
    if os.path.exists(d):
        shutil.rmtree(d)
    os.makedirs(os.path.join(d, 'rom'))
    shutil.copy(os.path.join(REPO, rom_rel), os.path.join(d, 'rom', 'current.bin'))
    shutil.copy(os.path.join(REPO, 'rom', 'ae5l600l.bin'), os.path.join(d, 'rom', 'stock.bin'))
    for f in BLIND_FILES:
        os.makedirs(os.path.join(d, os.path.dirname(f)), exist_ok=True)
        shutil.copy(os.path.join(REPO, f), os.path.join(d, f))
    blind = open(os.path.join(AGENT_FILES, 'BLIND.md')).read()
    for name in ('BLIND.md', 'AGENTS.md'):          # Codex auto-loads AGENTS.md from its cwd
        open(os.path.join(d, name), 'w').write(blind)
    open(os.path.join(d, 'pack.md'), 'w').write(pack)
    probe = subprocess.run([sys.executable, '-I', '-c',
                            "import sys; sys.path.insert(0,'scripts'); import defs, desc_types, sh2e_disasm; "
                            "d=defs.load(); print(len(d.tables))"], cwd=d, capture_output=True, text=True)
    if probe.returncode != 0:
        raise SystemExit(f'blind workspace {d} is not self-sufficient:\n{probe.stderr}')
    return d


def exclude_records():
    ex = os.path.join(REPO, '.git', 'info', 'exclude')
    cur = open(ex).read() if os.path.exists(ex) else ''
    if '.pipeline/' not in cur.split('\n'):
        open(ex, 'a').write(('' if cur.endswith('\n') or not cur else '\n') + '.pipeline/\n')


def cmd_new(a):
    slug = a.slug
    if not re.match(r'^[a-z][a-z0-9-]{1,40}$', slug):
        raise SystemExit('slug: lowercase letters, digits and dashes, starting with a letter')
    if os.path.exists(rec(slug, 'item.json')) and not a.force:
        raise SystemExit(f'{slug} exists; `run.py stages {slug}` resumes it (or --force to rebuild)')
    addrs = [int(x, 16) for x in a.addrs.split(',')]
    claim = a.claim_text + '\n' if a.claim_text else extract_claim(a.claim_file, a.section)
    rom_rel = a.rom or current_rom()
    exclude_records()
    os.makedirs(rec(slug), exist_ok=True)
    pack = build_pack(rom_rel, addrs)
    open(rec(slug, 'claim.md'), 'w').write(claim)
    open(rec(slug, 'pack.md'), 'w').write(pack)
    for who in ('claude', 'codex'):
        make_blind_dir(slug, who, rom_rel, pack)
    item = {'slug': slug, 'track': 'verify', 'addrs': [hex(x) for x in addrs], 'rom': rom_rel,
            'claim_source': a.claim_file and f'{a.claim_file} {a.section or ""}'.strip() or 'text',
            'reviewer': a.reviewer, 'created': datetime.date.today().isoformat(), 'rounds': 0,
            'blind_dirs': {w: blind_dir(slug, w) for w in ('claude', 'codex')}}
    save_item(slug, item)
    say(f'records : {rec(slug)}')
    say(f'blind   : {blind_dir(slug, "claude")}\n          {blind_dir(slug, "codex")}')
    say(f'pack    : {len(pack)} chars; claim: {len(claim)} chars (the blind folders do not contain it)')
    if a.dry_run:
        say('dry run: no herdr workspace. Prompts the stages would send:')
        for role, text in prompts(slug, item).items():
            say(f'  [{role}] {text}')
        return 0
    open_workspace(slug, item)
    return 0


def open_workspace(slug, item):
    """Build the item's herdr workspace (four panes) in the rom session and start the runner in it."""
    ensure_server()
    ws = herdr('workspace', 'create', '--cwd', REPO, '--label', f'rom/{slug}', '--no-focus')['result']
    wid, root = ws['workspace']['workspace_id'], ws['root_pane']['pane_id']
    rev = herdr('pane', 'split', root, '--direction', 'right', '--cwd', blind_dir(slug, 'codex'))['result']['pane']['pane_id']
    tracer = herdr('pane', 'split', root, '--direction', 'down', '--cwd', REPO)['result']['pane']['pane_id']
    blindc = herdr('pane', 'split', rev, '--direction', 'down', '--cwd', blind_dir(slug, 'claude'))['result']['pane']['pane_id']
    for p, label in ((root, 'runner'), (rev, 'reviewer (blind, then critic)'), (tracer, 'tracer'),
                     (blindc, 'blind claude')):
        herdr('pane', 'rename', p, label, check=False)
    item['panes'] = {'runner': root, 'reviewer': rev, 'tracer': tracer, 'blind_claude': blindc}
    item['workspace'] = wid
    save_item(slug, item)
    herdr('pane', 'run', root, f'python3 {os.path.join(HERE, "run.py")} stages {slug}')
    say(f'workspace rom/{slug} is up in the herdr session "{SESSION}"; the runner is its top-left pane.')
    say('Watch it and answer gates:  rom console   (or: rom attach)')


def cmd_open(a):
    """Rebuild an existing item's workspace (after a herdr restart, or a closed workspace) and resume it."""
    item = load_item(a.slug)
    ws = item.get('workspace')
    if ws and server_running():
        live = [w['workspace_id'] for w in herdr('workspace', 'list')['result']['workspaces']]
        if ws in live:
            raise SystemExit(f'{a.slug} is already open ({ws}); `rom console` to watch it')
    open_workspace(a.slug, item)
    return 0


def cmd_attach(a):
    ensure_server()
    os.execvpe('herdr', ['herdr', 'session', 'attach', SESSION], herdr_env())


def cmd_console(a):
    import console
    return console.start(open_browser=not a.no_browser)


# ------------------------------------------------------------------ stages
def prompts(slug, item):
    r = rec(slug)
    return {
        'blind': 'Read BLIND.md in this folder and follow it exactly. Write answer.md here, then stop.',
        'settle': f'Read {AGENT_FILES}/settle.md and follow it exactly. ITEM: {r}',
        'critique': (f'READ-ONLY. Read {AGENT_FILES}/critique.md and follow it exactly. ITEM: {r} '
                     f'OUT: {blind_dir(slug, "codex")}/critique-pass<N>.md PASS: <N>'),
        'apply': f'Read {AGENT_FILES}/apply.md and follow it exactly. ITEM: {r}',
    }


def wait_unblocked(name, pane):
    """An agent showing a dialog (folder trust, a permission) waits for the owner, never crashes the run."""
    said = False
    while agent_status(name) in ('blocked', 'unknown'):
        if not said:
            say(f'   >>> {name} is waiting on a dialog in its pane ({pane}). Answer it in'
                f'  rom console  (or rom attach); the runner continues by itself')
            said = True
        time.sleep(3)


def ensure_agent(name, kind, pane, args):
    if agent_status(name):
        wait_unblocked(name, pane)
        return
    r = subprocess.run(['herdr', '--session', SESSION, 'agent', 'start', name, '--kind', kind, '--pane', pane,
                        '--timeout', '120000', '--', *args], capture_output=True, text=True, env=herdr_env())
    if r.returncode != 0:
        if 'agent_not_ready' in r.stdout + r.stderr or agent_status(name):
            wait_unblocked(name, pane)
            return
        raise SystemExit(f'could not start {name}: {(r.stderr or r.stdout).strip()}')


def send_once(slug, item, key, name, text):
    """Prompt an agent unless this exact step was already sent and the agent is still on it."""
    sent = item.setdefault('sent', {})
    if sent.get(key) and agent_status(name) == 'working':
        say(f'   {name} is already working on {key}; not re-sending')
        return
    herdr('agent', 'prompt', name, text)
    sent[key] = datetime.datetime.now().isoformat(timespec='seconds')
    save_item(slug, item)


def blind_claude_args():
    return ['--model', CLAUDE_MODEL, '--allowedTools', 'Read', 'Write', 'Grep', 'Glob',
            'Bash(python3:*)', 'Bash(xxd:*)']


def reviewer_args(item):
    if item['reviewer'] == 'gemini':
        return ['--include-directories', REPO]
    return ['-s', 'workspace-write', '-a', 'never']


def stage_blind(slug, item):
    out_c, out_x = rec(slug, 'blind-claude.md'), rec(slug, 'blind-codex.md')
    for who, out in (('claude', out_c), ('codex', out_x)):      # finished before a restart: just collect
        src = os.path.join(blind_dir(slug, who), 'answer.md')
        if not has_headings(out, BLIND_HEADINGS) and has_headings(src, BLIND_HEADINGS):
            shutil.copy(src, out)
            say(f'   blind {who}: answer already written; collected')
    if has_headings(out_c, BLIND_HEADINGS) and has_headings(out_x, BLIND_HEADINGS):
        return
    say('== 1 blind: two readers, two vendors, no claim')
    bc, rv = agent_name('blind', slug), agent_name('rev', slug)
    p = prompts(slug, item)['blind']
    jobs = []
    if not has_headings(out_x, BLIND_HEADINGS):
        ensure_agent(rv, item['reviewer'], item['panes']['reviewer'], reviewer_args(item))
        send_once(slug, item, 'blind-codex', rv, p)
        jobs.append((rv, os.path.join(blind_dir(slug, 'codex'), 'answer.md'), out_x))
    if not has_headings(out_c, BLIND_HEADINGS):
        ensure_agent(bc, 'claude', item['panes']['blind_claude'], blind_claude_args())
        send_once(slug, item, 'blind-claude', bc, p)
        jobs.append((bc, os.path.join(blind_dir(slug, 'claude'), 'answer.md'), out_c))
    for name, src, dst in jobs:
        while not wait_for(name, src, BLIND_HEADINGS, 'blind answer'):
            if name == rv:
                ensure_agent(rv, item['reviewer'], item['panes']['reviewer'], reviewer_args(item))
            else:
                ensure_agent(bc, 'claude', item['panes']['blind_claude'], blind_claude_args())
            item.setdefault('sent', {}).pop('blind-codex' if name == rv else 'blind-claude', None)
            send_once(slug, item, 'blind-codex' if name == rv else 'blind-claude', name, p)
        shutil.copy(src, dst)
        say(f'   {name}: answer copied to {os.path.relpath(dst, REPO)}')
    if agent_status(bc):
        herdr('agent', 'prompt', bc, '/exit', check=False)     # its job is done; free the pane


def last_pass(slug):
    txt = open(rec(slug, 'settle.md')).read()
    ns = [int(n) for n in re.findall(r'(?m)^### Pass (\d+)', txt)]
    return max(ns) if ns else 0


def stage_settle(slug, item):
    tr = agent_name('tracer', slug)
    ensure_agent(tr, 'claude', item['panes']['tracer'], ['--model', CLAUDE_MODEL])
    say('== 2 settle' + (f' (fix round {item["rounds"]})' if item['rounds'] else ''))
    before = os.path.getmtime(rec(slug, 'settle.md')) if os.path.exists(rec(slug, 'settle.md')) else 0
    herdr('agent', 'prompt', tr, prompts(slug, item)['settle'])
    while True:
        if not wait_for(tr, rec(slug, 'settle.md'), SETTLE_HEADINGS, 'settle.md'):
            ensure_agent(tr, 'claude', item['panes']['tracer'], ['--model', CLAUDE_MODEL])
            herdr('agent', 'prompt', tr, prompts(slug, item)['settle'])
            continue
        if os.path.getmtime(rec(slug, 'settle.md')) > before:
            break
        time.sleep(5)
    say('   ' + outcome(slug))


def outcome(slug):
    m = re.search(r'(?m)^\*\*Outcome:\*\*.*$', open(rec(slug, 'settle.md')).read())
    return m.group(0) if m else '(no outcome line)'


def stage_critique(slug, item):
    n = last_pass(slug) + 1
    rv = agent_name('rev', slug)
    ensure_agent(rv, item['reviewer'], item['panes']['reviewer'], reviewer_args(item))
    out = os.path.join(blind_dir(slug, 'codex'), f'critique-pass{n}.md')
    say(f'== 3 critique, pass {n}')
    p = prompts(slug, item)['critique'].replace('<N>', str(n))
    herdr('agent', 'prompt', rv, p)
    while not wait_for(rv, out, [], f'critique pass {n}'):
        ensure_agent(rv, item['reviewer'], item['panes']['reviewer'], reviewer_args(item))
        herdr('agent', 'prompt', rv, p)
    body = open(out).read().strip()
    with open(rec(slug, 'settle.md'), 'a') as f:
        f.write('\n\n' + body + '\n')
    objections = 0 if re.search(r'no objections', body.split('\n')[0], re.I) else body.count('\n- ')
    say(f'   pass {n}: {objections} objection(s), appended to settle.md')
    return objections


def stage_apply(slug, item):
    tr = agent_name('tracer', slug)
    ensure_agent(tr, 'claude', item['panes']['tracer'], ['--model', CLAUDE_MODEL])
    say('== 5 apply')
    herdr('agent', 'prompt', tr, prompts(slug, item)['apply'])
    while not wait_for(tr, rec(slug, 'settle.md'), SETTLE_HEADINGS + ['## Applied'], '## Applied in settle.md'):
        ensure_agent(tr, 'claude', item['panes']['tracer'], ['--model', CLAUDE_MODEL])
        herdr('agent', 'prompt', tr, prompts(slug, item)['apply'])
    say(subprocess.run(['git', 'diff', '--stat'], cwd=REPO, capture_output=True, text=True).stdout)
    if ask('Commit these changes?', ['yes', 'no']) == 'yes':
        status = subprocess.run(['git', 'status', '--porcelain'], cwd=REPO, capture_output=True, text=True).stdout
        paths = [ln[3:].strip('"') for ln in status.splitlines() if ln[3:] and not ln[3:].startswith('.pipeline')]
        subprocess.run(['git', 'add', '--', *paths], cwd=REPO, check=True)
        msg = (f'Verify {slug}: {outcome(slug).replace("**Outcome:**", "").strip()}\n\n'
               f'Verify-track item {slug}: two blind readers (Claude, {item["reviewer"]}), settled from bytes, '
               f'{last_pass(slug)} critique pass(es).\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n')
        subprocess.run(['git', 'commit', '-q', '-F', '-'], input=msg, text=True, cwd=REPO, check=True)
        say(subprocess.run(['git', 'log', '--oneline', '-1'], cwd=REPO, capture_output=True, text=True).stdout)


def cmd_stages(a):
    slug = a.slug
    item = load_item(slug)
    say(f'AE5L600L verify pipeline -- {slug} -- addresses {", ".join(item["addrs"])}')
    stage_blind(slug, item)
    if not has_headings(rec(slug, 'settle.md'), SETTLE_HEADINGS):
        stage_settle(slug, item)
    while True:
        if item.get('need_critique', True):         # a settle or fix round not yet critiqued
            objections = stage_critique(slug, item)
            item['need_critique'] = False
            save_item(slug, item)
        else:
            objections = None
        say(f'\n== 4 gate\n   {outcome(slug)}\n   records: {rec(slug, "settle.md")}')
        choices = ['accept', 'fix', 'stop'] if item['rounds'] < MAX_ROUNDS else ['accept', 'stop']
        if objections:
            say(f'   the reviewer raised {objections} objection(s) in the last pass')
        ans = ask('Accept the settlement and apply it, run a fix round, or stop?', choices)
        if ans == 'stop':
            say('STOPPED. Resume with: python3 pipeline/run.py stages ' + slug)
            return 0
        if ans == 'fix':
            item['rounds'] += 1
            item['need_critique'] = True
            save_item(slug, item)
            stage_settle(slug, item)
            continue
        break
    stage_apply(slug, item)
    item['done'] = datetime.datetime.now().isoformat(timespec='seconds')
    save_item(slug, item)
    say('DONE')
    return 0


def cmd_status(a):
    slugs = [a.slug] if a.slug else (sorted(os.listdir(RECORDS)) if os.path.isdir(RECORDS) else [])
    for s in slugs:
        it = load_item(s)
        st = ('done' if it.get('done') else
              'gate/critique' if os.path.exists(rec(s, 'settle.md')) else
              'settle' if os.path.exists(rec(s, 'blind-codex.md')) and os.path.exists(rec(s, 'blind-claude.md')) else
              'blind')
        print(f'{s:30s} {st:14s} rounds {it["rounds"]}  {it["claim_source"]}')
        if os.path.exists(rec(s, 'settle.md')):
            print('    ' + outcome(s))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    n = sub.add_parser('new')
    n.add_argument('slug')
    n.add_argument('--addrs', required=True, help='comma-separated hex addresses')
    g = n.add_mutually_exclusive_group(required=True)
    g.add_argument('--claim-file')
    g.add_argument('--claim-text')
    n.add_argument('--section', help='markdown heading prefix to extract from --claim-file, e.g. "## 9."')
    n.add_argument('--rom', help='repo-relative bin (default: newest 20.19 rev)')
    n.add_argument('--reviewer', choices=['codex', 'gemini'], default='codex')
    n.add_argument('--dry-run', action='store_true')
    n.add_argument('--force', action='store_true')
    s = sub.add_parser('stages')
    s.add_argument('slug')
    sub.add_parser('attach')
    o = sub.add_parser('open')
    o.add_argument('slug')
    c = sub.add_parser('console')
    c.add_argument('--no-browser', action='store_true')
    t = sub.add_parser('status')
    t.add_argument('slug', nargs='?')
    a = ap.parse_args()
    return {'new': cmd_new, 'stages': cmd_stages, 'status': cmd_status, 'attach': cmd_attach,
            'open': cmd_open, 'console': cmd_console}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())
