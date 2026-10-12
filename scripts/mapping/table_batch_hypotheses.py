"""Ask Claude, in bulk, what each unnamed ROM table is -- as HYPOTHESES to review.

    python scripts/mapping/table_batch_hypotheses.py prepare            # build requests, no spend
    python scripts/mapping/table_batch_hypotheses.py prepare --limit 5  # small trial set
    python scripts/mapping/table_batch_hypotheses.py submit             # send the batch (SPENDS)
    python scripts/mapping/table_batch_hypotheses.py collect            # fetch results, write report

WHAT THIS IS FOR
table_triage.py reduces the unnamed descriptors to the ones worth decoding. The
expensive step is still reading each consumer. This sends one request per table
through the Message Batches API (asynchronous, half price) with the evidence a
person would open first: the triage row, the decoded table, and the disassembly
around every call site with literal-pool values resolved.

WHAT COMES BACK IS A LEAD, NOT AN IDENTITY
Nothing here writes to the definition XMLs, the Ghidra import script or
corrections.md. The report goes to docs/exploration/ and every row carries the
model's own evidence class. CLAUDE.md rule 7 applies to this output exactly as
it applies to a Ghidra label: decode the consumer before building on it.

Needs: pip install anthropic, and ANTHROPIC_API_KEY set (or `ant auth login`).
"""
import argparse
import json
import os
import re
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, HERE)
import desc_types as T           # noqa: E402
import sh2e_disasm as D          # noqa: E402
import table_triage as TT        # noqa: E402

REPO = TT.REPO
OUT_DIR = os.path.join(REPO, 'docs', 'exploration', 'table_hypotheses')
REQUESTS = os.path.join(OUT_DIR, 'requests.jsonl')
STATE = os.path.join(OUT_DIR, 'batch_state.json')
RESULTS = os.path.join(OUT_DIR, 'results.json')
REPORT = os.path.join(OUT_DIR, 'report.md')

MODEL = 'claude-opus-5-5'
MAX_TOKENS = 16000
PRICE_IN, PRICE_OUT = 4.00, 20.00     # USD per million tokens, claude-opus-5-5
BATCH_DISCOUNT = 0.5
EST_OUTPUT_TOKENS = 2500              # per table; the 5-table trial measured ~1,700 on short windows
CHARS_PER_TOKEN = 1.6                 # measured on the trial: hex-heavy listings tokenise poorly

# Each call site is shown with its WHOLE FUNCTION where the bounds can be found.
# The first trial sent a fixed window and 3 of 5 answers stalled on "the input is
# loaded before the window" / "the consumer is after it".
MAX_BACK, MAX_FWD = 700, 500          # instructions searched for the function's entry / end
BEFORE, AFTER = 200, 120              # fallback window when no entry is found
MAX_FUNCS = 4                         # distinct functions shown per table
MAX_PROMPT_CHARS = 90000              # stop adding functions past this

SYSTEM = """You are helping reverse-engineer a 2013 Subaru WRX engine computer ROM \
(AE5L600L, Renesas SH7058, an SH-2E core: SH-2 integer instructions plus a \
single-precision FPU, big-endian).

Each request describes ONE calibration table that the code provably reads through \
the table-lookup routines but that no definition file names. Geometry, cell type, \
scaling, axis breakpoints and data are known from bytes. Only the meaning is missing. \
Your job is to propose what the table is, from the evidence given, and to be exact \
about how strong that evidence is.

How this project works, and what it has learned the hard way:
- A label is not evidence. Labels in the listing are tagged [TRACED] (the address was \
decoded and machine-checked, though the NAME may still be wrong), [CITED] (a lead) or \
[UNVERIFIED] (the name is the only artefact). Every identity this project inferred from \
a label or from a nearby label turned out wrong. Reason from what the code does with \
the value, not from names.
- An axis name marked "from definition" is ground truth: that axis array is shared \
with a table the definition files do name.
- Matching a magnitude is not identifying a quantity. A range of 0..100 is not \
therefore a percentage.
- Find what consumes the looked-up value: which register it lands in, what it is \
multiplied by, added to, compared against or stored to. Check for a clamp or a \
multiplier that would make the table inert.
- The subsystem hint and the RAM names in the triage row are hints only.
- Each listing is meant to be the whole function around the call site. Its bounds were \
found by a heuristic (a run of stack pushes marks an entry), so it can start late, stop \
early or run into a neighbour, and the header says when only a fixed window is shown. \
Literal pools sit inside the listing; data decoded as instructions looks like nonsense \
and must be ignored. If the input or the consumer is not in the listing, say so rather \
than guessing.
- A value stored to RAM and read by a different function is a dead end here. Name the \
RAM address in next_step so its readers can be searched.
- Displacements in the listing are already in bytes.
- These tables use ECU-internal units: temperatures in Celsius, speed in km/h, \
engine load in g/rev.

Evidence classes for your answer:
- "observed": the listing shows the value being used in a way that fixes its meaning.
- "inferred": a chain of reasoning with at least one unverified link. Name the weakest link.
- "hunch": consistent with the data, not supported by the code shown.

If the evidence does not support any identity, say "unknown". An honest "unknown" with \
a good next step is more useful than a confident guess."""

SCHEMA = {
    'type': 'object',
    'properties': {
        'proposed_name': {'type': 'string',
                          'description': 'Short descriptive name, or "unknown".'},
        'what_it_does': {'type': 'string',
                         'description': 'One or two plain sentences.'},
        'axis_meanings': {'type': 'array', 'items': {'type': 'string'}},
        'output_units': {'type': 'string'},
        'evidence_class': {'type': 'string', 'enum': ['observed', 'inferred', 'hunch', 'unknown']},
        'evidence': {'type': 'array', 'items': {'type': 'string'},
                     'description': 'Each item cites an address and instruction from the listing.'},
        'weakest_link': {'type': 'string'},
        'live_lever': {'type': 'string', 'enum': ['yes', 'no', 'cannot_tell']},
        'tuning_relevance': {'type': 'string', 'enum': ['high', 'medium', 'low', 'none']},
        'next_step': {'type': 'string',
                      'description': 'The cheapest check that would confirm or refute this.'},
    },
    'required': ['proposed_name', 'what_it_does', 'axis_meanings', 'output_units',
                 'evidence_class', 'evidence', 'weakest_link', 'live_lever',
                 'tuning_relevance', 'next_step'],
    'additionalProperties': False,
}


def tagged_labels():
    """address -> (name, evidence tag) from the Ghidra import script."""
    if not os.path.exists(TT.JAVA):
        return {}
    src = open(TT.JAVA, encoding='utf-8', errors='replace').read()
    out = {}
    pat = r'labelComment\((0x[0-9A-Fa-f]+)L?,\s*"([^"]+)"(?:,\s*"\[(TRACED|CITED|UNVERIFIED)\])?'
    for m in re.finditer(pat, src):
        out[int(m.group(1), 16)] = (m.group(2), m.group(3) or 'UNVERIFIED')
    return out


def fmt(v):
    return ('%.5g' % v) if isinstance(v, float) else str(v)


def table_text(rom, desc):
    tab = T.read_table(rom, desc)
    ax = tab['axes']
    lines = ['%s axis breakpoints: %s' % (k.upper(), ', '.join(fmt(v) for v in ax[k]))
             for k in ('y', 'x') if k in ax]
    if tab['dim'] == '2D':
        lines.append('values, one line per X breakpoint, columns along Y:')
        for xv, row in zip(ax['x'], tab['values']):
            lines.append('  X=%s: %s' % (fmt(xv), ', '.join(fmt(v) for v in row)))
    else:
        lines.append('values: ' + ', '.join(fmt(v) for v in tab['values']))
    return '\n'.join(lines)


def _word(rom, a):
    return struct.unpack_from('>H', rom, a)[0]


def _is_push(w):
    """A register being saved to the stack: the start of nearly every function here."""
    return ((w & 0xF00F) == 0x2F06          # mov.l Rm,@-r15
            or (w & 0xFF0F) == 0xFF0B       # fmov.s FRm,@-r15
            or w in (0x4F22, 0x4F02, 0x4F12, 0x4F13))   # sts.l pr/mach/macl, stc.l gbr


def _is_exit(w):
    return w == 0x000B or (w & 0xF0FF) == 0x402B or (w & 0xF000) == 0xA000   # rts, jmp @Rn, bra


def function_bounds(rom, site):
    """(start, end, whole) for the function containing `site`.

    HEURISTIC, not a decode: the entry is the nearest preceding run of stack
    pushes, the end is the next such run after an rts/jmp/bra. A leaf function
    that saves nothing is missed, in which case a fixed window is returned and
    `whole` is False.
    """
    start = None
    for a in range(site - 2, max(0x400, site - MAX_BACK * 2), -2):
        if _is_push(_word(rom, a)) and not _is_push(_word(rom, a - 2)):
            start = a
            break
    if start is None:
        return max(0, site - BEFORE * 2), min(len(rom) - 2, site + AFTER * 2), False
    end, left = min(len(rom) - 2, site + MAX_FWD * 2), False
    for a in range(site + 2, end, 2):
        w = _word(rom, a)
        if left and _is_push(w) and not _is_push(_word(rom, a - 2)):
            end = a
            break
        left = left or _is_exit(w)
    return start, end, True


def listing(rom, start, end, marks, labels, desc):
    out = []
    for pc, w, txt, _ in D.disasm(rom, start, end):
        note = ''
        m = re.search(r'@\(0x([0-9A-Fa-f]+)\)', txt)
        if m and (w >> 12) in (0x9, 0xD):
            t = int(m.group(1), 16)
            if (w >> 12) == 0xD and t + 4 <= len(rom):
                v = struct.unpack_from('>I', rom, t)[0]
                note = '  ; = 0x%08X' % v
                if v == desc:
                    note += '  <-- THIS TABLE\'S DESCRIPTOR'
                elif v in labels:
                    note += '  %s [%s]' % labels[v]
            elif (w >> 12) == 0x9 and t + 2 <= len(rom):
                note = '  ; = 0x%04X' % struct.unpack_from('>H', rom, t)[0]
        m = re.search(r'\b(?:bsr|jsr|bra|jmp)\s+0x([0-9A-Fa-f]+)', txt)
        if m and int(m.group(1), 16) in labels:
            note += '  ; %s [%s]' % labels[int(m.group(1), 16)]
        out.append('%s %06X: %s%s' % ('>>' if pc in marks else '  ', pc, txt, note))
    return '\n'.join(out)


def build_prompt(rom, row, labels):
    desc = int(row['desc'], 16)
    axis_lines = []
    which = ('Y', 'X') if row['dim'] == '2D' else ('X',)
    for k, addr, name in zip(which, row['axes'], row['axis_names']):
        axis_lines.append('  %s axis at %s: %s' % (k, addr, ('"%s" (from definition)' % name)
                                                   if name else 'no name known'))
    parts = [
        'TABLE DESCRIPTOR %s' % row['desc'],
        'geometry: %s %s, cell type %s, scale %s, bias %s' % (
            row['dim'], row['shape'], row['type'], fmt(row['scale']), fmt(row['bias'])),
        'data at %s, value range %s .. %s' % (row['data'], fmt(row['lo']), fmt(row['hi'])),
        'axes:\n' + '\n'.join(axis_lines),
        'triage hints (NOT evidence): subsystem "%s" matched by %s; nearby RAM names: %s' % (
            row['subsystem'] or 'unassigned', row['matched_by'] or 'nothing',
            ', '.join(row['ram']) or 'none'),
        '',
        'DECODED TABLE (physical values)',
        table_text(rom, desc),
    ]
    sites = [int(s, 16) for s in row['sites']]
    if not sites:
        parts += ['', 'NO DIRECT CALL SITE was found. The descriptor is probably reached '
                      'through a pointer table. Say what can and cannot be concluded.']
    funcs = {}                                  # (start, end, whole) -> call sites inside it
    for s in sites:
        funcs.setdefault(function_bounds(rom, s), []).append(s)
    shown, size = 0, sum(len(p) for p in parts)
    for (start, end, whole), inside in funcs.items():
        if shown == MAX_FUNCS or (shown and size > MAX_PROMPT_CHARS):
            break
        text = listing(rom, start, end, set(inside), labels, desc)
        parts += ['', '%s 0x%06X-0x%06X, loading the descriptor at %s (marked ">>")' % (
            'FUNCTION' if whole else 'FIXED WINDOW (no function entry found)', start, end,
            ', '.join('0x%06X' % s for s in inside)), text]
        shown, size = shown + 1, size + len(text)
    if len(funcs) > shown:
        parts.append('\n(%d further functions that load this descriptor are not shown)'
                     % (len(funcs) - shown))
    parts += ['', 'What is this table? Answer in the required JSON.']
    return '\n'.join(parts)


def select(args):
    rows, _, _ = TT.triage(args.rom)
    rows = [r for r in rows if not r['flat'] and r['subsystem'] != 'diagnostic']
    if args.subsystem:
        rows = [r for r in rows if args.subsystem.lower() in (r['subsystem'] or 'unassigned').lower()]
    if args.with_sites:
        rows = [r for r in rows if r['sites']]
    if args.only:
        want = {int(x, 16) for x in args.only}
        rows = [r for r in rows if int(r['desc'], 16) in want]
    return rows[:args.limit] if args.limit else rows


def cmd_prepare(args):
    rom = TT.load_rom(args.rom)
    labels = tagged_labels()
    rows = select(args)
    if not rows:
        sys.exit('no tables selected')
    os.makedirs(OUT_DIR, exist_ok=True)
    chars = 0
    with open(REQUESTS, 'w', encoding='utf-8', newline='\n') as fh:
        for r in rows:
            prompt = build_prompt(rom, r, labels)
            chars += len(prompt)
            fh.write(json.dumps({'custom_id': 'desc-' + r['desc'][2:], 'row': r,
                                 'prompt': prompt}) + '\n')
    n = len(rows)
    tok_in = int((chars + len(SYSTEM) * n) / CHARS_PER_TOKEN)
    tok_out = EST_OUTPUT_TOKENS * n
    cost = (tok_in * PRICE_IN + tok_out * PRICE_OUT) / 1e6 * BATCH_DISCOUNT
    print('rom      : %s' % os.path.basename(args.rom))
    print('tables   : %d  (%d with a call site)' % (n, sum(1 for r in rows if r['sites'])))
    print('wrote    : %s' % os.path.relpath(REQUESTS, REPO))
    print('ESTIMATE : ~%s input tokens, ~%s output tokens -> about $%.2f at batch price'
          % (format(tok_in, ','), format(tok_out, ','), cost))
    print('           (input from character count; output is a GUESS of %d tokens per table.'
          % EST_OUTPUT_TOKENS)
    print('            Run a --limit 5 batch first and read the real usage from `collect`.)')
    print('next     : read a prompt in requests.jsonl, then `submit`')


def load_requests():
    if not os.path.exists(REQUESTS):
        sys.exit('run `prepare` first')
    return [json.loads(line) for line in open(REQUESTS, encoding='utf-8')]


def cmd_submit(args):
    import anthropic
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request

    if os.path.exists(STATE) and not args.force:
        sys.exit('a batch is already recorded in %s -- run `collect`, or pass --force'
                 % os.path.relpath(STATE, REPO))
    reqs = load_requests()
    if not args.yes:
        ans = input('Submit %d requests to %s at effort %s? This spends API credit. [y/N] '
                    % (len(reqs), MODEL, args.effort))
        if ans.strip().lower() != 'y':
            sys.exit('not submitted')
    system = [{'type': 'text', 'text': SYSTEM, 'cache_control': {'type': 'ephemeral'}}]
    client = anthropic.Anthropic()
    batch = client.messages.batches.create(requests=[
        Request(custom_id=r['custom_id'], params=MessageCreateParamsNonStreaming(
            model=MODEL, max_tokens=MAX_TOKENS, system=system,
            output_config={'effort': args.effort,
                           'format': {'type': 'json_schema', 'schema': SCHEMA}},
            messages=[{'role': 'user', 'content': r['prompt']}]))
        for r in reqs])
    with open(STATE, 'w', encoding='utf-8', newline='\n') as fh:
        json.dump({'batch_id': batch.id, 'submitted': time.strftime('%Y-%m-%d %H:%M:%S'),
                   'count': len(reqs), 'model': MODEL, 'effort': args.effort}, fh, indent=1)
    print('submitted batch %s (%d requests). Most batches finish within an hour.' % (batch.id, len(reqs)))
    print('next: `collect` (add --wait to poll until it ends)')


def cmd_collect(args):
    import anthropic

    if not os.path.exists(STATE):
        sys.exit('no batch recorded -- run `submit` first')
    state = json.load(open(STATE, encoding='utf-8'))
    client = anthropic.Anthropic()
    while True:
        batch = client.messages.batches.retrieve(state['batch_id'])
        c = batch.request_counts
        print('status %s: %d processing, %d succeeded, %d errored'
              % (batch.processing_status, c.processing, c.succeeded, c.errored))
        if batch.processing_status == 'ended' or not args.wait:
            break
        time.sleep(60)
    if batch.processing_status != 'ended':
        sys.exit('not finished yet -- run `collect` again later')

    rows = {r['custom_id']: r['row'] for r in load_requests()}
    found, failed, tin, tout = [], [], 0, 0
    for res in client.messages.batches.results(state['batch_id']):
        row = rows.get(res.custom_id, {'desc': res.custom_id})
        if res.result.type != 'succeeded':
            failed.append((row['desc'], res.result.type))
            continue
        msg = res.result.message
        tin += (msg.usage.input_tokens + (msg.usage.cache_read_input_tokens or 0)
                + (msg.usage.cache_creation_input_tokens or 0))
        tout += msg.usage.output_tokens
        if msg.stop_reason != 'end_turn':
            failed.append((row['desc'], 'stopped: %s' % msg.stop_reason))
            continue
        text = next((b.text for b in msg.content if b.type == 'text'), '')
        try:
            found.append({'row': row, 'answer': json.loads(text)})
        except ValueError:
            failed.append((row['desc'], 'reply was not valid JSON'))

    with open(RESULTS, 'w', encoding='utf-8', newline='\n') as fh:
        json.dump({'batch': state, 'results': found, 'failed': failed}, fh, indent=1)
    write_report(state, found, failed, tin, tout)
    cost = (tin * PRICE_IN + tout * PRICE_OUT) / 1e6 * BATCH_DISCOUNT
    print('%d answers, %d failed' % (len(found), len(failed)))
    print('usage: %s input tokens, %s output tokens -> at most $%.2f (cache reads cost less)'
          % (format(tin, ','), format(tout, ','), cost))
    print('wrote: %s' % os.path.relpath(REPORT, REPO))
    print('       %s' % os.path.relpath(RESULTS, REPO))


def write_report(state, found, failed, tin, tout):
    rank_e = {'observed': 0, 'inferred': 1, 'hunch': 2, 'unknown': 3}
    rank_t = {'high': 0, 'medium': 1, 'low': 2, 'none': 3}
    found.sort(key=lambda f: (rank_e[f['answer']['evidence_class']],
                              rank_t[f['answer']['tuning_relevance']], f['row']['desc']))
    L = ['# Unnamed-table hypotheses',
         '',
         '> **These are leads, not identities.** Generated by `scripts/mapping/table_batch_hypotheses.py`',
         '> (batch %s, %s, model %s, effort %s). Nothing here has been checked against ROM bytes'
         % (state['batch_id'], state['submitted'], state['model'], state['effort']),
         '> by a person or by the verifier. Decode the consumer before building on any row.',
         '',
         '%d tables answered, %d failed. %s input and %s output tokens.'
         % (len(found), len(failed), format(tin, ','), format(tout, ',')),
         '',
         '## Ranked',
         '',
         '| Descriptor | Shape | Proposed name | Evidence | Live lever | Tuning relevance |',
         '|---|---|---|---|---|---|']
    for f in found:
        r, a = f['row'], f['answer']
        L.append('| %s | %s %s | %s | %s | %s | %s |' % (
            r['desc'], r['dim'], r['shape'], a['proposed_name'].replace('|', '/'),
            a['evidence_class'], a['live_lever'], a['tuning_relevance']))
    L += ['', '## Detail', '']
    for f in found:
        r, a = f['row'], f['answer']
        L += ['### %s -- %s' % (r['desc'], a['proposed_name']),
              '',
              '%s %s %s, data %s, range %s .. %s. Triage hint: %s.' % (
                  r['dim'], r['shape'], r['type'], r['data'], fmt(r['lo']), fmt(r['hi']),
                  r['subsystem'] or 'unassigned'),
              '',
              a['what_it_does'],
              '',
              '- **Evidence class:** %s' % a['evidence_class'],
              '- **Axes:** %s' % ('; '.join(a['axis_meanings']) or 'not stated'),
              '- **Output units:** %s' % a['output_units'],
              '- **Live lever:** %s. **Tuning relevance:** %s' % (a['live_lever'], a['tuning_relevance']),
              '- **Weakest link:** %s' % a['weakest_link'],
              '- **Next step:** %s' % a['next_step'],
              '- **Cited:**']
        L += ['  - %s' % e for e in a['evidence']] or ['  - none']
        L.append('')
    if failed:
        L += ['## Failed', ''] + ['- %s: %s' % f for f in failed]
    with open(REPORT, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join(L) + '\n')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('prepare', help='build requests.jsonl and estimate cost (no spend)')
    p.add_argument('--rom', default=TT.DEFAULT_ROM)
    p.add_argument('--limit', type=int, help='only the first N selected tables')
    p.add_argument('--subsystem', help='only tables whose subsystem hint contains this text')
    p.add_argument('--with-sites', action='store_true', help='only tables with a direct call site')
    p.add_argument('--only', nargs='+', metavar='ADDR', help='specific descriptor addresses')
    p.set_defaults(fn=cmd_prepare)
    p = sub.add_parser('submit', help='send requests.jsonl as a batch (SPENDS API credit)')
    p.add_argument('--effort', default='high', choices=['low', 'medium', 'high', 'xhigh', 'max'])
    p.add_argument('--yes', action='store_true', help='skip the confirmation prompt')
    p.add_argument('--force', action='store_true', help='replace the recorded batch id')
    p.set_defaults(fn=cmd_submit)
    p = sub.add_parser('collect', help='fetch results and write the report')
    p.add_argument('--wait', action='store_true', help='poll every minute until the batch ends')
    p.set_defaults(fn=cmd_collect)
    args = ap.parse_args()
    args.fn(args)


if __name__ == '__main__':
    main()
