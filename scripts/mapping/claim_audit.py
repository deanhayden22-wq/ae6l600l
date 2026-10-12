"""Blind audit of the conclusions this project TUNES FROM: memory notes and subsystem docs.

    python scripts/mapping/claim_audit.py prepare            # build evidence packs (no spend)
    python scripts/mapping/claim_audit.py prepare --limit 10 # small trial
    python scripts/mapping/claim_audit.py submit             # blind pass (SPENDS)
    python scripts/mapping/claim_audit.py collect --wait     # fetch answers, send for grading (SPENDS)
    python scripts/mapping/claim_audit.py report --wait      # fetch grades, write the report

WHAT A CLAIM IS
One memory note, or one `## ` section of a subsystem doc, that cites at least
two ROM or RAM addresses. The claim text is HIDDEN from the blind reader. It is
given only the addresses and an evidence pack built mechanically from bytes:
what each address holds, any definition-file name for it, and the functions that
reference the most of those addresses. It is asked what mechanism they take part
in. A second request then lists which statements in the claim the blind answer
supports, contradicts, or could not test.

LIMITS
* The evidence pack follows direct literal-pool references only. Indexed and
  GBR-relative access is invisible to it, so "nothing reads this" is never
  established here.
* A claim about logs or driving cannot be tested from code and is reported as
  untestable, not as agreement.
* A contradiction means one side is wrong. Decode it by hand before believing
  either. Nothing here edits a doc or a memory note.
"""
import argparse
import collections
import glob
import json
import os
import re
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, HERE)
import desc_types as T               # noqa: E402
import sh2e_disasm as D              # noqa: E402
import table_triage as TT            # noqa: E402
import table_batch_hypotheses as B   # noqa: E402
import blind_audit as A              # noqa: E402

REPO = TT.REPO
OUT_DIR = os.path.join(REPO, 'docs', 'exploration', 'claim_audit')
REQUESTS = os.path.join(OUT_DIR, 'requests.jsonl')
ANSWERS = os.path.join(OUT_DIR, 'answers.json')
STATE = os.path.join(OUT_DIR, 'state.json')
REPORT = os.path.join(OUT_DIR, 'report.md')
MEMORY_DIR = os.path.expanduser(
    os.path.join('~', '.claude', 'projects', 'C--Users-Dean-Documents-GitHub-ae6l600l', 'memory'))

# State and worklist docs describe the current tune or open work, not a mechanism.
SKIP_DOCS = {'corrections.md', 'verification-status.md', 'open-holes.md', 'analysis-plan.md',
             'README.md', 'AE5L600L_table_inventory.md', 'open-issues.md', 'tune-state.md',
             'logs.md', 'workflow.md'}
MAX_ADDRS = 24
MAX_FUNCS = 8
MAX_CHARS = 80000

SYSTEM = """You are helping reverse-engineer a 2013 Subaru WRX engine computer ROM \
(AE5L600L, Renesas SH7058, an SH-2E core: SH-2 integer instructions plus a \
single-precision FPU, big-endian).

Each request lists some ADDRESSES OF INTEREST and an evidence pack built from ROM bytes: \
what each address holds, and the functions that reference the most of them. Describe the \
mechanism these addresses take part in, from the code.

- Names marked [DEFINITION] come from the ECU definition files and are ground truth for \
that table or axis. Names marked [VERIFIED-BOTH] are RAM variables cross-checked against \
definition axis names. [TRACED] names are shared maths and table-lookup helpers. Every \
other address is deliberately unnamed. Reason from what the code does.
- Function bounds were found by a heuristic, so a listing can stop early or run into a \
neighbour. Literal pools sit inside listings; data decoded as instructions looks like \
nonsense and must be ignored. Displacements are already in bytes.
- ">>" marks an instruction that loads or sits at an address of interest.
- The pack follows direct literal references only. An address reached by indexed or \
GBR-relative access will look unreferenced. Never conclude "nothing reads this" or \
"nothing writes this" from the pack.
- For each address say what it is and how its value is used. Say what the inputs and \
outputs of the mechanism are. Check for clamps, zero multipliers, flags and constants \
that would make part of it inert in this calibration, and say so with the value.
- Units are ECU-internal: Celsius, km/h, engine load in g/rev.

Evidence classes: "observed" (the code fixes the meaning), "inferred" (a chain with an \
unverified link; name it), "hunch" (consistent, not supported by the code shown). Say \
"unknown" for anything the pack does not show."""

SCHEMA = {
    'type': 'object',
    'properties': {
        'mechanism': {'type': 'string', 'description': 'What the code does with these addresses.'},
        'addresses': {'type': 'array', 'items': {
            'type': 'object',
            'properties': {'address': {'type': 'string'}, 'role': {'type': 'string'},
                           'evidence_class': {'type': 'string',
                                              'enum': ['observed', 'inferred', 'hunch', 'unknown']}},
            'required': ['address', 'role', 'evidence_class'], 'additionalProperties': False}},
        'inert_or_gated': {'type': 'string',
                           'description': 'Anything shown to be inert, clamped or gated, with values. "none found" if none.'},
        'evidence': {'type': 'array', 'items': {'type': 'string'}},
        'not_shown': {'type': 'string', 'description': 'What the pack does not let you determine.'},
    },
    'required': ['mechanism', 'addresses', 'inert_or_gated', 'evidence', 'not_shown'],
    'additionalProperties': False,
}

JUDGE_SYSTEM = """You compare a CLAIM ON RECORD about an engine computer ROM with a BLIND \
ANSWER written from the code by a reader who could not see the claim. You see no code.

The claim is a project note. It mixes statements about the code (what an address is, how \
a value is used, what is inert) with statements about logs, driving, history and advice. \
Only the statements about the code can be tested.

Break the claim into its distinct testable statements about the code and sort each into:
- supported: the blind answer independently says the same thing.
- contradicted: the blind answer says something that cannot both be true. Quote both sides.
- not_addressed: the blind answer does not cover it.
Ignore differences of naming and wording. A blind answer that is vaguer than the claim \
does not contradict it.

Overall grade:
- "agree": the main testable statements are supported and none is contradicted.
- "partly_agree": some supported, none contradicted, the central one not addressed.
- "disagree": at least one testable statement is contradicted.
- "blind_abstained": the blind answer offers nothing to compare.
- "not_comparable": the claim has no testable statement about the code."""

JUDGE_SCHEMA = {
    'type': 'object',
    'properties': {
        'grade': {'type': 'string', 'enum': ['agree', 'partly_agree', 'disagree',
                                             'blind_abstained', 'not_comparable']},
        'supported': {'type': 'array', 'items': {'type': 'string'}},
        'contradicted': {'type': 'array', 'items': {'type': 'string'},
                         'description': 'Each as: claim says X; blind answer says Y.'},
        'not_addressed': {'type': 'array', 'items': {'type': 'string'}},
        'reason': {'type': 'string'},
    },
    'required': ['grade', 'supported', 'contradicted', 'not_addressed', 'reason'],
    'additionalProperties': False,
}


def cited_addresses(text):
    """ROM and RAM addresses in the order they first appear."""
    out = []
    for m in re.finditer(r'0x([0-9A-Fa-f]{4,8})\b|\b(FFFF[0-9A-Fa-f]{4})\b', text):
        v = int(m.group(1) or m.group(2), 16)
        if (0x400 <= v < 0x100000 or 0xFFFF0000 <= v <= 0xFFFFBFFF) and v not in out:
            out.append(v)
    return out


def load_claims():
    claims = []
    for f in sorted(glob.glob(os.path.join(MEMORY_DIR, '*.md'))):
        name = os.path.basename(f)
        if name == 'MEMORY.md':
            continue
        text = open(f, encoding='utf-8', errors='replace').read()
        claims.append(dict(id='mem-' + name[:-3], source='memory', where=name, text=text))
    for f in sorted(glob.glob(os.path.join(REPO, 'docs', '*.md'))):
        name = os.path.basename(f)
        if name in SKIP_DOCS or name.startswith('code_chase'):
            continue
        text = open(f, encoding='utf-8', errors='replace').read()
        for i, sec in enumerate(re.split(r'\n(?=## )', text)):
            title = sec.strip().split('\n')[0].lstrip('# ').strip()[:70]
            claims.append(dict(id='doc-%s-%02d' % (name[:-3], i), source='docs',
                               where='%s :: %s' % (name, title), text=sec))
    return [c for c in claims if len(cited_addresses(c['text'])) >= 2]


class Rom:
    def __init__(self, path):
        self.rom = TT.load_rom(path)
        self.occ, self.pcref = TT.build_indexes(self.rom)
        self.by_data, self.by_axis = TT.definition_index()
        self.desc = {}                       # descriptor -> (data, axes)
        self.data_to_desc = {}
        for a in TT.descriptor_candidates():
            try:
                two = T.is_2d(self.rom, a)
                off = T._OFF['2D' if two else '1D']
                data = struct.unpack_from('>I', self.rom, a + off['data'])[0]
                axes = ([struct.unpack_from('>I', self.rom, a + off[k])[0] for k in ('yaxis', 'xaxis')]
                        if two else [struct.unpack_from('>I', self.rom, a + off['axis'])[0]])
                T.read_table(self.rom, a)
            except Exception:
                continue
            self.desc[a] = (data, axes)
            self.data_to_desc.setdefault(data, a)
        self.labels = dict(A.grounded_labels())
        for a, (data, axes) in self.desc.items():
            if data in self.by_data:
                self.labels[a] = ('descriptor of table "%s"' % self.by_data[data], 'DEFINITION')
        for a, n in self.by_data.items():
            self.labels.setdefault(a, ('table "%s"' % n, 'DEFINITION'))
        for a, n in self.by_axis.items():
            self.labels.setdefault(a, ('axis "%s"' % n, 'DEFINITION'))

    def sites(self, v):
        return [c for s in self.occ.get(v, []) for c in self.pcref.get(s, [])]

    def describe(self, v):
        rom = self.rom
        name = ('  name: %s [%s]' % self.labels[v]) if v in self.labels else ''
        if v >= 0xFFFF0000:
            return 'RAM. %d direct literal reference(s).%s' % (len(self.sites(v)), name)
        if v in self.desc or v in self.data_to_desc:
            d = v if v in self.desc else self.data_to_desc[v]
            kind = 'table descriptor' if v in self.desc else 'table data (descriptor 0x%05X)' % d
            return '%s.%s\n%s' % (kind, name, '\n'.join('    ' + ln for ln in
                                                       B.table_text(rom, d).split('\n')[:22]))
        if v < 0xA0000:
            s, e, whole = B.function_bounds(rom, v + 2 if B._is_push(B._word(rom, v)) else v)
            return 'code, in the listing 0x%06X-0x%06X.' % (s, e)
        f = struct.unpack_from('>f', rom, v & ~3)[0] if v + 4 <= len(rom) else float('nan')
        return ('calibration data.%s  As float32: %s. As uint16: %d. As uint8: %d. '
                '%d direct literal reference(s).' % (
                    name, B.fmt(f) if abs(f) < 1e7 and f == f else 'not a plausible float',
                    struct.unpack_from('>H', rom, v & ~1)[0], rom[v], len(self.sites(v))))

    def functions_for(self, addrs):
        """{(start, end): set(cited addresses it touches)}"""
        funcs = collections.defaultdict(set)
        for v in addrs:
            refs = list(self.sites(v))
            if v in self.data_to_desc:
                refs += self.sites(self.data_to_desc[v])
            if 0x400 <= v < 0xA0000 and not v & 1:
                refs.append(v + 2 if B._is_push(B._word(self.rom, v)) else v)
            for s in refs[:40]:
                st, en, _ = B.function_bounds(self.rom, s)
                funcs[(st, en)].add(v)
        return funcs

    def marks(self, start, end, addrs):
        want = set(addrs) | {self.data_to_desc[v] for v in addrs if v in self.data_to_desc}
        out = set()
        for pc in range(start, end, 2):
            w = B._word(self.rom, pc)
            if pc in want:
                out.add(pc)
            if (w >> 12) == 0xD:
                t = (pc & ~3) + 4 + (w & 0xFF) * 4
                if t + 4 <= len(self.rom) and struct.unpack_from('>I', self.rom, t)[0] in want:
                    out.add(pc)
        return out

    def pack(self, addrs):
        addrs = addrs[:MAX_ADDRS]
        parts = ['ADDRESSES OF INTEREST']
        for v in addrs:
            parts.append('- 0x%0*X: %s' % (8 if v >= 0xFFFF0000 else 6, v, self.describe(v)))
        funcs = self.functions_for(addrs)
        ranked = sorted(funcs.items(), key=lambda kv: (-len(kv[1]), kv[0][1] - kv[0][0]))
        size, shown = sum(len(p) for p in parts), 0
        for (st, en), touched in ranked:
            if shown == MAX_FUNCS:
                break
            text = B.listing(self.rom, st, en, self.marks(st, en, addrs), self.labels, None)
            if shown and size + len(text) > MAX_CHARS:
                continue
            parts += ['', 'FUNCTION 0x%06X-0x%06X (touches %d of the addresses)'
                      % (st, en, len(touched)), text]
            size, shown = size + len(text), shown + 1
        if len(ranked) > shown:
            parts.append('\n(%d further functions reference these addresses and are not shown)'
                         % (len(ranked) - shown))
        if not ranked:
            parts.append('\nNo function with a direct literal reference to any of these was found.')
        parts += ['', 'Describe the mechanism these addresses take part in. Answer in the required JSON.']
        return '\n'.join(parts), shown


def cmd_prepare(args):
    R = Rom(args.rom)
    print('ROM      : %s' % os.path.basename(args.rom))
    claims = load_claims()
    if args.only:
        claims = [c for c in claims if any(k in c['id'] for k in args.only)]
    if args.limit:
        step = max(1, len(claims) // args.limit)
        claims = claims[::step][:args.limit]          # spread across memory and docs
    os.makedirs(OUT_DIR, exist_ok=True)
    chars, nofunc = 0, 0
    with open(REQUESTS, 'w', encoding='utf-8', newline='\n') as fh:
        for c in claims:
            addrs = cited_addresses(c['text'])
            prompt, shown = R.pack(addrs)
            nofunc += not shown
            chars += len(prompt) + len(SYSTEM)
            fh.write(json.dumps(dict(custom_id=c['id'][:60], source=c['source'], where=c['where'],
                                     claim=c['text'][:7000], n_addrs=len(addrs),
                                     n_funcs=shown, prompt=prompt)) + '\n')
    n = len(claims)
    tok_in, tok_out = int(chars / B.CHARS_PER_TOKEN), 3500 * n
    blind = (tok_in * B.PRICE_IN + tok_out * B.PRICE_OUT) / 1e6 * B.BATCH_DISCOUNT
    judge = n * (4000 * B.PRICE_IN + 1500 * B.PRICE_OUT) / 1e6 * B.BATCH_DISCOUNT
    by = collections.Counter(c['source'] for c in claims)
    print('claims   : %d  (%s); %d have no function in their pack'
          % (n, ', '.join('%d %s' % (v, k) for k, v in by.items()), nofunc))
    print('wrote    : %s' % os.path.relpath(REQUESTS, REPO))
    print('ESTIMATE : blind pass about $%.2f, grading about $%.2f  (input measured from the pack'
          % (blind, judge))
    print('           sizes; output and grading are guesses until a trial reports)')
    print('next     : `submit`')


def load_items():
    if not os.path.exists(REQUESTS):
        sys.exit('run `prepare` first')
    return [json.loads(line) for line in open(REQUESTS, encoding='utf-8')]


def state(update=None):
    s = json.load(open(STATE, encoding='utf-8')) if os.path.exists(STATE) else {}
    if update is not None:
        s.update(update)
        with open(STATE, 'w', encoding='utf-8', newline='\n') as fh:
            json.dump(s, fh, indent=1)
    return s


def cost(tin, tout):
    return (tin * B.PRICE_IN + tout * B.PRICE_OUT) / 1e6 * B.BATCH_DISCOUNT


def cmd_submit(args):
    import anthropic
    if state().get('blind_batch') and not args.force:
        sys.exit('a blind batch is already recorded -- run `collect`, or pass --force')
    items = load_items()
    A._confirm(args, 'Submit %d blind requests to %s at effort %s?' % (len(items), B.MODEL, args.effort))
    batch = A._batch(anthropic.Anthropic(),
                     [(it['custom_id'], SYSTEM, SCHEMA, it['prompt']) for it in items], args.effort)
    if os.path.exists(STATE):
        os.remove(STATE)
    state({'blind_batch': batch.id, 'submitted': time.strftime('%Y-%m-%d %H:%M:%S'),
           'model': B.MODEL, 'effort': args.effort, 'count': len(items)})
    print('submitted blind batch %s (%d requests)\nnext: `collect --wait`' % (batch.id, len(items)))


def cmd_collect(args):
    import anthropic
    st = state()
    if not st.get('blind_batch'):
        sys.exit('run `submit` first')
    if st.get('judge_batch') and not args.force:
        sys.exit('grading already submitted -- run `report`, or pass --force')
    client = anthropic.Anthropic()
    ok, bad, tin, tout = A._results(client, st['blind_batch'], args.wait)
    with open(ANSWERS, 'w', encoding='utf-8', newline='\n') as fh:
        json.dump({'answers': ok, 'failed': bad}, fh, indent=1)
    print('%d blind answers, %d failed; %s input and %s output tokens (at most $%.2f)'
          % (len(ok), len(bad), format(tin, ','), format(tout, ','), cost(tin, tout)))
    items = {it['custom_id']: it for it in load_items()}
    A._confirm(args, 'Send %d answers for grading?' % len(ok))
    entries = [(cid, JUDGE_SYSTEM, JUDGE_SCHEMA, 'CLAIM ON RECORD (%s)\n%s\n\nBLIND ANSWER\n%s' % (
        items[cid]['where'], items[cid]['claim'],
        json.dumps({k: v for k, v in ans.items() if k != 'evidence'}, indent=1)))
        for cid, ans in ok.items()]
    batch = A._batch(client, entries, 'high')
    state({'judge_batch': batch.id, 'blind_tokens': [tin, tout]})
    print('submitted grading batch %s\nnext: `report --wait`' % batch.id)


FALLBACK_BETA = 'server-side-fallback-2026-07-01'
RETRY_GRADES = os.path.join(OUT_DIR, 'grades_retry.json')


def _one(client, system, schema, user, effort):
    """One non-batch request with the server-side refusal fallback.

    The Batches API rejects `fallbacks`, which is why declined items are retried
    here one at a time and at full price. Returns (parsed json or None, note, usage).
    """
    with client.beta.messages.stream(
            model=B.MODEL, max_tokens=B.MAX_TOKENS,
            betas=[FALLBACK_BETA], fallbacks='default',
            system=[{'type': 'text', 'text': system, 'cache_control': {'type': 'ephemeral'}}],
            output_config={'effort': effort, 'format': {'type': 'json_schema', 'schema': schema}},
            messages=[{'role': 'user', 'content': user}]) as stream:
        msg = stream.get_final_message()
    use = (msg.usage.input_tokens + (msg.usage.cache_read_input_tokens or 0)
           + (msg.usage.cache_creation_input_tokens or 0), msg.usage.output_tokens)
    if msg.stop_reason != 'end_turn':
        why = msg.stop_reason
        if msg.stop_reason == 'refusal' and msg.stop_details:
            why += ' (%s)' % msg.stop_details.category
        return None, 'stopped: %s, even with fallback' % why, use
    try:
        return json.loads(next(b.text for b in msg.content if b.type == 'text')), msg.model, use
    except (ValueError, StopIteration):
        return None, 'reply was not valid JSON', use


def cmd_retry(args):
    """Re-send the items the batch declined, one at a time, with the fallback model allowed."""
    import anthropic
    if not os.path.exists(ANSWERS):
        sys.exit('run `collect` first')
    blind = json.load(open(ANSWERS, encoding='utf-8'))
    items = {it['custom_id']: it for it in load_items()}
    todo = [cid for cid in blind['failed'] if cid in items]
    if not todo:
        sys.exit('nothing to retry')
    # Not batch price, and a declined request runs on the fallback model's own rates.
    tok = sum((len(items[c]['prompt']) + len(SYSTEM)) / B.CHARS_PER_TOKEN for c in todo)
    est = (tok * 5.0 + len(todo) * (4500 * 25.0 + 4000 * 5.0 + 1500 * 25.0)) / 1e6
    A._confirm(args, 'Retry %d declined claims one at a time, with the fallback model allowed? '
                     'Estimated $%.2f at full (non-batch) price.' % (len(todo), est))
    client = anthropic.Anthropic()
    extra = json.load(open(RETRY_GRADES, encoding='utf-8')) if os.path.exists(RETRY_GRADES) else {}
    tin = tout = 0
    for n, cid in enumerate(todo, 1):
        it = items[cid]
        try:
            ans, note, use = _one(client, SYSTEM, SCHEMA, it['prompt'], 'high')
            tin, tout = tin + use[0], tout + use[1]
            if ans is None:
                blind['failed'][cid] = note
                print('[%d/%d] %s: %s' % (n, len(todo), it['where'][:55], note))
                continue
            grade, gnote, use = _one(
                client, JUDGE_SYSTEM, JUDGE_SCHEMA,
                'CLAIM ON RECORD (%s)\n%s\n\nBLIND ANSWER\n%s' % (
                    it['where'], it['claim'],
                    json.dumps({k: v for k, v in ans.items() if k != 'evidence'}, indent=1)), 'high')
            tin, tout = tin + use[0], tout + use[1]
        except anthropic.APIError as e:
            print('[%d/%d] %s: API error, left as failed (%s)' % (n, len(todo), it['where'][:55], e))
            continue
        blind['answers'][cid] = ans
        del blind['failed'][cid]
        if grade is None:
            blind['failed'][cid] = 'grading ' + gnote
        else:
            extra[cid] = grade
        print('[%d/%d] %s: answered by %s, %s' % (
            n, len(todo), it['where'][:55], note,
            grade['grade'] if grade else 'grading failed'))
        with open(ANSWERS, 'w', encoding='utf-8', newline='\n') as fh:
            json.dump(blind, fh, indent=1)
        with open(RETRY_GRADES, 'w', encoding='utf-8', newline='\n') as fh:
            json.dump(extra, fh, indent=1)
    with open(ANSWERS, 'w', encoding='utf-8', newline='\n') as fh:
        json.dump(blind, fh, indent=1)
    print('%s input and %s output tokens; roughly $%.2f if all of it ran on the fallback model'
          % (format(tin, ','), format(tout, ','), (tin * 5.0 + tout * 25.0) / 1e6))
    print('next: `report`')


def cmd_report(args):
    import anthropic
    st = state()
    if not st.get('judge_batch'):
        sys.exit('run `collect` first')
    grades, bad, tin, tout = A._results(anthropic.Anthropic(), st['judge_batch'], args.wait)
    if os.path.exists(RETRY_GRADES):
        grades.update(json.load(open(RETRY_GRADES, encoding='utf-8')))
    blind = json.load(open(ANSWERS, encoding='utf-8'))
    items = load_items()
    order = ['agree', 'partly_agree', 'disagree', 'blind_abstained', 'not_comparable']
    L = ['# Blind audit of tuning conclusions', '',
         '> Memory notes and subsystem-doc sections, re-derived from ROM bytes by a reader that',
         '> could not see them, then compared statement by statement. **A contradiction means one',
         '> side is wrong, not which.** Decode it by hand before changing a doc or a tune.',
         '> Batches %s (blind) and %s (grading), model %s, %s.'
         % (st['blind_batch'], st['judge_batch'], st['model'], st['submitted']),
         '', '## By source', '',
         '| Source | Claims | ' + ' | '.join(order) + ' | no answer |', '|---|---|' + '---|' * 6]
    for src in ('memory', 'docs'):
        its = [it for it in items if it['source'] == src]
        c = collections.Counter(grades[it['custom_id']]['grade'] for it in its
                                if it['custom_id'] in grades)
        L.append('| %s | %d | %s | %d |' % (src, len(its), ' | '.join(str(c[o]) for o in order),
                                            len(its) - sum(c.values())))
    tot = collections.Counter()
    for g in grades.values():
        tot['supported'] += len(g['supported'])
        tot['contradicted'] += len(g['contradicted'])
        tot['not_addressed'] += len(g['not_addressed'])
    L += ['', 'Individual statements: %d supported, **%d contradicted**, %d not addressed.'
          % (tot['supported'], tot['contradicted'], tot['not_addressed']),
          '', '## Contradictions', '']
    graded = [it for it in items if it['custom_id'] in grades]
    graded.sort(key=lambda it: (-len(grades[it['custom_id']]['contradicted']), it['custom_id']))
    for it in graded:
        g = grades[it['custom_id']]
        if not g['contradicted']:
            continue
        L += ['### %s' % it['where'], '']
        L += ['- **Contradicted:** %s' % s for s in g['contradicted']]
        L += ['- Supported: %d statement(s). Not addressed: %d.' % (len(g['supported']),
                                                                     len(g['not_addressed'])),
              '- Blind mechanism: %s' % blind['answers'][it['custom_id']]['mechanism'][:900],
              '- Inert or gated: %s' % blind['answers'][it['custom_id']]['inert_or_gated'][:500], '']
    L += ['## Everything else', '', '| Claim | Grade | Supported | Not addressed | Functions shown |',
          '|---|---|---|---|---|']
    for it in graded:
        g = grades[it['custom_id']]
        if not g['contradicted']:
            L.append('| %s | %s | %d | %d | %d |' % (it['where'].replace('|', '/'), g['grade'],
                                                     len(g['supported']), len(g['not_addressed']),
                                                     it['n_funcs']))
    failed = dict(blind['failed'])
    failed.update({k: 'grading ' + v for k, v in bad.items()})
    if failed:
        L += ['', '## No answer', ''] + ['- %s: %s' % kv for kv in sorted(failed.items())]
    with open(REPORT, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join(L) + '\n')
    print('graded %d; grading used %s input and %s output tokens (at most $%.2f)'
          % (len(grades), format(tin, ','), format(tout, ','), cost(tin, tout)))
    print('wrote: %s' % os.path.relpath(REPORT, REPO))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('prepare', help='build the evidence packs (no spend)')
    p.add_argument('--rom', default=TT.DEFAULT_ROM)
    p.add_argument('--limit', type=int, help='only N claims, spread across the set')
    p.add_argument('--only', nargs='+', help='only claims whose id contains one of these')
    p.set_defaults(fn=cmd_prepare)
    p = sub.add_parser('submit', help='send the blind requests (SPENDS)')
    p.add_argument('--effort', default='high', choices=['low', 'medium', 'high', 'xhigh', 'max'])
    p.add_argument('--yes', action='store_true')
    p.add_argument('--force', action='store_true')
    p.set_defaults(fn=cmd_submit)
    p = sub.add_parser('collect', help='fetch blind answers and send them for grading (SPENDS)')
    p.add_argument('--wait', action='store_true')
    p.add_argument('--yes', action='store_true')
    p.add_argument('--force', action='store_true')
    p.set_defaults(fn=cmd_collect)
    p = sub.add_parser('retry', help='re-send declined claims one at a time with the fallback '
                                     'model allowed (SPENDS, full price)')
    p.add_argument('--yes', action='store_true')
    p.set_defaults(fn=cmd_retry)
    p = sub.add_parser('report', help='fetch the grades and write the report')
    p.add_argument('--wait', action='store_true')
    p.set_defaults(fn=cmd_report)
    args = ap.parse_args()
    args.fn(args)


if __name__ == '__main__':
    main()
