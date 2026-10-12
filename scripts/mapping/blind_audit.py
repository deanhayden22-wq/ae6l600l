"""Blind audit: re-derive a random sample of SETTLED claims from bytes, then compare.

    python scripts/mapping/blind_audit.py prepare            # pick the sample, build requests (no spend)
    python scripts/mapping/blind_audit.py submit             # send the blind requests (SPENDS)
    python scripts/mapping/blind_audit.py collect            # fetch blind answers, send them for grading (SPENDS)
    python scripts/mapping/blind_audit.py report             # fetch the grades, write the report

WHAT THIS MEASURES
Three groups, 30 of each by default, drawn with a fixed seed:

  named_table        a table the definition XMLs name. The name and axis names are
                     HIDDEN. Mostly community ground truth, so this group measures
                     how good the blind reader is -- the calibration for the others.
  traced_function    a function whose Ghidra label is tagged [TRACED]. The label is
                     HIDDEN. Tests this project's own past naming.
  unverified_function  the same, for labels tagged [UNVERIFIED] -- where the name is
                     the only artefact.

A second request then grades each blind answer against the claim on record. The
grader sees no code, only the two descriptions.

HOW TO READ THE RESULT
Agreement is weak evidence the claim is right. Disagreement means ONE side is
wrong and says nothing about which: every disagreement is a decode-by-hand item.
The named_table agreement rate is the ceiling to read the other two against.
Nothing here edits a label, a definition or corrections.md.
"""
import argparse
import collections
import json
import os
import random
import re
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, HERE)
import defs                          # noqa: E402
import desc_types as T               # noqa: E402
import table_triage as TT            # noqa: E402
import table_batch_hypotheses as B   # noqa: E402

REPO = TT.REPO
OUT_DIR = os.path.join(REPO, 'docs', 'exploration', 'blind_audit')
REQUESTS = os.path.join(OUT_DIR, 'requests.jsonl')
ANSWERS = os.path.join(OUT_DIR, 'answers.json')
STATE = os.path.join(OUT_DIR, 'state.json')
REPORT = os.path.join(OUT_DIR, 'report.md')

GROUPS = ['named_table', 'traced_function', 'unverified_function']

FUNC_SYSTEM = """You are helping reverse-engineer a 2013 Subaru WRX engine computer ROM \
(AE5L600L, Renesas SH7058, an SH-2E core: SH-2 integer instructions plus a \
single-precision FPU, big-endian).

Each request shows ONE function. Say what it does, from the code, and be exact about \
how strong the evidence is.

- Most addresses in the listing carry no name on purpose. The few that do are either \
RAM variables whose identity was cross-checked against the definition files \
([VERIFIED-BOTH]) or shared maths and table-lookup helpers ([TRACED]). Reason from what \
the code does.
- The function's bounds were found by a heuristic, so the listing can stop early or run \
into a neighbour. Literal pools sit inside it; data decoded as instructions looks like \
nonsense and must be ignored.
- Displacements are already in bytes.
- Describe the mechanism first (what is read, computed, compared, stored), then the \
most likely purpose. If the purpose cannot be told from the code, say "unknown" and \
describe the mechanism only.

Evidence classes: "observed" (the code fixes the meaning), "inferred" (a chain with an \
unverified link; name it), "hunch" (consistent, not supported by the code shown)."""

FUNC_SCHEMA = {
    'type': 'object',
    'properties': {
        'proposed_name': {'type': 'string'},
        'mechanism': {'type': 'string', 'description': 'What the code reads, computes and stores.'},
        'purpose': {'type': 'string', 'description': 'Most likely purpose, or "unknown".'},
        'evidence_class': {'type': 'string', 'enum': ['observed', 'inferred', 'hunch', 'unknown']},
        'evidence': {'type': 'array', 'items': {'type': 'string'}},
        'weakest_link': {'type': 'string'},
    },
    'required': ['proposed_name', 'mechanism', 'purpose', 'evidence_class', 'evidence',
                 'weakest_link'],
    'additionalProperties': False,
}

JUDGE_SYSTEM = """You compare two descriptions of the same item in an engine computer ROM \
and grade whether they agree. You see no code. One description is the CLAIM ON RECORD \
(a definition-file table name, or a project label and its comment). The other is a BLIND \
ANSWER written from the code by a reader who could not see the claim.

Grade on substance, not wording. Different names for the same thing agree.

- "agree": same quantity or function, same role.
- "partly_agree": right subsystem or right mechanism, but the specific identity differs \
or the blind answer is vaguer than the claim.
- "disagree": they describe different things, or the blind answer contradicts a specific \
statement in the claim.
- "blind_abstained": the blind answer says unknown and offers nothing to compare.
- "not_comparable": the claim on record is too thin or too generic to test.

For a table, compare what the table is, what its axes are and what its output is. A \
blind answer that gets the mechanism right but cannot name the purpose is partly_agree."""

JUDGE_SCHEMA = {
    'type': 'object',
    'properties': {
        'grade': {'type': 'string', 'enum': ['agree', 'partly_agree', 'disagree',
                                             'blind_abstained', 'not_comparable']},
        'reason': {'type': 'string', 'description': 'One or two sentences.'},
        'point_of_difference': {'type': 'string',
                                'description': 'The specific statement they differ on, or "none".'},
    },
    'required': ['grade', 'reason', 'point_of_difference'],
    'additionalProperties': False,
}


def label_comments():
    """address -> full comment text from the Ghidra import script."""
    src = open(TT.JAVA, encoding='utf-8', errors='replace').read()
    out = {}
    pat = r'labelComment\((0x[0-9A-Fa-f]+)L?,\s*"[^"]+",\s*((?:"(?:[^"\\]|\\.)*"\s*\+?\s*)+)\)'
    for m in re.finditer(pat, src):
        text = ''.join(re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(2)))
        out[int(m.group(1), 16)] = text
    return out


def named_tables(rom):
    occ, pcref = TT.build_indexes(rom)
    by_data, _ = TT.definition_index()
    d = defs.load()
    out = []
    for a in TT.descriptor_candidates():
        try:
            two = T.is_2d(rom, a)
            off = T._OFF['2D' if two else '1D']
            data = struct.unpack_from('>I', rom, a + off['data'])[0]
            axes = ([struct.unpack_from('>I', rom, a + off['yaxis'])[0],
                     struct.unpack_from('>I', rom, a + off['xaxis'])[0]] if two else
                    [struct.unpack_from('>I', rom, a + off['axis'])[0]])
            tab = T.read_table(rom, a)
        except Exception:
            continue
        if data not in by_data:
            continue
        sites = [c for s in occ.get(a, []) for c in pcref.get(s, [])]
        if not sites:
            continue
        t = d.get(by_data[data])
        vals = ([v for r in tab['values'] for v in r] if two else list(tab['values']))
        row = dict(desc='0x%05X' % a, dim=tab['dim'], type=tab['type_name'],
                   shape=('%dx%d' % (len(tab['values']), len(tab['values'][0]))) if two
                   else 'x%d' % len(tab['values']),
                   scale=tab['scale'], bias=tab['bias'], data='0x%05X' % data,
                   lo=round(min(vals), 5), hi=round(max(vals), 5),
                   axes=['0x%05X' % x for x in axes], axis_names=[None] * len(axes),
                   sites=['0x%05X' % s for s in sites], ram=[], subsystem='', matched_by='')
        claim = 'Definition-file table "%s"' % t.name
        if getattr(t, 'category', None):
            claim += ', category "%s"' % t.category
        ax = ['%s' % (x.name or 'unnamed') for x in (t.axes or [])]
        if ax:
            claim += '. Axes: ' + '; '.join(ax)
        units = getattr(getattr(t, 'scaling', None), 'units', None)
        if units:
            claim += '. Output units: %s' % units
        if getattr(t, 'description', None):
            claim += '. Description: %s' % t.description
        out.append((a, row, claim))
    return out


def function_labels(rom, tag):
    labels = B.tagged_labels()
    comments = label_comments()
    out = []
    for a, (name, t) in labels.items():
        if t != tag or not (0x400 <= a < 0xA0000):
            continue
        if not (B._is_push(B._word(rom, a)) and not B._is_push(B._word(rom, a - 2))):
            continue                        # only labels that sit on a function entry
        out.append((a, name, 'Project label "%s" [%s]. Comment: %s'
                    % (name, tag, comments.get(a, '(none)'))))
    return out


def grounded_labels():
    """The only names a blind reader is allowed to see.

    A project label on a neighbouring RAM variable or callee leaks the subsystem
    and inflates agreement, so everything is stripped except names grounded
    outside this project's own labelling:
      * RAM variables flagged VERIFIED-BOTH in docs/verification-status.json
        (identity tied to a definition-file axis name), and
      * the shared maths / table-lookup helpers at 0xBE000-0xBEFFF tagged [TRACED].
    """
    keep = {}
    status = json.load(open(os.path.join(REPO, 'docs', 'verification-status.json'),
                            encoding='utf-8'))
    for e in status['entities']:
        if e.get('kind') == 'ram' and e.get('flag') == 'VERIFIED-BOTH':
            keep[int(e['address'], 16)] = (e['name'], 'VERIFIED-BOTH')
    for a, (name, tag) in B.tagged_labels().items():
        if 0xBE000 <= a < 0xBF000 and tag == 'TRACED':
            keep[a] = (name, tag)
    return keep


def cmd_prepare(args):
    rom = TT.load_rom(args.rom)
    labels = B.tagged_labels() if args.all_labels else grounded_labels()
    print('ROM      : %s' % os.path.basename(args.rom))
    print('labels shown to the blind reader: %d%s' % (
        len(labels), ' (ALL project labels -- agreement will be inflated)' if args.all_labels
        else ' (verified RAM identities and shared helpers only)'))
    rng = random.Random(args.seed)
    os.makedirs(OUT_DIR, exist_ok=True)
    items = []
    done = set()
    for path in args.exclude or []:
        done |= {json.loads(line)['custom_id'] for line in open(path, encoding='utf-8')}
    if done:
        print('excluding %d items already audited' % len(done))

    pool = [p for p in named_tables(rom) if 'tab-%05X' % p[0] not in done] \
        if 'named_table' in args.groups else []
    for a, row, claim in rng.sample(pool, min(args.n, len(pool))):
        prompt = B.build_prompt(rom, row, labels).replace(
            'triage hints (NOT evidence): subsystem "unassigned" matched by nothing; '
            'nearby RAM names: none\n', '')
        items.append(dict(custom_id='tab-%05X' % a, group='named_table', addr='0x%05X' % a,
                          claim=claim, prompt=prompt))

    for tag, group in (('TRACED', 'traced_function'), ('UNVERIFIED', 'unverified_function')):
        pool = [p for p in function_labels(rom, tag) if 'fn-%05X' % p[0] not in done] \
            if group in args.groups else []
        for a, name, claim in rng.sample(pool, min(args.n, len(pool))):
            start, end, _ = B.function_bounds(rom, a + 2)
            hidden = {k: v for k, v in labels.items() if k != a}
            prompt = ('FUNCTION at 0x%06X (listing 0x%06X-0x%06X)\n%s\n\nWhat does this '
                      'function do? Answer in the required JSON.'
                      % (a, start, end, B.listing(rom, start, end, set(), hidden, None)))
            items.append(dict(custom_id='fn-%05X' % a, group=group, addr='0x%05X' % a,
                              claim=claim, prompt=prompt))

    with open(REQUESTS, 'w', encoding='utf-8', newline='\n') as fh:
        for it in items:
            fh.write(json.dumps(it) + '\n')
    counts = collections.Counter(it['group'] for it in items)
    chars = sum(len(it['prompt']) + len(B.SYSTEM) for it in items)
    tok_in = int(chars / B.CHARS_PER_TOKEN)
    tok_out = 2300 * len(items)             # measured ~2,230 per table on the full run
    blind = (tok_in * B.PRICE_IN + tok_out * B.PRICE_OUT) / 1e6 * B.BATCH_DISCOUNT
    judge = len(items) * (1500 * B.PRICE_IN + 600 * B.PRICE_OUT) / 1e6 * B.BATCH_DISCOUNT
    print('sample   : %s  (seed %d)' % (', '.join('%d %s' % (v, k) for k, v in counts.items()),
                                        args.seed))
    print('wrote    : %s' % os.path.relpath(REQUESTS, REPO))
    print('ESTIMATE : blind pass about $%.2f, grading pass about $%.2f (both inferred from the'
          % (blind, judge))
    print('           table run\'s measured rates; the grading figure is a guess)')
    print('next     : `submit`')


def load_items():
    if not os.path.exists(REQUESTS):
        sys.exit('run `prepare` first')
    return [json.loads(line) for line in open(REQUESTS, encoding='utf-8')]


def _batch(client, entries, effort):
    """entries: (custom_id, system text, schema, user text)."""
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request
    return client.messages.batches.create(requests=[
        Request(custom_id=cid, params=MessageCreateParamsNonStreaming(
            model=B.MODEL, max_tokens=B.MAX_TOKENS,
            system=[{'type': 'text', 'text': system, 'cache_control': {'type': 'ephemeral'}}],
            output_config={'effort': effort, 'format': {'type': 'json_schema', 'schema': schema}},
            messages=[{'role': 'user', 'content': user}]))
        for cid, system, schema, user in entries])


def _results(client, batch_id, wait):
    """Returns ({custom_id: parsed json}, {custom_id: failure reason}, tokens in, tokens out)."""
    while True:
        b = client.messages.batches.retrieve(batch_id)
        c = b.request_counts
        print('status %s: %d processing, %d succeeded, %d errored'
              % (b.processing_status, c.processing, c.succeeded, c.errored))
        if b.processing_status == 'ended':
            break
        if not wait:
            sys.exit('not finished yet -- run this again later, or add --wait')
        time.sleep(60)
    ok, bad, tin, tout = {}, {}, 0, 0
    for res in client.messages.batches.results(batch_id):
        if res.result.type != 'succeeded':
            bad[res.custom_id] = res.result.type
            continue
        msg = res.result.message
        tin += (msg.usage.input_tokens + (msg.usage.cache_read_input_tokens or 0)
                + (msg.usage.cache_creation_input_tokens or 0))
        tout += msg.usage.output_tokens
        if msg.stop_reason != 'end_turn':
            why = msg.stop_reason
            if msg.stop_reason == 'refusal' and msg.stop_details:
                why += ' (%s)' % msg.stop_details.category
            bad[res.custom_id] = 'stopped: %s' % why
            continue
        try:
            ok[res.custom_id] = json.loads(next(b.text for b in msg.content if b.type == 'text'))
        except (ValueError, StopIteration):
            bad[res.custom_id] = 'reply was not valid JSON'
    return ok, bad, tin, tout


def _state(update=None):
    s = json.load(open(STATE, encoding='utf-8')) if os.path.exists(STATE) else {}
    if update:
        s.update(update)
        with open(STATE, 'w', encoding='utf-8', newline='\n') as fh:
            json.dump(s, fh, indent=1)
    return s


def _confirm(args, what):
    if not args.yes and input('%s This spends API credit. [y/N] ' % what).strip().lower() != 'y':
        sys.exit('not submitted')


def cmd_submit(args):
    import anthropic
    if _state().get('blind_batch') and not args.force:
        sys.exit('a blind batch is already recorded -- run `collect`, or pass --force')
    items = load_items()
    _confirm(args, 'Submit %d blind requests to %s at effort %s?' % (len(items), B.MODEL, args.effort))
    entries = [(it['custom_id'],
                B.SYSTEM if it['group'] == 'named_table' else FUNC_SYSTEM,
                B.SCHEMA if it['group'] == 'named_table' else FUNC_SCHEMA,
                it['prompt']) for it in items]
    batch = _batch(anthropic.Anthropic(), entries, args.effort)
    if os.path.exists(STATE):
        os.remove(STATE)
    _state({'blind_batch': batch.id, 'submitted': time.strftime('%Y-%m-%d %H:%M:%S'),
            'model': B.MODEL, 'effort': args.effort, 'count': len(items)})
    print('submitted blind batch %s (%d requests)\nnext: `collect --wait`' % (batch.id, len(items)))


def cmd_collect(args):
    import anthropic
    st = _state()
    if not st.get('blind_batch'):
        sys.exit('run `submit` first')
    if st.get('judge_batch') and not args.force:
        sys.exit('grading already submitted -- run `report`, or pass --force')
    client = anthropic.Anthropic()
    ok, bad, tin, tout = _results(client, st['blind_batch'], args.wait)
    with open(ANSWERS, 'w', encoding='utf-8', newline='\n') as fh:
        json.dump({'answers': ok, 'failed': bad}, fh, indent=1)
    print('%d blind answers, %d failed; %s input and %s output tokens (at most $%.2f)'
          % (len(ok), len(bad), format(tin, ','), format(tout, ','),
             (tin * B.PRICE_IN + tout * B.PRICE_OUT) / 1e6 * B.BATCH_DISCOUNT))
    items = {it['custom_id']: it for it in load_items()}
    _confirm(args, 'Send %d answers for grading?' % len(ok))
    entries = []
    for cid, ans in ok.items():
        blind = {k: v for k, v in ans.items() if k not in ('evidence', 'next_step')}
        entries.append((cid, JUDGE_SYSTEM, JUDGE_SCHEMA,
                        'CLAIM ON RECORD\n%s\n\nBLIND ANSWER\n%s'
                        % (items[cid]['claim'], json.dumps(blind, indent=1))))
    batch = _batch(client, entries, 'medium')
    _state({'judge_batch': batch.id, 'blind_tokens': [tin, tout]})
    print('submitted grading batch %s\nnext: `report --wait`' % batch.id)


def cmd_report(args):
    import anthropic
    st = _state()
    if not st.get('judge_batch'):
        sys.exit('run `collect` first')
    grades, bad, tin, tout = _results(anthropic.Anthropic(), st['judge_batch'], args.wait)
    blind = json.load(open(ANSWERS, encoding='utf-8'))
    items = load_items()
    order = ['agree', 'partly_agree', 'disagree', 'blind_abstained', 'not_comparable']
    groups = ['named_table', 'traced_function', 'unverified_function']
    L = ['# Blind audit of settled claims', '',
         '> A sample of claims this project treats as settled, re-derived from bytes by a reader',
         '> that could not see the claim, then graded against it. **Agreement is weak evidence;',
         '> disagreement means one side is wrong, not which.** Every disagreement below is a',
         '> decode-by-hand item. Batches %s (blind) and %s (grading), model %s, %s.'
         % (st['blind_batch'], st['judge_batch'], st['model'], st['submitted']),
         '', '## Agreement by group', '',
         '| Group | Sampled | ' + ' | '.join(order) + ' | no answer |', '|---|---|' + '---|' * 6]
    for g in groups:
        its = [it for it in items if it['group'] == g]
        c = collections.Counter(grades[it['custom_id']]['grade'] for it in its
                                if it['custom_id'] in grades)
        L.append('| %s | %d | %s | %d |' % (g, len(its), ' | '.join(str(c[o]) for o in order),
                                            len(its) - sum(c.values())))
    L += ['', '## How the blind reader\'s own confidence held up (named tables only)', '',
          '| Blind evidence class | ' + ' | '.join(order) + ' |', '|---|' + '---|' * 5]
    cal = collections.defaultdict(collections.Counter)
    for it in items:
        cid = it['custom_id']
        if it['group'] == 'named_table' and cid in grades and cid in blind['answers']:
            cal[blind['answers'][cid]['evidence_class']][grades[cid]['grade']] += 1
    for cls in ('observed', 'inferred', 'hunch', 'unknown'):
        if cls in cal:
            L.append('| %s | %s |' % (cls, ' | '.join(str(cal[cls][o]) for o in order)))
    for g in groups:
        L += ['', '## %s' % g, '']
        its = [it for it in items if it['group'] == g and it['custom_id'] in grades]
        its.sort(key=lambda it: order.index(grades[it['custom_id']]['grade']) if
                 grades[it['custom_id']]['grade'] != 'disagree' else -1)
        for it in its:
            cid, gr, ans = it['custom_id'], grades[it['custom_id']], blind['answers'][it['custom_id']]
            L += ['### %s -- %s' % (it['addr'], gr['grade'].upper()), '',
                  '- **On record:** %s' % it['claim'][:700],
                  '- **Blind (%s):** %s -- %s' % (
                      ans['evidence_class'], ans['proposed_name'],
                      ans.get('what_it_does') or ans.get('purpose', '')),
                  '- **Grader:** %s' % gr['reason'],
                  '- **Differs on:** %s' % gr['point_of_difference'], '']
    failed = dict(blind['failed'])
    failed.update({k: 'grading ' + v for k, v in bad.items()})
    if failed:
        L += ['## No answer', ''] + ['- %s: %s' % kv for kv in sorted(failed.items())]
    with open(REPORT, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join(L) + '\n')
    print('graded %d; grading used %s input and %s output tokens (at most $%.2f)'
          % (len(grades), format(tin, ','), format(tout, ','),
             (tin * B.PRICE_IN + tout * B.PRICE_OUT) / 1e6 * B.BATCH_DISCOUNT))
    print('wrote: %s' % os.path.relpath(REPORT, REPO))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('prepare', help='pick the sample and build requests (no spend)')
    p.add_argument('--rom', default=TT.DEFAULT_ROM)
    p.add_argument('--n', type=int, default=30, help='items per group')
    p.add_argument('--seed', type=int, default=1)
    p.add_argument('--groups', nargs='+', default=GROUPS, choices=GROUPS,
                   help='which groups to sample (default: all three)')
    p.add_argument('--exclude', nargs='+', metavar='REQUESTS_JSONL',
                   help='skip items listed in an earlier run\'s requests file')
    p.add_argument('--all-labels', action='store_true',
                   help='show every project label in the listings (not blind; for comparison)')
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
    p = sub.add_parser('report', help='fetch the grades and write the report')
    p.add_argument('--wait', action='store_true')
    p.set_defaults(fn=cmd_report)
    args = ap.parse_args()
    args.fn(args)


if __name__ == '__main__':
    main()
