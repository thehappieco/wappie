"""Regenerate the shared emoji catalogue from a pinned Unicode data file.

Usage: python3 internal/emoji/generate.py /path/to/emoji-test-17.txt
Source: https://www.unicode.org/Public/17.0.0/emoji/emoji-test.txt
Data license: LICENSE-UNICODE.txt (Unicode License V3).
"""
import hashlib
import json
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_bytes()
assert hashlib.sha256(source).hexdigest() == '1d8a944f88d7952f7ef7c5167fef3c67995bcae24543949710231b03a201acda'
groups = []
canonical = {}
pending = []
for line in source.decode().splitlines():
    if line.startswith('# group: '):
        group = {'name': line.removeprefix('# group: '), 'emojis': []}
        groups.append(group)
    if not line or line.startswith('#'):
        continue
    fields = line.split('#', 1)[0].split(';')
    status = fields[1].strip()
    if status == 'component':
        continue
    value = ''.join(chr(int(cp, 16)) for cp in fields[0].split())
    key = value.replace('\ufe0f', '')
    if status == 'fully-qualified':
        assert key not in canonical
        row = [value]
        group['emojis'].append(row)
        canonical[key] = row
    else:
        assert status in ('minimally-qualified', 'unqualified')
        pending.append((key, value))
for key, value in pending:
    assert key in canonical
    canonical[key].append(value)
result = {'version': '17.0', 'groups': [g for g in groups if g['emojis']]}
Path(__file__).with_name('emoji.json').write_text(json.dumps(result, ensure_ascii=False, separators=(',', ':')) + '\n')
print(len(canonical), 'complete emoji,', len(pending), 'presentation aliases')
