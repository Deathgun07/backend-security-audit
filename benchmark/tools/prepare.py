#!/usr/bin/env python3
"""Build the blinded audit copies used by the benchmark.

Usage: python3 -I prepare.py <src_dir> <out_dir>
  <src_dir> must contain clones of juice-shop, NodeGoat and DVWA (see benchmark/README.md for the commits).
Hints are removed so the auditor cannot read the answers, and line numbers are always preserved:
  - Juice Shop: `vuln-code-snippet` annotations stripped (code before them kept), challenge identifiers renamed ch_N,
    coding-challenge routes/data, tests and docs removed.
  - NodeGoat: JS comments and HTML comments blanked (they contain "Fix for A1 ..."), tutorial and docs removed.
  - DVWA: comments in vulnerabilities/*/source blanked, help pages and docs removed (module names cannot be hidden).
"""
import os, re, shutil, sys

SRC, OUT = sys.argv[1], sys.argv[2]

def copy(name, dest, skip):
    s, d = os.path.join(SRC, name), os.path.join(OUT, dest)
    shutil.rmtree(d, ignore_errors=True)
    def ign(dirpath, names):
        rel = os.path.relpath(dirpath, s); out = {'.git', 'node_modules'}
        for n in names:
            if any(re.fullmatch(x, os.path.normpath(os.path.join(rel, n))) for x in skip): out.add(n)
        return out
    shutil.copytree(s, d, ignore=ign)
    return d

def walk(d, exts):
    for root, _, files in os.walk(d):
        for f in files:
            if f.endswith(exts): yield os.path.join(root, f)

def rw(p, fn):
    s = open(p, encoding='utf-8', errors='replace').read(); t = fn(s)
    if t != s: open(p, 'w', encoding='utf-8').write(t)

def blank_js_comments(src):
    out, i, n, q = [], 0, len(src), None
    while i < n:
        c = src[i]
        if q:
            out.append(c)
            if c == '\\' and i + 1 < n: out.append(src[i + 1]); i += 2; continue
            if c == q: q = None
            i += 1; continue
        if c in '"\'`': q = c; out.append(c); i += 1; continue
        if src.startswith('//', i):
            j = src.find('\n', i); i = n if j < 0 else j; continue
        if src.startswith('/*', i):
            j = src.find('*/', i + 2); j = n if j < 0 else j + 2
            out.append('\n' * src[i:j].count('\n')); i = j; continue
        out.append(c); i += 1
    return ''.join(out)

# app-a: OWASP Juice Shop
d = copy('juice-shop', 'app-a', [r'test', r'data/static/codefixes', r'data/static/challenges\.yml', r'README.*', r'CONTRIBUTING\.md',
         r'HALL_OF_FAME\.md', r'SECURITY\.md', r'screenshots', r'\.github', r'monitoring', r'cypress.*', r'.*\.spec\.ts',
         r'routes/vulnCodeSnippet\.ts', r'routes/vulnCodeFixes\.ts'])
EXTS = ('.ts', '.js', '.html', '.json', '.yml')
names = set()
for p in walk(d, EXTS): names |= set(re.findall(r'\b[a-z][A-Za-z0-9]*Challenge\b', open(p, encoding='utf-8', errors='replace').read()))
mapping = {n: f'ch_{i}' for i, n in enumerate(sorted(names), 1)}
ANN = re.compile(r'[ \t]*(//[ \t]*vuln-code-snippet[^\n]*|<!--[ \t]*vuln-code-snippet.*?-->|/\*[ \t]*vuln-code-snippet.*?\*/)')
for p in walk(d, EXTS):
    rw(p, lambda s: re.sub(r'\b[a-z][A-Za-z0-9]*Challenge\b', lambda m: mapping[m.group(0)], ANN.sub('', s)))
open(os.path.join(OUT, 'app-a.challenge-mapping.tsv'), 'w').write(''.join(f'{v}\t{k}\n' for k, v in mapping.items()))

# app-b: OWASP NodeGoat
d = copy('NodeGoat', 'app-b', [r'app/views/tutorial', r'app/routes/tutorial\.js', r'README.*', r'test', r'\.github', r'artifacts', r'docker-compose.*'])
for p in walk(d, ('.js',)):
    if 'assets' not in p and 'vendor' not in p: rw(p, blank_js_comments)
for p in walk(d, ('.html',)):
    rw(p, lambda s: re.sub(r'.*Insecure App.*', '', re.sub(r'<!--.*?-->', lambda m: '\n' * m.group(0).count('\n'), s, flags=re.S)))
p = os.path.join(d, 'app/views/login.html'); L = open(p).read().split('\n')
for i in (45, 46): L[i] = ''   # project blurb ("an educational ... application vulnerable to the OWASP Top 10")
open(p, 'w').write('\n'.join(L))

# app-c: DVWA
d = copy('DVWA', 'app-c', [r'vulnerabilities/[^/]+/help', r'README.*', r'docs', r'\.github', r'CHANGELOG.*', r'SECURITY\.md'])
def dvwa(s):
    t = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group(0).count('\n'), s, flags=re.S)
    return '\n'.join('' if re.match(r'\s*(//|#)', l) else re.sub(r'\s//\s.*$', '', l) for l in t.split('\n'))
for p in walk(os.path.join(d, 'vulnerabilities'), ('.php',)):
    if os.path.basename(os.path.dirname(p)) == 'source': rw(p, dvwa)
print('done:', ', '.join(sorted(os.listdir(OUT))))
