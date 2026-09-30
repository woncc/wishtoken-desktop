"""Check publishable Git files without printing potentially secret contents."""
from pathlib import Path
import argparse
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PARTS = {
    '.handoff', '.codex', '.claude', 'node_modules', 'captures', 'sessions',
    'reports', 'analysis', 'handoff', 'diagnostics', 'screenshots',
}
FORBIDDEN_NAMES = {
    'auth.json', 'accounts.json', 'config.json', 'bridge-identity.json',
    'desktop.json', 'history.json', '.env', '.envrc', 'credentials.json', 'tokens.json',
    'session.json', 'cookies.json', 'cookies.txt', 'id_rsa', 'id_ed25519',
    'id_ecdsa', 'id_dsa', 'id_ecdsa_sk', 'id_ed25519_sk',
}
FORBIDDEN_SUFFIXES = {
    '.jsonl', '.log', '.bak', '.exe', '.zip', '.dmg', '.pem', '.key', '.env',
    '.har', '.pcap', '.pcapng', '.p12', '.pfx', '.kdbx',
}
RULES = {
    'private key': re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'JWT literal': re.compile(rb'eyJ[A-Za-z0-9_-]{25,}\.[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{15,}'),
    'secret token literal': re.compile(rb'(?:sk-(?:proj-)?|gh[pousr]_|github_pat_|rt_)[A-Za-z0-9_-]{25,}'),
    'personal Windows path': re.compile(rb'[CD]:[/\\](?:Users|Git_Project)[/\\](?:Mayn|rain|kawang|gptbridge|WishToApp)', re.I),
}

FOLD_PARTS = {part.casefold() for part in FORBIDDEN_PARTS}
FOLD_NAMES = {item.casefold() for item in FORBIDDEN_NAMES}

def path_reason(rel):
    path = Path(rel)
    parts = {part.casefold() for part in path.parts}
    name = path.name.casefold()
    if parts & FOLD_PARTS or name in FOLD_NAMES or private_filename(name):
        return 'private state or generated artifact path'
    if name.startswith('.env.') or name.startswith(('sub2api-account-', 'sub2api-rotation-')) or path.suffix.casefold() in FORBIDDEN_SUFFIXES:
        return 'private state or generated artifact path'
    return ''

def private_filename(name):
    if name.startswith('.envrc') or name.startswith(('handoff-', 'handoff_')):
        return True
    stem = Path(name).stem.replace('_', '-')
    return stem == 'handoff' or stem == 'auth-snapshot' or stem.startswith('auth-snapshot-')

def content_reasons(data):
    found = []
    for label, pattern in RULES.items():
        if pattern.search(data):
            found.append(label)
    return found

def text_reason(data):
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        return 'unexpected non-UTF8 source file'
    if '\ufffd' in text:
        return 'Unicode replacement character'
    return ''

def secrets_from(samples):
    secrets = set()
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ('access_token', 'refresh_token', 'id_token', 'api_key') and isinstance(item, str) and len(item) > 12:
                    secrets.add(item.encode())
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    for sample in samples:
        walk(json.loads(sample.read_text(encoding='utf-8-sig')))
    return secrets

def self_test():
    blocked = (
        '.env.local', 'config/.env.production', 'secrets.env', 'handoff/notes.md',
        'Diagnostics/capture.png', 'screenshots/ui.png', 'credentials.json',
        'nested/auth.json', 'sub2api-account-1.json', 'trace.jsonl', 'notes.bak',
        'id_rsa', 'ID_RSA', 'Accounts.json', 'tokens.json',
        '.envrc', 'config/.envrc.local', 'id_ecdsa', 'id_ed25519_sk',
        'notes/HANDOFF.md', 'Handoff-notes.txt', 'auth_snapshot.json',
        'capture.har', 'trace.pcapng', 'cert.p12', 'vault.kdbx', 'Cookies.json',
    )
    allowed = (
        'internal/server/management_credentials_test.go', 'internal/basispoints/envelope.go',
        'desktop/assets/icon.png', 'README.md', 'scripts/check-public.py', 'internal/config/config.go',
        'internal/oauth/login.go', 'docs/handover-not-private.md',
    )
    for rel in blocked:
        if not path_reason(rel):
            raise SystemExit(f'self-test failed: {rel} was not blocked')
    for rel in allowed:
        if path_reason(rel):
            raise SystemExit(f'self-test failed: {rel} was blocked')
    private = b'-----BEGIN ' + b'OPENSSH ' + b'PRIVATE KEY-----'
    jwt = b'eyJ' + b'a' * 25 + b'.' + b'b' * 30 + b'.' + b'c' * 15
    token = b'rt_' + b'a' * 25
    personal = b'C:/Users/' + b'Mayn' + b'/project'
    unrelated = b'C:/Users/' + b'other' + b'/project'
    if content_reasons(private) != ['private key'] or content_reasons(jwt) != ['JWT literal'] or content_reasons(token) != ['secret token literal']:
        raise SystemExit('self-test failed: secret content was not detected')
    if content_reasons(b'rt_' + b'short') or content_reasons(b'package server\nfunc ok() {}\n') or content_reasons(b'ordinary source text'):
        raise SystemExit('self-test failed: ordinary content was blocked')
    if 'personal Windows path' not in content_reasons(personal):
        raise SystemExit('self-test failed: personal path was not detected')
    if content_reasons(unrelated):
        raise SystemExit('self-test failed: unrelated Windows path was blocked')

def main():
    self_test()
    parser = argparse.ArgumentParser()
    parser.add_argument('--sample', type=Path, action='append', default=[], help='Optional private credential files; only exact matching is performed')
    args = parser.parse_args()
    raw = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT)
    files = sorted(set(p.decode('utf-8') for p in raw.split(bytes([0])) if p))
    secrets = secrets_from(args.sample)
    findings = []
    for rel in files:
        path = ROOT / rel
        if reason := path_reason(rel):
            findings.append((rel, reason))
        if path.is_symlink():
            findings.append((rel, 'symlink requires manual publication review'))
            continue
        data = path.read_bytes()
        if any(token in data for token in secrets):
            findings.append((rel, 'authorized sample credential found'))
        for label in content_reasons(data):
            findings.append((rel, label))
        if path.suffix.lower() not in ('.png', '.ico', '.icns'):
            if reason := text_reason(data):
                findings.append((rel, reason))
    for rel, reason in findings:
        print(f'BLOCKED {rel}: {reason}')
    if findings:
        raise SystemExit(1)
    print(f'Public-source check passed: {len(files)} files, {len(secrets)} private credential values checked; no values printed.')

if __name__ == '__main__':
    main()
