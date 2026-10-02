"""Check publishable Git files without printing potentially secret contents."""
from pathlib import Path
import argparse
import json
import re
import subprocess
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PARTS = {
    '.handoff', '.codex', '.claude', 'node_modules', 'captures', 'sessions',
    'reports', 'analysis', 'handoff', 'diagnostics', 'screenshots',
}
FORBIDDEN_NAMES = {
    'auth.json', 'accounts.json', 'config.json', 'bridge-identity.json',
    'desktop.json', 'history.json', 'launch-history.json',
    'cockpit-integration.json', 'cockpit-process.json',
    'codex_instances.json', 'secrets.json', 'credentials', 'credentials.json',
    '.env', '.envrc', 'tokens.json',
    'session.json', 'cookies.json', 'cookies.txt', 'id_rsa', 'id_ed25519',
    'id_ecdsa', 'id_dsa', 'id_ecdsa_sk', 'id_ed25519_sk',
    '.netrc', '_netrc', '.git-credentials', '.npmrc', '.pypirc', '.pgpass',
}
FORBIDDEN_SUFFIXES = {
    '.jsonl', '.log', '.bak', '.exe', '.zip', '.dmg', '.pem', '.key', '.env',
    '.har', '.pcap', '.pcapng', '.p12', '.pfx', '.kdbx',
    '.ppk', '.p8', '.jks', '.keystore',
    '.sqlite', '.sqlite3', '.db', '.ovpn', '.psafe3',
    '.gpg', '.pgp', '.age',
}
COMPRESSED_SUFFIXES = {'.gz', '.gzip', '.bz2', '.xz', '.zst', '.br', '.7z', '.tar', '.tgz', '.lz4', '.lzma', '.zstd', '.rar', '.cab'}
PARTIAL_SUFFIXES = {'.crdownload', '.part', '.partial', '.download'}
# NFKC folds a halfwidth full stop into an ideographic one, which is still not ASCII '.'.
DOT_LIKE = {ord('\u3002'): '.'}
# These do not NFKC-fold to ':'. A following stream name must not hide auth.json.
COLON_LIKE = {
    ord('\u2236'): ':',
    ord('\u02d0'): ':',
    ord('\u02d1'): ':',
    ord('\ua789'): ':',
    ord('\u02f8'): ':',
    ord('\u0703'): ':',
    ord('\u0704'): ':',
    ord('\u0705'): ':',
    ord('\u0706'): ':',
    ord('\u0707'): ':',
    ord('\u0708'): ':',
    ord('\u0709'): ':',
    ord('\u0589'): ':',
    ord('\u05c3'): ':',
    ord('\u1361'): ':',
    ord('\u1365'): ':',
    ord('\u1366'): ':',
    ord('\u205a'): ':',
}
BACKUP_SUFFIXES = {
    '.orig', '.save', '.old', '.copy', '.backup', '.bak2',
    '.swp', '.swo', '.swn', '.tmp',
}
RULES = {
    'private key': re.compile(rb'-----BEGIN (?:(?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----'),
    'JWT literal': re.compile(rb'eyJ[A-Za-z0-9_-]{25,}\.[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{15,}'),
    'secret token literal': re.compile(rb'(?:sk-(?:proj-)?|gh[pousr]_|github_pat_|rt_)[A-Za-z0-9_-]{25,}'),
    'personal Windows path': re.compile(rb'[CD]:[/\\](?:Users|Git_Project)[/\\](?:Mayn|rain|kawang|gptbridge|WishToApp)', re.I),
}

FOLD_PARTS = {part.casefold() for part in FORBIDDEN_PARTS}
FOLD_NAMES = {item.casefold() for item in FORBIDDEN_NAMES}

NUMBERED_BACKUP = re.compile(r'\.(?:bak|old|orig|save|backup|copy|tmp)\d+$')
EDITOR_NUMBER = re.compile(r'(?:\.~\d+|~\d+)$')
COPY_INDEX = re.compile(r' \(\d+\)$')

def forbidden_name(folded):
    if folded in FOLD_NAMES:
        return True
    bare = folded[1:] if folded.startswith('.') else folded
    return bare in FOLD_NAMES

def normalize_component(name):
    # Compatibility forms such as fullwidth letters and colons fold to ASCII.
    # Format, control, and line-separator characters can sit inside a name
    # without changing how a person reads it.
    folded = unicodedata.normalize('NFKC', name).translate(DOT_LIKE).translate(COLON_LIKE).casefold()
    return ''.join(ch for ch in folded if unicodedata.category(ch) not in {'Cf', 'Cc', 'Zl', 'Zp'})

def strip_edges(value):
    while value and (value[0] in ' \t' or value[-1] in ' \t.'):
        if value[0] in ' \t':
            value = value[1:]
        else:
            value = value[:-1]
    return value

def glue_extension(value):
    # A space beside the last dot hides auth.json as "auth .json".
    stem, dot, ext = value.rpartition('.')
    if not dot:
        return value
    return stem.rstrip(' \t') + dot + ext.lstrip(' \t')

def visible_name(name):
    # Windows ignores trailing dots and spaces. Editors, NTFS streams, and
    # Unicode lookalikes can hide the same forbidden name.
    folded = strip_edges(normalize_component(name))
    if ':' in folded:
        folded = strip_edges(folded.split(':', 1)[0])
    return glue_extension(folded)

def strip_alias(folded):
    folded = glue_extension(strip_edges(folded))
    if folded.startswith('.#'):
        folded = folded[2:]
    if folded.startswith('#') and folded.endswith('#') and len(folded) > 2:
        folded = folded[1:-1]
    while folded.endswith('~'):
        folded = folded[:-1]
    changed = True
    while changed and folded:
        changed = False
        folded = glue_extension(strip_edges(folded))
        editor = EDITOR_NUMBER.search(folded)
        if editor and editor.start() > 0:
            folded = folded[:editor.start()]
            changed = True
            continue
        suffix = Path(folded).suffix
        stem = Path(folded).stem
        if stem.endswith(' copy') and stem[:-5]:
            folded = stem[:-5] + suffix
            changed = True
            continue
        if suffix in BACKUP_SUFFIXES or suffix in COMPRESSED_SUFFIXES or suffix in PARTIAL_SUFFIXES or suffix == '.txt' or NUMBERED_BACKUP.fullmatch(suffix) or re.fullmatch(r'\.\d+', suffix):
            if stem and stem != folded:
                folded = strip_edges(stem)
                changed = True
                continue
        if stem and COPY_INDEX.search(stem):
            rebuilt = COPY_INDEX.sub('', stem) + suffix
            if rebuilt and rebuilt != folded:
                folded = rebuilt
                changed = True
    return folded

def secret_alias(name):
    folded = visible_name(name)
    if not folded:
        return False
    if folded.startswith('._') and folded[2:] and secret_alias(folded[2:]):
        return True
    if folded.startswith('copy of ') and secret_alias(folded[8:]):
        return True
    folded = strip_alias(folded)
    if forbidden_name(folded):
        return True
    # A trailing .txt can hide a forbidden suffix, as in accounts.json.bak.txt.
    return Path(folded).suffix in FORBIDDEN_SUFFIXES

# NFKC already folds fullwidth solidus and reverse solidus. These remaining
# slash lookalikes, plus the yen and won signs Windows still treats as
# separators, must split a path before any component is judged. Set minus,
# the reverse solidus operator, and big reverse solidus do not NFKC-fold
# to a backslash, so they must be listed beside their forward twins.
SEPARATOR_LIKE = {
    ord('\\'): '/',
    ord('\u00a5'): '/',
    ord('\u20a9'): '/',
    ord('\u2044'): '/',
    ord('\u2215'): '/',
    ord('\u2216'): '/',
    ord('\u29f5'): '/',
    ord('\u29f8'): '/',
    ord('\u29f9'): '/',
    ord('\ufe68'): '/',
    ord('\uff0f'): '/',
    ord('\uff3c'): '/',
}

def normalized_rel(rel):
    folded = unicodedata.normalize('NFKC', rel).translate(DOT_LIKE).translate(SEPARATOR_LIKE)
    return folded.replace('\\', '/')

def forbidden_suffix(name):
    if not name:
        return False
    if name.startswith('.env.') or name.startswith(('sub2api-account-', 'sub2api-rotation-')):
        return True
    # A colon splits an NTFS stream name. The stream can still end in .log or
    # .bak.txt, so judge the unsplit filename before that split is trusted.
    folded = strip_alias(name)
    return Path(name).suffix in FORBIDDEN_SUFFIXES or Path(folded).suffix in FORBIDDEN_SUFFIXES

def piece_private(name):
    name = strip_edges(name)
    if not name:
        return False
    if name in FOLD_PARTS or name in FOLD_NAMES or secret_alias(name) or private_filename(name):
        return True
    return forbidden_suffix(name)

def component_private(part):
    name = visible_name(part)
    whole = strip_edges(normalize_component(part))
    if not name and not whole:
        return False
    if name and piece_private(name):
        return True
    if whole != name and forbidden_suffix(whole):
        return True
    # filename:auth.json and filename:id_rsa keep the forbidden name in the
    # NTFS stream. The base name is ordinary, so the stream has to be judged too.
    if ':' in whole:
        for piece in whole.split(':'):
            if piece_private(piece):
                return True
    return False

def path_reason(rel):
    # A private name is not safe just because a later component looks ordinary.
    # auth.json/payload.txt and a backslash twin are the same leak.
    for part in Path(normalized_rel(rel)).parts:
        if component_private(part):
            return 'private state or generated artifact path'
    return ''

def private_filename(name):
    if name.startswith('.envrc') or name.startswith(('handoff-', 'handoff_')) or name.startswith('.owner-'):
        return True
    if '.bak-' in name or '.gptbridge-backup-' in name:
        return True
    path = Path(name)
    if path.suffix == '.tmp' and path.stem in FOLD_NAMES:
        return True
    stem = path.stem.replace('_', '-')
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
        '.netrc', 'home/_netrc', 'keys/id.ppk', 'AuthKey.p8', 'store.jks', 'app.keystore',
        'launch-history.json', 'nested/cockpit-integration.json', 'cockpit-process.json',
        'config.toml.bak-20261001-030405', 'codex_instances.json.gptbridge-backup-20261001',
        'accounts.json.tmp', '.owner-12345',
        'accounts.json.orig', 'nested/auth.json.old', 'Accounts.JSON.save', 'config.json~',
        '.#tokens.json', '.accounts.json.swp', '#credentials.json#', 'id_rsa.orig',
        'auth.json.orig.old', 'ID_ED25519.BACKUP', '.git-credentials', 'home/.npmrc',
        '.pypirc', '.pgpass', 'aws/credentials', 'secrets.json', 'codex_instances.json',
        'cache.sqlite', 'state.sqlite3', 'app.db', 'tunnel.ovpn', 'vault.psafe3',
        'accounts.json.bak3', 'auth.json.backup2', 'credentials.json.1', '._auth.json',
        '._accounts.json', 'auth.json.~1~', 'auth.json~1', 'id_rsa.old2', 'tokens.json.orig2',
        'config.json.save1', 'home/.netrc.bak3', 'Copy of auth.json', 'auth (1).json',
        'accounts copy.json', 'nested/auth.json.bak3', 'ID_ED25519.OLD2', '._.netrc',
        'id_rsa.txt', 'accounts.json.txt', 'nested/auth.json.txt', 'credentials.txt', 'ID_ED25519.TXT',
        'accounts.json.bak.txt', 'notes.bak.txt', 'auth.json.log.txt', 'trace.jsonl.txt', 'auth.json.bak.txt.1', 'Accounts.JSON.BAK.TXT',
        'auth.json.', 'accounts.json ', ' auth.json', 'Copy of auth.json.',
        'id_rsa.gpg', 'secrets.age', 'keys/backup.pgp', 'auth.json.gz', 'nested/credentials.json.bz2',
        'auth.json\u200b', 'auth\u200b.json', 'accounts.json::$DATA', 'id_rsa:secret', 'tokens.json.xz',
        'auth.json\u00a0', 'auth.json\u3000', 'auth.json\u202f', 'auth.json\u205f', 'auth.json\u202e',
        '\u202eauth.json', 'auth.json\u200e', 'id_rsa\u200f', 'credentials.json\u2066',
        'auth.json\r', 'auth.json\n', 'auth.json\x00', 'secrets.env\u00a0', 'notes.bak\u3000',
        'auth.json\u2024', 'auth.json\u3002', 'auth\uff0ejson', '\uff41\uff55\uff54\uff48.json', '\uff41\uff43\uff43\uff4f\uff55\uff4e\uff54\uff53\uff0e\uff4a\uff53\uff4f\uff4e',
        'auth.json\uff1a$DATA', 'Copy of auth.json\u00a0', 'auth.json\u00a0.txt', 'auth .json',
        'Diagnostics\u00a0/capture.png', 'auth.json\u2028', 'accounts .json.gz',
        'auth.json.br', 'accounts.json.7z', 'credentials.json.tar', 'auth.json.tgz', 'tokens.json.lz4',
        'secrets.json.lzma', 'id_rsa.rar', 'nested/auth.json.cab', 'auth.json.tar.gz', 'tokens.json.zstd',
        'credentials/notes.txt', 'auth.json/payload.txt', 'nested/accounts.json/extra.txt',
        'accounts.json.bak/notes.txt', 'Copy of auth.json/secret.txt', 'auth.json.gz/readme.txt',
        '.env.local/settings.yml', 'config/.env.production/app.txt', 'handoff-notes/readme.md',
        '.owner-12345/state.txt', 'auth-snapshot-1/data.txt', 'id_rsa/x',
        'ID_RSA/x', 'secrets.env/x', 'sub2api-account-1.json/x',
        'notes.bak/readme.md', 'auth.json.tar.gz/x', 'tokens.json.crdownload/x',
        '.#tokens.json/x', '._auth.json/x', 'config.toml.bak-20261001/x',
        'auth.json:secret/file.txt', 'auth.json\\notes.txt', 'credentials\\token.txt',
        'auth.json\u2044secret.txt', 'auth.json\u2215secret.txt', 'accounts.json\u29f8extra.txt',
        'auth.json\u2216secret.txt', 'accounts.json\u29f5extra.txt', 'tokens.json\u29f9notes.txt',
        'Diagnostics\u2216capture.png', 'credentials\u29f9token.txt', 'nested/id_rsa\u29f5x',
        'auth.json\u00a5secret.txt', 'tokens.json\u20a9extra.txt', 'auth.json\uff0fsecret.txt',
        'accounts.json\uff3cnotes.txt', 'Diagnostics\u2044capture.png', 'auth.json\u200b/payload.txt',
        'auth.json.crdownload', 'auth.json.part', 'credentials.json.partial', 'accounts.json.download',
        'auth.json\u0705secret.txt', 'id_rsa\u02d1', 'accounts.json\u1365extra', 'tokens.json\u205anotes',
        'credentials\u05c3token', 'nested/auth.json\u0709/payload.txt', 'ID_RSA\u0706x', 'auth.json\u2236secret.txt',
        'Copy of auth.json\u1361notes', 'auth\u3002json\u0708secret', 'notes.bak\u0589readme',
        'notes\u0705trace.log', 'readme\u0705trace.log.txt', 'notes:trace.log',
        'readme:auth.json', 'notes:id_rsa', 'docs:credentials.json', 'readme:.env',
        'nested/file:accounts.json', 'readme:Copy of auth.json', 'notes:auth.json:$DATA',
        'file:id_rsa.txt', 'readme:accounts.json.bak', 'script:tokens.json.gz', 'readme\u0705auth.json',
        'notes:ID_RSA', 'file:.netrc', 'readme:auth.json.txt',
    )
    allowed = (
        'internal/server/management_credentials_test.go', 'internal/basispoints/envelope.go',
        'desktop/assets/icon.png', 'README.md', 'scripts/check-public.py', 'internal/config/config.go',
        'internal/oauth/login.go', 'docs/handover-not-private.md',
        'docs/assets/accounts.png', 'internal/localcodex/models.json', 'notes.tmp', 'script.go.swp',
        'id_rsa.pub', 'script (1).go', 'notes.bak3', 'Copy of README.md', '._script.go',
        'notes.txt', 'docs/readme.txt', 'script.go.txt',
        'models.json.txt', 'notes.txt.', 'readme.gz', 'script.go.xz', 'models.json.gz',
        'script.go:Zone.Identifier', 'notes\u00a0.txt', 'readme\u3002txt', 'script.go\u200b',
        'models.json:Zone.Identifier', 'notes:readme.txt', 'file:notes.tmp',
        'notes .txt', 'models .json.gz', 'id_rsa.pub\u200e', 'id_rsa .pub',
        'notes.bak3/readme.md', 'script.go.swp/foo.txt', 'models.json.gz/foo.txt',
        'id_rsa.pub/foo.txt', 'Copy of README.md/img.png', 'docs/handover-not-private/readme.md',
        'notes\\readme.txt', 'readme\u2044notes.txt', 'script.go\u00a5extra.txt',
        'models.json\uff0freadme.txt',
        'readme\u2216notes.txt', 'script.go\u29f5extra.txt', 'models.json\u29f9readme.txt',
        'readme.br', 'notes.tar', 'script.go.part', 'models.json.7z', 'readme.tgz', 'notes.crdownload',
        'script.go\u0705extra', 'notes\u1365txt', 'readme\u205anotes.txt', 'id_rsa.pub\u02d1extra',
        'models.json\u0589readme',
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
    encrypted = b'-----BEGIN ' + b'ENCRYPTED ' + b'PRIVATE KEY-----'
    dsa = b'-----BEGIN ' + b'DSA ' + b'PRIVATE KEY-----'
    pgp = b'-----BEGIN ' + b'PGP PRIVATE KEY BLOCK-----'
    if content_reasons(private) != ['private key'] or content_reasons(encrypted) != ['private key'] or content_reasons(dsa) != ['private key'] or content_reasons(pgp) != ['private key'] or content_reasons(jwt) != ['JWT literal'] or content_reasons(token) != ['secret token literal']:
        raise SystemExit('self-test failed: secret content was not detected')
    if content_reasons(b'-----BEGIN PUBLIC KEY-----') or content_reasons(b'-----BEGIN CERTIFICATE-----'):
        raise SystemExit('self-test failed: public key material was blocked')
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
