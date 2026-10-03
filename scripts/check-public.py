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
    '.sqlite-wal', '.sqlite-shm', '.sqlite-journal',
    '.sqlite3-wal', '.sqlite3-shm', '.sqlite3-journal',
    '.db-wal', '.db-shm', '.db-journal',
    '.gpg', '.pgp', '.age',
}
COMPRESSED_SUFFIXES = {'.gz', '.gzip', '.bz2', '.xz', '.zst', '.br', '.7z', '.tar', '.tgz', '.lz4', '.lzma', '.zstd', '.rar', '.cab'}
PARTIAL_SUFFIXES = {'.crdownload', '.part', '.partial', '.download'}
# Hangul fillers and the braille blank are letters or symbols, so they are not
# format characters. U+3164 and U+FFA0 NFKC-fold to U+1160. None of them has ink.
BLANK_FILLERS = frozenset('\u115f\u1160\u3164\uffa0\u2800')
# NFKC folds a halfwidth full stop into an ideographic one, which is still not ASCII '.'.
# These other full stops do not NFKC-fold to '.' either. Armenian full stop is a
# colon lookalike and is folded with the colons instead.
DOT_LIKE = {
    ord('\u3002'): '.',
    ord('\u06d4'): '.',
    ord('\u0701'): '.',
    ord('\u0702'): '.',
    ord('\u1362'): '.',
    ord('\u166e'): '.',
    # These stay full stops here so auth.json still matches. UTS #39 skeletons
    # them as colons; the proxy redactor folds that shape separately.
    ord('\u1803'): '.',
    ord('\u1809'): '.',
    ord('\u2cf9'): '.',
    ord('\u2cfe'): '.',
    ord('\u2e3c'): '.',
    ord('\ua4ff'): '.',
    ord('\ua60e'): '.',
    ord('\ua6f3'): '.',
    ord('\U00016af5'): '.',
    ord('\U00016e98'): '.',
    ord('\U0001bc9f'): '.',
    ord('\U0001da88'): '.',
    # These do not NFKC-fold to '.'. Lisu mya ti, the Kharoshthi punctuation
    # dot, and Meetei Mayek lum iyek still hide auth.json and .netrc.
    # Lisu tone mya cya is confusable with two full stops and does not fold.
    ord('\ua4f8'): '.',
    ord('\U00010a50'): '.',
    ord('\uabec'): '.',
    ord('\ua4fa'): '.',
    # Unicode confusables map these to FULL STOP, and none of them NFKC-fold
    # to '.'. Arabic-indic zero and the extended zero are the digit forms.
    # The siyaq half maps through that zero, and the musical augmentation
    # dot is a combining mark rather than a letter.
    ord('\u0660'): '.',
    ord('\u06f0'): '.',
    ord('\U0001ecae'): '.',
    ord('\U0001d16d'): '.',
    # These NFKC-fold to '.' or to the ideographic full stop above. One dot
    # leader, small full stop, and fullwidth full stop fold to '.'. Vertical
    # ideographic full stop and halfwidth ideographic full stop fold to
    # U+3002. The raw forms are listed so a reordered normalization cannot
    # hide auth.json. Credential redaction does not run NFKC.
    ord('\u2024'): '.',
    ord('\uFE52'): '.',
    ord('\uFF0E'): '.',
    ord('\uFE12'): '.',
    ord('\uFF61'): '.',
}
# These do not NFKC-fold to ':'. A following stream name must not hide auth.json.
# Mongolian colon and Bamum colon are the same kind of separator.
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
    ord('\u1804'): ':',
    ord('\ua6f4'): ':',
    # These NFKC-fold to the modifier colons above. Listing them keeps a raw
    # superscript from hiding the stream split if normalization is reordered.
    ord('\U00010781'): ':',
    ord('\U00010782'): ':',
    # NFKC expands this to '::=', which leaves '=' stuck to the next name.
    # Fold it before normalization so the stream split still sees that name.
    ord('\u2a74'): ':',
    # These do not NFKC-fold to ':'. Tricolon, colon-equals, equals-colon,
    # the Z notation type colon, and the triple colon operator still separate
    # a following private name.
    ord('\u205d'): ':',
    ord('\u2254'): ':',
    ord('\u2255'): ':',
    ord('\u2982'): ':',
    ord('\u2af6'): ':',
    # These do not NFKC-fold to ':'. Cuneiform colon punctuation and the
    # SignWriting colon still separate a following private name.
    ord('\U00012471'): ':',
    ord('\U00012472'): ':',
    ord('\U00012473'): ':',
    ord('\U00012474'): ':',
    ord('\U0001DA8A'): ':',
    # The vertical two-dot leader NFKC-folds to '..', so a following private
    # name would survive unless it is folded first. The other two-dot marks
    # do not NFKC-fold to ':' either.
    ord('\ufe30'): ':',
    ord('\u16ec'): ':',
    ord('\u0831'): ':',
    ord('\U00010af5'): ':',
    ord('\U0001123a'): ':',
    ord('\ua4fd'): ':',
    # Visarga signs are spacing marks shaped like a colon. Bengali visarga is
    # the confusable prototype; the other script visargas, Tibetan rnam bcad,
    # and Khmer reahmuk fold with it. None of them NFKC-fold to ':'.
    ord('\u0903'): ':',
    ord('\u0a83'): ':',
    ord('\U00011002'): ':',
    ord('\U00011082'): ':',
    ord('\U00011182'): ':',
    ord('\U000115BE'): ':',
    ord('\U000116AC'): ':',
    ord('\U00011838'): ':',
    ord('\u0983'): ':',
    ord('\u0a03'): ':',
    ord('\u0c03'): ':',
    ord('\u0c83'): ':',
    ord('\u0d03'): ':',
    ord('\u0d83'): ':',
    ord('\u0f7f'): ':',
    ord('\u1038'): ':',
    ord('\u17c7'): ':',
    ord('\U00011303'): ':',
    ord('\U000114C1'): ':',
    ord('\U000119DF'): ':',
    ord('\U00011A39'): ':',
    ord('\U00011C3E'): ':',
    # These symbols do not NFKC-fold to ':'. Ethiopic short rikrik, musical
    # repeat dots, and Tolong Siki sela still separate a following private
    # name. Greek acrophonic two is a letter-number and stays unmapped.
    ord('\u1393'): ':',
    ord('\U0001d108'): ':',
    ord('\U00011dd9'): ':',
    # Proportion and squared four-dot punctuation are confusable with '::'
    # and do not NFKC-fold to ':'. A following private name still has to split.
    ord('\u2237'): ':',
    ord('\u2e2c'): ':',
}
# These do not NFKC-fold to '-'. Non-breaking hyphen folds to U+2010, and
# small em dash folds to an em dash, so both are listed. The em dash and the
# horizontal bar do not fold either. Vertical em dash NFKC-folds to an em
# dash, so it is listed beside them. Arabic full stop is
# already a dot above; skeletoning it as a hyphen would hide auth.json.
# Batak panongonan and the Tai Laing tone mark are spacing marks, so they
# have to be folded before those marks are stripped.
HYPHEN_LIKE = {
    ord('\u2010'): '-',
    ord('\u2011'): '-',
    ord('\u2012'): '-',
    ord('\u2013'): '-',
    ord('\u2014'): '-',
    ord('\u2015'): '-',
    ord('\uFE31'): '-',
    ord('\uFE58'): '-',
    ord('\u2043'): '-',
    ord('\u02D7'): '-',
    ord('\u2212'): '-',
    ord('\u2796'): '-',
    ord('\U00010191'): '-',
    ord('\u2CBA'): '-',
    ord('\u2CBB'): '-',
    ord('\u174D'): '-',
    ord('\u1BF3'): '-',
    ord('\uAA7D'): '-',
    # These script hyphens do not NFKC-fold to '-'. Maqaf, the oblique and
    # double hyphens, and the Yezidi hyphenation mark still split
    # launch-history.json and the sqlite sidecars.
    ord('\u058A'): '-',
    ord('\u05BE'): '-',
    ord('\u1400'): '-',
    ord('\u1806'): '-',
    ord('\u2E17'): '-',
    ord('\u2E1A'): '-',
    ord('\u2E40'): '-',
    ord('\u2E5D'): '-',
    ord('\u30A0'): '-',
    ord('\U00010EAD'): '-',
    # Two-em and three-em dashes, the wave dash, and the wavy dash do not
    # NFKC-fold to '-'. Each one still splits a hyphenated private name.
    ord('\u2E3A'): '-',
    ord('\u2E3B'): '-',
    ord('\u301C'): '-',
    ord('\u3030'): '-',
    # These NFKC-fold to '-' or to a dash already listed. Superscript and
    # subscript minus fold to U+2212, vertical en dash folds to an en dash,
    # and small hyphen-minus and fullwidth hyphen-minus fold to '-'. The
    # raw forms are listed so a reordered normalization cannot hide
    # launch-history.json. Credential redaction does not run NFKC.
    ord('\u207B'): '-',
    ord('\u208B'): '-',
    ord('\uFE32'): '-',
    ord('\uFE63'): '-',
    ord('\uFF0D'): '-',
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

def collapse_dots(value):
    # Two-dot leader and ellipsis normalize to repeated ASCII dots. Those
    # repeats still hide auth.json and .netrc unless they are folded first.
    while '..' in value:
        value = value.replace('..', '.')
    return value

def strip_marks(value):
    # Variation selectors, enclosing marks, and spacing combining marks do
    # not add a base letter. A combining accent has to go before NFKC, or it
    # composes into a different letter and auth.json no longer matches.
    # Colon and dot lookalikes are translated first, including visarga and
    # the musical augmentation dot, so those separators survive this pass.
    return ''.join(ch for ch in value if unicodedata.category(ch) not in {'Mn', 'Me', 'Mc'})

def fold_separators(value, separators):
    # Colon, dot, and hyphen lookalikes are translated before marks are removed.
    # The musical augmentation dot is a spacing mark and must stay a dot.
    # Ogham space is the only space separator that does not NFKC-fold to
    # ASCII space, so a trailing mark would otherwise hide id_rsa.
    # A spacing mark shaped like a hyphen has to become '-' before it is
    # stripped, or launch-history.json collapses into one word.
    value = value.replace('\u1680', ' ')
    value = value.translate(COLON_LIKE).translate(DOT_LIKE).translate(HYPHEN_LIKE).translate(separators)
    value = strip_marks(value)
    value = unicodedata.normalize('NFKC', value)
    value = value.translate(DOT_LIKE).translate(separators).translate(COLON_LIKE).translate(HYPHEN_LIKE)
    value = strip_marks(value)
    return value

def normalize_component(name):
    # Compatibility forms such as fullwidth letters and colons fold to ASCII.
    # Colon lookalikes are folded first: double colon equal expands to '::='
    # and would otherwise leave '=' glued to the following stream name.
    # Format, control, and line-separator characters can sit inside a name
    # without changing how a person reads it. Blank fillers are letters or
    # symbols, so the category check does not remove them.
    folded = fold_separators(name, {}).casefold()
    cleaned = ''.join(ch for ch in folded if unicodedata.category(ch) not in {'Cf', 'Cc', 'Zl', 'Zp'} and ch not in BLANK_FILLERS)
    return collapse_dots(cleaned)

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
# Solidus with overbar and reverse solidus with a horizontal stroke are the
# same kind of operator and do not NFKC-fold to a slash either.
SEPARATOR_LIKE = {
    ord('\\'): '/',
    ord('\u00a5'): '/',
    ord('\u20a9'): '/',
    ord('\u2044'): '/',
    ord('\u2215'): '/',
    ord('\u2216'): '/',
    ord('\u29f5'): '/',
    ord('\u29f6'): '/',
    ord('\u29f7'): '/',
    ord('\u29f8'): '/',
    ord('\u29f9'): '/',
    ord('\ufe68'): '/',
    ord('\uff0f'): '/',
    ord('\uff3c'): '/',
    # These do not NFKC-fold to a slash. Philippine single punctuation, the
    # box-drawing diagonals, and the mathematical diagonals still split a
    # private name from the following component.
    ord('\u1735'): '/',
    ord('\u2571'): '/',
    ord('\u2572'): '/',
    # Short box-drawing diagonals are those strokes cut in half. None of
    # them NFKC-fold to a slash, but each one still splits the next
    # component. The negative short diagonal is that rising stroke in
    # negative. It does not NFKC-fold to a slash, but it still splits the
    # next component. The light diagonal cross is folded with the square
    # diagonals. The light diagonal from upper centre to middle left to
    # lower centre is folded with them. The light diagonal from upper
    # centre to middle right to lower centre is folded with them. The
    # other chevron diagonals and the negative diamond stay out.
    ord('\U0001fba0'): '/',
    ord('\U0001fba1'): '/',
    ord('\U0001fba2'): '/',
    ord('\U0001fba3'): '/',
    ord('\U0001fbbe'): '/',
    # The upper right block diagonal from upper centre to lower right is
    # that falling stroke as a narrow block. It does not NFKC-fold to a
    # slash, but it still splits the next component. The upper right block
    # diagonal from upper left to lower middle right is that same stroke
    # as a wider block. It does not NFKC-fold to a slash either, but it
    # still splits the next component. The upper right block diagonal from
    # upper middle left to lower middle right is that falling stroke across
    # the middle. It does not NFKC-fold to a slash either, but it still
    # splits the next component. The upper right block diagonal from upper
    # centre to lower middle right is that falling stroke stopped before
    # the corner. It does not NFKC-fold to a slash either, but it still
    # splits the next component. The upper right block diagonal from upper
    # left to upper middle right is that falling stroke along the top. It
    # does not NFKC-fold to a slash either, but it still splits the next
    # component. The upper right block diagonal from upper centre to upper
    # middle right is that shorter falling stroke along the top. It does
    # not NFKC-fold to a slash either, but it still splits the next
    # component. The upper right block diagonal from upper left to lower
    # centre is that wider falling stroke stopped at the lower centre. It
    # does not NFKC-fold to a slash either, but it still splits the next
    # component. The upper right block diagonal from upper middle left to
    # lower right is that falling stroke continued to the corner. It does
    # not NFKC-fold to a slash either, but it still splits the next
    # component. The upper right block diagonal from upper middle left to
    # lower centre is that shorter falling stroke stopped at the lower
    # centre. It does not NFKC-fold to a slash either, but it still splits
    # the next component. The upper right block diagonal from lower middle
    # left to lower right is that short falling stroke along the lower
    # edge. It does not NFKC-fold to a slash either, but it still splits
    # the next component. The upper right block diagonal from lower middle
    # left to lower centre is that shorter falling stroke stopped before
    # the corner. It does not NFKC-fold to a slash either, but it still
    # splits the next component. The lower left block diagonal from upper
    # centre to lower right is that falling stroke as a narrow block. It
    # does not NFKC-fold to a slash either, but it still splits the next
    # component. The lower left block diagonal from upper left to lower
    # middle right is that same falling stroke as a wider block. It does
    # not NFKC-fold to a slash either, but it still splits the next
    # component. The lower left block diagonal from upper middle left to
    # lower middle right is that falling stroke across the middle. It does
    # not NFKC-fold to a slash either, but it still splits the next
    # component. The lower left block diagonal from upper centre to lower
    # middle right is that falling stroke stopped before the corner. It
    # does not NFKC-fold to a slash either, but it still splits the next
    # component. The lower left block diagonal from upper left to upper
    # middle right is that falling stroke along the top. It does not
    # NFKC-fold to a slash either, but it still splits the next component.
    # The lower left block diagonal from upper centre to upper middle
    # right is that shorter falling stroke along the top. It does not
    # NFKC-fold to a slash either, but it still splits the next component.
    # The lower left block diagonal from upper left to lower centre is
    # that wider falling stroke stopped at the lower centre. It does not
    # NFKC-fold to a slash either, but it still splits the next component.
    # The lower left block diagonal from upper middle left to lower right
    # is that falling stroke continued to the corner. It does not NFKC-fold
    # to a slash either, but it still splits the next component. The lower
    # left block diagonal from upper middle left to lower centre is that
    # shorter falling stroke stopped at the lower centre. It does not
    # NFKC-fold to a slash either, but it still splits the next component.
    # The lower left block diagonal from lower middle left to lower right
    # is that short falling stroke along the lower edge. It does not
    # NFKC-fold to a slash either, but it still splits the next component.
    # The lower left block diagonal from lower middle left to lower centre
    # is that shorter falling stroke stopped before the corner. It does not
    # NFKC-fold to a slash either, but it still splits the next component.
    # The lower right block diagonal from lower left to upper centre is
    # that rising stroke as a narrow block. It does not NFKC-fold to a
    # slash either, but it still splits the next component. The lower
    # right block diagonal from lower middle left to upper right is that
    # same rising stroke as a wider block. It does not NFKC-fold to a
    # slash either, but it still splits the next component. The lower
    # right block diagonal from lower middle left to upper middle right
    # is that rising stroke across the middle. It does not NFKC-fold to
    # a slash either, but it still splits the next component. The lower
    # right block diagonal from lower middle left to upper centre is that
    # rising stroke stopped at the centre. It does not NFKC-fold to a
    # slash either, but it still splits the next component. The lower
    # right block diagonal from upper middle left to upper right is that
    # rising stroke along the top. It does not NFKC-fold to a slash
    # either, but it still splits the next component. The lower right
    # block diagonal from upper middle left to upper centre is that
    # shorter rising stroke along the top. It does not NFKC-fold to a
    # slash either, but it still splits the next component. The lower
    # right block diagonal from lower centre to upper right is that
    # wider rising stroke starting at the lower centre. It does not
    # NFKC-fold to a slash either, but it still splits the next
    # component. The lower right block diagonal from lower left to upper
    # middle right is that rising stroke continued to the corner. It does
    # not NFKC-fold to a slash either, but it still splits the next
    # component. The lower right block diagonal from lower centre to upper
    # middle right is that shorter rising stroke starting at the lower
    # centre. It does not NFKC-fold to a slash either, but it still splits
    # the next component. The lower right block diagonal from lower left to
    # lower middle right is that short rising stroke along the lower edge.
    # It does not NFKC-fold to a slash either, but it still splits the next
    # component. The lower right block diagonal from lower centre to lower
    # middle right is that shorter rising stroke stopped before the corner.
    # It does not NFKC-fold to a slash either, but it still splits the next
    # component. The other wider upper-left block diagonals stay out.
    ord('\U0001fb66'): '/',
    ord('\U0001fb65'): '/',
    ord('\U0001fb67'): '/',
    ord('\U0001fb64'): '/',
    ord('\U0001fb63'): '/',
    ord('\U0001fb62'): '/',
    ord('\U0001fb56'): '/',
    ord('\U0001fb55'): '/',
    ord('\U0001fb54'): '/',
    ord('\U0001fb53'): '/',
    ord('\U0001fb52'): '/',
    ord('\U0001fb50'): '/',
    ord('\U0001fb4f'): '/',
    ord('\U0001fb51'): '/',
    ord('\U0001fb4e'): '/',
    ord('\U0001fb4d'): '/',
    ord('\U0001fb4c'): '/',
    ord('\U0001fb40'): '/',
    ord('\U0001fb3f'): '/',
    ord('\U0001fb3e'): '/',
    ord('\U0001fb3d'): '/',
    ord('\U0001fb3c'): '/',
    ord('\U0001fb45'): '/',
    ord('\U0001fb44'): '/',
    ord('\U0001fb46'): '/',
    ord('\U0001fb43'): '/',
    ord('\U0001fb42'): '/',
    ord('\U0001fb41'): '/',
    ord('\U0001fb4b'): '/',
    ord('\U0001fb4a'): '/',
    ord('\U0001fb49'): '/',
    ord('\U0001fb48'): '/',
    ord('\U0001fb47'): '/',
    # The upper left block diagonal from lower left to upper centre is
    # that rising stroke as a narrow block. It does not NFKC-fold to a
    # slash, but it still splits the next component. The upper left block
    # diagonal from lower middle left to upper right is that same stroke
    # as a wider block. It does not NFKC-fold to a slash either, but it
    # still splits the next component. The upper left block diagonal from
    # lower middle left to upper middle right is that rising stroke across
    # the middle. It does not NFKC-fold to a slash either, but it still
    # splits the next component. The upper left block diagonal from lower
    # middle left to upper centre is that rising stroke stopped at the
    # centre. It does not NFKC-fold to a slash either, but it still splits
    # the next component. The upper left block diagonal from upper middle
    # left to upper right is that rising stroke along the top. It does not
    # NFKC-fold to a slash either, but it still splits the next component.
    # The upper left block diagonal from upper middle left to upper centre
    # is that shorter rising stroke along the top. It does not NFKC-fold
    # to a slash either, but it still splits the next component.
    # The upper left block diagonal from lower centre to upper right is
    # that wider rising stroke starting at the lower centre. It does not
    # NFKC-fold to a slash either, but it still splits the next component.
    # The upper left block diagonal from lower left to upper middle right
    # is that rising stroke continued to the corner. It does not NFKC-fold
    # to a slash either, but it still splits the next component.
    # The upper left block diagonal from lower centre to upper middle right
    # is that shorter rising stroke starting at the lower centre. It does
    # not NFKC-fold to a slash either, but it still splits the next
    # component. The upper left block diagonal from lower left to lower
    # middle right is that short rising stroke along the lower edge. It
    # does not NFKC-fold to a slash either, but it still splits the next
    # component. The upper left block diagonal from lower centre to lower
    # middle right is that shorter rising stroke stopped before the corner.
    # It does not NFKC-fold to a slash either, but it still splits the next
    # component. The light box-drawing diagonals that turn a corner stay out.
    ord('\U0001fb5b'): '/',
    ord('\U0001fb5a'): '/',
    ord('\U0001fb5c'): '/',
    ord('\U0001fb59'): '/',
    ord('\U0001fb58'): '/',
    ord('\U0001fb57'): '/',
    ord('\U0001fb61'): '/',
    ord('\U0001fb60'): '/',
    ord('\U0001fb5f'): '/',
    ord('\U0001fb5e'): '/',
    ord('\U0001fb5d'): '/',
    ord('\u27cb'): '/',
    ord('\u27cd'): '/',
    # The caret insertion point does not NFKC-fold to a slash, but it is
    # confusable with one and still splits a private name from the next part.
    ord('\u2041'): '/',
    # Double and triple solidus operators, and the OCR double backslash, do
    # not NFKC-fold to a slash. Each one still splits the following component.
    ord('\u2afd'): '/',
    ord('\u2afb'): '/',
    ord('\u244a'): '/',
    # CJK strokes P and SP are confusable with a solidus, and stroke D with a
    # reverse solidus. None of them NFKC-fold to a slash.
    ord('\u31d2'): '/',
    ord('\u31d3'): '/',
    ord('\u31d4'): '/',
    # Greek notation slashes and the vertical kana repeat halves do not
    # NFKC-fold to a slash, but each one still splits the next component.
    # The voiced upper half is that slash plus dakuten, and the lower half
    # is the backslash twin. The full vertical repeat is not a slash.
    ord('\u3033'): '/',
    ord('\u3034'): '/',
    ord('\u3035'): '/',
    ord('\U0001d23a'): '/',
    ord('\U0001d20f'): '/',
    ord('\U0001d23b'): '/',
    # Very heavy solidus and very heavy reverse solidus do not NFKC-fold
    # to a slash, but each one still splits the next component.
    ord('\U0001f67c'): '/',
    ord('\U0001f67d'): '/',
    # The dotted solidus does not NFKC-fold to a slash either.
    ord('\u2e4a'): '/',
    # The modifier letter dot slash is that same dotted stroke in small
    # form. It does not NFKC-fold to a slash, but it still splits the next
    # component. The dot vertical bar and the dot horizontal bar stay out.
    ord('\ua718'): '/',
    # Katakana no, Old Coptic esh, and the slash radical skeleton to a solidus
    # and do not NFKC-fold to one. The radical's ideograph is that same
    # prototype. Halfwidth katakana no folds to katakana no, so the post-NFKC
    # translate covers it. The small Old Coptic esh does not NFKC-fold to the
    # capital, so the capital entry does not cover it. The dot radical and its
    # ideograph skeleton to a reverse solidus instead.
    ord('\u30ce'): '/',
    ord('\u4e3f'): '/',
    ord('\u2f03'): '/',
    ord('\u2cc6'): '/',
    ord('\u2cc7'): '/',
    ord('\u4e36'): '/',
    ord('\u2f02'): '/',
    # Account of, addressed to the subject, care of, and cada una expand to a
    # letter, an ASCII solidus, and a letter. That glues both neighboring
    # components, so a private name on either side stays hidden. They do not
    # NFKC-fold to a slash by themselves. The other letterlike signs have no
    # slash and stay out.
    ord('\u2100'): '/',
    ord('\u2101'): '/',
    ord('\u2105'): '/',
    ord('\u2106'): '/',
    # Vulgar fractions expand to digits around a fraction slash. Those digits
    # glue onto both neighboring components, so a private name stays hidden.
    # Fraction numerator one has no trailing digit: a following name is already
    # exposed, and the name before it is not. None of them NFKC-fold to a
    # slash. The fraction slash itself is already a separator.
    ord('\u00bc'): '/',
    ord('\u00bd'): '/',
    ord('\u00be'): '/',
    ord('\u2150'): '/',
    ord('\u2151'): '/',
    ord('\u2152'): '/',
    ord('\u2153'): '/',
    ord('\u2154'): '/',
    ord('\u2155'): '/',
    ord('\u2156'): '/',
    ord('\u2157'): '/',
    ord('\u2158'): '/',
    ord('\u2159'): '/',
    ord('\u215a'): '/',
    ord('\u215b'): '/',
    ord('\u215c'): '/',
    ord('\u215d'): '/',
    ord('\u215e'): '/',
    ord('\u215f'): '/',
    ord('\u2189'): '/',
    # These CJK squares expand to letters around a solidus or a division
    # slash. The extra letters glue a private name to the neighboring
    # component. They do not NFKC-fold to a slash by themselves. Squares
    # with no slash stay out.
    ord('\u3328'): '/',
    ord('\u3329'): '/',
    ord('\u33a7'): '/',
    ord('\u33a8'): '/',
    ord('\u33ae'): '/',
    ord('\u33af'): '/',
    ord('\u33c6'): '/',
    ord('\u33de'): '/',
    ord('\u33df'): '/',
    # Reverse solidus preceding subset and superset preceding solidus do not
    # NFKC-fold to a slash. Each skeleton still has a slash plus a syllabic
    # letter, and that letter glues a private name to the next component.
    ord('\u27c8'): '/',
    ord('\u27c9'): '/',
    # APL slash bar and backslash bar do not NFKC-fold to a slash. Each one
    # still splits the next component. Quad slash and quad backslash put
    # that bar inside a square. The square would glue a private name to the
    # next component, so each stays one slash. Circled division slash and
    # circled reverse solidus put that slash inside a circle. The circle
    # would glue a private name to the next component, so each stays one
    # slash. APL circle backslash is that slash inside an APL circle. The
    # circle would glue a private name to the next component, so it stays
    # one slash. The circled division sign and the combining enclosing
    # circle backslash stay out.
    ord('\u233f'): '/',
    ord('\u2340'): '/',
    ord('\u2341'): '/',
    ord('\u2342'): '/',
    ord('\u2349'): '/',
    ord('\u2298'): '/',
    ord('\u29b8'): '/',
    # Squared rising and falling diagonal slashes do not NFKC-fold to a
    # slash, but each one still splits the next component.
    ord('\u29c4'): '/',
    ord('\u29c5'): '/',
    # The upper left to lower right fill is that falling stroke repeated
    # across the cell. It does not NFKC-fold to a slash, but it still splits
    # the next component. The upper right to lower left fill is that rising
    # stroke repeated across the cell. It does not NFKC-fold to a slash
    # either, but it still splits the next component.
    ord('\U0001fb98'): '/',
    ord('\U0001fb99'): '/',
    # The square with upper left to lower right fill puts that falling
    # stroke inside a square. The square would glue a private name to the
    # next component, so it stays one slash. It does not NFKC-fold to a
    # slash. The square with upper right to lower left fill puts that
    # rising stroke inside a square. The square would glue a private name
    # to the next component, so it stays one slash. It does not NFKC-fold
    # to a slash either. The square with diagonal crosshatch fill puts
    # both strokes inside a square. The rising stroke still splits the
    # next component, and the square would glue a private name to it, so
    # it stays one slash. It does not NFKC-fold to a slash either. The
    # light diagonal cross puts both strokes in the cell. The rising
    # stroke still splits the next component, so it stays one slash. It
    # does not NFKC-fold to a slash either. The light diagonal from upper
    # centre to middle left to lower centre turns a corner. Its rising
    # half still splits the next component, so it stays one slash. It does
    # not NFKC-fold to a slash either. The light diagonal from upper centre
    # to middle right to lower centre turns a corner. Its rising half still
    # splits the next component, so it stays one slash. It does not
    # NFKC-fold to a slash either. The light diagonal from middle left to
    # lower centre to middle right turns a corner. Its rising half still
    # splits the next component, so it stays one slash. It does not
    # NFKC-fold to a slash either. The light diagonal from middle left to
    # upper centre to middle right turns a corner. Its rising half still
    # splits the next component, so it stays one slash. It does not
    # NFKC-fold to a slash either. The light diagonal from upper centre to
    # middle left and middle right to lower centre puts both rising
    # strokes in the cell. Each rising stroke still splits the next
    # component, so it stays one slash. It does not NFKC-fold to a slash
    # either. The light diagonal from upper centre to middle right and
    # middle left to lower centre puts both falling strokes in the cell.
    # Each falling stroke still splits the next component, so it stays
    # one slash. It does not NFKC-fold to a slash either. The light
    # diagonal from upper centre to middle right to lower centre to
    # middle left turns through both halves. Its rising half still
    # splits the next component, so it stays one slash. It does not
    # NFKC-fold to a slash either. The light diagonal from upper centre
    # to middle left to lower centre to middle right turns through both
    # halves. Its rising half still splits the next component, so it
    # stays one slash. It does not NFKC-fold to a slash either. The
    # light diagonal from middle left to upper centre to middle right to
    # lower centre turns through both halves. Its rising half still
    # splits the next component, so it stays one slash. It does not
    # NFKC-fold to a slash either. The light diagonal from middle right
    # to upper centre to middle left to lower centre turns through both
    # halves. Its rising half still splits the next component, so it
    # stays one slash. It does not NFKC-fold to a slash either. The
    # light diagonal diamond and the negative diamond stay out.
    ord('\u25a7'): '/',
    ord('\u25a8'): '/',
    ord('\u25a9'): '/',
    ord('\u2573'): '/',
    ord('\U0001fba4'): '/',
    ord('\U0001fba5'): '/',
    ord('\U0001fba6'): '/',
    ord('\U0001fba7'): '/',
    ord('\U0001fba8'): '/',
    ord('\U0001fba9'): '/',
    ord('\U0001fbaa'): '/',
    ord('\U0001fbab'): '/',
    ord('\U0001fbac'): '/',
    ord('\U0001fbad'): '/',
}

def normalized_rel(rel):
    # Fold colon lookalikes before NFKC. Double colon equal expands to '::='
    # and would otherwise glue '=' onto the following name. The same mark
    # fold used for a single filename applies to the whole relative path.
    return fold_separators(rel, SEPARATOR_LIKE).replace('\\', '/')

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

# Unicode tag space and tag punctuation do not NFKC-fold. They are format
# characters, so the component reading strips them. That still blocks a tag
# sitting inside auth.json, but it also glues auth.json to the next component,
# joins "Copy of" into one word, and deletes the dot, colon, or hyphen the
# private name needs. The punctuation reading is tried only after that strip
# reading fails. Language tag and cancel tag are not ASCII copies and stay out.
# Tag letters are the same kind of format character. Stripping one deletes the
# letter auth.json needs. That reading is tried after punctuation, including
# when the same name also uses a tag separator. An inserted tag letter is
# still removed by the strip reading. Tag digits are a later reading: stripping
# one deletes the digit in id_ed25519, while folding it keeps an inserted tag
# letter from renaming that file.
TAG_PUNCT_CHARS = frozenset('\U000E0020\U000E002D\U000E002E\U000E002F\U000E003A\U000E005C')
TAG_PUNCT = str.maketrans({
    0xE0020: ' ',
    0xE002D: '-',
    0xE002E: '.',
    0xE002F: '/',
    0xE003A: ':',
    0xE005C: '/',
})
_TAG_LETTERS = (*range(0xE0041, 0xE005B), *range(0xE0061, 0xE007B))
TAG_LETTER_CHARS = frozenset(chr(cp) for cp in _TAG_LETTERS)
TAG_LETTER = str.maketrans({cp: chr(cp - 0xE0000) for cp in _TAG_LETTERS})
_TAG_DIGITS = range(0xE0030, 0xE003A)
TAG_DIGIT_CHARS = frozenset(chr(cp) for cp in _TAG_DIGITS)
TAG_DIGIT = str.maketrans({cp: chr(cp - 0xE0000) for cp in _TAG_DIGITS})
# Tag low line copies '_' and does not NFKC-fold. Stripping it joins id_rsa
# into one word. The low-line reading is tried after digits. Folding only the
# low line still strips any other tag, so an extra tag letter cannot rename
# the file. A second reading folds the other tag copies too.
TAG_LOW_LINE = '\U000E005F'
TAG_LOW_LINE_FOLD = str.maketrans({0xE005F: '_'})
# Tag tilde copies '~' and does not NFKC-fold. It is a format character, so
# the component reading strips it. That turns auth.json~1 into auth.json1 and
# the editor-number alias never runs. The tilde reading is tried after the
# low line. Folding only the tilde still strips any other tag, so an extra
# tag letter cannot rename the file. A second reading folds the other tag
# copies too.
TAG_TILDE = '\U000E007E'
TAG_TILDE_FOLD = str.maketrans({0xE007E: '~'})
# Tag parentheses copy '(' and ')' and do not NFKC-fold. They are format
# characters, so the component reading strips them. That turns
# auth (1).json into auth 1.json and the copy-index alias never runs.
# The parenthesis reading is tried after the tilde. Folding only the
# parentheses still strips any other tag, so an extra tag letter cannot
# rename the file. A second reading folds the other tag copies too.
TAG_PAREN_CHARS = frozenset('\U000E0028\U000E0029')
TAG_PAREN_FOLD = str.maketrans({0xE0028: '(', 0xE0029: ')'})

def path_reason(rel):
    # A private name is not safe just because a later component looks ordinary.
    # auth.json/payload.txt and a backslash twin are the same leak.
    # Soft hyphen is a format character. Stripping it keeps a split auth.json
    # blocked, but it also joins launch-history.json into one word. The hyphen
    # reading is tried only after that strip reading fails.
    if reason := component_path_reason(rel):
        return reason
    shy = chr(0x00AD)
    if shy in rel:
        if reason := component_path_reason(rel.replace(shy, '-')):
            return reason
    has_tag_punct = any(ch in TAG_PUNCT_CHARS for ch in rel)
    has_tag_letter = any(ch in TAG_LETTER_CHARS for ch in rel)
    if has_tag_punct:
        # Punctuation folding still strips any other tag, so an extra tag
        # letter beside auth.json cannot spell a different filename.
        if reason := component_path_reason(rel.translate(TAG_PUNCT)):
            return reason
    if has_tag_letter:
        folded = rel.translate(TAG_LETTER)
        if has_tag_punct:
            folded = rel.translate(TAG_PUNCT).translate(TAG_LETTER)
        if reason := component_path_reason(folded):
            return reason
    if any(ch in TAG_DIGIT_CHARS for ch in rel):
        # Digit folding still strips any other tag, so an extra tag letter
        # beside id_ed25519 cannot spell a different filename.
        if reason := component_path_reason(rel.translate(TAG_DIGIT)):
            return reason
        folded = rel.translate(TAG_PUNCT).translate(TAG_LETTER).translate(TAG_DIGIT)
        if reason := component_path_reason(folded):
            return reason
    if TAG_LOW_LINE in rel:
        if reason := component_path_reason(rel.translate(TAG_LOW_LINE_FOLD)):
            return reason
        folded = rel.translate(TAG_PUNCT).translate(TAG_LETTER).translate(TAG_DIGIT).translate(TAG_LOW_LINE_FOLD)
        if reason := component_path_reason(folded):
            return reason
    if TAG_TILDE in rel:
        if reason := component_path_reason(rel.translate(TAG_TILDE_FOLD)):
            return reason
        folded = rel.translate(TAG_PUNCT).translate(TAG_LETTER).translate(TAG_DIGIT).translate(TAG_LOW_LINE_FOLD).translate(TAG_TILDE_FOLD)
        if reason := component_path_reason(folded):
            return reason
    if any(ch in TAG_PAREN_CHARS for ch in rel):
        if reason := component_path_reason(rel.translate(TAG_PAREN_FOLD)):
            return reason
        folded = rel.translate(TAG_PUNCT).translate(TAG_LETTER).translate(TAG_DIGIT).translate(TAG_LOW_LINE_FOLD).translate(TAG_TILDE_FOLD).translate(TAG_PAREN_FOLD)
        if reason := component_path_reason(folded):
            return reason
    return ''

def component_path_reason(rel):
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


def math_ascii(cp):
    # Same ranges the credential redactor folds. Greek mathematical letters
    # and the holes reserved for letterlike forms are not ASCII copies.
    if 0x1D400 <= cp <= 0x1D419:
        return chr(cp - 0x1D400 + ord('A'))
    if 0x1D41A <= cp <= 0x1D433:
        return chr(cp - 0x1D41A + ord('a'))
    if 0x1D434 <= cp <= 0x1D44D:
        return chr(cp - 0x1D434 + ord('A'))
    if 0x1D44E <= cp <= 0x1D454:
        return chr(cp - 0x1D44E + ord('a'))
    if 0x1D456 <= cp <= 0x1D467:
        return chr(cp - 0x1D456 + ord('i'))
    if 0x1D468 <= cp <= 0x1D481:
        return chr(cp - 0x1D468 + ord('A'))
    if 0x1D482 <= cp <= 0x1D49B:
        return chr(cp - 0x1D482 + ord('a'))
    if cp == 0x1D49C:
        return 'A'
    if 0x1D49E <= cp <= 0x1D49F:
        return chr(cp - 0x1D49E + ord('C'))
    if cp == 0x1D4A2:
        return 'G'
    if 0x1D4A5 <= cp <= 0x1D4A6:
        return chr(cp - 0x1D4A5 + ord('J'))
    if 0x1D4A9 <= cp <= 0x1D4AC:
        return chr(cp - 0x1D4A9 + ord('N'))
    if 0x1D4AE <= cp <= 0x1D4B5:
        return chr(cp - 0x1D4AE + ord('S'))
    if 0x1D4B6 <= cp <= 0x1D4B9:
        return chr(cp - 0x1D4B6 + ord('a'))
    if cp == 0x1D4BB:
        return 'f'
    if 0x1D4BD <= cp <= 0x1D4C3:
        return chr(cp - 0x1D4BD + ord('h'))
    if 0x1D4C5 <= cp <= 0x1D4CF:
        return chr(cp - 0x1D4C5 + ord('p'))
    if 0x1D4D0 <= cp <= 0x1D4E9:
        return chr(cp - 0x1D4D0 + ord('A'))
    if 0x1D4EA <= cp <= 0x1D503:
        return chr(cp - 0x1D4EA + ord('a'))
    if 0x1D504 <= cp <= 0x1D505:
        return chr(cp - 0x1D504 + ord('A'))
    if 0x1D507 <= cp <= 0x1D50A:
        return chr(cp - 0x1D507 + ord('D'))
    if 0x1D50D <= cp <= 0x1D514:
        return chr(cp - 0x1D50D + ord('J'))
    if 0x1D516 <= cp <= 0x1D51C:
        return chr(cp - 0x1D516 + ord('S'))
    if 0x1D51E <= cp <= 0x1D537:
        return chr(cp - 0x1D51E + ord('a'))
    if 0x1D538 <= cp <= 0x1D539:
        return chr(cp - 0x1D538 + ord('A'))
    if 0x1D53B <= cp <= 0x1D53E:
        return chr(cp - 0x1D53B + ord('D'))
    if 0x1D540 <= cp <= 0x1D544:
        return chr(cp - 0x1D540 + ord('I'))
    if cp == 0x1D546:
        return 'O'
    if 0x1D54A <= cp <= 0x1D550:
        return chr(cp - 0x1D54A + ord('S'))
    if 0x1D552 <= cp <= 0x1D56B:
        return chr(cp - 0x1D552 + ord('a'))
    if 0x1D56C <= cp <= 0x1D585:
        return chr(cp - 0x1D56C + ord('A'))
    if 0x1D586 <= cp <= 0x1D59F:
        return chr(cp - 0x1D586 + ord('a'))
    if 0x1D5A0 <= cp <= 0x1D5B9:
        return chr(cp - 0x1D5A0 + ord('A'))
    if 0x1D5BA <= cp <= 0x1D5D3:
        return chr(cp - 0x1D5BA + ord('a'))
    if 0x1D5D4 <= cp <= 0x1D5ED:
        return chr(cp - 0x1D5D4 + ord('A'))
    if 0x1D5EE <= cp <= 0x1D607:
        return chr(cp - 0x1D5EE + ord('a'))
    if 0x1D608 <= cp <= 0x1D621:
        return chr(cp - 0x1D608 + ord('A'))
    if 0x1D622 <= cp <= 0x1D63B:
        return chr(cp - 0x1D622 + ord('a'))
    if 0x1D63C <= cp <= 0x1D655:
        return chr(cp - 0x1D63C + ord('A'))
    if 0x1D656 <= cp <= 0x1D66F:
        return chr(cp - 0x1D656 + ord('a'))
    if 0x1D670 <= cp <= 0x1D689:
        return chr(cp - 0x1D670 + ord('A'))
    if 0x1D68A <= cp <= 0x1D6A3:
        return chr(cp - 0x1D68A + ord('a'))
    if 0x1D7CE <= cp <= 0x1D7D7:
        return chr(cp - 0x1D7CE + ord('0'))
    if 0x1D7D8 <= cp <= 0x1D7E1:
        return chr(cp - 0x1D7D8 + ord('0'))
    if 0x1D7E2 <= cp <= 0x1D7EB:
        return chr(cp - 0x1D7E2 + ord('0'))
    if 0x1D7EC <= cp <= 0x1D7F5:
        return chr(cp - 0x1D7EC + ord('0'))
    if 0x1D7F6 <= cp <= 0x1D7FF:
        return chr(cp - 0x1D7F6 + ord('0'))
    return {
        0x2102: 'C', 0x210A: 'g', 0x210B: 'H', 0x210C: 'H', 0x210D: 'H',
        0x210E: 'h', 0x2110: 'I', 0x2111: 'I', 0x2112: 'L', 0x2113: 'l',
        0x2115: 'N', 0x2119: 'P', 0x211A: 'Q', 0x211B: 'R', 0x211C: 'R',
        0x211D: 'R', 0x2124: 'Z', 0x2128: 'Z', 0x212C: 'B', 0x212D: 'C',
        0x212F: 'e', 0x2130: 'E', 0x2131: 'F', 0x2133: 'M', 0x2134: 'o',
        0x2145: 'D', 0x2146: 'd', 0x2147: 'e', 0x2148: 'i', 0x2149: 'j',
    }.get(cp)


def enclosed_ascii(cp):
    # Circled digits one through nine, circled zero, and circled or squared
    # letters fold to one ASCII character. Numbers above nine expand to two
    # digits in circled_number.
    if 0x2460 <= cp <= 0x2468:
        return chr(cp - 0x2460 + ord('1'))
    if 0x24B6 <= cp <= 0x24CF:
        return chr(cp - 0x24B6 + ord('A'))
    if 0x24D0 <= cp <= 0x24E9:
        return chr(cp - 0x24D0 + ord('a'))
    if cp == 0x24EA:
        return '0'
    if cp == 0x1F12B:
        return 'C'
    if cp == 0x1F12C:
        return 'R'
    if 0x1F130 <= cp <= 0x1F149:
        return chr(cp - 0x1F130 + ord('A'))
    return None


def circled_number(cp):
    # NFKC expands these to two ASCII digits. Negative circled numbers and
    # numbers on black squares do not, so they stay out.
    if 0x2469 <= cp <= 0x2473:
        return str((cp - 0x2469) + 10)
    if 0x3251 <= cp <= 0x325F:
        return str((cp - 0x3251) + 21)
    if 0x32B1 <= cp <= 0x32BF:
        return str((cp - 0x32B1) + 36)
    return None


def super_sub_ascii(cp):
    # Superscript and subscript letters and digits NFKC-fold to one ASCII
    # character. The holes in those blocks are not letters and stay out.
    singles = {
        0x00AA: 'a', 0x00BA: 'o', 0x00B2: '2', 0x00B3: '3', 0x00B9: '1',
        0x2070: '0', 0x2071: 'i', 0x207F: 'n',
    }
    if cp in singles:
        return singles[cp]
    if 0x2074 <= cp <= 0x2079:
        return chr(cp - 0x2074 + ord('4'))
    if 0x2080 <= cp <= 0x2089:
        return chr(cp - 0x2080 + ord('0'))
    if 0x2090 <= cp <= 0x2093:
        return 'aeox'[cp - 0x2090]
    if 0x2095 <= cp <= 0x209C:
        return 'hklmnpst'[cp - 0x2095]
    return None

def modifier_ascii(cp):
    # Modifier letters that NFKC-fold to one ASCII letter. The credential
    # redactor uses the same set. Latin subscript letters in the phonetic
    # blocks do the same, so they are listed too. Kelvin sign and the
    # information source are the letterlike symbols with that one-letter
    # fold. Hooked, turned, and non-Latin modifiers are not ASCII copies.
    # Roman numerals and segmented digits stay out. Long s is folded
    # separately.
    return {
        0x02B0: 'h', 0x02B2: 'j', 0x02B3: 'r', 0x02B7: 'w', 0x02B8: 'y',
        0x02E1: 'l', 0x02E2: 's', 0x02E3: 'x',
        0x1D2C: 'A', 0x1D2E: 'B', 0x1D30: 'D', 0x1D31: 'E',
        0x1D33: 'G', 0x1D34: 'H', 0x1D35: 'I', 0x1D36: 'J', 0x1D37: 'K',
        0x1D38: 'L', 0x1D39: 'M', 0x1D3A: 'N', 0x1D3C: 'O', 0x1D3E: 'P',
        0x1D3F: 'R', 0x1D40: 'T', 0x1D41: 'U', 0x1D42: 'W',
        0x1D43: 'a', 0x1D47: 'b', 0x1D48: 'd', 0x1D49: 'e', 0x1D4D: 'g',
        0x1D4F: 'k', 0x1D50: 'm', 0x1D52: 'o', 0x1D56: 'p', 0x1D57: 't',
        0x1D58: 'u', 0x1D5B: 'v',
        0x1D62: 'i', 0x1D63: 'r', 0x1D64: 'u', 0x1D65: 'v',
        0x1D9C: 'c', 0x1DA0: 'f', 0x1DBB: 'z',
        0x2C7C: 'j', 0x2C7D: 'V',
        0xA7F2: 'C', 0xA7F3: 'F', 0xA7F4: 'Q',
        0x107A5: 'q',
        0x212A: 'K', 0x2139: 'i',
    }.get(cp)


def segmented_digit(cp):
    # Segmented digits NFKC-fold to one ASCII digit. This pass does not run
    # NFKC. Circled numbers, parenthesized numbers, and digit full stops are
    # other folds, so they stay out of this one.
    if 0x1FBF0 <= cp <= 0x1FBF9:
        return chr(cp - 0x1FBF0 + ord('0'))
    return None


def roman_ascii(cp):
    # Roman numerals that NFKC-fold to one ASCII letter. Additive numerals
    # expand to more than one letter and stay out. Archaic thousand signs
    # do not fold to ASCII.
    return {
        0x2160: 'I', 0x2164: 'V', 0x2169: 'X', 0x216C: 'L',
        0x216D: 'C', 0x216E: 'D', 0x216F: 'M',
        0x2170: 'i', 0x2174: 'v', 0x2179: 'x', 0x217C: 'l',
        0x217D: 'c', 0x217E: 'd', 0x217F: 'm',
    }.get(cp)


def additive_roman(cp):
    # Roman numerals that NFKC expands to more than one ASCII letter.
    # Single-letter numerals are folded by roman_ascii. Archaic thousand
    # signs and late forms do not fold to ASCII letters.
    return {
        0x2161: 'II', 0x2162: 'III', 0x2163: 'IV', 0x2165: 'VI',
        0x2166: 'VII', 0x2167: 'VIII', 0x2168: 'IX',
        0x216A: 'XI', 0x216B: 'XII',
        0x2171: 'ii', 0x2172: 'iii', 0x2173: 'iv', 0x2175: 'vi',
        0x2176: 'vii', 0x2177: 'viii', 0x2178: 'ix',
        0x217A: 'xi', 0x217B: 'xii',
    }.get(cp)


def long_s_ascii(cp):
    # Latin small letter long s NFKC-folds to ASCII s. Long s with a dot
    # or a stroke stays phonetic. The long s t ligature expands to "st"
    # and stays on the ligature fold. Subscript s is a superscript fold.
    if cp == 0x017F:
        return 's'
    return None


def latin_ligature(cp):
    # Latin ligatures and compatibility digraphs that NFKC expands to
    # ASCII letters. Long s, roman numerals, the trademark sign, and
    # squared unit symbols stay on their own folds.
    return {
        0x0132: 'IJ', 0x0133: 'ij',
        0x01C7: 'LJ', 0x01C8: 'Lj', 0x01C9: 'lj',
        0x01CA: 'NJ', 0x01CB: 'Nj', 0x01CC: 'nj',
        0x01F1: 'DZ', 0x01F2: 'Dz', 0x01F3: 'dz',
        0xFB00: 'ff', 0xFB01: 'fi', 0xFB02: 'fl',
        0xFB03: 'ffi', 0xFB04: 'ffl',
        0xFB05: 'st', 0xFB06: 'st',
    }.get(cp)


def low_line_ascii(cp):
    # Presentation forms and the fullwidth low line NFKC-fold to ASCII '_'.
    # A double low line expands to a space plus a mark, and a low macron
    # does not fold to '_'. Fullwidth low line is also inside the fullwidth
    # ASCII block, so either pass produces the same byte.
    if cp in {0xFE33, 0xFE34, 0xFE4D, 0xFE4E, 0xFE4F, 0xFF3F}:
        return '_'
    return None

def fold_content(data):
    # Tag ASCII copies a stored byte and does not NFKC-fold. Other format
    # characters, including the language tag and cancel tag, only split a
    # token. Combining marks do the same. Fullwidth ASCII is a compatibility
    # copy of the same byte: this pass does not run NFKC, so leaving it in
    # place split a token, JWT, private key, or personal path. Fold the
    # copies, then drop format characters and marks. Line breaks stay put so
    # a wrapped sk- line is not glued to the next line.
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        return data
    out = []
    changed = False
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
            changed = True
            continue
        # U+FF01..U+FF5E is fullwidth ASCII punctuation, digits, and letters.
        # The offset is the NFKC compatibility mapping. Ideographic space is
        # not in this block and stays out, so it cannot join two lines.
        if 0xFF01 <= cp <= 0xFF5E:
            out.append(chr(cp - 0xFEE0))
            changed = True
            continue
        # Mathematical letters and digits NFKC-fold to ASCII. This pass does
        # not run NFKC, so a token written with them stayed split. Greek
        # mathematical letters are not in math_ascii and stay out.
        mapped = math_ascii(cp)
        if mapped is not None:
            out.append(mapped)
            changed = True
            continue
        # Circled and squared alphanumerics NFKC-fold to one ASCII letter or
        # digit. This pass does not run NFKC. Numbers above nine expand to
        # two digits; a list marker still cannot spell a token by itself.
        mapped = enclosed_ascii(cp)
        if mapped is not None:
            out.append(mapped)
            changed = True
            continue
        expanded = circled_number(cp)
        if expanded is not None:
            out.append(expanded)
            changed = True
            continue
        # Superscript and subscript forms NFKC-fold to ASCII. This pass does
        # not run NFKC, so a token written with them stayed split.
        mapped = super_sub_ascii(cp)
        if mapped is not None:
            out.append(mapped)
            changed = True
            continue
        # Modifier letters NFKC-fold to one ASCII letter. This pass does not
        # run NFKC, so a token written with them stayed split. Phonetic
        # modifiers that are not ASCII copies stay out.
        mapped = modifier_ascii(cp)
        if mapped is not None:
            out.append(mapped)
            changed = True
            continue
        # Segmented digits NFKC-fold to ASCII digits. This pass does not run
        # NFKC, so a token or JWT written with them stayed split.
        mapped = segmented_digit(cp)
        if mapped is not None:
            out.append(mapped)
            changed = True
            continue
        # Single-letter roman numerals NFKC-fold to ASCII. This pass does
        # not run NFKC, so a token written with them stayed split. Additive
        # numerals expand to more than one letter and stay out.
        mapped = roman_ascii(cp)
        if mapped is not None:
            out.append(mapped)
            changed = True
            continue
        # Additive roman numerals expand to more than one ASCII letter.
        # This pass does not run NFKC, so a token written with them stayed
        # split. One numeral is not long enough to spell a token by itself.
        expanded = additive_roman(cp)
        if expanded is not None:
            out.append(expanded)
            changed = True
            continue
        # Latin small letter long s NFKC-folds to ASCII s. This pass does
        # not run NFKC, so a token, JWT, or personal path written with it
        # stayed split. Long s with a dot or a stroke stays phonetic, and
        # the long s t ligature expands to two letters on its own fold.
        mapped = long_s_ascii(cp)
        if mapped is not None:
            out.append(mapped)
            changed = True
            continue
        # Latin ligatures and compatibility digraphs expand to ASCII
        # letters. This pass does not run NFKC, so a token or JWT written
        # with them stayed split. One ligature is not long enough to spell
        # a token by itself. Long s and roman numerals stay on their own folds.
        expanded = latin_ligature(cp)
        if expanded is not None:
            out.append(expanded)
            changed = True
            continue
        # Low lines NFKC-fold to ASCII '_'. This pass does not run NFKC, so
        # a token or JWT written with a presentation form stayed split. A
        # double low line and a low macron are not '_', so they stay out.
        mapped = low_line_ascii(cp)
        if mapped is not None:
            out.append(mapped)
            changed = True
            continue
        # Hyphen lookalikes are the same set the path check uses. This pass
        # does not run NFKC, so a token, JWT, or PEM header written with one
        # stayed split. Fold them before marks are dropped: a spacing hyphen
        # would otherwise disappear, and the header would no longer match.
        # Soft hyphen is format, not in this table, and is folded next.
        mapped = HYPHEN_LIKE.get(cp)
        if mapped is not None:
            out.append(mapped)
            changed = True
            continue
        # Soft hyphen is a format character. Dropping it with the other
        # format characters removes a hyphen a PEM header or sk- prefix
        # needs, so the secret stayed hidden. Fold it to ASCII '-' first.
        # Other format characters still only split a token.
        if cp == 0x00AD:
            out.append('-')
            changed = True
            continue
        # Full stops are the same set the path check uses. This pass does
        # not run NFKC, so a JWT whose separators were one-dot leaders or
        # ideographic stops stayed split. Spacing stops are folded here too:
        # dropping the musical augmentation dot would erase the separator.
        # A full stop is not a token character, so it still splits sk- text.
        mapped = DOT_LIKE.get(cp)
        if mapped is not None:
            out.append(mapped)
            changed = True
            continue
        # Colon lookalikes are the same set the path check uses. This pass
        # does not run NFKC, so a personal Windows path whose drive separator
        # was a ratio, modifier colon, or visarga stayed split. Spacing
        # visargas are folded here too: dropping one would erase the
        # separator. Double colon equal stays one colon, matching the path
        # check, instead of expanding to '::='. A colon is not a token
        # character, so it still splits sk- text.
        mapped = COLON_LIKE.get(cp)
        if mapped is not None:
            out.append(mapped)
            changed = True
            continue
        # Slash lookalikes are the same set the path check uses. This pass
        # does not run NFKC, so a personal Windows path written with a yen
        # sign, division slash, or small reverse solidus stayed split.
        # Fullwidth solidus is already folded above. Expanding forms such as
        # vulgar fractions stay one slash, matching the path check, so the
        # extra digits cannot glue the name back together. A slash is not a
        # token character, so it still splits sk- text.
        mapped = SEPARATOR_LIKE.get(cp)
        if mapped is not None:
            out.append(mapped)
            changed = True
            continue
        # Mn/Me/Mc add no base letter. Dropping them keeps a split token
        # visible to the byte patterns. Cc and line separators stay, so a
        # wrapped line is not joined.
        if unicodedata.category(ch) in {'Cf', 'Mn', 'Me', 'Mc'}:
            changed = True
            continue
        out.append(ch)
    if not changed:
        return data
    return ''.join(out).encode('utf-8')

def content_reasons(data):
    views = (data, fold_content(data))
    found = []
    for label, pattern in RULES.items():
        if any(pattern.search(view) for view in views):
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
        'cache.sqlite-wal', 'state.sqlite-shm', 'app.sqlite-journal',
        'nested/state.sqlite3-wal', 'CACHE.SQLITE3-SHM', 'app.sqlite3-journal',
        'vault.db-wal', 'vault.db-shm', 'vault.db-journal',
        'Copy of cache.sqlite-wal', 'state.sqlite-wal.txt', 'nested/vault.db-shm/extra.txt',
        'launch\u2010history.json', 'cache.sqlite\u2011wal', 'vault.db\u2212journal',
        'cockpit\u2013integration.json', 'bridge\u2012identity.json', 'nested/state.sqlite3\ufe58shm',
        'sub2api\u2043account-1.json', 'handoff\u02d7notes.txt', 'config.toml.bak\u2796date',
        'codex_instances.json.gptbridge\U00010191backup-1', 'Copy of cache.sqlite\u2cbbwal',
        'launch\u1bf3history.json', 'cockpit\uaa7dprocess.json', 'nested/vault.db\u2cbashm/extra.txt',
        'auth.json.gptbridge\u174dbackup-1',
        'launch\u2014history.json', 'cache.sqlite\u2014wal', 'vault.db\u2015journal',
        'launch\u058ahistory.json', 'cache.sqlite\u05bewal', 'vault.db\u1400journal',
        'launch\u1806history.json', 'cockpit\u2e17integration.json', 'bridge\u2e1aidentity.json',
        'state.sqlite3\u2e40shm', 'cache.sqlite\u2e5dwal', 'nested/vault.db\u30a0journal/extra.txt',
        'launch\U00010eadhistory.json', 'Copy of cache.sqlite\u058awal',
        'launch\u2e3ahistory.json', 'cache.sqlite\u2e3bwal', 'vault.db\u301cjournal',
        'nested/cockpit\u3030integration.json', 'Copy of cache.sqlite\u2e3awal',
        'launch\u207bhistory.json', 'cache.sqlite\u208bwal', 'vault.db\ufe32journal',
        'launch\ufe63history.json', 'cache.sqlite\uff0dwal',
        'nested/cockpit\ufe63integration.json', 'bridge\ufe32identity.json',
        'state.sqlite3\u207bshm', 'Copy of cache.sqlite\uff0dwal',
        'nested/cockpit\u2014integration.json', 'bridge\ufe31identity.json',
        'state.sqlite3\u2015shm', 'Copy of cache.sqlite\ufe31wal',
        'launch\u00adhistory.json', 'cache.sqlite\u00adwal', 'vault.db\u00adjournal',
        'nested/cockpit\u00adintegration.json', 'au\u00adth.json', 'Copy of cache.sqlite\u00adwal',
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
        'auth\u2024json', 'accounts\ufe52json', 'credentials\ufe12json', 'tokens\uff61json',
        'nested/auth\u2024json/extra.txt', 'Copy of auth\ufe52json', 'auth\ufe12json.txt',
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
        'auth.json\u29f6secret.txt', 'credentials\u29f7token.txt', 'notes\u29f6id_rsa',
        'nested/id_rsa\u29f7x', 'Diagnostics\u29f6capture.png', 'tokens.json\u29f7extra.txt',
        'Diagnostics\u2216capture.png', 'credentials\u29f9token.txt', 'nested/id_rsa\u29f5x',
        'auth.json\u1735secret.txt', 'credentials\u2571token.txt', 'notes\u27cbid_rsa',
        'tokens.json\u2572extra.txt', 'accounts.json\u27cdnotes.txt', 'Diagnostics\u2571capture.png',
        'nested/id_rsa\u1735x', 'auth.json\u2572notes.txt',
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
        'readme\u1804auth.json', 'notes\ua6f4id_rsa', 'auth.json\u1804secret',
        'docs\ua6f4credentials.json', 'nested/file\u1804accounts.json', 'ID_RSA\ua6f4x',
        'readme\U00010781auth.json', 'notes\U00010782id_rsa', 'auth.json\U00010781secret',
        'docs\U00010782credentials.json', 'nested/file\U00010781accounts.json', 'ID_RSA\U00010782x',
        'readme\u2a74auth.json', 'notes\u2a74id_rsa', 'docs\u2a74credentials.json',
        'nested/file\u2a74accounts.json', 'ID_RSA\u2a74x', 'file\u2a74.netrc',
        'readme\u205dauth.json', 'notes\u2254id_rsa', 'file\u2255credentials.json',
        'docs\u2982accounts.json', 'nested/file\u2af6.netrc', 'ID_RSA\u205dx',
        'readme\U00012471auth.json', 'notes\U00012472id_rsa', 'file\U00012473credentials.json',
        'docs\U00012474accounts.json', 'nested/file\U0001DA8A.netrc', 'ID_RSA\U00012473x',
        'readme\u16ecauth.json', 'notes\u0831id_rsa', 'file\U00010af5credentials.json',
        'docs\U0001123aaccounts.json', 'nested/file\ua4fd.netrc', 'ID_RSA\ufe30x',
        'auth.json\ufe30secret', 'readme\ufe30auth.json',
        'readme\u0903auth.json', 'readme\u0a83id_rsa', 'readme\U00011002credentials.json',
        'readme\U00011082accounts.json', 'readme\U00011182.netrc', 'readme\U000115BE.env',
        'readme\U000116ACtokens.json', 'readme\U00011838secrets.json', 'readme\u0983auth.json',
        'readme\u0a03id_rsa', 'readme\u0c03credentials.json', 'readme\u0c83accounts.json',
        'readme\u0d03.netrc', 'readme\u0d83.env', 'readme\u0f7ftokens.json',
        'readme\u1038secrets.json', 'readme\u17c7auth.json', 'readme\U00011303id_rsa',
        'readme\U000114C1credentials.json', 'readme\U000119DFaccounts.json',
        'readme\U00011A39.netrc', 'readme\U00011C3E.env', 'auth.json\u0903secret',
        'nested/file\u0983.netrc',
        'auth\u06d4json', 'accounts\u0701json', 'credentials\u0702json', 'tokens\u1362json',
        'notes\u166ebak', '\u1803netrc', 'secrets\u1809env', 'id_ed25519\u2cf9txt',
        'auth\u2cfejson.txt', 'accounts\u2e3cjson.gz', 'tokens\ua4ffjson', 'credentials\ua60ejson',
        'auth\ua6f3json', 'notes\U00016af5bak', '\U00016e98netrc', 'id_rsa\U0001bc9ftxt',
        'accounts\U0001da88json',
        'auth..json', 'accounts...json', 'credentials....json', '..netrc', '...netrc',
        'auth\u2025json', 'accounts\u2026json', '\u2026netrc', 'id_rsa\u2025txt',
        'nested/tokens..json/extra.txt', 'Copy of auth...json',
        'auth\ua4f8json', 'accounts\U00010a50json', 'credentials\uabecjson',
        '\U00010a50netrc', 'id_rsa\ua4f8txt', 'Copy of auth\uabecjson',
        'nested/tokens\ua4f8json/extra.txt', 'auth\ua4f8\ua4f8json',
        'auth\ua4fajson', '\ua4fanetrc', 'id_rsa\ua4fatxt', 'Copy of auth\ua4fajson',
        'nested/tokens\ua4fajson/extra.txt', 'auth\ua4fa\ua4fajson', 'accounts\ua4fajson.txt',
        'auth\u0660json', 'accounts\u06f0json', 'credentials\U0001ecaejson',
        '\u0660netrc', '\u06f0env', 'id_rsa\U0001d16dtxt', 'secrets\u06f0env',
        'auth\u0660json.txt', 'Copy of auth\u06f0json', 'auth\u0660\u0660json',
        'nested/tokens\U0001ecaejson/extra.txt', 'ID_ED25519\u0660TXT',
        'auth.json\u2041secret.txt', 'credentials\u2041token.txt', 'notes\u2041id_rsa',
        'nested/id_rsa\u2041x', 'Diagnostics\u2041capture.png', 'tokens.json\u2041extra.txt',
        'auth.json\u2afdsecret.txt', 'credentials\u2afbtoken.txt', 'notes\u244aid_rsa',
        'nested/id_rsa\u2afdx', 'Diagnostics\u2afbcapture.png', 'tokens.json\u244aextra.txt',
        'auth.json\u31d2secret.txt', 'credentials\u31d3token.txt', 'notes\u31d4id_rsa',
        'nested/id_rsa\u31d2x', 'Diagnostics\u31d3capture.png', 'tokens.json\u31d4extra.txt',
        'auth.json\u3033secret.txt', 'auth.json\u3034secret.txt', 'credentials\u3035token.txt', 'credentials\U0001d23atoken.txt', 'notes\U0001d20fid_rsa',
        'nested/id_rsa\U0001d23bx', 'Diagnostics\u3033capture.png', 'tokens.json\U0001d23aextra.txt',
        'auth.json\U0001f67csecret.txt', 'credentials\U0001f67dtoken.txt', 'notes\U0001f67cid_rsa',
        'nested/id_rsa\U0001f67dx', 'Diagnostics\U0001f67ccapture.png', 'tokens.json\U0001f67dextra.txt',
        'auth.json\u2e4asecret.txt', 'credentials\u2e4atoken.txt', 'notes\u2e4aid_rsa',
        'nested/id_rsa\u2e4ax', 'Diagnostics\u2e4acapture.png', 'tokens.json\u2e4aextra.txt',
        'auth.json\u30cesecret.txt', 'credentials\u4e3ftoken.txt', 'notes\u2f03id_rsa',
        'nested/id_rsa\u2cc6x', 'tokens.json\u4e36extra.txt', 'auth.json\u2f02secret.txt',
        'auth.json\u2cc7secret.txt', 'credentials\u2cc7token.txt', 'notes\u2cc7id_rsa',
        'nested/id_rsa\u2cc7x', 'Diagnostics\u2cc7capture.png', 'tokens.json\u2cc7extra.txt',
        'readme\u2cc7auth.json', 'file\u2cc7.netrc', 'ID_RSA\u2cc7x',
        'notes\uff89id_rsa', 'accounts.json\u4e3fnotes.txt', 'readme\u30ceauth.json',
        'file\u2cc6.netrc', 'ID_RSA\u4e36x', 'credentials\uff89token.txt',
        'auth.json\u2100secret.txt', 'credentials\u2101token.txt', 'notes\u2105id_rsa',
        'nested/id_rsa\u2106x', 'Diagnostics\u2100capture.png', 'tokens.json\u2101extra.txt',
        'readme\u2105auth.json', 'file\u2106.netrc', 'ID_RSA\u2100x',
        'auth.json\u00bcsecret.txt', 'credentials\u00bdtoken.txt', 'notes\u00beid_rsa',
        'nested/id_rsa\u2150x', 'Diagnostics\u2152capture.png', 'tokens.json\u215fextra.txt',
        'readme\u2153auth.json', 'file\u2189.netrc', 'ID_RSA\u215ex',
        'auth.json\u3328secret.txt', 'notes\u3329id_rsa', 'credentials\u33a8token.txt',
        'nested/id_rsa\u33afx', 'Diagnostics\u33aecapture.png', 'tokens.json\u33c6extra.txt',
        'readme\u33deauth.json', 'file\u33df.netrc', 'ID_RSA\u33a7x',
        'auth.json\u27c8secret.txt', 'credentials\u27c9token.txt', 'notes\u27c8id_rsa',
        'nested/id_rsa\u27c9x', 'Diagnostics\u27c8capture.png', 'tokens.json\u27c9extra.txt',
        'readme\u27c8auth.json', 'file\u27c9.netrc', 'ID_RSA\u27c8x',
        'auth.json\u29c4secret.txt', 'credentials\u29c5token.txt', 'notes\u29c4id_rsa',
        'nested/id_rsa\u29c5x', 'Diagnostics\u29c4capture.png', 'tokens.json\u29c5extra.txt',
        'readme\u29c4auth.json', 'file\u29c5.netrc', 'ID_RSA\u29c4x',
        'auth.json\U000E002Fsecret.txt', 'credentials\U000E005Ctoken.txt', 'notes\U000E002Fid_rsa',
        'nested/id_rsa\U000E005Cx', 'Diagnostics\U000E002Fcapture.png', 'tokens.json\U000E002Fextra.txt',
        'readme\U000E005Cauth.json', 'file\U000E002F.netrc', 'ID_RSA\U000E005Cx',
        'auth\U000E002Ejson', 'accounts\U000E002Ejson', '\U000E002Enetrc',
        'notes\U000E003Aid_rsa', 'launch\U000E002Dhistory.json',
        'readme\U000E003Aauth.json', 'Copy of auth\U000E002Ejson',
        'nested/tokens\U000E002Ejson/extra.txt', 'au\U000E002Fth.json', 'a\U000E002Euth.json',
        'auth.json\U000E0001',
        'Copy\U000E0020of auth.json', 'Copy of\U000E0020auth.json',
        'Copy of auth\U000E0020.json',
        'a\U000E0075th.json', '\U000E0061uth.json', 't\U000E006Fkens.json',
        'ID_\U000E0052SA', '\U000E0041CCOUNTS.JSON',
        'au\U000E0074h.json', 'Copy of a\U000E0075th.json',
        'nested/\U000E0061uth.json/extra.txt', 'launch-\U000E0068istory.json',
        'au\U000E0074h\U000E002Ejson', 'credentials\U000E002Ejs\U000E006Fn',
        '\U000E002En\U000E0065trc', 'id_rs\U000E0061', 'auth.json\U000E0061',
        'id_ed\U000E00325519', 'ID_ED\U000E00325519',
        'id_ed\U000E00325519\U000E0061', 'id_\U000E0065d\U000E00325519',
        'nested/id_ed\U000E00325519/extra.txt', 'id_ed2551\U000E0039',
        'id\U000E005Frsa', 'ID\U000E005FRSA', 'auth\U000E005Fsnapshot.json',
        'codex\U000E005Finstances.json', 'id\U000E005Frsa\U000E0061',
        'i\U000E0064\U000E005Frsa', 'nested/id\U000E005Frsa/extra.txt',
        'id\U000E005Fed\U000E00325519',
        'auth.json\U000E007E1', 'tokens.json\U000E007E2',
        'nested/credentials.json\U000E007E1', 'ID_RSA\U000E007E3',
        'au\U000E0074h.json\U000E007E1', 'id\U000E005Frsa\U000E007E1',
        'Copy of auth.json\U000E007E1',
        'auth \U000E00281\U000E0029.json', 'accounts \U000E00282\U000E0029.json',
        'auth (1\U000E0029.json', 'auth \U000E00281).json',
        'nested/tokens \U000E00281\U000E0029.json', 'ID_RSA \U000E00281\U000E0029',
        'a\U000E0075th \U000E00281\U000E0029.json', 'id\U000E005Frsa \U000E00281\U000E0029',
        'Copy\U000E0020of auth \U000E00281\U000E0029.json',
        'readme\u1393auth.json', 'notes\U0001d108id_rsa', 'file\U00011dd9credentials.json',
        'docs\u1393accounts.json', 'nested/file\U0001d108.netrc', 'ID_RSA\U00011dd9x',
        'auth.json\u1393secret', 'readme\U0001d108.env', 'file\U00011dd9.netrc',
        'readme\u1393auth\u0660json',
        'readme\u2237auth.json', 'notes\u2e2cid_rsa', 'file\u2237credentials.json',
        'docs\u2e2caccounts.json', 'nested/file\u2237.netrc', 'ID_RSA\u2e2cx',
        'auth.json\u2237secret', 'readme\u2e2c.env', 'file\u2237.netrc',
        'auth.json\ufe0e', 'auth.json\ufe0f', 'auth\ufe0e.json', 'auth.\ufe0ejson',
        'accounts.json\u0332', 'id_rsa\u20dd', '.netrc\u180b', 'credentials.json\u0489',
        'tokens.json\u20e3', 'auth.json\u0301', 'a\u0301uth.json', 'auth\u180c.json',
        'Copy of auth.json\ufe0f', 'nested/auth\ufe0e.json/extra.txt',
        'accounts.json\u180d.txt', 'secrets.env\u20dd', 'id_rsa\ufe0f.txt',
        'auth\u3164.json', 'auth.json\u3164', 'auth\uffa0.json', 'id_rsa\u2800', 'credentials.json\u115f',
        '.netrc\u1160', 'tokens.json\u2800', 'ID_RSA\uffa0',
        'nested/auth\u3164.json/extra.txt', 'Copy of auth\u2800.json', 'auth.json\u3164.txt',
        'secrets.env\u115f', 'auth\u115f.json\u2800',
        'id_rsa\u1680', 'auth.json\u1680', 'auth\u1680.json', 'accounts\u1680.json',
        '.netrc\u1680', 'ID_RSA\u1680', 'auth.json\u1680.txt', 'nested/auth\u1680.json/extra.txt',
        'Copy of auth.json\u1680', 'notes\u1680.bak', 'credentials\u1680.json.gz',
        'auth\u093e.json', 'accounts\u093e.json', 'credentials\u0bbe.json',
        'id_rsa\u302e', '.netrc\u302f', 'tokens\u093e.json',
        'auth.json\u093e', 'ID_RSA\u302e', 'auth\u093e\u302e.json',
        'au\u093eth.json', 'nested/auth\u093e.json/extra.txt',
        'Copy of auth\u302e.json', 'auth\u093e.json.txt', 'secrets.env\u0bbe',
    )
    allowed = (
        'internal/server/management_credentials_test.go', 'internal/basispoints/envelope.go',
        'desktop/assets/icon.png', 'README.md', 'scripts/check-public.py', 'internal/config/config.go',
        'internal/oauth/login.go', 'docs/handover-not-private.md',
        'docs/assets/accounts.png', 'internal/localcodex/models.json', 'notes.tmp', 'script.go.swp',
        'id_rsa.pub', 'script (1).go', 'notes.bak3', 'Copy of README.md', '._script.go',
        'notes.txt', 'docs/readme.txt', 'script.go.txt', 'readme.db.md', 'notes.database',
        'models.json.txt', 'notes.txt.', 'readme.gz', 'script.go.xz', 'models.json.gz',
        'script.go:Zone.Identifier', 'notes\u00a0.txt', 'readme\u3002txt', 'script.go\u200b',
        'models.json:Zone.Identifier', 'notes:readme.txt', 'file:notes.tmp',
        'notes .txt', 'models .json.gz', 'id_rsa.pub\u200e', 'id_rsa .pub',
        'notes.bak3/readme.md', 'script.go.swp/foo.txt', 'models.json.gz/foo.txt',
        'id_rsa.pub/foo.txt', 'Copy of README.md/img.png', 'docs/handover-not-private/readme.md',
        'notes\\readme.txt', 'readme\u2044notes.txt', 'script.go\u00a5extra.txt',
        'models.json\uff0freadme.txt',
        'readme\u2216notes.txt', 'script.go\u29f5extra.txt', 'models.json\u29f9readme.txt',
        'notes\u29f6readme.txt', 'script.go\u29f7extra.txt', 'id_rsa.pub\u29f6foo.txt',
        'models.json\u29f7readme.txt',
        'readme\u2571notes.txt', 'script.go\u27cbextra.txt', 'models.json\u2572readme.txt',
        'id_rsa.pub\u1735foo.txt', 'notes\u27cdreadme.txt',
        'readme.br', 'notes.tar', 'script.go.part', 'models.json.7z', 'readme.tgz', 'notes.crdownload',
        'script.go\u0705extra', 'notes\u1365txt', 'readme\u205anotes.txt', 'id_rsa.pub\u02d1extra',
        'notes\u1804readme.txt', 'script.go\ua6f4Zone.Identifier', 'models.json\u1804readme.txt',
        'notes\U00010781readme.txt', 'script.go\U00010782Zone.Identifier', 'models.json\U00010781readme.txt',
        'notes\u2a74readme.txt', 'script.go\u2a74Zone.Identifier', 'id_rsa.pub\u2a74extra',
        'notes\u205dreadme.txt', 'script.go\u2254Zone.Identifier', 'models.json\u2af6readme.txt',
        'notes\U00012471readme.txt', 'script.go\U00012472Zone.Identifier', 'models.json\U0001DA8Areadme.txt',
        'notes\u16ecreadme.txt', 'script.go\u0831Zone.Identifier', 'models.json\U00010af5readme.txt',
        'notes\U0001123areadme.txt', 'script.go\ua4fdZone.Identifier', 'id_rsa.pub\ufe30extra',
        'readme\ufe30md',
        'notes\u0903readme.txt', 'notes\u0a83readme.txt', 'notes\U00011002readme.txt',
        'notes\U00011082readme.txt', 'notes\U00011182readme.txt', 'notes\U000115BEreadme.txt',
        'notes\U000116ACreadme.txt', 'notes\U00011838readme.txt', 'notes\u0983readme.txt',
        'notes\u0a03readme.txt', 'notes\u0c03readme.txt', 'notes\u0c83readme.txt',
        'notes\u0d03readme.txt', 'notes\u0d83readme.txt', 'notes\u0f7freadme.txt',
        'notes\u1038readme.txt', 'notes\u17c7readme.txt', 'notes\U00011303readme.txt',
        'notes\U000114C1readme.txt', 'notes\U000119DFreadme.txt', 'notes\U00011A39readme.txt',
        'notes\U00011C3Ereadme.txt', 'script.go\u0903Zone.Identifier', 'id_rsa.pub\u0983extra',
        'notes\u06d4txt', 'script\u0701go', 'models\u1362json', 'id_rsa\u166epub', 'readme\u2e3cmd',
        'notes\u2024txt', 'script\ufe52go', 'id_rsa\ufe12pub', 'readme\uff61md', 'models\u2024json',
        'notes..txt', 'script...go', 'models..json', 'id_rsa..pub', 'readme\u2026md',
        'notes\ua4f8txt', 'script\U00010a50go', 'models\uabecjson', 'id_rsa\ua4f8pub', 'readme\uabecmd',
        'notes\ua4fatxt', 'script\ua4fago', 'models\ua4fajson', 'id_rsa\ua4fapub', 'readme\ua4famd',
        'models.json\u0589readme',
        'notes\u0660txt', 'script\u06f0go', 'models\U0001ecaejson', 'id_rsa\u0660pub', 'readme\U0001d16dmd',
        'notes\u2041readme.txt', 'script.go\u2041Zone.Identifier', 'id_rsa.pub\u2041foo.txt',
        'notes\u2afdreadme.txt', 'script.go\u2afbextra.txt', 'id_rsa.pub\u244afoo.txt',
        'models.json\u2afdreadme.txt',
        'notes\u31d2readme.txt', 'script.go\u31d3Zone.Identifier', 'id_rsa.pub\u31d4foo.txt',
        'notes\u3033readme.txt', 'notes\u3034readme.txt', 'script.go\u3035Zone.Identifier', 'script.go\U0001d23aZone.Identifier', 'id_rsa.pub\U0001d20ffoo.txt',
        'models.json\U0001d23breadme.txt',
        'notes\U0001f67creadme.txt', 'script.go\U0001f67dZone.Identifier', 'id_rsa.pub\U0001f67cfoo.txt',
        'models.json\U0001f67dreadme.txt',
        'notes\u2e4areadme.txt', 'script.go\u2e4aZone.Identifier', 'id_rsa.pub\u2e4afoo.txt',
        'models.json\u2e4areadme.txt',
        'notes\u30cereadme.txt', 'script.go\u4e3fZone.Identifier', 'id_rsa.pub\u2f03foo.txt',
        'models.json\u2cc6readme.txt', 'notes\u4e36readme.txt', 'script.go\u2f02Zone.Identifier',
        'notes\u2cc7readme.txt', 'script.go\u2cc7Zone.Identifier', 'id_rsa.pub\u2cc7foo.txt',
        'models.json\u2cc7readme.txt', 'readme\u2cc7md',
        'id_rsa.pub\uff89foo.txt', 'readme\u30cemd',
        'notes\u2100readme.txt', 'script.go\u2101Zone.Identifier', 'id_rsa.pub\u2105foo.txt',
        'models.json\u2106readme.txt', 'readme\u2100md',
        'notes\u00bcreadme.txt', 'script.go\u00bdZone.Identifier', 'id_rsa.pub\u00befoo.txt',
        'models.json\u2150readme.txt', 'readme\u215fmd', 'notes\u2189readme.txt',
        'notes\u3328readme.txt', 'script.go\u3329Zone.Identifier', 'id_rsa.pub\u33a7foo.txt',
        'models.json\u33c6readme.txt', 'readme\u33dfmd',
        'notes\u27c8readme.txt', 'script.go\u27c9Zone.Identifier', 'id_rsa.pub\u27c8foo.txt',
        'models.json\u27c9readme.txt', 'readme\u27c8md',
        'notes\u29c4readme.txt', 'script.go\u29c5Zone.Identifier', 'id_rsa.pub\u29c4foo.txt',
        'models.json\u29c5readme.txt', 'readme\u29c4md',
        'notes\U000E002Freadme.txt', 'script.go\U000E005CZone.Identifier', 'id_rsa.pub\U000E002Ffoo.txt',
        'models.json\U000E002Freadme.txt', 'readme\U000E002Fmd',
        'notes\U000E002Etxt', 'script\U000E002Ego', 'id_rsa\U000E002Epub',
        'notes\U000E003Areadme.txt', 'script.go\U000E002Dextra',
        'au\U000E002Fth.txt', 'notes\U000E0001readme.txt',
        'Copy\U000E0020of README.md', 'notes\U000E0020readme.txt',
        'script\U000E0020.go', 'id_rsa\U000E0020.pub',
        'notes\U000E0061.txt', 'script\U000E0067o.go', 'id_rs\U000E0061.pub',
        'readme\U000E0041md', 'au\U000E0074h.txt',
        'docs/handover-not-private\U000E0061.md',
        'notes\U000E0031.txt', 'script\U000E0030.go', 'id_ed\U000E00325519.pub',
        'readme\U000E0039md',
        'id\U000E005Frsa.pub', 'script\U000E005F.go', 'notes\U000E005F.txt',
        'notes\U000E007E.txt', 'readme\U000E007Emd', 'notes\U000E007E1.txt',
        'script.go\U000E007E1', 'id_rsa.pub\U000E007E1',
        'notes \U000E00281\U000E0029.txt', 'script \U000E00281\U000E0029.go',
        'readme\U000E0028md', 'models\U000E0029.json',
        'notes\u1393readme.txt', 'models.json\U0001d108readme.txt', 'id_rsa.pub\U00011dd9extra',
        'notes\u2237readme.txt', 'models.json\u2e2creadme.txt', 'id_rsa.pub\u2237extra',
        'script.go\u2e2cZone.Identifier',
        'script.go\ufe0e', 'id_rsa.pub\ufe0f', 'notes\u0301.txt', 'readme\u20dd.md',
        'models.json\u0332', 'notes\u180b.txt',
        'notes\u3164.txt', 'script.go\u2800', 'readme\u1160.md', 'models.json\uffa0',
        'notes\u1680.txt', 'script.go\u1680', 'id_rsa.pub\u1680', 'au\u1680th.json',
        'readme\u1680md',
        'notes\u093e.txt', 'script\u093e.go', 'id_rsa\u093e.pub', 'readme\u302e.md',
        'models\u302f.json', 'notes\u0bbereadme.txt',
        'notes\u2010readme.txt', 'au\u2010th.json', 'script.go\u2212extra',
        'readme\u2014md', 'au\u2014th.json', 'script.go\u2015extra', 'notes\ufe31.txt',
        'au\u058ath.json', 'au\u05beth.json', 'au\u1400th.json', 'au\u1806th.json',
        'script.go\u2e17extra', 'notes\u2e1a.txt', 'readme\u2e40md', 'notes\u2e5d.txt',
        'script.go\u30a0extra', 'au\U00010eadth.json',
        'au\u2e3ath.json', 'au\u2e3bth.json', 'script.go\u301cextra', 'notes\u3030.txt',
        'auth\u174djson',
        'au\u207bth.json', 'au\u208bth.json', 'au\ufe32th.json', 'au\ufe63th.json', 'au\uff0dth.json',
        'notes\ufe63.txt', 'script.go\uff0dextra', 'auth\uff0djson',
        'notes\u00ad.txt', 'script.go\u00adextra',
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
    hidden_token = b'sk-' + b'a' * 10 + '\U000E0001'.encode() + b'a' * 20
    tag_hyphen = 'sk\U000E002D'.encode() + b'a' * 30
    tag_body = ('sk-' + '\U000E0061' * 30).encode()
    hidden_key = '-----BEGIN \U000E004FPENSSH PRIVATE KEY-----'.encode()
    hidden_jwt = b'eyJ' + b'a' * 25 + b'.' + b'b' * 10 + '\U000E007F'.encode() + b'b' * 20 + b'.' + b'c' * 15
    if content_reasons(hidden_token) != ['secret token literal'] or content_reasons(tag_hyphen) != ['secret token literal'] or content_reasons(tag_body) != ['secret token literal']:
        raise SystemExit('self-test failed: a tag-hidden token was not detected')
    if content_reasons(hidden_key) != ['private key'] or content_reasons(hidden_jwt) != ['JWT literal']:
        raise SystemExit('self-test failed: a tag-hidden key or JWT was not detected')
    if content_reasons(b'sk-\n' + b'a' * 30) or content_reasons(b'rt_' + b'short' + '\U000E0001'.encode()):
        raise SystemExit('self-test failed: ordinary wrapped text was blocked')
    if content_reasons('-----BEGIN PU\U000E0042LIC KEY-----'.encode()):
        raise SystemExit('self-test failed: a tagged public key was blocked')
    marked_token = ('sk-' + 'a' * 10 + '\u0301' + 'a' * 20).encode()
    marked_key = '-----BEGIN OPE\u0301NSSH PRIVATE KEY-----'.encode()
    marked_jwt = b'eyJ' + b'a' * 25 + b'.' + ('b' * 10 + '\u0301' + 'b' * 20).encode() + b'.' + b'c' * 15
    if content_reasons(marked_token) != ['secret token literal'] or content_reasons(marked_key) != ['private key'] or content_reasons(marked_jwt) != ['JWT literal']:
        raise SystemExit('self-test failed: a mark-hidden secret was not detected')
    if content_reasons('caf\u0301e'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\u0301' + 'short').encode()):
        raise SystemExit('self-test failed: an ordinary mark was blocked')
    wide_token = ('\uff53\uff4b-' + '\uff41' * 30).encode()
    wide_hyphen = ('sk' + '\uff0d' + 'a' * 30).encode()
    wide_key = ('\uff0d' * 5 + '\uff22\uff25\uff27\uff29\uff2e OPENSSH PRIVATE KEY' + '\uff0d' * 5).encode()
    wide_jwt = ('\uff45\uff59\uff2a' + '\uff41' * 25 + '\uff0e' + '\uff42' * 30 + '.' + '\uff43' * 15).encode()
    wide_path = '\uff23\uff1a/Users/Mayn/project'.encode()
    if content_reasons(wide_token) != ['secret token literal'] or content_reasons(wide_hyphen) != ['secret token literal']:
        raise SystemExit('self-test failed: a fullwidth token was not detected')
    if content_reasons(wide_key) != ['private key'] or content_reasons(wide_jwt) != ['JWT literal']:
        raise SystemExit('self-test failed: a fullwidth key or JWT was not detected')
    if 'personal Windows path' not in content_reasons(wide_path):
        raise SystemExit('self-test failed: a fullwidth personal path was not detected')
    ordinary = '\u8bf4\u660e\uff1a\u4e0d\u8981\u63d0\u4ea4\uff08\u5bc6\u94a5\uff09\uff1b'
    if content_reasons(ordinary.encode()) or content_reasons(('\uff53\uff4b-' + '\uff41' * 10).encode()) or content_reasons('-----\uff22\uff25\uff27\uff29\uff2e PUBLIC KEY-----'.encode()) or content_reasons(('sk-\n' + '\uff41' * 30).encode()):
        raise SystemExit('self-test failed: ordinary fullwidth text was blocked')
    if math_ascii(0x1D400) != 'A' or math_ascii(0x1D41A) != 'a' or math_ascii(0x1D455) is not None or math_ascii(0x1D6FC) is not None or math_ascii(0x210E) != 'h' or math_ascii(0x1D7CE) != '0' or math_ascii(0x212A) is not None:
        raise SystemExit('self-test failed: mathematical ASCII fold is wrong')
    math_token = ('sk-' + '\U0001D41A' * 30).encode()
    math_digit = ('rt_' + '\U0001D7CE' * 30).encode()
    math_key = ('-----' + '\U0001D401\U0001D404\U0001D406\U0001D408\U0001D40D' + ' OPENSSH PRIVATE KEY-----').encode()
    math_jwt = ('\U0001D41E\U0001D432\U0001D409' + '\U0001D41A' * 25 + '.' + '\U0001D41B' * 30 + '.' + '\U0001D41C' * 15).encode()
    math_path = '\U0001D402:/Users/Mayn/project'.encode()
    hole = ('sk-' + 'a' * 10 + '\U0001D455' + 'a' * 20).encode()
    greek = ('sk-' + 'a' * 10 + '\U0001D6FC' + 'a' * 20).encode()
    if content_reasons(math_token) != ['secret token literal'] or content_reasons(math_digit) != ['secret token literal']:
        raise SystemExit('self-test failed: a mathematical token was not detected')
    if content_reasons(math_key) != ['private key'] or content_reasons(math_jwt) != ['JWT literal']:
        raise SystemExit('self-test failed: a mathematical key or JWT was not detected')
    if 'personal Windows path' not in content_reasons(math_path):
        raise SystemExit('self-test failed: a mathematical personal path was not detected')
    if content_reasons(hole) or content_reasons(greek) or content_reasons('\U0001D465 = 1'.encode()) or content_reasons(('-----' + '\U0001D401\U0001D404\U0001D406\U0001D408\U0001D40D' + ' PUBLIC KEY-----').encode()):
        raise SystemExit('self-test failed: ordinary mathematical text was blocked')
    if enclosed_ascii(0x2460) != '1' or enclosed_ascii(0x2468) != '9' or enclosed_ascii(0x24EA) != '0' or enclosed_ascii(0x24B6) != 'A' or enclosed_ascii(0x24D0) != 'a' or enclosed_ascii(0x24E9) != 'z' or enclosed_ascii(0x2469) is not None or enclosed_ascii(0x1F130) != 'A' or enclosed_ascii(0x1F12B) != 'C':
        raise SystemExit('self-test failed: enclosed ASCII fold is wrong')
    enc_token = ('sk-' + '\u24d0' * 30).encode()
    enc_digit = ('rt_' + '\u2460' * 30).encode()
    enc_key = ('-----' + '\u24b7\u24ba\u24bc\u24be\u24c3' + ' OPENSSH PRIVATE KEY-----').encode()
    enc_jwt = ('\u24d4\u24e8\u24bf' + '\u24d0' * 25 + '.' + '\u24d1' * 30 + '.' + '\u24d2' * 15).encode()
    enc_path = '\u24b8:/Users/Mayn/project'.encode()
    enc_square = ('ghp_' + '\U0001F130' * 30).encode()
    enc_ten = ('sk-' + 'a' * 10 + '\u2469' + 'a' * 20).encode()
    if content_reasons(enc_token) != ['secret token literal'] or content_reasons(enc_digit) != ['secret token literal'] or content_reasons(enc_square) != ['secret token literal']:
        raise SystemExit('self-test failed: an enclosed token was not detected')
    if content_reasons(enc_key) != ['private key'] or content_reasons(enc_jwt) != ['JWT literal']:
        raise SystemExit('self-test failed: an enclosed key or JWT was not detected')
    if 'personal Windows path' not in content_reasons(enc_path):
        raise SystemExit('self-test failed: an enclosed personal path was not detected')
    if content_reasons('step \u2460'.encode()) or content_reasons(('-----' + '\u24b7\u24ba\u24bc\u24be\u24c3' + ' PUBLIC KEY-----').encode()):
        raise SystemExit('self-test failed: ordinary enclosed text was blocked')
    if circled_number(0x2469) != '10' or circled_number(0x2473) != '20' or circled_number(0x3251) != '21' or circled_number(0x325F) != '35' or circled_number(0x32B1) != '36' or circled_number(0x32BF) != '50' or circled_number(0x24EB) is not None or circled_number(0x2460) is not None:
        raise SystemExit('self-test failed: circled number fold is wrong')
    enc_twenty = ('rt_' + '\u3251' * 13).encode()
    if content_reasons(enc_ten) != ['secret token literal'] or content_reasons(enc_twenty) != ['secret token literal']:
        raise SystemExit('self-test failed: a multi-digit circled number was not detected')
    if content_reasons('step \u2469'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\u2469').encode()) or content_reasons(('sk-' + 'a' * 10 + '\u24eb' + 'a' * 20).encode()):
        raise SystemExit('self-test failed: an ordinary circled number was blocked')
    if super_sub_ascii(0x00B9) != '1' or super_sub_ascii(0x2070) != '0' or super_sub_ascii(0x2079) != '9' or super_sub_ascii(0x2071) != 'i' or super_sub_ascii(0x207F) != 'n' or super_sub_ascii(0x2080) != '0' or super_sub_ascii(0x2089) != '9' or super_sub_ascii(0x2090) != 'a' or super_sub_ascii(0x209C) != 't' or super_sub_ascii(0x00AA) != 'a' or super_sub_ascii(0x207A) is not None or super_sub_ascii(0x2094) is not None:
        raise SystemExit('self-test failed: superscript fold is wrong')
    sup_token = ('sk-' + '\u2071' * 30).encode()
    sub_digit = ('rt_' + '\u2080' * 30).encode()
    ordinal = ('ghp_' + '\u00aa' * 30).encode()
    if content_reasons(sup_token) != ['secret token literal'] or content_reasons(sub_digit) != ['secret token literal'] or content_reasons(ordinal) != ['secret token literal']:
        raise SystemExit('self-test failed: a superscript token was not detected')
    if content_reasons('m\u00b2'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\u207a' + 'a' * 20).encode()) or content_reasons(('sk-' + '\u2071' * 10).encode()):
        raise SystemExit('self-test failed: ordinary superscript text was blocked')
    if modifier_ascii(0x02B0) != 'h' or modifier_ascii(0x02B1) is not None or modifier_ascii(0x02E2) != 's' or modifier_ascii(0x1D2C) != 'A' or modifier_ascii(0x1D2D) is not None or modifier_ascii(0x1D4A) is not None or modifier_ascii(0x1D62) != 'i' or modifier_ascii(0x2C7C) != 'j' or modifier_ascii(0x2C7D) != 'V' or modifier_ascii(0xA7F2) != 'C' or modifier_ascii(0x107A5) != 'q' or modifier_ascii(0x212A) != 'K' or modifier_ascii(0x2139) != 'i' or modifier_ascii(0x017F) is not None or modifier_ascii(0x2160) is not None or modifier_ascii(0x1FBF0) is not None:
        raise SystemExit('self-test failed: modifier ASCII fold is wrong')
    mod_token = ('sk-' + '\u02e2' * 30).encode()
    mod_sub = ('rt_' + '\u1d62' * 30).encode()
    mod_q = ('ghp_' + '\U000107a5' * 30).encode()
    mod_kelvin = ('gho_' + '\u212a' * 30).encode()
    mod_key = ('-----BEGIN ' + '\U00001D3C\U00001D3E\U00001D31' + 'NSSH PRIVATE KEY-----').encode()
    mod_jwt = ('\u1d49\u02b8\U00001D36' + '\u1d43' * 25 + '.' + '\u1d47' * 30 + '.' + '\u1d9c' * 15).encode()
    mod_path = '\uA7F2:/Users/\U00001D42\u2139\u02e2\u02b0\U00001D40\u1d52\U00001D2C\u1d56\u1d56/project'.encode()
    mod_hole = ('sk-' + 'a' * 10 + '\u1d4a' + 'a' * 20).encode()
    if content_reasons(mod_token) != ['secret token literal'] or content_reasons(mod_sub) != ['secret token literal'] or content_reasons(mod_q) != ['secret token literal'] or content_reasons(mod_kelvin) != ['secret token literal']:
        raise SystemExit('self-test failed: a modifier token was not detected')
    if content_reasons(mod_key) != ['private key'] or content_reasons(mod_jwt) != ['JWT literal']:
        raise SystemExit('self-test failed: a modifier key or JWT was not detected')
    if 'personal Windows path' not in content_reasons(mod_path):
        raise SystemExit('self-test failed: a modifier personal path was not detected')
    if content_reasons(mod_hole) or content_reasons('see \u02b0 later'.encode()) or content_reasons(('sk-' + '\u02e2' * 10).encode()) or content_reasons(('-----BEGIN ' + '\U00001D3E' + 'UBLIC KEY-----').encode()):
        raise SystemExit('self-test failed: ordinary modifier text was blocked')
    if segmented_digit(0x1FBEF) is not None or segmented_digit(0x1FBF0) != '0' or segmented_digit(0x1FBF1) != '1' or segmented_digit(0x1FBF5) != '5' or segmented_digit(0x1FBF9) != '9' or segmented_digit(0x1FBFA) is not None or segmented_digit(0x2469) is not None or segmented_digit(0x2474) is not None or segmented_digit(0x2488) is not None or segmented_digit(0x24EA) is not None or segmented_digit(ord('5')) is not None:
        raise SystemExit('self-test failed: segmented digit fold is wrong')
    if sum(segmented_digit(cp) is not None for cp in range(0x1FBE0, 0x1FC10)) != 10:
        raise SystemExit('self-test failed: segmented digit fold count is wrong')
    seg_token = ('rt_' + '\U0001fbf0' * 30).encode()
    seg_mix = ('sk-' + 'a' * 10 + '\U0001fbf5' + 'a' * 20).encode()
    seg_jwt = ('eyJ' + 'a' * 20 + '\U0001fbf1' * 5 + '.' + 'b' * 25 + '\U0001fbf2' * 5 + '.' + 'c' * 10 + '\U0001fbf9' * 5).encode()
    if content_reasons(seg_token) != ['secret token literal'] or content_reasons(seg_mix) != ['secret token literal'] or content_reasons(seg_jwt) != ['JWT literal']:
        raise SystemExit('self-test failed: a segmented digit secret was not detected')
    if content_reasons('see \U0001fbf0 later'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\u2474' + 'a' * 20).encode()) or content_reasons(('sk-' + 'a' * 10 + '\u2488' + 'a' * 20).encode()) or content_reasons(('rt_' + '\U0001fbf0' * 10).encode()) or content_reasons(('sk-' + 'a' * 10 + '\u24eb' + 'a' * 20).encode()):
        raise SystemExit('self-test failed: ordinary segmented text was blocked')
    if roman_ascii(0x215F) is not None or roman_ascii(0x2160) != 'I' or roman_ascii(0x2161) is not None or roman_ascii(0x2164) != 'V' or roman_ascii(0x2169) != 'X' or roman_ascii(0x216C) != 'L' or roman_ascii(0x216D) != 'C' or roman_ascii(0x216E) != 'D' or roman_ascii(0x216F) != 'M' or roman_ascii(0x2170) != 'i' or roman_ascii(0x2171) is not None or roman_ascii(0x2174) != 'v' or roman_ascii(0x2179) != 'x' or roman_ascii(0x217C) != 'l' or roman_ascii(0x217D) != 'c' or roman_ascii(0x217E) != 'd' or roman_ascii(0x217F) != 'm' or roman_ascii(0x2180) is not None or roman_ascii(0x2183) is not None:
        raise SystemExit('self-test failed: roman numeral fold is wrong')
    if sum(roman_ascii(cp) is not None for cp in range(0x2150, 0x2190)) != 14:
        raise SystemExit('self-test failed: roman numeral fold count is wrong')
    roman_token = ('sk-' + '\u2170' * 30).encode()
    roman_upper = ('ghp_' + '\u2164' * 30).encode()
    roman_key = ('-----BEGIN OPENSSH PR' + '\u2160' + 'VATE KEY-----').encode()
    roman_jwt = ('eyJ' + '\u2170' * 25 + '.' + '\u2174' * 30 + '.' + '\u2179' * 15).encode()
    roman_path = ('\u216d' + ':/Users/Mayn/project').encode()
    if content_reasons(roman_token) != ['secret token literal'] or content_reasons(roman_upper) != ['secret token literal']:
        raise SystemExit('self-test failed: a roman token was not detected')
    if content_reasons(roman_key) != ['private key'] or content_reasons(roman_jwt) != ['JWT literal']:
        raise SystemExit('self-test failed: a roman key or JWT was not detected')
    if 'personal Windows path' not in content_reasons(roman_path):
        raise SystemExit('self-test failed: a roman personal path was not detected')
    if content_reasons('chapter \u2160 later'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\u2180' + 'a' * 20).encode()) or content_reasons(('sk-' + '\u2170' * 10).encode()) or content_reasons(('-----BEGIN ' + '\u216d' + 'ERTIFICATE-----').encode()):
        raise SystemExit('self-test failed: ordinary roman text was blocked')
    if additive_roman(0x2161) != 'II' or additive_roman(0x2162) != 'III' or additive_roman(0x2163) != 'IV' or additive_roman(0x2165) != 'VI' or additive_roman(0x2166) != 'VII' or additive_roman(0x2167) != 'VIII' or additive_roman(0x2168) != 'IX' or additive_roman(0x216A) != 'XI' or additive_roman(0x216B) != 'XII' or additive_roman(0x2171) != 'ii' or additive_roman(0x2172) != 'iii' or additive_roman(0x2173) != 'iv' or additive_roman(0x2175) != 'vi' or additive_roman(0x2176) != 'vii' or additive_roman(0x2177) != 'viii' or additive_roman(0x2178) != 'ix' or additive_roman(0x217A) != 'xi' or additive_roman(0x217B) != 'xii' or additive_roman(0x2160) is not None or additive_roman(0x2164) is not None or additive_roman(0x2170) is not None or additive_roman(0x2180) is not None or additive_roman(0x2185) is not None or additive_roman(0x2153) is not None:
        raise SystemExit('self-test failed: additive roman fold is wrong')
    if sum(additive_roman(cp) is not None for cp in range(0x2150, 0x2190)) != 18:
        raise SystemExit('self-test failed: additive roman fold count is wrong')
    add_token = ('rt_' + '\u2166' * 9).encode()
    add_mix = ('sk-' + 'a' * 10 + '\u2161' + 'a' * 20).encode()
    add_jwt = ('eyJ' + '\u2177' * 7 + '.' + '\u2176' * 10 + '.' + '\u2175' * 8).encode()
    if content_reasons(add_token) != ['secret token literal'] or content_reasons(add_mix) != ['secret token literal'] or content_reasons(add_jwt) != ['JWT literal']:
        raise SystemExit('self-test failed: an additive roman secret was not detected')
    if content_reasons('see \u2161 later'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\u2180' + 'a' * 20).encode()) or content_reasons(('sk-' + 'a' * 10 + '\u2185' + 'a' * 20).encode()) or content_reasons(('sk-' + '\u2166' * 2).encode()) or content_reasons(('sk-' + 'a' * 10 + '\u2153' + 'a' * 20).encode()):
        raise SystemExit('self-test failed: ordinary additive roman text was blocked')
    if long_s_ascii(0x017F) != 's' or long_s_ascii(ord('s')) is not None or long_s_ascii(0xFB05) is not None or long_s_ascii(0x1E9B) is not None or long_s_ascii(0x1E9C) is not None or long_s_ascii(0x1E9D) is not None or long_s_ascii(0x209B) is not None:
        raise SystemExit('self-test failed: long s fold is wrong')
    if sum(long_s_ascii(cp) is not None for cp in range(0x30000)) != 1:
        raise SystemExit('self-test failed: long s fold count is wrong')
    long_token = ('sk-' + '\u017f' * 30).encode()
    long_prefix = ('\u017fk-' + 'a' * 30).encode()
    long_mix = ('sk-' + 'a' * 10 + '\u017f' + 'a' * 20).encode()
    long_jwt = ('eyJ' + '\u017f' * 25 + '.' + '\u017f' * 30 + '.' + '\u017f' * 15).encode()
    long_path = 'C:/U\u017fers/Mayn'.encode()
    if content_reasons(long_token) != ['secret token literal'] or content_reasons(long_prefix) != ['secret token literal'] or content_reasons(long_mix) != ['secret token literal']:
        raise SystemExit('self-test failed: a long s token was not detected')
    if content_reasons(long_jwt) != ['JWT literal']:
        raise SystemExit('self-test failed: a long s JWT was not detected')
    if 'personal Windows path' not in content_reasons(long_path):
        raise SystemExit('self-test failed: a long s personal path was not detected')
    if content_reasons('long \u017f word'.encode()) or content_reasons('see \ufb05 later'.encode()) or content_reasons('see \u1e9b later'.encode()) or content_reasons('see \u1e9c later'.encode()) or content_reasons(('sk-' + '\u017f' * 10).encode()) or content_reasons('C:/U\u1e9bsers/Mayn'.encode()):
        raise SystemExit('self-test failed: ordinary long s text was blocked')
    if latin_ligature(0x0132) != 'IJ' or latin_ligature(0x0133) != 'ij' or latin_ligature(0x01C7) != 'LJ' or latin_ligature(0x01C8) != 'Lj' or latin_ligature(0x01C9) != 'lj' or latin_ligature(0x01CA) != 'NJ' or latin_ligature(0x01CB) != 'Nj' or latin_ligature(0x01CC) != 'nj' or latin_ligature(0x01F1) != 'DZ' or latin_ligature(0x01F2) != 'Dz' or latin_ligature(0x01F3) != 'dz' or latin_ligature(0xFB00) != 'ff' or latin_ligature(0xFB01) != 'fi' or latin_ligature(0xFB02) != 'fl' or latin_ligature(0xFB03) != 'ffi' or latin_ligature(0xFB04) != 'ffl' or latin_ligature(0xFB05) != 'st' or latin_ligature(0xFB06) != 'st' or latin_ligature(ord('f')) is not None or latin_ligature(0x017F) is not None or latin_ligature(0x2161) is not None or latin_ligature(0x2122) is not None or latin_ligature(0x2116) is not None or latin_ligature(0x3373) is not None or latin_ligature(0xFB07) is not None:
        raise SystemExit('self-test failed: latin ligature fold is wrong')
    if sum(latin_ligature(cp) is not None for cp in range(0x30000)) != 18:
        raise SystemExit('self-test failed: latin ligature fold count is wrong')
    lig_fi = ('sk-' + '\ufb01' * 13).encode()
    lig_st = ('rt_' + '\ufb06' * 13).encode()
    lig_long_st = ('ghp_' + '\ufb05' * 13).encode()
    lig_ffi = ('sk-' + 'a' * 10 + '\ufb03' + 'a' * 14).encode()
    lig_dz = ('sk-' + 'a' * 10 + '\u01f1' + 'a' * 13).encode()
    lig_ij = ('gho_' + '\u0133' * 13).encode()
    lig_jwt = ('eyJ' + 'a' * 23 + '\ufb01' + '.' + 'b' * 28 + '\ufb01' + '.' + 'c' * 13 + '\ufb01').encode()
    if content_reasons(lig_fi) != ['secret token literal'] or content_reasons(lig_st) != ['secret token literal'] or content_reasons(lig_long_st) != ['secret token literal'] or content_reasons(lig_ffi) != ['secret token literal'] or content_reasons(lig_dz) != ['secret token literal'] or content_reasons(lig_ij) != ['secret token literal']:
        raise SystemExit('self-test failed: a ligature token was not detected')
    if content_reasons(lig_jwt) != ['JWT literal']:
        raise SystemExit('self-test failed: a ligature JWT was not detected')
    if content_reasons('see \ufb05 later'.encode()) or content_reasons('the \ufb01le stays'.encode()) or content_reasons('see \u2122 later'.encode()) or content_reasons('see \u2116 later'.encode()) or content_reasons('see \u3373 later'.encode()) or content_reasons(('sk-' + '\ufb01' * 10).encode()) or content_reasons(('sk-' + 'a' * 10 + '\u01f1' + 'a' * 12).encode()) or content_reasons('see \ufb07 later'.encode()):
        raise SystemExit('self-test failed: ordinary ligature text was blocked')
    if low_line_ascii(0xFE33) != '_' or low_line_ascii(0xFE34) != '_' or low_line_ascii(0xFE4D) != '_' or low_line_ascii(0xFE4E) != '_' or low_line_ascii(0xFE4F) != '_' or low_line_ascii(0xFF3F) != '_' or low_line_ascii(ord('_')) is not None or low_line_ascii(0x2017) is not None or low_line_ascii(0x02CD) is not None or low_line_ascii(0xFF0D) is not None or low_line_ascii(0x0332) is not None:
        raise SystemExit('self-test failed: low line fold is wrong')
    if sum(low_line_ascii(cp) is not None for cp in range(0x30000)) != 6:
        raise SystemExit('self-test failed: low line fold count is wrong')
    low_mix = ('sk-' + 'a' * 10 + '\ufe4d' + 'a' * 20).encode()
    low_wavy = ('rt_' + 'a' * 10 + '\ufe34' + 'a' * 14).encode()
    low_pat = ('github' + '\ufe4f' + 'pat_' + 'a' * 25).encode()
    low_jwt = ('eyJ' + 'a' * 24 + '\ufe33' + '.' + 'b' * 30 + '.' + 'c' * 15).encode()
    low_wide = ('ghp_' + 'a' * 12 + '\uff3f' + 'a' * 12).encode()
    if content_reasons(low_mix) != ['secret token literal'] or content_reasons(low_wavy) != ['secret token literal'] or content_reasons(low_pat) != ['secret token literal'] or content_reasons(low_wide) != ['secret token literal']:
        raise SystemExit('self-test failed: a low line token was not detected')
    if content_reasons(low_jwt) != ['JWT literal']:
        raise SystemExit('self-test failed: a low line JWT was not detected')
    if content_reasons('see \u2017 later'.encode()) or content_reasons('see \u02cd later'.encode()) or content_reasons('low \uff3f line'.encode()) or content_reasons(('sk-' + '\ufe4d' * 10).encode()) or content_reasons(('sk-' + 'a' * 10 + '\u2017' + 'a' * 20).encode()) or content_reasons(('sk-' + 'a' * 10 + '\u02cd' + 'a' * 20).encode()):
        raise SystemExit('self-test failed: ordinary low line text was blocked')
    if len(HYPHEN_LIKE) != 37 or HYPHEN_LIKE[0x2011] != '-' or HYPHEN_LIKE[0x2013] != '-' or HYPHEN_LIKE[0x2014] != '-' or HYPHEN_LIKE[0x2015] != '-' or HYPHEN_LIKE[0x2212] != '-' or HYPHEN_LIKE[0x05BE] != '-' or HYPHEN_LIKE[0x207B] != '-' or HYPHEN_LIKE[0x208B] != '-' or HYPHEN_LIKE[0x2E3A] != '-' or HYPHEN_LIKE[0x301C] != '-' or HYPHEN_LIKE[0xFF0D] != '-' or HYPHEN_LIKE.get(0x2016) is not None or HYPHEN_LIKE.get(0x00AD) is not None or HYPHEN_LIKE.get(ord('-')) is not None:
        raise SystemExit('self-test failed: hyphen lookalike table is wrong')
    hy_nb = ('rt_sub' + '\u2011' + 'mitted_' + 'a' * 14).encode()
    hy_minus = ('sk-' + 'a' * 10 + '\u2212' + 'a' * 14).encode()
    hy_maqaf = ('ghp_' + 'a' * 10 + '\u05be' + 'a' * 14).encode()
    hy_super = ('gho_' + 'a' * 12 + '\u207b' + 'a' * 12).encode()
    hy_wave = ('eyJ' + 'a' * 20 + '\u301c' + 'a' * 4 + '.' + 'b' * 30 + '.' + 'c' * 15).encode()
    hy_pem = ('\u2014' * 5 + 'BEGIN OPENSSH PRIVATE KEY' + '\u2014' * 5).encode()
    if content_reasons(hy_nb) != ['secret token literal'] or content_reasons(hy_minus) != ['secret token literal'] or content_reasons(hy_maqaf) != ['secret token literal'] or content_reasons(hy_super) != ['secret token literal']:
        raise SystemExit('self-test failed: a hyphen-lookalike token was not detected')
    if content_reasons(hy_wave) != ['JWT literal']:
        raise SystemExit('self-test failed: a hyphen-lookalike JWT was not detected')
    if content_reasons(hy_pem) != ['private key']:
        raise SystemExit('self-test failed: a hyphen-lookalike private key was not detected')
    if content_reasons('re\u2013try later'.encode()) or content_reasons('re\u2014try later'.encode()) or content_reasons('re\u05betry later'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\u2016' + 'a' * 20).encode()):
        raise SystemExit('self-test failed: ordinary hyphen text was blocked')
    shy_pem = ('----' + '\u00ad' + 'BEGIN OPENSSH PRIVATE KEY-----').encode()
    shy_prefix = ('sk' + '\u00ad' + 'a' * 30).encode()
    shy_token = ('sk-' + 'a' * 12 + '\u00ad' + 'a' * 12).encode()
    shy_jwt = ('eyJ' + 'a' * 24 + '\u00ad' + '.' + 'b' * 29 + '\u00ad' + '.' + 'c' * 14 + '\u00ad').encode()
    if content_reasons(shy_pem) != ['private key']:
        raise SystemExit('self-test failed: a soft-hyphen private key was not detected')
    if content_reasons(shy_prefix) != ['secret token literal'] or content_reasons(shy_token) != ['secret token literal']:
        raise SystemExit('self-test failed: a soft-hyphen token was not detected')
    if content_reasons(shy_jwt) != ['JWT literal']:
        raise SystemExit('self-test failed: a soft-hyphen JWT was not detected')
    if content_reasons('slow\u00adown'.encode()) or content_reasons(('----BEGIN OPENSSH PRIVATE KEY-----').encode()) or content_reasons(('sk-' + 'a' * 12 + '\u200b' + 'a' * 12).encode()) or content_reasons(('sk' + '\u00ad' + 'a' * 10).encode()):
        raise SystemExit('self-test failed: ordinary soft hyphen text was blocked')
    if len(DOT_LIKE) != 31 or DOT_LIKE[0x2024] != '.' or DOT_LIKE[0x3002] != '.' or DOT_LIKE[0x0660] != '.' or DOT_LIKE[0x06F0] != '.' or DOT_LIKE[0xFE52] != '.' or DOT_LIKE[0xFF0E] != '.' or DOT_LIKE[0xABEC] != '.' or DOT_LIKE[0x1D16D] != '.' or DOT_LIKE.get(0x2025) is not None or DOT_LIKE.get(0x00B7) is not None or DOT_LIKE.get(ord('.')) is not None:
        raise SystemExit('self-test failed: full stop table is wrong')
    dot_leader = ('eyJ' + 'a' * 25 + '\u2024' + 'b' * 30 + '\u2024' + 'c' * 15).encode()
    dot_ideo = ('eyJ' + 'a' * 25 + '\u3002' + 'b' * 30 + '\u3002' + 'c' * 15).encode()
    dot_zero = ('eyJ' + 'a' * 25 + '\u0660' + 'b' * 30 + '\u06f0' + 'c' * 15).encode()
    dot_music = ('eyJ' + 'a' * 25 + '\U0001d16d' + 'b' * 30 + '.' + 'c' * 15).encode()
    if content_reasons(dot_leader) != ['JWT literal'] or content_reasons(dot_ideo) != ['JWT literal'] or content_reasons(dot_zero) != ['JWT literal'] or content_reasons(dot_music) != ['JWT literal']:
        raise SystemExit('self-test failed: a full-stop JWT was not detected')
    if content_reasons('see file\u2024txt later'.encode()) or content_reasons('end\u2025 next'.encode()) or content_reasons(('eyJ' + 'a' * 10 + '\u2024' + 'b' * 10 + '\u2024' + 'c' * 10).encode()) or content_reasons(('sk-' + 'a' * 10 + '\u2024' + 'a' * 20).encode()) or content_reasons(('eyJ' + 'a' * 25 + '\u00b7' + 'b' * 30 + '.' + 'c' * 15).encode()):
        raise SystemExit('self-test failed: ordinary full stop text was blocked')
    if len(COLON_LIKE) != 66 or COLON_LIKE[0x2236] != ':' or COLON_LIKE[0x0903] != ':' or COLON_LIKE[0x02D0] != ':' or COLON_LIKE[0x0589] != ':' or COLON_LIKE[0x2237] != ':' or COLON_LIKE[0x2A74] != ':' or COLON_LIKE[0x10781] != ':' or COLON_LIKE.get(0x003A) is not None or COLON_LIKE.get(0xFF1A) is not None or COLON_LIKE.get(0x2025) is not None:
        raise SystemExit('self-test failed: colon lookalike table is wrong')
    colon_ratio = 'C\u2236/Users/Mayn'.encode()
    colon_visarga = 'D\u0903/Git_Project/rain'.encode()
    colon_mod = 'C\u02d0\\Users\\kawang'.encode()
    colon_eq = 'c\u2a74/users/WishToApp'.encode()
    colon_super = 'C\U00010781/Users/gptbridge'.encode()
    if 'personal Windows path' not in content_reasons(colon_ratio) or 'personal Windows path' not in content_reasons(colon_visarga) or 'personal Windows path' not in content_reasons(colon_mod) or 'personal Windows path' not in content_reasons(colon_eq) or 'personal Windows path' not in content_reasons(colon_super):
        raise SystemExit('self-test failed: a colon-lookalike personal path was not detected')
    if content_reasons('see \u2236 later'.encode()) or content_reasons('see \u0903 later'.encode()) or content_reasons('C\u2236/Users/other'.encode()) or content_reasons('C\u2025/Users/Mayn'.encode()) or content_reasons(('sk-' + '\u2236' + 'a' * 30).encode()) or content_reasons(('sk-' + 'a' * 10 + '\u0903' + 'a' * 20).encode()):
        raise SystemExit('self-test failed: ordinary colon text was blocked')
    if len(SEPARATOR_LIKE) != 152 or SEPARATOR_LIKE[0x00A5] != '/' or SEPARATOR_LIKE[0x20A9] != '/' or SEPARATOR_LIKE[0x2215] != '/' or SEPARATOR_LIKE[0x2216] != '/' or SEPARATOR_LIKE[0x2044] != '/' or SEPARATOR_LIKE[0xFE68] != '/' or SEPARATOR_LIKE[0x00BC] != '/' or SEPARATOR_LIKE[0xFF0F] != '/' or SEPARATOR_LIKE[0xFF3C] != '/' or SEPARATOR_LIKE.get(ord('/')) is not None or SEPARATOR_LIKE.get(0x2025) is not None:
        raise SystemExit('self-test failed: slash lookalike table is wrong')
    slash_yen = 'C:\u00a5Users\u00a5Mayn'.encode()
    slash_won = 'D:\u20a9Git_Project\u20a9kawang'.encode()
    slash_div = 'C:\u2215Users\u2215gptbridge'.encode()
    slash_set = 'C:\u2216Users\u2216rain'.encode()
    slash_small = 'C:\ufe68Users\ufe68WishToApp'.encode()
    slash_frac = 'C:\u00bcUsers\u00bcMayn'.encode()
    slash_wide = 'C:\uff0fUsers\uff0fMayn'.encode()
    slash_apl = 'C:\u233fUsers\u233fMayn'.encode()
    slash_apl_back = 'C:\u2340Users\u2340kawang'.encode()
    slash_quad = 'C:\u2341Users\u2341Mayn'.encode()
    slash_quad_back = 'C:\u2342Users\u2342kawang'.encode()
    slash_circled = 'C:\u2298Users\u2298Mayn'.encode()
    slash_circled_back = 'C:\u29b8Users\u29b8kawang'.encode()
    slash_apl_circle = 'C:\u2349Users\u2349kawang'.encode()
    slash_short = 'C:\U0001fba0Users\U0001fba0Mayn'.encode()
    slash_short_back = 'D:\U0001fba1Git_Project\U0001fba1kawang'.encode()
    slash_short_lower = 'C:\U0001fba2Users\U0001fba2rain'.encode()
    slash_short_rise = 'C:\U0001fba3Users\U0001fba3gptbridge'.encode()
    slash_neg = 'C:\U0001fbbeUsers\U0001fbbeWishToApp'.encode()
    slash_mod = 'C:\ua718Users\ua718Mayn'.encode()
    slash_block = 'C:\U0001fb66Users\U0001fb66Mayn'.encode()
    slash_wide_block = 'C:\U0001fb65Users\U0001fb65kawang'.encode()
    slash_mid_block = 'C:\U0001fb67Users\U0001fb67gptbridge'.encode()
    slash_inner_block = 'C:\U0001fb64Users\U0001fb64WishToApp'.encode()
    slash_top_block = 'C:\U0001fb63Users\U0001fb63rain'.encode()
    slash_short_top_block = 'C:\U0001fb62Users\U0001fb62kawang'.encode()
    slash_lower_centre_block = 'C:\U0001fb56Users\U0001fb56gptbridge'.encode()
    slash_outer_block = 'C:\U0001fb55Users\U0001fb55WishToApp'.encode()
    slash_short_lower_centre_block = 'C:\U0001fb54Users\U0001fb54Mayn'.encode()
    slash_lower_block = 'C:\U0001fb53Users\U0001fb53kawang'.encode()
    slash_short_lower_block = 'C:\U0001fb52Users\U0001fb52gptbridge'.encode()
    slash_lower_left_block = 'C:\U0001fb50Users\U0001fb50Mayn'.encode()
    slash_wide_lower_left = 'C:\U0001fb4fUsers\U0001fb4fkawang'.encode()
    slash_mid_lower_left = 'C:\U0001fb51Users\U0001fb51gptbridge'.encode()
    slash_inner_lower_left = 'C:\U0001fb4eUsers\U0001fb4eWishToApp'.encode()
    slash_top_lower_left = 'C:\U0001fb4dUsers\U0001fb4drain'.encode()
    slash_short_top_lower_left = 'C:\U0001fb4cUsers\U0001fb4cMayn'.encode()
    slash_lower_centre_lower_left = 'C:\U0001fb40Users\U0001fb40kawang'.encode()
    slash_outer_lower_left = 'C:\U0001fb3fUsers\U0001fb3fgptbridge'.encode()
    slash_short_lower_centre_lower_left = 'C:\U0001fb3eUsers\U0001fb3eWishToApp'.encode()
    slash_lower_lower_left = 'C:\U0001fb3dUsers\U0001fb3drain'.encode()
    slash_short_lower_lower_left = 'C:\U0001fb3cUsers\U0001fb3cMayn'.encode()
    slash_rise_block = 'C:\U0001fb5bUsers\U0001fb5brain'.encode()
    slash_wide_rise = 'C:\U0001fb5aUsers\U0001fb5aMayn'.encode()
    slash_mid_rise = 'C:\U0001fb5cUsers\U0001fb5crain'.encode()
    slash_inner_rise = 'C:\U0001fb59Users\U0001fb59kawang'.encode()
    slash_top_rise = 'C:\U0001fb58Users\U0001fb58Mayn'.encode()
    slash_short_top_rise = 'C:\U0001fb57Users\U0001fb57rain'.encode()
    slash_lower_right_block = 'C:\U0001fb45Users\U0001fb45Mayn'.encode()
    slash_wide_lower_right = 'C:\U0001fb44Users\U0001fb44kawang'.encode()
    slash_mid_lower_right = 'C:\U0001fb46Users\U0001fb46gptbridge'.encode()
    slash_inner_lower_right = 'C:\U0001fb43Users\U0001fb43WishToApp'.encode()
    slash_top_lower_right = 'C:\U0001fb42Users\U0001fb42rain'.encode()
    slash_short_top_lower_right = 'C:\U0001fb41Users\U0001fb41Mayn'.encode()
    slash_lower_centre_lower_right = 'C:\U0001fb4bUsers\U0001fb4bkawang'.encode()
    slash_outer_lower_right = 'C:\U0001fb4aUsers\U0001fb4agptbridge'.encode()
    slash_short_lower_centre_lower_right = 'C:\U0001fb49Users\U0001fb49WishToApp'.encode()
    slash_lower_lower_right = 'C:\U0001fb48Users\U0001fb48rain'.encode()
    slash_short_lower_lower_right = 'C:\U0001fb47Users\U0001fb47Mayn'.encode()
    slash_lower_centre_upper_left = 'C:\U0001fb61Users\U0001fb61kawang'.encode()
    slash_outer_upper_left = 'C:\U0001fb60Users\U0001fb60gptbridge'.encode()
    slash_short_lower_centre_upper_left = 'C:\U0001fb5fUsers\U0001fb5fWishToApp'.encode()
    slash_lower_upper_left = 'C:\U0001fb5eUsers\U0001fb5erain'.encode()
    slash_short_lower_upper_left = 'C:\U0001fb5dUsers\U0001fb5dMayn'.encode()
    slash_upper_left_lower_right_fill = 'C:\U0001fb98Users\U0001fb98Mayn'.encode()
    slash_upper_right_lower_left_fill = 'C:\U0001fb99Users\U0001fb99kawang'.encode()
    slash_square_upper_left_lower_right = 'C:\u25a7Users\u25a7gptbridge'.encode()
    slash_square_upper_right_lower_left = 'C:\u25a8Users\u25a8WishToApp'.encode()
    slash_square_diagonal_crosshatch = 'C:\u25a9Users\u25a9rain'.encode()
    slash_light_diagonal_cross = 'C:\u2573Users\u2573Mayn'.encode()
    slash_light_diagonal_corner = 'C:\U0001fba4Users\U0001fba4kawang'.encode()
    slash_light_diagonal_right_corner = 'C:\U0001fba5Users\U0001fba5gptbridge'.encode()
    slash_light_diagonal_lower_corner = 'C:\U0001fba6Users\U0001fba6rain'.encode()
    slash_light_diagonal_top_corner = 'C:\U0001fba7Users\U0001fba7Mayn'.encode()
    slash_light_diagonal_paired_rise = 'C:\U0001fba8Users\U0001fba8WishToApp'.encode()
    slash_light_diagonal_paired_fall = 'C:\U0001fba9Users\U0001fba9Mayn'.encode()
    slash_light_diagonal_long_right = 'C:\U0001fbaaUsers\U0001fbaarain'.encode()
    slash_light_diagonal_long_left = 'C:\U0001fbabUsers\U0001fbabgptbridge'.encode()
    slash_light_diagonal_long_upper = 'C:\U0001fbacUsers\U0001fbacWishToApp'.encode()
    slash_light_diagonal_long_right_upper = 'C:\U0001fbadUsers\U0001fbadrain'.encode()
    if any('personal Windows path' not in content_reasons(item) for item in (slash_yen, slash_won, slash_div, slash_set, slash_small, slash_frac, slash_wide, slash_apl, slash_apl_back, slash_quad, slash_quad_back, slash_circled, slash_circled_back, slash_apl_circle, slash_short, slash_short_back, slash_short_lower, slash_short_rise, slash_neg, slash_mod, slash_block, slash_wide_block, slash_mid_block, slash_inner_block, slash_top_block, slash_short_top_block, slash_lower_centre_block, slash_outer_block, slash_short_lower_centre_block, slash_lower_block, slash_short_lower_block, slash_lower_left_block, slash_wide_lower_left, slash_mid_lower_left, slash_inner_lower_left, slash_top_lower_left, slash_short_top_lower_left, slash_lower_centre_lower_left, slash_outer_lower_left, slash_short_lower_centre_lower_left, slash_lower_lower_left, slash_short_lower_lower_left, slash_rise_block, slash_wide_rise, slash_mid_rise, slash_inner_rise, slash_top_rise, slash_short_top_rise, slash_lower_right_block, slash_wide_lower_right, slash_mid_lower_right, slash_inner_lower_right, slash_top_lower_right, slash_short_top_lower_right, slash_lower_centre_lower_right, slash_outer_lower_right, slash_short_lower_centre_lower_right, slash_lower_lower_right, slash_short_lower_lower_right, slash_lower_centre_upper_left, slash_outer_upper_left, slash_short_lower_centre_upper_left, slash_lower_upper_left, slash_short_lower_upper_left, slash_upper_left_lower_right_fill, slash_upper_right_lower_left_fill, slash_square_upper_left_lower_right, slash_square_upper_right_lower_left, slash_square_diagonal_crosshatch, slash_light_diagonal_cross, slash_light_diagonal_corner, slash_light_diagonal_right_corner, slash_light_diagonal_lower_corner, slash_light_diagonal_top_corner, slash_light_diagonal_paired_rise, slash_light_diagonal_paired_fall, slash_light_diagonal_long_right, slash_light_diagonal_long_left, slash_light_diagonal_long_upper, slash_light_diagonal_long_right_upper)):
        raise SystemExit('self-test failed: a slash-lookalike personal path was not detected')
    if content_reasons('see \u00a5 later'.encode()) or content_reasons('see \u3031 later'.encode()) or content_reasons('see \u3035 later'.encode()) or content_reasons('see \u30ce later'.encode()) or content_reasons('about \u00bc later'.encode()) or content_reasons('see \u233f later'.encode()) or content_reasons('see \u2340 later'.encode()) or content_reasons('see \u2341 later'.encode()) or content_reasons('see \u2342 later'.encode()) or content_reasons('see \u2298 later'.encode()) or content_reasons('see \u29b8 later'.encode()) or content_reasons('see \u2349 later'.encode()) or content_reasons('see \u20e0 later'.encode()) or content_reasons('C:\u2349Users\u2349other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\u2349' + 'a' * 20).encode()) or content_reasons('see \u2a38 later'.encode()) or content_reasons('C:\u2298Users\u2298other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\u2298' + 'a' * 20).encode()) or content_reasons('C:\u2215Users\u2215other'.encode()) or content_reasons('C:\u2215tmp\u2215Mayn'.encode()) or content_reasons('C:\u233fUsers\u233fother'.encode()) or content_reasons(('sk-' + '\u2215' + 'a' * 30).encode()) or content_reasons(('sk-' + 'a' * 10 + '\u00a5' + 'a' * 20).encode()) or content_reasons(('sk-' + 'a' * 10 + '\u233f' + 'a' * 20).encode()) or content_reasons('see \U0001fba0 later'.encode()) or content_reasons('see \u2573 later'.encode()) or content_reasons('see \U0001fba4 later'.encode()) or content_reasons('see \U0001fbbe later'.encode()) or content_reasons('see \U0001fbbf later'.encode()) or content_reasons('C:\U0001fbbeUsers\U0001fbbeother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fbbe' + 'a' * 20).encode()) or content_reasons('C:\U0001fba0Users\U0001fba0other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fba0' + 'a' * 20).encode()) or content_reasons('see \ua718 later'.encode()) or content_reasons('see \ua717 later'.encode()) or content_reasons('see \ua719 later'.encode()) or content_reasons('C:\ua718Users\ua718other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\ua718' + 'a' * 20).encode()) or content_reasons('see \U0001fb66 later'.encode()) or content_reasons('see \U0001fb65 later'.encode()) or content_reasons('see \U0001fb64 later'.encode()) or content_reasons('see \U0001fb63 later'.encode()) or content_reasons('see \U0001fb62 later'.encode()) or content_reasons('see \U0001fb67 later'.encode()) or content_reasons('see \U0001fb68 later'.encode()) or content_reasons('C:\U0001fb66Users\U0001fb66other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb66' + 'a' * 20).encode()) or content_reasons('C:\U0001fb65Users\U0001fb65other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb65' + 'a' * 20).encode()) or content_reasons('C:\U0001fb67Users\U0001fb67other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb67' + 'a' * 20).encode()) or content_reasons('C:\U0001fb64Users\U0001fb64other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb64' + 'a' * 20).encode()) or content_reasons('C:\U0001fb63Users\U0001fb63other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb63' + 'a' * 20).encode()) or content_reasons('see \U0001fb56 later'.encode()) or content_reasons('see \U0001fb55 later'.encode()) or content_reasons('see \U0001fb54 later'.encode()) or content_reasons('see \U0001fb53 later'.encode()) or content_reasons('see \U0001fb52 later'.encode()) or content_reasons('see \U0001fb51 later'.encode()) or content_reasons('see \U0001fb50 later'.encode()) or content_reasons('see \U0001fb4f later'.encode()) or content_reasons('see \U0001fb4e later'.encode()) or content_reasons('see \U0001fb4d later'.encode()) or content_reasons('see \U0001fb4c later'.encode()) or content_reasons('see \U0001fb40 later'.encode()) or content_reasons('see \U0001fb3f later'.encode()) or content_reasons('see \U0001fb3e later'.encode()) or content_reasons('see \U0001fb3d later'.encode()) or content_reasons('see \U0001fb3c later'.encode()) or content_reasons('see \U0001fb41 later'.encode()) or content_reasons('see \U0001fb42 later'.encode()) or content_reasons('C:\U0001fb3cUsers\U0001fb3cother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb3c' + 'a' * 20).encode()) or content_reasons('C:\U0001fb3dUsers\U0001fb3dother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb3d' + 'a' * 20).encode()) or content_reasons('C:\U0001fb3eUsers\U0001fb3eother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb3e' + 'a' * 20).encode()) or content_reasons('C:\U0001fb3fUsers\U0001fb3fother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb3f' + 'a' * 20).encode()) or content_reasons('C:\U0001fb40Users\U0001fb40other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb40' + 'a' * 20).encode()) or content_reasons('C:\U0001fb4cUsers\U0001fb4cother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb4c' + 'a' * 20).encode()) or content_reasons('C:\U0001fb4dUsers\U0001fb4dother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb4d' + 'a' * 20).encode()) or content_reasons('C:\U0001fb4eUsers\U0001fb4eother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb4e' + 'a' * 20).encode()) or content_reasons('C:\U0001fb51Users\U0001fb51other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb51' + 'a' * 20).encode()) or content_reasons('C:\U0001fb4fUsers\U0001fb4fother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb4f' + 'a' * 20).encode()) or content_reasons('C:\U0001fb50Users\U0001fb50other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb50' + 'a' * 20).encode()) or content_reasons('C:\U0001fb52Users\U0001fb52other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb52' + 'a' * 20).encode()) or content_reasons('C:\U0001fb53Users\U0001fb53other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb53' + 'a' * 20).encode()) or content_reasons('C:\U0001fb54Users\U0001fb54other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb54' + 'a' * 20).encode()) or content_reasons('C:\U0001fb55Users\U0001fb55other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb55' + 'a' * 20).encode()) or content_reasons('C:\U0001fb56Users\U0001fb56other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb56' + 'a' * 20).encode()) or content_reasons('C:\U0001fb62Users\U0001fb62other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb62' + 'a' * 20).encode()) or content_reasons('see \U0001fb5b later'.encode()) or content_reasons('see \U0001fb5a later'.encode()) or content_reasons('see \U0001fb59 later'.encode()) or content_reasons('see \U0001fb58 later'.encode()) or content_reasons('see \U0001fb57 later'.encode()) or content_reasons('see \U0001fb5c later'.encode()) or content_reasons('see \U0001fb5d later'.encode()) or content_reasons('C:\U0001fb5bUsers\U0001fb5bother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb5b' + 'a' * 20).encode()) or content_reasons('C:\U0001fb5aUsers\U0001fb5aother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb5a' + 'a' * 20).encode()) or content_reasons('C:\U0001fb5cUsers\U0001fb5cother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb5c' + 'a' * 20).encode()) or content_reasons('C:\U0001fb59Users\U0001fb59other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb59' + 'a' * 20).encode()) or content_reasons('C:\U0001fb58Users\U0001fb58other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb58' + 'a' * 20).encode()) or content_reasons('C:\U0001fb57Users\U0001fb57other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb57' + 'a' * 20).encode()) or content_reasons('see \U0001fb45 later'.encode()) or content_reasons('see \U0001fb44 later'.encode()) or content_reasons('see \U0001fb46 later'.encode()) or content_reasons('C:\U0001fb45Users\U0001fb45other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb45' + 'a' * 20).encode()) or content_reasons('see \U0001fb44 later'.encode()) or content_reasons('see \U0001fb43 later'.encode()) or content_reasons('see \U0001fb46 later'.encode()) or content_reasons('C:\U0001fb44Users\U0001fb44other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb44' + 'a' * 20).encode()) or content_reasons('see \U0001fb46 later'.encode()) or content_reasons('see \U0001fb47 later'.encode()) or content_reasons('see \U0001fb43 later'.encode()) or content_reasons('C:\U0001fb46Users\U0001fb46other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb46' + 'a' * 20).encode()) or content_reasons('see \U0001fb43 later'.encode()) or content_reasons('see \U0001fb42 later'.encode()) or content_reasons('see \U0001fb47 later'.encode()) or content_reasons('C:\U0001fb43Users\U0001fb43other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb43' + 'a' * 20).encode()) or content_reasons('see \U0001fb42 later'.encode()) or content_reasons('see \U0001fb41 later'.encode()) or content_reasons('see \U0001fb47 later'.encode()) or content_reasons('C:\U0001fb42Users\U0001fb42other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb42' + 'a' * 20).encode()) or content_reasons('see \U0001fb41 later'.encode()) or content_reasons('see \U0001fb40 later'.encode()) or content_reasons('see \U0001fb47 later'.encode()) or content_reasons('see \U0001fb48 later'.encode()) or content_reasons('C:\U0001fb41Users\U0001fb41other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb41' + 'a' * 20).encode()) or content_reasons('see \U0001fb4b later'.encode()) or content_reasons('see \U0001fb4a later'.encode()) or content_reasons('see \U0001fb49 later'.encode()) or content_reasons('C:\U0001fb4bUsers\U0001fb4bother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb4b' + 'a' * 20).encode()) or content_reasons('see \U0001fb4a later'.encode()) or content_reasons('see \U0001fb49 later'.encode()) or content_reasons('see \U0001fb48 later'.encode()) or content_reasons('C:\U0001fb4aUsers\U0001fb4aother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb4a' + 'a' * 20).encode()) or content_reasons('see \U0001fb49 later'.encode()) or content_reasons('see \U0001fb48 later'.encode()) or content_reasons('see \U0001fb47 later'.encode()) or content_reasons('C:\U0001fb49Users\U0001fb49other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb49' + 'a' * 20).encode()) or content_reasons('see \U0001fb48 later'.encode()) or content_reasons('see \U0001fb47 later'.encode()) or content_reasons('see \U0001fb49 later'.encode()) or content_reasons('C:\U0001fb48Users\U0001fb48other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb48' + 'a' * 20).encode()) or content_reasons('see \U0001fb47 later'.encode()) or content_reasons('see \U0001fb61 later'.encode()) or content_reasons('see \U0001fb68 later'.encode()) or content_reasons('C:\U0001fb47Users\U0001fb47other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb47' + 'a' * 20).encode()) or content_reasons('see \U0001fb61 later'.encode()) or content_reasons('see \U0001fb60 later'.encode()) or content_reasons('see \U0001fb68 later'.encode()) or content_reasons('C:\U0001fb61Users\U0001fb61other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb61' + 'a' * 20).encode()) or content_reasons('see \U0001fb60 later'.encode()) or content_reasons('see \U0001fb5f later'.encode()) or content_reasons('see \U0001fb68 later'.encode()) or content_reasons('C:\U0001fb60Users\U0001fb60other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb60' + 'a' * 20).encode()) or content_reasons('see \U0001fb5f later'.encode()) or content_reasons('see \U0001fb5e later'.encode()) or content_reasons('see \U0001fb68 later'.encode()) or content_reasons('C:\U0001fb5fUsers\U0001fb5fother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb5f' + 'a' * 20).encode()) or content_reasons('see \U0001fb5e later'.encode()) or content_reasons('see \U0001fb5d later'.encode()) or content_reasons('see \U0001fb68 later'.encode()) or content_reasons('C:\U0001fb5eUsers\U0001fb5eother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb5e' + 'a' * 20).encode()) or content_reasons('see \U0001fb5d later'.encode()) or content_reasons('see \U0001fba4 later'.encode()) or content_reasons('see \U0001fb68 later'.encode()) or content_reasons('C:\U0001fb5dUsers\U0001fb5dother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb5d' + 'a' * 20).encode()) or content_reasons('see \U0001fb98 later'.encode()) or content_reasons('see \U0001fb99 later'.encode()) or content_reasons('see \U0001fb68 later'.encode()) or content_reasons('C:\U0001fb98Users\U0001fb98other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb98' + 'a' * 20).encode()) or content_reasons('see \U0001fb99 later'.encode()) or content_reasons('see \U0001fb68 later'.encode()) or content_reasons('C:\U0001fb99Users\U0001fb99other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fb99' + 'a' * 20).encode()) or content_reasons('see \u25a7 later'.encode()) or content_reasons('see \u25a8 later'.encode()) or content_reasons('see \u25a9 later'.encode()) or content_reasons('C:\u25a7Users\u25a7other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\u25a7' + 'a' * 20).encode()) or content_reasons('see \u25a8 later'.encode()) or content_reasons('see \u25a9 later'.encode()) or content_reasons('C:\u25a8Users\u25a8other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\u25a8' + 'a' * 20).encode()) or content_reasons('see \u25a9 later'.encode()) or content_reasons('see \u25a6 later'.encode()) or content_reasons('see \u2573 later'.encode()) or content_reasons('C:\u25a9Users\u25a9other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\u25a9' + 'a' * 20).encode()) or content_reasons('see \u2573 later'.encode()) or content_reasons('see \U0001fba4 later'.encode()) or content_reasons('C:\u2573Users\u2573other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\u2573' + 'a' * 20).encode()) or content_reasons('see \U0001fba4 later'.encode()) or content_reasons('see \U0001fba5 later'.encode()) or content_reasons('C:\U0001fba4Users\U0001fba4other'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fba4' + 'a' * 20).encode()) or content_reasons('see \U0001fbad later'.encode()) or content_reasons('see \U0001fbae later'.encode()) or content_reasons('C:\U0001fbadUsers\U0001fbadother'.encode()) or content_reasons(('sk-' + 'a' * 10 + '\U0001fbad' + 'a' * 20).encode()):
        raise SystemExit('self-test failed: ordinary slash text was blocked')

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
