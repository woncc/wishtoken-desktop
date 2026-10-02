'use strict';

const accountID = /^acc-[a-zA-Z0-9-]{1,80}$/;
function cleanChannel(value) {
  const channel = value ?? 'bps';
  if (!['bps', 'codex'].includes(channel)) throw new Error('请选择 BPS 或原生通道');
  return channel;
}
function requireChannel(value) {
  if (value !== 'bps' && value !== 'codex') throw new Error('请选择 BPS 或原生通道');
  return value;
}
function cleanModel(value) {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9.-]{1,80}$/.test(value)) throw new Error('模型无效');
  return value;
}
function cleanEffort(value) {
  if (!['low', 'medium', 'high', 'xhigh'].includes(value)) throw new Error('推理档位无效');
  return value;
}
function cleanProbe(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('测试参数无效');
  return { account_id: requireID(input.account_id), model: cleanModel(input.model), effort: cleanEffort(input.effort), channel: requireChannel(input.channel) };
}
const SECRET_KEYS = new Set(['access_token', 'accesstoken', 'refresh_token', 'refreshtoken', 'id_token', 'idtoken', 'api_key', 'apikey', 'authorization', 'password', 'secret', 'client_secret', 'clientsecret', 'cockpit_key', 'cockpitkey', 'gptbridge_codex_key', 'personal_access_token', 'personalaccesstoken', 'openai_api_key', 'openaiapikey', 'experimental_bearer_token', 'bearer_token', 'bearertoken', 'auth_token', 'authtoken', 'response_id', 'responseid']);
const SECRET_TEXT = [
  [/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, '[凭据已隐藏]'],
  [/\bBearer\s+[A-Za-z0-9._~+/-]{12,}/gi, 'Bearer [凭据已隐藏]'],
  [/\brt_[A-Za-z0-9_-]{8,}\b/g, '[凭据已隐藏]'],
  [/\b(?:sk|rk)-[A-Za-z0-9_-]{12,}\b/g, '[凭据已隐藏]'],
  [/(cockpit-auth\/)[A-Fa-f0-9]{32,}/gi, '$1[凭据已隐藏]'],
  [/((?:access_token|refresh_token|id_token|api_key|cockpit_key|client_secret|personal_access_token|experimental_bearer_token|openai_api_key|response_id)["'\s:=]{1,8})[^\s"',&<]{8,}/gi, '$1[凭据已隐藏]']
];
// A space, newline, or extra @ defeats a normal URL parse. Those passwords are
// removed from renderer text too. Username-only values stay; the settings
// field is copied back after this pass so the editor can round-trip.
// A single-label, short, hex, or decimal host counts only with an explicit
// port. "v1:2@beta" and "user:secret@10.1" stay ordinary text.
// %3A is a port colon too. A literal-colon host check leaves the password in
// "user:secret@127.0.0.1%3A7890". Four numeric labels can omit the port, the
// same way a dotted IPv4 address already can.
// %2E is a host dot, including a nested %252E. U+FF0E U+FE52 U+2024 fold to
// "." under NFKC, and so do their percent-encoded forms. A literal-dot check
// leaves the password in "user:secret@127%2E0%2E0%2E1:7890". Fullwidth digits
// are numeric labels as well.
// Port digits can be percent-encoded, including a nested %2537, or fullwidth.
// A literal-digit check leaves the password in
// "user:secret@127.0.0.1%3A%37%38%39%30". One digit still does not make a
// single-label host count.
// Fullwidth digits can be percent-encoded too. U+FF10..U+FF19 are the bytes
// EF BC 90..EF BC 99, and each byte can carry the same extra %25 layers.
// A literal fullwidth check leaves the password in
// "user:secret@my-proxy:%EF%BC%97%EF%BC%98%EF%BC%99%EF%BC%90" and in a numeric
// host such as
// "user:secret@%EF%BC%91%EF%BC%92%EF%BC%97%2E%EF%BC%90%2E%EF%BC%90%2E%EF%BC%91:7890".
// Superscript and subscript digits do not fold to 0-9. They still count as
// port and numeric-host digits. Their UTF-8 bytes can be percent-encoded,
// including a nested %25 layer on each byte: C2 B2/B3/B9, E2 81 B0/B4-B9,
// and E2 82 80-89. Otherwise "user:secret@my-proxy:\u2077\u2078\u2079\u2070"
// and "user:secret@10.1:%E2%82%88%E2%82%80%E2%82%88%E2%82%80" keep the password.
// A closing quote, bracket, or sentence mark is not part of the host. The
// lookahead has to accept it, or "(user:secret@127.0.0.1:7890)" keeps the password.
// A backtick, pipe, or backslash after the port is a boundary too, including
// the fullwidth forms. Curly quotes count because straight quotes already do.
// Otherwise a single-label host such as "user:secret@my-proxy:7890`next"
// keeps the password.
// A query, path, or fragment marker is a boundary too. Otherwise
// "http://example.com/?x=user:secret@10.0.0.8:1080" keeps the password.
// The same markers can sit inside the password. A URL parser rejects
// "http://user:secret/token@10.0.0.8:1080", but the raw text, and the
// "invalid port" fragment of that error, still contain the secret.
// "=" and "&" are not part of the username, so a query key stays in place.
// They also end the host. Fullwidth, small, superscript, and subscript forms
// fold to the same joiners, and so do their percent-encoded forms. Otherwise
// "a=1&user:secret@my-proxy:7890&b=2" keeps the password.
// An opening bracket ends the host too. Fullwidth, small, superscript,
// subscript, and vertical forms fold to ASCII brackets, and so do their
// percent-encoded forms. Otherwise "user:secret@my-proxy:7890<br>"
// keeps the password.
// A tilde, star, plus, dollar, or caret ends the host too. Fullwidth,
// small, superscript, and subscript forms fold to those marks, and so
// do their percent-encoded forms. Otherwise "user:secret@my-proxy:7890~tmp"
// keeps the password.
// A semicolon or comma ends the host too. The Greek question mark and the
// small, vertical, and fullwidth forms fold to those marks, and so do their
// percent-encoded forms. Otherwise "user:secret@my-proxy:7890%3Bnext"
// keeps the password.
// An exclamation mark ends the host too. Small, vertical, and fullwidth
// forms fold to "!", and so do their percent-encoded forms. Otherwise
// "user:secret@my-proxy:7890%21next" keeps the password.
// A path, query, or fragment marker ends the host too. Literal "/" "?" "#"
// already do. Percent-encoding hides the same cut, including a nested
// %252F, and U+FF0F U+FE16 U+FE56 U+FF1F U+FE5F U+FF03 fold to those marks.
// Otherwise "user:secret@my-proxy:7890%2Fnext" keeps the password.
// A whitespace character ends the host too. The literal forms already do.
// Percent-encoding hides that cut, including a nested %2520. Otherwise
// "user:secret@my-proxy:7890%20next" keeps the password.
// A closing quote ends the host too. Straight and curly quotes already do.
// Percent-encoding hides that cut, including a nested %2522. U+FF02 and
// U+FF07 fold to straight quotes, and so do their percent-encoded forms.
// Otherwise "user:secret@my-proxy:7890%22next" keeps the password.
// A backtick, pipe, or backslash ends the host too. The literal forms already
// do, including the fullwidth forms. Percent-encoding hides that cut, including
// a nested %2560. U+1FEF folds to a backtick and U+FE68 folds to a backslash,
// and so do their percent-encoded forms. Otherwise
// "user:secret@my-proxy:7890%60next" keeps the password.
// A C0 control or DEL ends the host too. Tab and the newline controls are
// already whitespace. Percent-encoding hides the rest, including a nested
// %2500. Otherwise "user:secret@my-proxy:7890%00next" keeps the password.
// A sentence period ends the host too. "." and "。" already do.
// Percent-encoding hides that cut, including a nested %252E. U+FF0E
// U+FE52 U+2024 fold to ".", and U+FE12 U+FF61 fold to "。".
// Otherwise "user:secret@my-proxy:7890%2Enext" keeps the password.
// A colon after the port ends the host too. A literal colon already does.
// Percent-encoding hides that cut, including a nested %253A, and so do the
// colon lookalikes. Mongolian and Manchu full stops are the same kind of
// separator. Otherwise "user:secret@my-proxy:7890%3Anext" and
// "user:secret@my-proxy\u18037890" keep the password.
// Proportion and squared four-dot punctuation are the same kind of separator.
// Otherwise "user:secret@my-proxy\u22377890" keeps the password.
// Ethiopic short rikrik, musical repeat dots, and Tolong Siki sela are separators too.
// Otherwise "user:secret@my-proxy\u13937890" keeps the password.
// U+0705 through U+0709 are the remaining Syriac colons. They do not fold to
// ":". Otherwise "user\u0705secret@127.0.0.1:7890" and
// "user:secret@my-proxy\u07057890" keep the password.
// A colon before the username is a boundary too, including those lookalikes.
// Otherwise "note :user:secret@10.1:8080" and
// "note \u0705user:secret@10.1:8080" keep the password.
// U+1365 and U+1366 are the Ethiopic colon and preface colon. They do not
// fold to ":". Otherwise "user\u1365secret@127.0.0.1:7890" and
// "user:secret@my-proxy\u13657890" keep the password.
// A colon before the username is a boundary too, including these marks.
// Otherwise "note \u1365user:secret@10.1:8080" keeps the password.
// U+1804 is the Mongolian colon. It does not fold to ":". Otherwise
// "user\u1804secret@127.0.0.1:7890" and "user:secret@my-proxy\u18047890"
// keep the password. A colon before the username is a boundary too.
// Otherwise "note \u1804user:secret@10.1:8080" keeps the password.
// U+02D1 is the modifier half triangular colon. It does not fold to ":".
// Otherwise "user\u02D1secret@127.0.0.1:7890" and
// "user:secret@my-proxy\u02D17890" keep the password. A colon before the
// username is a boundary too, or "note \u02D1user:secret@10.1:8080" keeps
// the password.
// The other Unicode confusables that map to one colon are separators too.
// U+05C3 U+0831 U+0903 U+0A83 U+1361 U+16EC U+205A and U+A4FD do not fold
// to ":". U+FE30 folds to ".." and already ends a host, but it does not yet
// divide userinfo or a port. Otherwise "user\u05C3secret@127.0.0.1:7890"
// and "user:secret@my-proxy\u16EC7890" keep the password. A colon before
// the username is a boundary too, or "note \u205Auser:secret@10.1:8080"
// keeps the password.
// U+2254, U+29F4, and U+2A74 are one mark that confuses with a colon plus
// more. U+2A74 folds to "::=" under NFKC, but the raw character does not,
// and U+2254 and U+29F4 do not fold to ":". U+2255 confuses with "=:" and
// does not fold to ":". Otherwise "user\u2254secret@127.0.0.1:7890" and
// "user:secret@my-proxy\u2A747890" keep the password. A colon before the
// username is a boundary too, or "note \u2255user:secret@10.1:8080" keeps
// the password.
// A middle dot after the port ends the host too. These marks do not fold to
// "." or "。" under NFKC, so the period cut never sees them. U+0387 folds to
// U+00B7 and U+FF65 folds to U+30FB. Percent-encoding hides the same cut,
// including a nested %25 layer. Otherwise "user:secret@my-proxy:7890%C2%B7next"
// keeps the password.
// Bullets, danda, the Arabic and Syriac full stops, and the two-dot leader do
// not fold to "." or U+3002. They still end the host and split its labels,
// including a nested percent-encoding. U+FE30 folds to the two-dot leader.
// Otherwise "user:secret@my-proxy:7890%E2%80%A2next" and
// "user:secret@127%E2%80%A20%E2%80%A20%E2%80%A21:7890" keep the password.
// U+3002 does not fold to ".". U+FE12 and U+FF61 fold to U+3002. Those marks
// already end a host, but "user:secret@127%E3%80%820%E3%80%820%E3%80%821:7890"
// kept the password because they did not split labels.
// Format characters and default ignorables are not part of a host, but they
// are also a boundary. Deleting one after a port would glue the next word on
// and keep the password. A mark counts inside a label only when another host
// character follows; otherwise the existing tail check still sees it.
// Supplementary format characters fold to U+200B first. U+200B is in this set.
// Percent-encoding hides the same mark. Each UTF-8 byte can carry the extra
// %25 layers already accepted for a port digit. Otherwise
// "user:secret@my%E2%80%8Bproxy:7890" keeps the password. The same encoding
// before a port digit hides it on a single-label host, or
// "user:secret@my-proxy:%E2%80%8B7890" keeps the password. A supplementary
// encoding folds to U+200B too. Text that is not a proxy stays as written.
const PROXY_MARK = '\u00AD\u034F\u0600\u0601\u0602\u0603\u0604\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2\u115F\u1160\u180E\u200B\u200C\u200D\u200E\u200F\u202A\u202B\u202C\u202D\u202E\u2060\u2061\u2062\u2063\u2064\u2066\u2067\u2068\u2069\u206A\u206B\u206C\u206D\u206E\u206F\u3164\uFE00\uFE01\uFE02\uFE03\uFE04\uFE05\uFE06\uFE07\uFE08\uFE09\uFE0A\uFE0B\uFE0C\uFE0D\uFE0E\uFE0F\uFEFF\uFFA0\uFFF9\uFFFA\uFFFB';
const MARK = `[${PROXY_MARK}]`;
const PROXY_BOUND = '[\\s"\'()<>\\[\\]{}/?#&=「」『』【】（）《》〈〉`｀|｜\\\\＼‘’“”＆﹠＝﹦⁼₌⁽⁾₍₎︵︶︷︸﹇﹈﹙﹚﹛﹜﹤﹥（）＜＞［］｛｝~*+$^～﹡＊⁺₊﬩﹢＋﹩＄＾;,;︔﹔；︐﹐，!︕﹗！／︖﹖？﹟＃＂＇`﹨\u0000-\u0008\u000E-\u001F\u007F．﹒․。︒｡··ᐧ‧∙⋅⸱・･\u2022\u2023\u2043\u204C\u204D\u25E6\u29BF\u0964\u0965\u06D4\u0701\u0702\u2025\uFE30:\uFE13\uFE55\uFF1A\u2236\u02D0\uA789\u02F8\u0703\u0704\u0589\u1803\u1809\u2237\u2E2C\u0705\u0706\u0707\u0708\u0709\u1393\u1365\u1366\u1804\u02D1\u05C3\u0831\u0903\u0A83\u1361\u16EC\u205A\uA4FD\u2254\u2255\u29F4\u2A74' + PROXY_MARK + ']';
const PROXY_USER = '[^\\s"\'()<>\\[\\]{}/?#:@=&「」『』【】（）《》〈〉`｀|｜\\\\＼‘’“”＆﹠＝﹦⁼₌⁽⁾₍₎︵︶︷︸﹇﹈﹙﹚﹛﹜﹤﹥（）＜＞［］｛｝~*+$^～﹡＊⁺₊﬩﹢＋﹩＄＾;,;︔﹔；︐﹐，!︕﹗！／︖﹖？﹟＃＂＇`﹨\u0000-\u0008\u000E-\u001F\u007F．﹒․。︒｡··ᐧ‧∙⋅⸱・･\u2022\u2023\u2043\u204C\u204D\u25E6\u29BF\u0964\u0965\u06D4\u0701\u0702\u2025\uFE30]';
const PROXY_TAIL = '[\\s/?#.,;:!)\\]}>"\'（）「」『』【】《》〈〉，。！？；、»«`｀|｜\\\\＼‘’“”&=＆﹠＝﹦⁼₌(<{\\[⁽⁾₍₎︵︶︷︸﹇﹈﹙﹚﹛﹜﹤﹥（）＜＞［］｛｝~*+$^～﹡＊⁺₊﬩﹢＋﹩＄＾;︔﹔︐﹐︕﹗／︖﹖？﹟＃＂＇`﹨\u0000-\u0008\u000E-\u001F\u007F．﹒․。︒｡··ᐧ‧∙⋅⸱・･\u2022\u2023\u2043\u204C\u204D\u25E6\u29BF\u0964\u0965\u06D4\u0701\u0702\u2025\uFE30' + PROXY_MARK + ']';
// Compatibility colons and other colon-shaped marks still divide userinfo.
// U+FE13 U+FE55 U+FF1A fold to ":" under NFKC. U+2236 U+02D0 U+A789 U+02F8
// U+0703 U+0704 U+0589 do not, but a password can hide behind them too.
// U+1803 and U+1809 do not fold to ":" either. They still divide userinfo
// and a port, or "user:secret@my-proxy\u18037890" keeps the password.
// U+2237 and U+2E2C do not fold to ":". They are confusable with "::"
// and still divide userinfo and a port, or "user:secret@my-proxy\u22377890"
// keeps the password.
// Percent-encoding of those UTF-8 bytes, including extra %25 layers, and a
// nested ASCII colon such as %253A, are separators as well. A lookalike in
// the port is a separator too, or the same mark before the port keeps the password.
// U+0705 through U+0709 are the remaining Syriac colons. They do not fold to
// ":" either. A colon before the username is a boundary too, including these
// marks, or "note :user:secret@10.1:8080" keeps the password.
// U+1365 and U+1366 are the Ethiopic colon and preface colon. They do not fold
// to ":" either. A colon before the username is a boundary too, including
// these marks, or "note \u1365user:secret@10.1:8080" keeps the password.
// U+1804 is the Mongolian colon. It does not fold to ":" either. A colon
// before the username is a boundary too, or "note \u1804user:secret@10.1:8080"
// keeps the password.
// U+02D1 is the modifier half triangular colon. It does not fold to ":"
// either. A colon before the username is a boundary too, or
// "note \u02D1user:secret@10.1:8080" keeps the password.
// U+05C3 U+0831 U+0903 U+0A83 U+1361 U+16EC U+205A and U+A4FD map to one
// colon and do not fold to ":". U+FE30 folds to ".." and is already a host
// boundary, but it still has to divide userinfo and a port. Otherwise
// "user\u05C3secret@127.0.0.1:7890" and "user:secret@my-proxy\uFE307890"
// keep the password.
// U+2254 maps to ":=", U+29F4 maps to a colon and an arrow, and U+2A74 maps
// to "::=". U+2A74 folds to "::=" under NFKC; the other two do not fold to
// ":". U+2255 maps to "=:". They still divide userinfo and a port, or
// "user\u2254secret@127.0.0.1:7890" and "user:secret@my-proxy\u2A747890"
// keep the password.
const COLON_CHARS = ['\uFE13', '\uFE55', '\uFF1A', '\u2236', '\u02D0', '\uA789', '\u02F8', '\u0703', '\u0704', '\u0589', '\u1803', '\u1809', '\u2237', '\u2E2C', '\u0705', '\u0706', '\u0707', '\u0708', '\u0709', '\u1365', '\u1366', '\u1804', '\u02D1', '\u05C3', '\u0831', '\u0903', '\u0A83', '\u1361', '\u16EC', '\u205A', '\uA4FD', '\uFE30', '\u2254', '\u2255', '\u29F4', '\u2A74'];
function percentBytes(char) {
  return encodeURIComponent(char).replace(/%([0-9A-F]{2})/g, (_match, hex) => {
    const cls = digit => (digit >= 'A' && digit <= 'F' ? `[${digit}${digit.toLowerCase()}]` : digit);
    return `%${hex.toUpperCase().split('').map(cls).join('')}`;
  });
}
function nestPercent(pattern, extra) {
  let out = pattern;
  for (let layer = 0; layer < extra; layer += 1) out = out.replace(/%/g, '%25');
  return out;
}
// U+1393, U+1D108, and U+11DD9 do not fold to ":". The last two are
// supplementary, so they stay out of the character classes and are only
// separators. Otherwise "user:secret@my-proxy\u13937890" keeps the password.
// U+1015B U+10AF5 U+11002 U+11082 U+11182 U+1123A U+115BE U+116AC and
// U+11838 map to one colon too. They are supplementary, so they are only
// separators. Otherwise "user:secret@my-proxy\u{1123A}7890" keeps the password.
const SIGN_COLONS = ['\u1393', '\u{1D108}', '\u{11DD9}', '\u{1015B}', '\u{10AF5}', '\u{11002}', '\u{11082}', '\u{11182}', '\u{1123A}', '\u{115BE}', '\u{116AC}', '\u{11838}'];
function colonSeparator() {
  const parts = [':', '%3[Aa]', '%25(?:25){0,2}3[Aa]'];
  for (const char of COLON_CHARS.concat(SIGN_COLONS)) {
    parts.push(char);
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const COLON_SEP = colonSeparator();
// U+FE6B and U+FF20 fold to "@" under NFKC. A nested %2540 hides the same
// terminator, so user:password%2540host still carries the password.
const AT_CHARS = ['\uFE6B', '\uFF20'];
function atSeparator() {
  const parts = ['@', '%40', '%25(?:25){0,2}40'];
  for (const char of AT_CHARS) {
    parts.push(char);
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const AT_SEP = atSeparator();
// U+FF0E U+FE52 U+2024 fold to "." under NFKC. A nested %252E hides the same dot.
// U+3002 does not. U+FE12 and U+FF61 fold to it, and a label split still hid
// the password. Middle dots, bullets, danda, Arabic and Syriac full stops, and
// the two-dot leader do not fold to "." either. They still split a host.
// Mongolian and Manchu full stops do not fold to "." either. A numeric host
// can hide a password behind them the same way a colon can.
const DOT_CHARS = ['\uFF0E', '\uFE52', '\u2024', '\u3002', '\uFE12', '\uFF61'];
const MIDDLE_CHARS = ['\u00B7', '\u0387', '\u1427', '\u2027', '\u2219', '\u22C5', '\u2E31', '\u30FB', '\uFF65'];
const STOP_CHARS = ['\u2022', '\u2023', '\u2043', '\u204C', '\u204D', '\u25E6', '\u29BF', '\u0964', '\u0965', '\u06D4', '\u0701', '\u0702', '\u2025', '\uFE30'];
const MONGOLIAN_STOPS = ['\u1803', '\u1809'];
function dotSeparator() {
  const parts = ['\\.', '%2[Ee]', '%25(?:25){0,2}2[Ee]'];
  for (const char of DOT_CHARS.concat(MIDDLE_CHARS, STOP_CHARS, MONGOLIAN_STOPS)) {
    parts.push(char);
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const DOT_SEP = dotSeparator();
const SCHEME_USER = '[^\\s/?#:@' + COLON_CHARS.join('') + ']+';
const proxyPort = COLON_SEP;
// Encoded U+FF10..U+FF19. {0,3} extra "25"s is the same 1..4 encoding depth
// already accepted for an ASCII port digit.
const FULLWIDTH_DIGIT = '%(?:25){0,3}[Ee][Ff]%(?:25){0,3}[Bb][Cc]%(?:25){0,3}9\\d';
const ALT_DIGIT = '[\\u00B2\\u00B3\\u00B9\\u2070\\u2074-\\u2079\\u2080-\\u2089]';
const ALT_DIGIT_ENC = '(?:%(?:25){0,3}[Cc]2%(?:25){0,3}[Bb][239]|%(?:25){0,3}[Ee]2%(?:25){0,3}81%(?:25){0,3}[Bb][04-9]|%(?:25){0,3}[Ee]2%(?:25){0,3}82%(?:25){0,3}8\\d)';
const DIGIT = `(?:\\d|[\\uFF10-\\uFF19]|${ALT_DIGIT}|${FULLWIDTH_DIGIT}|${ALT_DIGIT_ENC})`;
const numericLabel = `(?:(?:${DIGIT}(?:${MARK}(?=${DIGIT}))?){1,4}|0[xX][0-9A-Fa-f]{1,8})`;
const domainLabel = `(?:[A-Za-z0-9-](?:${MARK}(?=[A-Za-z0-9-]))?)+`;
const literalDomain = `(?:[A-Za-z0-9.-](?:${MARK}(?=[A-Za-z0-9.-]))?)+\\.(?:[A-Za-z](?:${MARK}(?=[A-Za-z]))?){2,}`;
const encodedDomain = `${domainLabel}(?:${MARK}?(?=${DOT_SEP})${DOT_SEP}${domainLabel})*${MARK}?(?=${DOT_SEP})${DOT_SEP}(?:[A-Za-z](?:${MARK}(?=[A-Za-z]))?){2,}`;
const fourNumeric = `${numericLabel}(?:${MARK}?(?=${DOT_SEP})${DOT_SEP}${numericLabel}){3}`;
const shortNumeric = `${numericLabel}(?:${MARK}?(?=${DOT_SEP})${DOT_SEP}${numericLabel}){0,2}`;
const LOCAL_HOST = 'localhost'.split('').map((ch, index, chars) => ch + (index < chars.length - 1 ? `(?:${MARK}(?=${chars[index + 1]}))?` : '')).join('');
const PORT_DIGIT = `(?:\\d|[\\uFF10-\\uFF19]|${ALT_DIGIT}|%3\\d|%25(?:25){0,2}3\\d|${FULLWIDTH_DIGIT}|${ALT_DIGIT_ENC})`;
// A mark between the colon and a port digit still belongs to the port when a
// digit follows. A single-label host requires that port, or the password stays.
const PORT_MARK = `(?:${MARK}(?=${PORT_DIGIT}))`;
const PORT_SOME = `${PORT_MARK}*${PORT_DIGIT}(?:${PORT_MARK}*${PORT_DIGIT})*`;
const PORT_REQUIRED = `${PORT_MARK}*${PORT_DIGIT}(?:${PORT_MARK}*${PORT_DIGIT}){1,4}`;
// U+FF06 U+FE60 fold to "&". U+FF1D U+FE66 U+207C U+208C fold to "=".
const QUERY_CHARS = ['\uFF06', '\uFE60', '\uFF1D', '\uFE66', '\u207C', '\u208C'];
function queryJoinTail() {
  const parts = ['%26', '%3[Dd]', '%25(?:25){0,2}26', '%25(?:25){0,2}3[Dd]'];
  for (const char of QUERY_CHARS) {
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const QUERY_JOIN = queryJoinTail();
// U+207D U+208D U+FE35 U+FE59 U+FF08 fold to "(". The same families fold
// to ")", "<", ">", "[", "]", "{", and "}". Literal fullwidth parentheses
// are already tails; a percent-encoded bracket still has to end the host.
const BRACKET_CHARS = ['\u207D', '\u207E', '\u208D', '\u208E', '\uFE35', '\uFE36', '\uFE37', '\uFE38', '\uFE47', '\uFE48', '\uFE59', '\uFE5A', '\uFE5B', '\uFE5C', '\uFE64', '\uFE65', '\uFF08', '\uFF09', '\uFF1C', '\uFF1E', '\uFF3B', '\uFF3D', '\uFF5B', '\uFF5D'];
function bracketTail() {
  const parts = ['%28', '%29', '%3[Cc]', '%3[Ee]', '%5[Bb]', '%5[Dd]', '%7[Bb]', '%7[Dd]', '%25(?:25){0,2}28', '%25(?:25){0,2}29', '%25(?:25){0,2}3[Cc]', '%25(?:25){0,2}3[Ee]', '%25(?:25){0,2}5[Bb]', '%25(?:25){0,2}5[Dd]', '%25(?:25){0,2}7[Bb]', '%25(?:25){0,2}7[Dd]'];
  for (const char of BRACKET_CHARS) {
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const BRACKET_JOIN = bracketTail();
// U+FF5E folds to "~". U+FE61 U+FF0A fold to "*". U+207A U+208A U+FB29
// U+FE62 U+FF0B fold to "+". U+FE69 U+FF04 fold to "$". U+FF3E folds to "^".
const SHELL_CHARS = ['\uFF5E', '\uFE61', '\uFF0A', '\u207A', '\u208A', '\uFB29', '\uFE62', '\uFF0B', '\uFE69', '\uFF04', '\uFF3E'];
function shellTail() {
  const parts = ['%7[Ee]', '%2[Aa]', '%2[Bb]', '%24', '%5[Ee]', '%25(?:25){0,2}7[Ee]', '%25(?:25){0,2}2[Aa]', '%25(?:25){0,2}2[Bb]', '%25(?:25){0,2}24', '%25(?:25){0,2}5[Ee]'];
  for (const char of SHELL_CHARS) {
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const SHELL_JOIN = shellTail();
// U+037E U+FE14 U+FE54 U+FF1B fold to ";". U+FE10 U+FE50 U+FF0C fold to ",".
const LIST_CHARS = ['\u037E', '\uFE14', '\uFE54', '\uFF1B', '\uFE10', '\uFE50', '\uFF0C'];
function listTail() {
  const parts = ['%3[Bb]', '%2[Cc]', '%25(?:25){0,2}3[Bb]', '%25(?:25){0,2}2[Cc]'];
  for (const char of LIST_CHARS) {
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const LIST_JOIN = listTail();
// U+FE15 U+FE57 U+FF01 fold to "!".
const BANG_CHARS = ['\uFE15', '\uFE57', '\uFF01'];
function bangTail() {
  const parts = ['%21', '%25(?:25){0,2}21'];
  for (const char of BANG_CHARS) {
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const BANG_JOIN = bangTail();
// U+FF0F folds to "/". U+FE16 U+FE56 U+FF1F fold to "?". U+FE5F U+FF03 fold to "#".
const PATH_CHARS = ['\uFF0F', '\uFE16', '\uFE56', '\uFF1F', '\uFE5F', '\uFF03'];
function pathTail() {
  const parts = ['%2[Ff]', '%3[Ff]', '%23', '%25(?:25){0,2}2[Ff]', '%25(?:25){0,2}3[Ff]', '%25(?:25){0,2}23'];
  for (const char of PATH_CHARS) {
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const PATH_JOIN = pathTail();
// These are the characters /\s/ already treats as a host boundary.
const SPACE_CHARS = ['\u0009', '\u000A', '\u000B', '\u000C', '\u000D', '\u0020', '\u00A0', '\u1680', '\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005', '\u2006', '\u2007', '\u2008', '\u2009', '\u200A', '\u2028', '\u2029', '\u202F', '\u205F', '\u3000', '\uFEFF'];
function spaceTail() {
  const parts = [];
  for (const char of SPACE_CHARS) {
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const SPACE_JOIN = spaceTail();
// U+FF02 folds to ". U+FF07 folds to '. Curly quotes stay quotes under NFKC,
// but a percent-encoded curly quote is still a host boundary.
const QUOTE_CHARS = ['\u2018', '\u2019', '\u201C', '\u201D', '\uFF02', '\uFF07'];
function quoteTail() {
  const parts = ['%22', '%27', '%25(?:25){0,2}22', '%25(?:25){0,2}27'];
  for (const char of QUOTE_CHARS) {
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const QUOTE_JOIN = quoteTail();
// U+1FEF folds to "`". U+FE68 folds to "\". Fullwidth forms are already tails.
const ESCAPE_CHARS = ['\u1FEF', '\uFE68', '\uFF40', '\uFF5C', '\uFF3C'];
function escapeTail() {
  const parts = ['%60', '%7[Cc]', '%5[Cc]', '%25(?:25){0,2}60', '%25(?:25){0,2}7[Cc]', '%25(?:25){0,2}5[Cc]'];
  for (const char of ESCAPE_CHARS) {
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const ESCAPE_JOIN = escapeTail();
const CONTROL_CHARS = [];
for (let cp = 0; cp <= 0x1F; cp += 1) {
  if (cp >= 0x09 && cp <= 0x0D) continue;
  CONTROL_CHARS.push(String.fromCodePoint(cp));
}
CONTROL_CHARS.push('\u007F');
function controlTail() {
  const parts = [];
  for (const char of CONTROL_CHARS) {
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const CONTROL_JOIN = controlTail();
const PERIOD_CHARS = ['\uFF0E', '\uFE52', '\u2024', '\u3002', '\uFE12', '\uFF61'];
function periodTail() {
  const parts = ['%2[Ee]', '%25(?:25){0,2}2[Ee]'];
  for (const char of PERIOD_CHARS) {
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const PERIOD_JOIN = periodTail();
// Interpuncts that stay themselves under NFKC. U+0387 folds to U+00B7.
// U+FF65 folds to U+30FB. A nested %25C2%25B7 hides the same middle dot.
function middleTail() {
  const parts = [];
  for (const char of MIDDLE_CHARS) {
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const MIDDLE_JOIN = middleTail();
// Encoded bullets and other stops. The literal marks are already tails.
function stopTail() {
  const parts = [];
  for (const char of STOP_CHARS) {
    const encoded = percentBytes(char);
    for (let extra = 0; extra < 4; extra += 1) parts.push(nestPercent(encoded, extra));
  }
  return `(?:${parts.join('|')})`;
}
const STOP_JOIN = stopTail();
const PROXY_HOST = `(?:(?:${MARK})*(?:\\[(?:[0-9A-Fa-f:.%]|${MARK})+\\]|${LOCAL_HOST}|${literalDomain}|${encodedDomain}|${fourNumeric})(?:${MARK}*${proxyPort}${PORT_SOME})?|(?:${MARK})*(?:${shortNumeric}|(?:${DIGIT}(?:${MARK}(?=${DIGIT}))?){4,10}|[A-Za-z](?:[A-Za-z0-9_-]|${MARK}(?=[A-Za-z0-9_-]))*)${MARK}*${proxyPort}${PORT_REQUIRED})(?=$|${PROXY_TAIL}|${QUERY_JOIN}|${BRACKET_JOIN}|${SHELL_JOIN}|${LIST_JOIN}|${BANG_JOIN}|${PATH_JOIN}|${SPACE_JOIN}|${QUOTE_JOIN}|${ESCAPE_JOIN}|${CONTROL_JOIN}|${PERIOD_JOIN}|${COLON_SEP}|${MIDDLE_JOIN}|${STOP_JOIN})`;
// "&#58;", "&#x3A;", and "&colon;" are a colon. "&#64;" and "&commat;" are "@".
// The same references hide a digit or a host dot, and a numeric reference may
// omit its semicolon. Nested "&amp;#58;" is still a colon. Decode those marks
// on a copy, then use the existing scrubber. Four passes cover the reference
// itself plus the same extra encoding depth already accepted for %2525253A.
// "&Assign;", "&Proportion;", "&bull;", and "&sup2;" are aliases for marks
// the numeric decoder already accepts. "&percnt;", "&#37;", and "&#x25;" are
// "%", so a percent-encoded colon can hide behind them. "&amp" and "&AMP"
// may omit the semicolon, including directly before the next name.
// encodeURIComponent("&#58;") is "%26%2358%3B". A nested "%2526" layer hides
// the same reference. Decode those spans on the copy before the scrubber.
// encodeURIComponent leaves digits and letters alone. Encoding those body
// characters too still hides the mark: "%26%23%35%38%3B" is "&#58;",
// "%26%23x%33%41%3B" is "&#x3A;", and "%26%63%6F%6C%6F%6E%3B" is "&colon;".
// A nested %25 layer on each of those bytes hides the same reference.
// Decode one accepted reference per pass, body included.
// A numeric reference can also be an invisible mark. "&#8203;" and "&#x200B;"
// are U+200B. A supplementary reference such as "&#xE0100;" folds to U+200B.
// Otherwise "user:secret@my&#8203;proxy:7890" keeps the password.
// "&ZeroWidthSpace;", "&zwnj;", "&zwj;", "&lrm;", "&rlm;", and "&shy;" are
// invisible marks. The semicolon is required. Otherwise
// "user:secret@my&ZeroWidthSpace;proxy:7890" keeps the password.
// "&NoBreak;", "&af;", "&it;", "&ic;", and the Negative*Space names are the
// same kind of mark. Otherwise "user:secret@my&NoBreak;proxy:7890" keeps
// the password. "&shy" may omit the semicolon when the next character does
// not continue a name. Otherwise "user:secret@my&shy-proxy:7890" keeps the
// password. "&shyproxy" is not a reference and stays as written.
const HTML_NAMED = new Map([
  ['amp', '&'],
  ['AMP', '&'],
  ['colon', ':'],
  ['Colon', '\u2237'],
  ['Proportion', '\u2237'],
  ['colone', '\u2254'],
  ['coloneq', '\u2254'],
  ['Assign', '\u2254'],
  ['Colone', '\u2A74'],
  ['eqcolon', '\u2255'],
  ['ecolon', '\u2255'],
  ['ratio', '\u2236'],
  ['RuleDelayed', '\u29F4'],
  ['commat', '@'],
  ['period', '.'],
  ['middot', '\u00B7'],
  ['centerdot', '\u00B7'],
  ['CenterDot', '\u00B7'],
  ['bull', '\u2022'],
  ['bullet', '\u2022'],
  ['hybull', '\u2043'],
  ['nldr', '\u2025'],
  ['ofcir', '\u29BF'],
  ['sdot', '\u22C5'],
  ['sup1', '\u00B9'],
  ['sup2', '\u00B2'],
  ['sup3', '\u00B3'],
  ['percnt', '%'],
  ['ZeroWidthSpace', '\u200B'],
  ['zwnj', '\u200C'],
  ['zwj', '\u200D'],
  ['lrm', '\u200E'],
  ['rlm', '\u200F'],
  ['shy', '\u00AD'],
  ['NoBreak', '\u2060'],
  ['ApplyFunction', '\u2061'],
  ['af', '\u2061'],
  ['InvisibleTimes', '\u2062'],
  ['it', '\u2062'],
  ['InvisibleComma', '\u2063'],
  ['ic', '\u2063'],
  ['NegativeMediumSpace', '\u200B'],
  ['NegativeThickSpace', '\u200B'],
  ['NegativeThinSpace', '\u200B'],
  ['NegativeVeryThinSpace', '\u200B']
]);
const HTML_LEGACY = ['AMP', 'amp', 'middot', 'sup1', 'sup2', 'sup3'];
const HTML_STRICT = [...HTML_NAMED.keys()].filter(name => !HTML_LEGACY.includes(name));
function namedAlt(names) {
  return names.slice().sort((a, b) => b.length - a.length || (a < b ? -1 : 1)).join('|');
}
function encByte(hexClass) {
  return `%(?:25){0,3}${hexClass}`;
}
const ENC_AMP = encByte('26');
const ENC_HASH = encByte('23');
const ENC_SEMI = encByte('3[Bb]');
const HTML_REF = new RegExp(`&#(0*[0-9]{1,7})(?![0-9]);?|&#[xX](0*[0-9a-fA-F]{1,6})(?![0-9a-fA-F]);?|&(?:(${namedAlt(HTML_LEGACY)});?|(${namedAlt(HTML_STRICT)});)`, 'g');
const ENC_NUMERIC = new RegExp(`${ENC_AMP}(?:${ENC_HASH}|#)(?:(0*[0-9]{1,7})(?![0-9])|[xX](0*[0-9a-fA-F]{1,6})(?![0-9a-fA-F]))(?:${ENC_SEMI}|;)?`, 'g');
const ENC_LEGACY = new RegExp(`${ENC_AMP}(${namedAlt(HTML_LEGACY)})(?:${ENC_SEMI}|;)?`, 'g');
const ENC_STRICT = new RegExp(`${ENC_AMP}(${namedAlt(HTML_STRICT)})(?:${ENC_SEMI}|;)`, 'g');
const ENC_TAIL = new RegExp(`(&(?:#(?:[0-9]{1,7}|[xX][0-9a-fA-F]{1,6})|${namedAlt([...HTML_NAMED.keys()])}))(?:${ENC_SEMI})`, 'g');
function proxyHtmlChars() {
  const chars = new Set([':', '@', '&', '.', '%']);
  for (const list of [COLON_CHARS, SIGN_COLONS, AT_CHARS, DOT_CHARS, MIDDLE_CHARS, STOP_CHARS, MONGOLIAN_STOPS]) {
    for (const char of list) chars.add(char);
  }
  for (let digit = 0; digit <= 9; digit += 1) chars.add(String(digit));
  for (let cp = 0xFF10; cp <= 0xFF19; cp += 1) chars.add(String.fromCodePoint(cp));
  for (const cp of [0xB2, 0xB3, 0xB9, 0x2070]) chars.add(String.fromCodePoint(cp));
  for (let cp = 0x2074; cp <= 0x2079; cp += 1) chars.add(String.fromCodePoint(cp));
  for (let cp = 0x2080; cp <= 0x2089; cp += 1) chars.add(String.fromCodePoint(cp));
  return chars;
}
const PROXY_HTML_CHARS = proxyHtmlChars();
function htmlProxyChar(cp) {
  if (!Number.isInteger(cp) || cp < 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return '';
  const char = String.fromCodePoint(cp);
  if (PROXY_HTML_CHARS.has(char) || PROXY_MARK_CODES.has(cp) || isSupplementaryInvisible(cp)) return char;
  // U+FE63 and U+FF0D fold to "-". A numeric reference has to yield the same
  // character so the label fold can see it.
  if (cp === 0xFE63 || cp === 0xFF0D) return char;
  return '';
}
const PROXY_MARK_CODES = new Set(Array.from(PROXY_MARK, char => char.codePointAt(0)));
const SUPP_INVISIBLE = /[\u{110BD}\u{110CD}\u{13430}-\u{1343F}\u{1BCA0}-\u{1BCA3}\u{1D173}-\u{1D17A}\u{E0001}\u{E0020}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;
function isProxyMark(char) {
  return PROXY_MARK_CODES.has(char.codePointAt(0));
}
function foldProxyInvisibles(text) {
  return text.replace(SUPP_INVISIBLE, '\u200B');
}
function isSupplementaryInvisible(cp) {
  if (cp < 0x110BD || cp > 0xE01EF) return false;
  SUPP_INVISIBLE.lastIndex = 0;
  const found = SUPP_INVISIBLE.test(String.fromCodePoint(cp));
  SUPP_INVISIBLE.lastIndex = 0;
  return found;
}
function readEncodedByte(text, index) {
  const encoded = /^%(?:25){0,3}([0-9A-Fa-f]{2})/.exec(text.slice(index));
  if (!encoded) return null;
  return { value: Number.parseInt(encoded[1], 16), next: index + encoded[0].length };
}
function decodeUtf8Scalar(bytes) {
  const b0 = bytes[0];
  if (bytes.length === 2) {
    const cp = ((b0 & 0x1F) << 6) | (bytes[1] & 0x3F);
    return cp >= 0x80 ? cp : null;
  }
  if (bytes.length === 3) {
    if (b0 === 0xE0 && bytes[1] < 0xA0) return null;
    if (b0 === 0xED && bytes[1] >= 0xA0) return null;
    const cp = ((b0 & 0x0F) << 12) | ((bytes[1] & 0x3F) << 6) | (bytes[2] & 0x3F);
    if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) return null;
    return cp;
  }
  if (bytes.length !== 4) return null;
  if (b0 === 0xF0 && bytes[1] < 0x90) return null;
  if (b0 === 0xF4 && bytes[1] > 0x8F) return null;
  const cp = ((b0 & 0x07) << 18) | ((bytes[1] & 0x3F) << 12) | ((bytes[2] & 0x3F) << 6) | (bytes[3] & 0x3F);
  if (cp < 0x10000 || cp > 0x10FFFF) return null;
  return cp;
}
function readEncodedProxyMark(text, index) {
  if (text[index] !== '%') return null;
  const first = readEncodedByte(text, index);
  if (!first) return null;
  const b0 = first.value;
  let needed = 0;
  if (b0 >= 0xC2 && b0 <= 0xDF) needed = 2;
  else if (b0 >= 0xE0 && b0 <= 0xEF) needed = 3;
  else if (b0 >= 0xF0 && b0 <= 0xF4) needed = 4;
  if (!needed) return null;
  const bytes = [b0];
  let cursor = first.next;
  for (let count = 1; count < needed; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next || next.value < 0x80 || next.value > 0xBF) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || (!PROXY_MARK_CODES.has(cp) && !isSupplementaryInvisible(cp))) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedProxyMarks(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const mark = readEncodedProxyMark(text, index);
    if (mark) {
      out += mark.char;
      index = mark.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function readHtmlAtom(text, index) {
  while (index < text.length && isProxyMark(text[index])) index += 1;
  if (index >= text.length) return null;
  const encoded = /^%(?:25){0,3}([0-9A-Fa-f]{2})/.exec(text.slice(index));
  if (encoded) {
    const cp = Number.parseInt(encoded[1], 16);
    if (cp >= 0x21 && cp <= 0x7E) return { char: String.fromCharCode(cp), next: index + encoded[0].length };
  }
  return { char: text[index], next: index + 1 };
}
function acceptedProxyRef(literal, nextChar) {
  let match = /^&#(0*[0-9]{1,7});?$/.exec(literal);
  if (match) {
    if (!literal.endsWith(';') && nextChar && /[0-9]/.test(nextChar)) return '';
    return htmlProxyChar(Number(match[1]));
  }
  match = /^&#[xX](0*[0-9a-fA-F]{1,6});?$/.exec(literal);
  if (match) {
    if (!literal.endsWith(';') && nextChar && /[0-9a-fA-F]/.test(nextChar)) return '';
    return htmlProxyChar(Number.parseInt(match[1], 16));
  }
  match = /^&([A-Za-z0-9]+);$/.exec(literal);
  if (match && HTML_NAMED.has(match[1])) return HTML_NAMED.get(match[1]);
  match = /^&([A-Za-z0-9]+)$/.exec(literal);
  if (match && HTML_LEGACY.includes(match[1])) return HTML_NAMED.get(match[1]) || '';
  // The named-character table includes "&shy" without a semicolon. A following
  // name character or "=" means it is not a reference.
  if (match && match[1] === 'shy' && !/[0-9A-Za-z=]/.test(nextChar || '')) return HTML_NAMED.get('shy') || '';
  return '';
}
const HTML_ATOM = /[A-Za-z0-9#xX;]/;
function parseProxyHtmlRef(text, index) {
  const atoms = [];
  let cursor = index;
  let lookahead = '';
  while (atoms.length < 48 && cursor < text.length) {
    const atom = readHtmlAtom(text, cursor);
    if (!atom) break;
    if (!atoms.length) {
      if (atom.char !== '&') return null;
    } else if (atom.char === ';') {
      atoms.push(atom);
      cursor = atom.next;
      break;
    } else if (!HTML_ATOM.test(atom.char)) {
      lookahead = atom.char;
      break;
    }
    atoms.push(atom);
    cursor = atom.next;
  }
  if (atoms.length < 2) return null;
  if (!lookahead && cursor < text.length) {
    const peek = readHtmlAtom(text, cursor);
    if (peek) lookahead = peek.char;
  }
  for (let count = atoms.length; count >= 2; count -= 1) {
    const literal = atoms.slice(0, count).map(item => item.char).join('');
    const nextChar = literal.endsWith(';') ? '' : (count < atoms.length ? atoms[count].char : lookahead);
    const char = acceptedProxyRef(literal, nextChar);
    if (char) return { char, next: atoms[count - 1].next };
  }
  return null;
}
function unwrapHtmlInteriors(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const ref = text[index] === '&' || text[index] === '%' ? parseProxyHtmlRef(text, index) : null;
    if (ref && ref.next > index) {
      out += ref.char;
      index = ref.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function decodeEncodedHtml(text) {
  return text
    .replace(ENC_NUMERIC, (match, dec, hex) => {
      const cp = dec != null ? Number(dec) : Number.parseInt(hex, 16);
      return htmlProxyChar(cp) || match;
    })
    .replace(ENC_LEGACY, (match, name) => HTML_NAMED.get(name) || match)
    .replace(ENC_STRICT, (match, name) => HTML_NAMED.get(name) || match)
    .replace(ENC_TAIL, '$1;');
}
function decodeProxyHtml(text) {
  let out = text;
  for (let pass = 0; pass < 4; pass += 1) {
    const next = decodeEncodedHtml(unwrapHtmlInteriors(out)).replace(HTML_REF, (match, dec, hex, legacy, strict) => {
      const named = legacy || strict;
      if (named) return HTML_NAMED.get(named) || match;
      const cp = dec != null ? Number(dec) : Number.parseInt(hex, 16);
      return htmlProxyChar(cp) || match;
    });
    if (next === out) break;
    out = next;
  }
  return out;
}
function noteSecret(secrets, secret) {
  if (secret) secrets.push(secret);
}
// A percent-encoded hyphen is still a hyphen inside a host label. The same
// extra "25" depth already accepted for a port digit applies. Otherwise
// "user:secret@my%2Dproxy:7890" and "user:secret@ex%252Dample.com" keep the
// password. An encoded underscore is the other mark a single-label host
// already allows. Otherwise "user:secret@my%5Fproxy:7890" keeps the password.
// U+FE63 and U+FF0D fold to "-" under NFKC. Their literal and percent-encoded
// forms kept the password too. A dash that does not fold to "-" stays as written.
function decodeEncodedLabelPunct(text) {
  return String(text)
    .replace(/%(?:25){0,3}2[Dd]/g, '-')
    .replace(/%(?:25){0,3}5[Ff]/g, '_')
    .replace(/%(?:25){0,3}[Ee][Ff]%(?:25){0,3}[Bb][Cc]%(?:25){0,3}8[Dd]/g, '-')
    .replace(/%(?:25){0,3}[Ee][Ff]%(?:25){0,3}[Bb]9%(?:25){0,3}[Aa]3/g, '-');
}
function foldLabelHyphens(text) {
  return text.replace(/[\uFE63\uFF0D]/g, '-');
}
function redactProxyCredentials(text) {
  const decoded = foldLabelHyphens(foldProxyInvisibles(decodeProxyHtml(foldProxyInvisibles(decodeEncodedProxyMarks(decodeEncodedLabelPunct(text))))));
  const redacted = scrubProxyCredentials(decoded);
  // A non-proxy such as "user&#58;secret@internal" must stay as written.
  // Decoding it first would only make the secret easier to read.
  return redacted === decoded ? text : redacted;
}
function scrubProxyCredentials(text) {
  // %3A is a colon. user%3Apassword decodes to a password, but a username-only
  // check never sees a separator and would leave the secret in renderer text.
  // The same encoding hides a port in user:password@127.0.0.1%3A7890.
  // %40 is @. user:password%40host still carries the password when that is the
  // only terminator a literal-at check would look for. A fullwidth or small
  // commercial at, and a nested %2540, hide that terminator too.
  // / ? # inside a password would end a real URL authority. Only the schemeless
  // pass can consume them, and a slash there cannot start "//" or it would eat
  // the scheme of "http://user@host".
  const sep = COLON_SEP;
  const bareUser = PROXY_USER.slice(0, -1) + COLON_CHARS.join('') + ']';
  const at = AT_SEP;
  const userinfo = String.raw`[^\s\/?#@]+(?:${at}[^\s\/?#@]+)*${at}`;
  // A later colon after / ? # means this match ran into the next credential
  // (host:port#user:secret). Reject that start so the inner password can match.
  const tightPiece = String.raw`(?:[^\s@/]|/(?!/))`;
  const tightScan = String.raw`(?:(?!${at})[^\s])`;
  const tightGuard = String.raw`(?!${tightScan}*(?:[/?#])${tightScan}*${COLON_SEP})`;
  const tightPassword = String.raw`(${tightGuard}${tightPiece}+(?:${at}${tightPiece}+)*)`;
  const tightSpaced = String.raw`(${tightGuard}(?:[^\s/]|/(?!/))*\s(?:[^\s/]|/(?!/)){0,200}?)`;
  const compact = new RegExp(String.raw`\b([a-z][a-z0-9+.-]*:\/\/)${SCHEME_USER}${sep}${userinfo}`, 'gi');
  const spaced = new RegExp(String.raw`\b([a-z][a-z0-9+.-]*:\/\/)${SCHEME_USER}${sep}[^\/?#]*\s[^\/?#]{0,200}?${at}(?=${PROXY_HOST})`, 'gi');
  const relative = new RegExp(String.raw`(^|${PROXY_BOUND})(\/\/)${SCHEME_USER}${sep}${userinfo}`, 'g');
  const relativeSpaced = new RegExp(String.raw`(^|${PROXY_BOUND})(\/\/)${SCHEME_USER}${sep}[^\/?#]*\s[^\/?#]{0,200}?${at}(?=${PROXY_HOST})`, 'g');
  const bare = new RegExp(String.raw`(^|${PROXY_BOUND})${bareUser}+${sep}${tightPassword}${at}(?=${PROXY_HOST})`, 'g');
  const bareSpaced = new RegExp(String.raw`(^|${PROXY_BOUND})${bareUser}+${sep}${tightSpaced}${at}(?=${PROXY_HOST})`, 'g');
  const secrets = [];
  // Schemeless matching runs first. A scheme pass stops at the first @, so
  // "user:p@ss/word@host" would otherwise keep the slash and the rest.
  text = text
    .replace(bare, (_match, bound, secret) => { noteSecret(secrets, secret); return bound; })
    .replace(bareSpaced, (_match, bound, secret) => { noteSecret(secrets, secret); return bound; })
    .replace(compact, '$1')
    .replace(spaced, '$1')
    .replace(relative, '$1$2')
    .replace(relativeSpaced, '$1$2');
  if (!secrets.length) return text;
  return text.replace(new RegExp(`invalid port "(?:${sep})([^"]*)"`, 'g'), (all, port) => {
    const leaked = secrets.some(secret => secret === port || secret.startsWith(`${port}/`) || secret.startsWith(`${port}?`) || secret.startsWith(`${port}#`) || secret.startsWith(`${port}\\`));
    return leaked ? 'invalid port ":[凭据已隐藏]"' : all;
  });
}
function redactText(value) {
  let text = String(value);
  for (const [pattern, replacement] of SECRET_TEXT) text = text.replace(pattern, replacement);
  return redactProxyCredentials(text);
}
function blockedKey(key) {
  const name = String(key);
  return name === '__proto__' || name === 'constructor' || name === 'prototype' || SECRET_KEYS.has(name.toLowerCase());
}
function redactPublic(value) {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(redactPublic);
  if (value == null || typeof value !== 'object') return value;
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    if (blockedKey(key)) continue;
    if (typeof item === 'string') out[key] = redactText(item);
    else if (item && typeof item === 'object') out[key] = redactPublic(item);
    else out[key] = item;
  }
  return out;
}
function withoutSecrets(value) {
  if (Array.isArray(value)) return value.map(withoutSecrets);
  if (!value || typeof value !== 'object') return value;
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    if (blockedKey(key)) continue;
    out[key] = item && typeof item === 'object' ? withoutSecrets(item) : item;
  }
  return out;
}
function requireID(id) {
  if (typeof id !== 'string' || !accountID.test(id)) throw new Error('账号标识无效');
  return id;
}
function cleanSettings(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('设置无效');
  const out = {};
  for (const k of ['auto_refresh', 'usage_probe']) {
    if (k in input) {
      if (typeof input[k] !== 'boolean') throw new Error('设置类型无效');
      out[k] = input[k];
    }
  }
  if ('proxy_url' in input) {
    if (typeof input.proxy_url !== 'string' || input.proxy_url.length > 2048) throw new Error('代理地址无效');
    out.proxy_url = input.proxy_url.trim();
  }
  return out;
}
function cleanLaunch(input) {
  if (!input || typeof input !== 'object') throw new Error('启动参数无效');
  requireID(input.account_id);
  const target = input.target || 'cli';
  if (!['cli', 'app'].includes(target)) throw new Error('启动目标无效');
  if (target === 'cli' && (typeof input.directory !== 'string' || !input.directory.trim() || input.directory.length > 4096)) throw new Error('请选择项目目录');
  const model = cleanModel(input.model);
  const effort = cleanEffort(input.effort);
  const channel = cleanChannel(input.channel), speed = input.speed ?? 'standard';
  if (!['standard', 'fast'].includes(speed)) throw new Error('请选择标准或快速模式');
  if (channel === 'bps' && speed !== 'standard') throw new Error('BPS 暂不支持快速模式，请选择标准速度或原生通道');
  const out = { account_id: input.account_id, directory: target === 'app' ? '' : input.directory, model, effort, resume: target === 'cli' && input.resume === true, target, channel, speed };
  if (target === 'app') {
    out.app_mode = input.app_mode ?? 'main';
    if (!['main', 'isolated'].includes(out.app_mode)) throw new Error('请选择主应用或独立实例');
  }
  for (const k of ['context_window', 'compact_limit']) {
    if (input[k] != null) {
      if (!Number.isSafeInteger(input[k])) throw new Error('上下文设置必须为整数');
      out[k] = input[k];
    }
  }
  return out;
}
function cleanPreferences(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('设置无效');
  const out = {};
  if ('account_speed' in input && input.account_speed != null) {
    const speed = input.account_speed;
    if (!speed || typeof speed !== 'object' || Array.isArray(speed)) throw new Error('速度设置无效');
    const value = speed.speed;
    if (value !== 'standard' && value !== 'fast') throw new Error('速度设置无效');
    out.account_speed = { id: requireID(speed.id), speed: value };
  }
  if ('compact_view' in input) {
    if (typeof input.compact_view !== 'boolean') throw new Error('设置类型无效');
    out.compact_view = input.compact_view;
  }
  for (const key of ['channel', 'pelican_channel']) if (key in input) out[key] = requireChannel(input[key]);
  if ('pelican_model' in input) out.pelican_model = cleanModel(input.pelican_model);
  if ('pelican_effort' in input) out.pelican_effort = cleanEffort(input.pelican_effort);
  if ('theme' in input) {
    if (!['system', 'light', 'dark'].includes(input.theme)) throw new Error('外观设置无效');
    out.theme = input.theme;
  }
  return out;
}
// Native theme only accepts three values. An unknown stored choice is left
// untouched and the control falls back without rewriting that preference.
function appliedTheme(value) {
  return value === 'light' || value === 'dark' || value === 'system' ? value : 'system';
}
function applyPreferences(prefs, input) {
  const patch = cleanPreferences(input);
  const next = withoutSecrets(prefs && typeof prefs === 'object' && !Array.isArray(prefs) ? prefs : {});
  if (patch.account_speed) next.account_speeds = { ...next.account_speeds, [patch.account_speed.id]: patch.account_speed.speed };
  for (const key of ['compact_view', 'channel', 'pelican_channel', 'pelican_model', 'pelican_effort', 'theme']) {
    if (Object.hasOwn(patch, key)) next[key] = patch[key];
  }
  return { prefs: next, theme: patch.theme };
}
function safeError(error) {
  return redactText(String(error?.message || error || '操作失败')).slice(0, 1200);
}
function asString(value) { return typeof value === 'string' ? value : ''; }
function asNumber(value) { return typeof value === 'number' && Number.isFinite(value) ? value : null; }
function publicWindow(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const out = {};
  if (typeof value.used_percent === 'number') out.used_percent = value.used_percent;
  if (typeof value.window_seconds === 'number') out.window_seconds = value.window_seconds;
  if (typeof value.reset_at === 'string') out.reset_at = value.reset_at;
  return Object.keys(out).length ? out : undefined;
}
function publicUsage(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const out = {};
  if (value.limit_reached === true) out.limit_reached = true;
  if (typeof value.updated_at === 'string') out.updated_at = value.updated_at;
  const primary = publicWindow(value.primary);
  const secondary = publicWindow(value.secondary);
  if (primary) out.primary = primary;
  if (secondary) out.secondary = secondary;
  return Object.keys(out).length ? out : undefined;
}
function publicAccount(account) {
  if (!account || typeof account !== 'object' || Array.isArray(account)) return null;
  return {
    id: asString(account.id), name: asString(account.name), email: asString(account.email), account_id: asString(account.account_id),
    plan_type: asString(account.plan_type), disabled: account.disabled === true, has_refresh_token: account.has_refresh_token === true,
    has_access_token: account.has_access_token === true, expired: account.expired === true, status: asString(account.status),
    last_error: asString(account.last_error), cooldown_until: asString(account.cooldown_until), expires_at: asString(account.expires_at),
    usage: publicUsage(account.usage)
  };
}
function publicHistory(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  const out = {};
  for (const key of ['id', 'account_id', 'directory', 'model', 'effort', 'channel', 'speed', 'target', 'app_mode']) {
    if (typeof record[key] === 'string') out[key] = record[key];
  }
  for (const key of ['context_window', 'compact_limit']) if (typeof record[key] === 'number') out[key] = record[key];
  if (typeof record.last_used === 'string') out.last_used = record.last_used;
  return out;
}
function publicModel(model) {
  if (!model || typeof model !== 'object' || typeof model.id !== 'string' || !model.id) return null;
  const out = { id: model.id };
  if (typeof model.display_name === 'string' && model.display_name) out.display_name = model.display_name;
  return out;
}
function publicPreferences(prefs) {
  const source = prefs && typeof prefs === 'object' && !Array.isArray(prefs) ? prefs : {};
  const out = {};
  for (const key of ['directory', 'target', 'app_mode', 'channel', 'account_id', 'model', 'effort', 'pelican_channel', 'pelican_model', 'pelican_effort', 'theme']) {
    if (typeof source[key] === 'string') out[key] = source[key];
  }
  for (const key of ['context_window', 'compact_limit']) if (typeof source[key] === 'number') out[key] = source[key];
  if (typeof source.compact_view === 'boolean') out.compact_view = source.compact_view;
  if (source.account_speeds && typeof source.account_speeds === 'object' && !Array.isArray(source.account_speeds)) {
    const speeds = {};
    for (const [id, speed] of Object.entries(source.account_speeds)) if (speed === 'standard' || speed === 'fast') speeds[id] = speed;
    out.account_speeds = speeds;
  }
  return out;
}
function publicSnapshot(input) {
  const status = input?.status && typeof input.status === 'object' ? input.status : {};
  const codex = input?.codex && typeof input.codex === 'object' ? input.codex : {};
  const app = codex.app && typeof codex.app === 'object' ? codex.app : {};
  const mainApp = codex.main_app && typeof codex.main_app === 'object' ? codex.main_app : {};
  const models = input?.models && typeof input.models === 'object' ? input.models : {};
  const settings = input?.settings && typeof input.settings === 'object' ? input.settings : {};
  const catalog = (list) => (Array.isArray(list) ? list.map(publicModel).filter(Boolean) : []);
  const view = redactPublic({
    status: { home: asString(status.home) },
    accounts: Array.isArray(input?.accounts) ? input.accounts.map(publicAccount).filter(Boolean) : [],
    codex: {
      installed: codex.installed === true, binary: asString(codex.binary), error: asString(codex.error),
      active_account_id: asString(codex.active_account_id), model: asString(codex.model), effort: asString(codex.effort),
      app: { installed: app.installed === true, binary: asString(app.binary), error: asString(app.error) },
      main_app: { active: mainApp.active === true, home: asString(mainApp.home) },
      history: Array.isArray(codex.history) ? codex.history.map(publicHistory).filter(Boolean) : []
    },
    models: { catalog: catalog(models.catalog), native_catalog: catalog(models.native_catalog), bps_models: Array.isArray(models.bps_models) ? models.bps_models.filter(id => typeof id === 'string') : [] },
    settings: { proxy_url: asString(settings.proxy_url), auto_refresh: settings.auto_refresh === true, usage_probe: settings.usage_probe === true },
    preferences: publicPreferences(input?.preferences),
    platform: asString(input?.platform), version: asString(input?.version)
  });
  // The proxy field is an editor. Redact the same URL everywhere else, but
  // keep this copy intact so saving the form does not drop its password.
  view.settings.proxy_url = asString(settings.proxy_url);
  return view;
}
function publicLogs(payload) {
  const records = Array.isArray(payload?.records) ? payload.records : [];
  return redactPublic({ records: records.filter(record => record && typeof record === 'object').map(record => ({
    time: asString(record.time), model: asString(record.model), response_model: asString(record.response_model), effort: asString(record.effort),
    route: asString(record.route), service_tier: asString(record.service_tier), response_service_tier: asString(record.response_service_tier),
    status: asNumber(record.status), stream_status: asString(record.stream_status), error: asString(record.error), duration_ms: asNumber(record.duration_ms)
  })) });
}
function publicProbe(result) {
  const value = result && typeof result === 'object' ? result : {};
  // Route is the observed upstream choice. Leave it empty when missing so the
  // renderer cannot relabel the probe as the channel currently selected.
  const out = { ok: value.ok === true, model: asString(value.model), effort: asString(value.effort), route: asString(value.route), duration_ms: asNumber(value.duration_ms) };
  if (typeof value.error === 'string' && value.error) out.error = value.error;
  return redactPublic(out);
}
function publicImport(result) {
  if (result == null) return null;
  const value = result && typeof result === 'object' ? result : {};
  return redactPublic({
    imported: asNumber(value.imported) || 0, merged: asNumber(value.merged) || 0, skipped: asNumber(value.skipped) || 0,
    warnings: Array.isArray(value.warnings) ? value.warnings.filter(item => typeof item === 'string') : [],
    ids: Array.isArray(value.ids) ? value.ids.filter(item => typeof item === 'string') : [],
    ...(typeof value.files === 'number' ? { files: value.files } : {})
  });
}
function objectValue(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}
function publicLaunch(result, options) {
  const value = objectValue(result);
  if (value.cancelled === true) return { cancelled: true };
  const requested = objectValue(options);
  const out = { ok: true };
  if (requested.target === 'app' && (requested.app_mode === 'main' || requested.app_mode === 'isolated')) out.app_mode = requested.app_mode;
  if (typeof value.warning === 'string' && value.warning) out.warning = value.warning;
  return redactPublic(out);
}
function publicRestore(result) {
  const value = objectValue(result);
  if (value.cancelled === true) return { cancelled: true };
  const out = {};
  if (value.restored === true) out.restored = true;
  if (typeof value.warning === 'string' && value.warning) out.warning = value.warning;
  return redactPublic(out);
}
function publicAccountAction(result) {
  const value = objectValue(result);
  if (typeof value.id === 'string' && value.id) return redactPublic(publicAccount(value));
  return { ok: true };
}
function publicUsageResult(result) {
  return redactPublic({ ok: true, ...(publicUsage(result) || {}) });
}
function publicSettings(result) {
  const value = objectValue(result);
  const proxy = asString(value.proxy_url);
  const out = redactPublic({ proxy_url: proxy, auto_refresh: value.auto_refresh === true, usage_probe: value.usage_probe === true });
  out.proxy_url = proxy;
  return out;
}
function publicApp(app) {
  const value = objectValue(app);
  const out = { installed: value.installed === true };
  if (typeof value.error === 'string' && value.error) out.error = value.error;
  return redactPublic(out);
}
function publicServiceState(result) {
  return { reused: objectValue(result).reused === true };
}
function publicAbout(info) {
  const value = objectValue(info);
  return { version: asString(value.version), platform: asString(value.platform), arch: asString(value.arch) };
}
function publicSelection(accountID) {
  return { account_id: accountID };
}
const PROXY_EDITOR_KEYS = new Set(['proxy_url', 'auto_refresh', 'usage_probe']);
function proxyEditor(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length > 0 && keys.every(key => PROXY_EDITOR_KEYS.has(key));
}
// IPC redacts the finished result. Restore only the proxy editor afterwards so
// the settings field still round-trips, while every other copy loses userinfo.
function rendererPayload(value) {
  const redacted = redactPublic(value);
  if (!value || typeof value !== 'object' || Array.isArray(value) || !redacted || typeof redacted !== 'object' || Array.isArray(redacted)) return redacted;
  const settings = value.settings;
  if (settings && typeof settings === 'object' && !Array.isArray(settings) && typeof settings.proxy_url === 'string' && redacted.settings && typeof redacted.settings === 'object' && !Array.isArray(redacted.settings)) {
    redacted.settings.proxy_url = settings.proxy_url;
  }
  if (proxyEditor(value) && typeof value.proxy_url === 'string') redacted.proxy_url = value.proxy_url;
  return redacted;
}
module.exports = { requireID, cleanSettings, cleanLaunch, cleanChannel, requireChannel, cleanModel, cleanEffort, cleanProbe, cleanPreferences, applyPreferences, appliedTheme, redactPublic, withoutSecrets, safeError, publicSnapshot, publicLogs, publicProbe, publicImport, publicLaunch, publicRestore, publicAccountAction, publicUsageResult, publicSettings, publicPreferences, publicApp, publicServiceState, publicAbout, publicSelection, rendererPayload };
