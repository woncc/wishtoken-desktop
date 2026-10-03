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
// Fullwidth, superscript, and subscript digits already count in a numeric host
// and a port. A letter label accepted only an ASCII digit, so the same marks
// kept the password in "user:secret@my\uFF10proxy:7890" and
// "user:secret@ex\u00B2ample.com:8080". Percent-encoding hides that digit too,
// including a nested %25. The redacted text keeps the original digit.
const LABEL_DIGIT = `(?:[\\uFF10-\\uFF19]|${ALT_DIGIT}|${FULLWIDTH_DIGIT}|${ALT_DIGIT_ENC})`;
const DOMAIN_UNIT = `(?:[A-Za-z0-9-]|${LABEL_DIGIT})`;
const domainLabel = `(?:${DOMAIN_UNIT}(?:${MARK}(?=${DOMAIN_UNIT}))?)+`;
const LITERAL_UNIT = `(?:[A-Za-z0-9.-]|${LABEL_DIGIT})`;
const literalDomain = `(?:${LITERAL_UNIT}(?:${MARK}(?=${LITERAL_UNIT}))?)+\\.(?:[A-Za-z](?:${MARK}(?=[A-Za-z]))?){2,}`;
const SINGLE_UNIT = `(?:[A-Za-z0-9_-]|${LABEL_DIGIT})`;
const singleLabel = `[A-Za-z](?:${SINGLE_UNIT}|${MARK}(?=${SINGLE_UNIT}))*`;
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
const PROXY_HOST = `(?:(?:${MARK})*(?:\\[(?:[0-9A-Fa-f:.%]|${MARK})+\\]|${LOCAL_HOST}|${literalDomain}|${encodedDomain}|${fourNumeric})(?:${MARK}*${proxyPort}${PORT_SOME})?|(?:${MARK})*(?:${shortNumeric}|(?:${DIGIT}(?:${MARK}(?=${DIGIT}))?){4,10}|${singleLabel})${MARK}*${proxyPort}${PORT_REQUIRED})(?=$|${PROXY_TAIL}|${QUERY_JOIN}|${BRACKET_JOIN}|${SHELL_JOIN}|${LIST_JOIN}|${BANG_JOIN}|${PATH_JOIN}|${SPACE_JOIN}|${QUOTE_JOIN}|${ESCAPE_JOIN}|${CONTROL_JOIN}|${PERIOD_JOIN}|${COLON_SEP}|${MIDDLE_JOIN}|${STOP_JOIN})`;
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
  ['NegativeVeryThinSpace', '\u200B'],
  ['hyphen', '\u2010'],
  ['dash', '\u2010'],
  ['ndash', '\u2013'],
  ['mdash', '\u2014'],
  ['minus', '\u2212'],
  ['horbar', '\u2015'],
  ['lowbar', '_'],
  ['UnderBar', '_']
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
  // U+FE63 and U+FF0D fold to "-". U+2010 does not, but "&hyphen;" is that
  // character. U+2011 folds to U+2010. U+2012, U+2013, U+2014, and U+2015 do
  // not fold to "-". "&ndash;" is U+2013, "&mdash;" is U+2014, "&minus;" is
  // U+2212, and "&horbar;" is U+2015. U+FE58 and U+FE31 fold to U+2014.
  // U+FE32 folds to U+2013. U+2E17, U+2E1A, U+2E3A, U+2E3B, U+2E40, and
  // U+2E5D do not fold to "-" either, and neither do U+058A, U+1400,
  // U+1806, U+02D7, U+207B, or U+208B. U+FE33, U+FE34, U+FE4D, U+FE4E, U+FE4F,
  // and U+FF3F fold to "_". "&lowbar;" and "&UnderBar;" are U+005F.
  // U+FF21..U+FF3A and U+FF41..U+FF5A fold to ASCII letters. U+24B6..U+24E9
  // fold to ASCII letters too. Letterlike symbols that fold to one ASCII
  // letter do as well, and so do U+00AA, U+00BA, and U+017F. Modifier
  // letters that fold to one ASCII letter do too, and so do superscript and
  // subscript letters, roman numerals that fold to one letter,
  // mathematical letters, enclosed letters, outlined capitals, outlined
  // digits, circled digits, mathematical digits, segmented digits,
  // Arabic-Indic digits, NKo digits, Devanagari digits, Bengali digits,
  // Gurmukhi digits, Gujarati digits, Oriya digits, Tamil digits,
  // Telugu digits, Kannada digits, Malayalam digits, Sinhala digits,
  // Thai digits, Lao digits, Tibetan digits, Myanmar digits, Myanmar Shan
  // digits, Khmer digits, Mongolian digits, Limbu digits, New Tai Lue
  // digits, Tai Tham Hora digits, Tai Tham Tham digits, Balinese digits,
  // Sundanese digits, Lepcha digits, Ol Chiki digits, Vai digits, Saurashtra digits, Kayah Li digits, Javanese digits, Myanmar Tai Laing digits, Cham digits, Meetei Mayek digits, Osmanya digits, Hanifi Rohingya digits, Garay digits, Brahmi digits, and Sora Sompeng digits, and Chakma digits, and Sharada digits, and Khudawadi digits, and Newa digits, and Tirhuta digits, and Modi digits, and Takri digits, and Ahom digits, and Warang Citi digits, and Dives Akuru digits, and Bhaiksuki digits, and Masaram Gondi digits, and Gunjala Gondi digits, and Tolong Siki digits, and Kawi digits, and Gurung Khema digits, and Mro digits, and Tangsa digits, and Pahawh Hmong digits, and Kirat Rai digits, and Nyiakeng Puachue Hmong digits, and Wancho digits, and Nag Mundari digits, and Ol Onal digits, and Adlam digits, and Myanmar Pao digits, and Myanmar Eastern Pwo Karen digits, and Sunuwar digits, and circled numbers ten through twenty, twenty-one through thirty-five, and thirty-six through fifty, and parenthesized numbers one through twenty, and digit full stops one through twenty, and parenthesized letters a through z, and parenthesized capitals A through Z, and a digit zero full stop, and a digit zero comma, and a digit one comma, and digit commas two through nine, and a tortoise shell bracketed S, and a squared CD, and a squared WZ, and a squared HV, and a squared MV, and a squared SD, and a squared SS, and a squared PPV, and a squared WC, and a raised MC sign, and a raised MD sign, and a raised MR sign, and a squared DJ, and a Latin capital ligature IJ, and a Latin small ligature ij, and a Latin capital letter LJ, and a Latin capital letter L with small letter J, and a Latin small letter LJ, and a Latin capital letter NJ, do too.
  // A numeric reference has to yield the same character so the label fold
  // can see it.
  if ((cp >= 0xFF21 && cp <= 0xFF3A) || (cp >= 0xFF41 && cp <= 0xFF5A)) return char;
  if (cp >= 0x24B6 && cp <= 0x24E9) return char;
  if (isLetterlikeLetter(cp) || isLatinCompatLetter(cp) || isModifierLetter(cp) || isSupSubLetter(cp) || isRomanLetter(cp) || isMathLetter(cp) || isEnclosedLetter(cp) || isOutlinedLetter(cp) || isOutlinedDigit(cp) || isCircledDigit(cp) || isMathDigit(cp) || isSegmentedDigit(cp) || isArabicDigit(cp) || isNkoDigit(cp) || isDevanagariDigit(cp) || isBengaliDigit(cp) || isGurmukhiDigit(cp) || isGujaratiDigit(cp) || isOriyaDigit(cp) || isTamilDigit(cp) || isTeluguDigit(cp) || isKannadaDigit(cp) || isMalayalamDigit(cp) || isSinhalaDigit(cp) || isThaiDigit(cp) || isLaoDigit(cp) || isTibetanDigit(cp) || isMyanmarDigit(cp) || isMyanmarShanDigit(cp) || isKhmerDigit(cp) || isMongolianDigit(cp) || isLimbuDigit(cp) || isNewTaiLueDigit(cp) || isTaiThamHoraDigit(cp) || isTaiThamThamDigit(cp) || isBalineseDigit(cp) || isSundaneseDigit(cp) || isLepchaDigit(cp) || isOlChikiDigit(cp) || isVaiDigit(cp) || isSaurashtraDigit(cp) || isKayahLiDigit(cp) || isJavaneseDigit(cp) || isMyanmarTaiLaingDigit(cp) || isChamDigit(cp) || isMeeteiMayekDigit(cp) || isOsmanyaDigit(cp) || isHanifiRohingyaDigit(cp) || isGarayDigit(cp) || isBrahmiDigit(cp) || isSoraSompengDigit(cp) || isChakmaDigit(cp) || isSharadaDigit(cp) || isKhudawadiDigit(cp) || isNewaDigit(cp) || isTirhutaDigit(cp) || isModiDigit(cp) || isTakriDigit(cp) || isAhomDigit(cp) || isWarangCitiDigit(cp) || isDivesAkuruDigit(cp) || isBhaiksukiDigit(cp) || isMasaramGondiDigit(cp) || isGunjalaGondiDigit(cp) || isTolongSikiDigit(cp) || isKawiDigit(cp) || isGurungKhemaDigit(cp) || isMroDigit(cp) || isTangsaDigit(cp) || isPahawhHmongDigit(cp) || isKiratRaiDigit(cp) || isNyiakengPuachueHmongDigit(cp) || isWanchoDigit(cp) || isNagMundariDigit(cp) || isOlOnalDigit(cp) || isAdlamDigit(cp) || isMyanmarPaoDigit(cp) || isEasternPwoKarenDigit(cp) || isSunuwarDigit(cp) || isCircledNumber(cp) || isParenthesizedNumber(cp) || isDigitFullStop(cp) || isParenthesizedLetter(cp) || isParenthesizedCapital(cp) || isDigitZeroFullStop(cp) || isDigitZeroComma(cp) || isDigitOneComma(cp) || isDigitCommaFromTwo(cp) || isTortoiseShellS(cp) || isSquaredCd(cp) || isSquaredWz(cp) || isSquaredHv(cp) || isSquaredMv(cp) || isSquaredSd(cp) || isSquaredSs(cp) || isSquaredPpv(cp) || isSquaredWc(cp) || isRaisedMc(cp) || isRaisedMd(cp) || isRaisedMr(cp) || isSquaredDj(cp) || isCapitalLigatureIj(cp) || isSmallLigatureIj(cp) || isCapitalLetterLj(cp) || isCapitalLWithSmallJ(cp) || isSmallLetterLj(cp) || isCapitalLetterNj(cp)) return char;
  if (cp === 0x02D7 || cp === 0x058A || cp === 0x1400 || cp === 0x1806 || cp === 0x2010 || cp === 0x207B || cp === 0x208B || cp === 0x2011 || cp === 0x2012 || cp === 0x2013 || cp === 0x2014 || cp === 0x2015 || cp === 0x2212 || cp === 0x2E17 || cp === 0x2E1A || cp === 0x2E3A || cp === 0x2E3B || cp === 0x2E40 || cp === 0x2E5D || cp === 0xFE31 || cp === 0xFE32 || cp === 0xFE33 || cp === 0xFE34 || cp === 0xFE4D || cp === 0xFE4E || cp === 0xFE4F || cp === 0xFE58 || cp === 0xFE63 || cp === 0xFF0D || cp === 0xFF3F) return char;
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
  const cont = index => bytes[index] >= 0x80 && bytes[index] <= 0xBF;
  // ASCII percent bytes are not a UTF-8 lead. Without this check, %42%45%46
  // becomes U+2146 and a numeric reference for a Tamil digit never reaches
  // the HTML decoder, so the password stays.
  if (bytes.length === 2) {
    if (b0 < 0xC2 || b0 > 0xDF || !cont(1)) return null;
    const cp = ((b0 & 0x1F) << 6) | (bytes[1] & 0x3F);
    return cp >= 0x80 ? cp : null;
  }
  if (bytes.length === 3) {
    if (b0 < 0xE0 || b0 > 0xEF || !cont(1) || !cont(2)) return null;
    if (b0 === 0xE0 && bytes[1] < 0xA0) return null;
    if (b0 === 0xED && bytes[1] >= 0xA0) return null;
    const cp = ((b0 & 0x0F) << 12) | ((bytes[1] & 0x3F) << 6) | (bytes[2] & 0x3F);
    if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) return null;
    return cp;
  }
  if (bytes.length !== 4) return null;
  if (b0 < 0xF0 || b0 > 0xF4 || !cont(1) || !cont(2) || !cont(3)) return null;
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
// forms kept the password too. U+2010 does not fold to "-". "&hyphen;" and
// "&dash;" are that character, and so are "&#8208;" and its percent-encoded
// UTF-8. Otherwise "user:secret@my&hyphen;proxy:7890" keeps the password.
// U+2011 folds to U+2010 under NFKC. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\u2011proxy:7890" keeps the password.
// U+2012 does not fold to "-". Its literal, percent-encoded, and numeric
// forms kept the password too. Otherwise "user:secret@my\u2012proxy:7890"
// keeps the password.
// U+2013 does not fold to "-". "&ndash;" is that character, and so are
// "&#8211;" and its percent-encoded UTF-8. Otherwise
// "user:secret@my\u2013proxy:7890" keeps the password.
// U+2014 does not fold to "-". "&mdash;" is that character, and so are
// "&#8212;" and its percent-encoded UTF-8. Otherwise
// "user:secret@my\u2014proxy:7890" keeps the password.
// U+2212 does not fold to "-" under NFKC. "&minus;" is that character, and
// so are "&#8722;" and its percent-encoded UTF-8. Otherwise
// "user:secret@my\u2212proxy:7890" keeps the password.
// U+2015 does not fold to "-" under NFKC. "&horbar;" is that character, and
// so are "&#8213;" and its percent-encoded UTF-8. Otherwise
// "user:secret@my\u2015proxy:7890" keeps the password.
// U+FE58 folds to U+2014 under NFKC, and U+2014 is already a hyphen here.
// Its literal, percent-encoded, and numeric forms kept the password too.
// Otherwise "user:secret@my\uFE58proxy:7890" keeps the password.
// U+FE31 folds to U+2014 under NFKC. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\uFE31proxy:7890" keeps the password.
// U+FE32 folds to U+2013 under NFKC, and U+2013 is already a hyphen here.
// Its literal, percent-encoded, and numeric forms kept the password too.
// Otherwise "user:secret@my\uFE32proxy:7890" keeps the password.
// U+FE33 folds to "_" under NFKC. A single-label host already allows that
// mark. Its literal, percent-encoded, and numeric forms kept the password
// too. Otherwise "user:secret@my\uFE33proxy:7890" keeps the password. A
// dotted host does not take an underscore, so
// "user:secret@ex\uFE33ample.com:8080" stays as written.
// U+FE34 folds to "_" under NFKC as well. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\uFE34proxy:7890" keeps the password.
// U+FE4D, U+FE4E, and U+FE4F fold to "_" under NFKC, and so does U+FF3F.
// A single-label host already allows that mark. "&lowbar;" and
// "&UnderBar;" are the same underscore. Their literal, percent-encoded,
// and numeric forms kept the password too. Otherwise
// "user:secret@my\uFE4Dproxy:7890" and "user:secret@my&lowbar;proxy:7890"
// keep the password. A dotted host does not take an underscore, so
// "user:secret@ex\uFE4Dample.com:8080" stays as written.
// U+2E17, U+2E1A, U+2E3A, U+2E3B, U+2E40, and U+2E5D are supplemental
// hyphens. They do not fold to "-" under NFKC. A host label already allows
// a hyphen, so the same marks kept the password. Their literal,
// percent-encoded, and numeric forms do too. Otherwise
// "user:secret@my\u2E17proxy:7890" and "user:secret@ex\u2E40ample.com:8080"
// keep the password. The redacted host uses an ASCII hyphen.
// U+058A, U+1400, and U+1806 are hyphens from other scripts. They do not
// fold to "-" under NFKC. A host label already allows a hyphen, so the same
// marks kept the password. Their literal, percent-encoded, and numeric forms
// do too. Otherwise "user:secret@my\u058Aproxy:7890" and
// "user:secret@ex\u1400ample.com:8080" keep the password.
// U+02D7, U+207B, and U+208B are minus signs. They do not fold to "-" under
// NFKC. U+2212 already does count as a hyphen. These three kept the password
// in a host label. Their literal, percent-encoded, and numeric forms do too.
// Otherwise "user:secret@my\u02D7proxy:7890" and
// "user:secret@ex\u207Bample.com:8080" keep the password.
function decodeEncodedLabelPunct(text) {
  return String(text)
    .replace(/%(?:25){0,3}2[Dd]/g, '-')
    .replace(/%(?:25){0,3}5[Ff]/g, '_')
    .replace(/%(?:25){0,3}[Ee][Ff]%(?:25){0,3}[Bb][Cc]%(?:25){0,3}8[Dd]/g, '-')
    .replace(/%(?:25){0,3}[Ee][Ff]%(?:25){0,3}[Bb]9%(?:25){0,3}[Aa]3/g, '-')
    .replace(/%(?:25){0,3}[Ee][Ff]%(?:25){0,3}[Bb]9%(?:25){0,3}98/g, '-')
    .replace(/%(?:25){0,3}[Ee][Ff]%(?:25){0,3}[Bb]8%(?:25){0,3}[Bb]1/g, '-')
    .replace(/%(?:25){0,3}[Ee][Ff]%(?:25){0,3}[Bb]8%(?:25){0,3}[Bb]2/g, '-')
    .replace(/%(?:25){0,3}[Ee][Ff]%(?:25){0,3}[Bb]8%(?:25){0,3}[Bb]3/g, '_')
    .replace(/%(?:25){0,3}[Ee][Ff]%(?:25){0,3}[Bb]8%(?:25){0,3}[Bb]4/g, '_')
    .replace(/%(?:25){0,3}[Ee][Ff]%(?:25){0,3}[Bb]9%(?:25){0,3}8[Dd]/g, '_')
    .replace(/%(?:25){0,3}[Ee][Ff]%(?:25){0,3}[Bb]9%(?:25){0,3}8[Ee]/g, '_')
    .replace(/%(?:25){0,3}[Ee][Ff]%(?:25){0,3}[Bb]9%(?:25){0,3}8[Ff]/g, '_')
    .replace(/%(?:25){0,3}[Ee][Ff]%(?:25){0,3}[Bb][Cc]%(?:25){0,3}[Bb][Ff]/g, '_')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}80%(?:25){0,3}90/g, '-')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}80%(?:25){0,3}91/g, '-')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}80%(?:25){0,3}92/g, '-')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}80%(?:25){0,3}93/g, '-')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}80%(?:25){0,3}94/g, '-')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}80%(?:25){0,3}95/g, '-')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}88%(?:25){0,3}92/g, '-')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}[Bb]8%(?:25){0,3}97/g, '-')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}[Bb]8%(?:25){0,3}9[Aa]/g, '-')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}[Bb]8%(?:25){0,3}[Bb][Aa]/g, '-')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}[Bb]8%(?:25){0,3}[Bb][Bb]/g, '-')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}[Bb]9%(?:25){0,3}80/g, '-')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}[Bb]9%(?:25){0,3}9[Dd]/g, '-')
    .replace(/%(?:25){0,3}[Dd]6%(?:25){0,3}8[Aa]/g, '-')
    .replace(/%(?:25){0,3}[Ee]1%(?:25){0,3}90%(?:25){0,3}80/g, '-')
    .replace(/%(?:25){0,3}[Ee]1%(?:25){0,3}[Aa]0%(?:25){0,3}86/g, '-')
    .replace(/%(?:25){0,3}[Cc][Bb]%(?:25){0,3}97/g, '-')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}81%(?:25){0,3}[Bb][Bb]/g, '-')
    .replace(/%(?:25){0,3}[Ee]2%(?:25){0,3}82%(?:25){0,3}8[Bb]/g, '-');
}
function foldLabelHyphens(text) {
  return text
    .replace(/[\u02D7\u058A\u1400\u1806\u2010\u2011\u2012\u2013\u2014\u2015\u207B\u208B\u2212\u2E17\u2E1A\u2E3A\u2E3B\u2E40\u2E5D\uFE31\uFE32\uFE58\uFE63\uFF0D]/g, '-')
    .replace(/[\uFE33\uFE34\uFE4D\uFE4E\uFE4F\uFF3F]/g, '_');
}
// U+FF21..U+FF3A and U+FF41..U+FF5A fold to A-Z and a-z under NFKC. A
// single-label or dotted host already allows those letters. Their literal,
// percent-encoded, and numeric forms kept the password too. Otherwise
// "user:secret@my\uFF4Dproxy:7890" and "user:secret@ex\uFF41mple.com:8080"
// keep the password. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
function readEncodedFullwidthLetter(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !((cp >= 0xFF21 && cp <= 0xFF3A) || (cp >= 0xFF41 && cp <= 0xFF5A))) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedFullwidthLetters(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedFullwidthLetter(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldFullwidthLetters(text) {
  return text.replace(/[\uFF21-\uFF3A\uFF41-\uFF5A]/g, char => String.fromCharCode(char.charCodeAt(0) - 0xFEE0));
}
// U+24B6..U+24E9 fold to A-Z and a-z under NFKC. A single-label or dotted
// host already allows those letters. Their literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\u24DCproxy:7890" and "user:secret@ex\u24D0mple.com:8080"
// keep the password. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
function readEncodedCircledLetter(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || cp < 0x24B6 || cp > 0x24E9) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedCircledLetters(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedCircledLetter(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldCircledLetters(text) {
  return text.replace(/[\u24B6-\u24E9]/g, char => {
    const cp = char.charCodeAt(0);
    return String.fromCharCode(cp <= 0x24CF ? cp - 0x24B6 + 0x41 : cp - 0x24D0 + 0x61);
  });
}
// These letterlike symbols fold to one ASCII letter under NFKC. A
// single-label or dotted host already allows that letter. Their literal,
// percent-encoded, and numeric forms kept the password too. Otherwise
// "user:secret@my\u212Aproxy:7890" and "user:secret@ex\u2139mple.com:8080"
// keep the password. Symbols that expand to more than one character, such
// as U+2121, stay as written. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
const LETTERLIKE_ASCII = {
  '\u2102': 'C',
  '\u210A': 'g',
  '\u210B': 'H',
  '\u210C': 'H',
  '\u210D': 'H',
  '\u210E': 'h',
  '\u2110': 'I',
  '\u2111': 'I',
  '\u2112': 'L',
  '\u2113': 'l',
  '\u2115': 'N',
  '\u2119': 'P',
  '\u211A': 'Q',
  '\u211B': 'R',
  '\u211C': 'R',
  '\u211D': 'R',
  '\u2124': 'Z',
  '\u2128': 'Z',
  '\u212A': 'K',
  '\u212C': 'B',
  '\u212D': 'C',
  '\u212F': 'e',
  '\u2130': 'E',
  '\u2131': 'F',
  '\u2133': 'M',
  '\u2134': 'o',
  '\u2139': 'i',
  '\u2145': 'D',
  '\u2146': 'd',
  '\u2147': 'e',
  '\u2148': 'i',
  '\u2149': 'j'
};
const LETTERLIKE_FOLD = new RegExp(`[${Object.keys(LETTERLIKE_ASCII).join('')}]`, 'g');
function isLetterlikeLetter(cp) {
  return Object.prototype.hasOwnProperty.call(LETTERLIKE_ASCII, String.fromCodePoint(cp));
}
function readEncodedLetterlikeLetter(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isLetterlikeLetter(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedLetterlikeLetters(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedLetterlikeLetter(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldLetterlikeLetters(text) {
  return text.replace(LETTERLIKE_FOLD, char => LETTERLIKE_ASCII[char]);
}
// U+00AA and U+00BA fold to "a" and "o". U+017F folds to "s". A
// single-label or dotted host already allows those letters. Their literal,
// percent-encoded, and numeric forms kept the password too. Otherwise
// "user:secret@my\u017Fproxy:7890" and "user:secret@ex\u00AAmple.com:8080"
// keep the password. The micro sign stays as written. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
const LATIN_COMPAT_ASCII = {
  '\u00AA': 'a',
  '\u00BA': 'o',
  '\u017F': 's'
};
const LATIN_COMPAT_FOLD = new RegExp(`[${Object.keys(LATIN_COMPAT_ASCII).join('')}]`, 'g');
function isLatinCompatLetter(cp) {
  return Object.prototype.hasOwnProperty.call(LATIN_COMPAT_ASCII, String.fromCodePoint(cp));
}
function readEncodedLatinCompatLetter(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 2; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xC2 || lead > 0xDF || bytes[1] < 0x80 || bytes[1] > 0xBF) return null;
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isLatinCompatLetter(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedLatinCompatLetters(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedLatinCompatLetter(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldLatinCompatLetters(text) {
  return text.replace(LATIN_COMPAT_FOLD, char => LATIN_COMPAT_ASCII[char]);
}
// These modifier letters fold to one ASCII letter under NFKC. A single-label
// or dotted host already allows that letter. Their literal, percent-encoded,
// and numeric forms kept the password too. Otherwise
// "user:secret@my\u02B0proxy:7890" and "user:secret@ex\u1D43mple.com:8080"
// keep the password. U+107A5 is the supplementary small q. A modifier letter
// that expands past one ASCII letter stays as written. The micro sign stays
// as written. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
const MODIFIER_LETTER_ASCII = new Map([
  [0x02B0, 'h'],
  [0x02B2, 'j'],
  [0x02B3, 'r'],
  [0x02B7, 'w'],
  [0x02B8, 'y'],
  [0x02E1, 'l'],
  [0x02E2, 's'],
  [0x02E3, 'x'],
  [0x1D2C, 'A'],
  [0x1D2E, 'B'],
  [0x1D30, 'D'],
  [0x1D31, 'E'],
  [0x1D33, 'G'],
  [0x1D34, 'H'],
  [0x1D35, 'I'],
  [0x1D36, 'J'],
  [0x1D37, 'K'],
  [0x1D38, 'L'],
  [0x1D39, 'M'],
  [0x1D3A, 'N'],
  [0x1D3C, 'O'],
  [0x1D3E, 'P'],
  [0x1D3F, 'R'],
  [0x1D40, 'T'],
  [0x1D41, 'U'],
  [0x1D42, 'W'],
  [0x1D43, 'a'],
  [0x1D47, 'b'],
  [0x1D48, 'd'],
  [0x1D49, 'e'],
  [0x1D4D, 'g'],
  [0x1D4F, 'k'],
  [0x1D50, 'm'],
  [0x1D52, 'o'],
  [0x1D56, 'p'],
  [0x1D57, 't'],
  [0x1D58, 'u'],
  [0x1D5B, 'v'],
  [0x1D9C, 'c'],
  [0x1DA0, 'f'],
  [0x1DBB, 'z'],
  [0x2C7D, 'V'],
  [0xA7F1, 'S'],
  [0xA7F2, 'C'],
  [0xA7F3, 'F'],
  [0xA7F4, 'Q'],
  [0x107A5, 'q']
]);
function isModifierLetter(cp) {
  return MODIFIER_LETTER_ASCII.has(cp);
}
function readEncodedModifierLetter(text, index) {
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
  if (cp == null || !isModifierLetter(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedModifierLetters(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedModifierLetter(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldModifierLetters(text) {
  let out = '';
  for (const char of text) {
    const ascii = MODIFIER_LETTER_ASCII.get(char.codePointAt(0));
    out += ascii || char;
  }
  return out;
}
// Superscript and subscript letters that fold to one ASCII letter under NFKC
// are host letters too. U+2071 folds to "i" and U+207F folds to "n".
// U+2090 through U+209C, U+1D62 through U+1D65, and U+2C7C are the subscript
// letters. Their literal, percent-encoded, and numeric forms kept the
// password. Otherwise "user:secret@my\u2071proxy:7890" and
// "user:secret@ex\u2090mple.com:8080" keep the password. Superscript digits
// are already port digits. The micro sign stays as written. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
const SUP_SUB_LETTER_ASCII = new Map([
  [0x1D62, 'i'],
  [0x1D63, 'r'],
  [0x1D64, 'u'],
  [0x1D65, 'v'],
  [0x2071, 'i'],
  [0x207F, 'n'],
  [0x2090, 'a'],
  [0x2091, 'e'],
  [0x2092, 'o'],
  [0x2093, 'x'],
  [0x2095, 'h'],
  [0x2096, 'k'],
  [0x2097, 'l'],
  [0x2098, 'm'],
  [0x2099, 'n'],
  [0x209A, 'p'],
  [0x209B, 's'],
  [0x209C, 't'],
  [0x2C7C, 'j']
]);
function isSupSubLetter(cp) {
  return SUP_SUB_LETTER_ASCII.has(cp);
}
function readEncodedSupSubLetter(text, index) {
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
  if (cp == null || !isSupSubLetter(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSupSubLetters(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedSupSubLetter(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSupSubLetters(text) {
  let out = '';
  for (const char of text) {
    const ascii = SUP_SUB_LETTER_ASCII.get(char.codePointAt(0));
    out += ascii || char;
  }
  return out;
}
// Roman numerals that fold to one ASCII letter under NFKC are host letters
// too. U+2160 folds to "I", U+216F folds to "M", and U+2170 folds to "i".
// Their literal, percent-encoded, and numeric forms kept the password.
// Otherwise "user:secret@my\u2160proxy:7890" and
// "user:secret@ex\u2170mple.com:8080" keep the password. A numeral that
// expands to more than one letter, such as U+2161, stays as written. The
// micro sign stays as written. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
const ROMAN_LETTER_ASCII = new Map([
  [0x2160, 'I'],
  [0x2164, 'V'],
  [0x2169, 'X'],
  [0x216C, 'L'],
  [0x216D, 'C'],
  [0x216E, 'D'],
  [0x216F, 'M'],
  [0x2170, 'i'],
  [0x2174, 'v'],
  [0x2179, 'x'],
  [0x217C, 'l'],
  [0x217D, 'c'],
  [0x217E, 'd'],
  [0x217F, 'm']
]);
function isRomanLetter(cp) {
  return ROMAN_LETTER_ASCII.has(cp);
}
function readEncodedRomanLetter(text, index) {
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
  if (cp == null || !isRomanLetter(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedRomanLetters(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedRomanLetter(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldRomanLetters(text) {
  let out = '';
  for (const char of text) {
    const ascii = ROMAN_LETTER_ASCII.get(char.codePointAt(0));
    out += ascii || char;
  }
  return out;
}
// Mathematical letters in U+1D400..U+1D6A3 that fold to one ASCII letter are
// host letters too. U+1D400 folds to "A" and U+1D433 folds to "z". The italic
// h hole at U+1D455 is not a letter. Their literal, percent-encoded, and
// numeric forms kept the password. Otherwise a bold or monospace letter
// inside the host keeps the password. Greek mathematical letters stay as written. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
const MATH_LETTER_RANGES = [
  [0x1D400, 0x1D419, 0x41],
  [0x1D41A, 0x1D433, 0x61],
  [0x1D434, 0x1D44D, 0x41],
  [0x1D44E, 0x1D454, 0x61],
  [0x1D456, 0x1D467, 0x69],
  [0x1D468, 0x1D481, 0x41],
  [0x1D482, 0x1D49B, 0x61],
  [0x1D49C, 0x1D49C, 0x41],
  [0x1D49E, 0x1D49F, 0x43],
  [0x1D4A2, 0x1D4A2, 0x47],
  [0x1D4A5, 0x1D4A6, 0x4A],
  [0x1D4A9, 0x1D4AC, 0x4E],
  [0x1D4AE, 0x1D4B5, 0x53],
  [0x1D4B6, 0x1D4B9, 0x61],
  [0x1D4BB, 0x1D4BB, 0x66],
  [0x1D4BD, 0x1D4C3, 0x68],
  [0x1D4C5, 0x1D4CF, 0x70],
  [0x1D4D0, 0x1D4E9, 0x41],
  [0x1D4EA, 0x1D503, 0x61],
  [0x1D504, 0x1D505, 0x41],
  [0x1D507, 0x1D50A, 0x44],
  [0x1D50D, 0x1D514, 0x4A],
  [0x1D516, 0x1D51C, 0x53],
  [0x1D51E, 0x1D537, 0x61],
  [0x1D538, 0x1D539, 0x41],
  [0x1D53B, 0x1D53E, 0x44],
  [0x1D540, 0x1D544, 0x49],
  [0x1D546, 0x1D546, 0x4F],
  [0x1D54A, 0x1D550, 0x53],
  [0x1D552, 0x1D56B, 0x61],
  [0x1D56C, 0x1D585, 0x41],
  [0x1D586, 0x1D59F, 0x61],
  [0x1D5A0, 0x1D5B9, 0x41],
  [0x1D5BA, 0x1D5D3, 0x61],
  [0x1D5D4, 0x1D5ED, 0x41],
  [0x1D5EE, 0x1D607, 0x61],
  [0x1D608, 0x1D621, 0x41],
  [0x1D622, 0x1D63B, 0x61],
  [0x1D63C, 0x1D655, 0x41],
  [0x1D656, 0x1D66F, 0x61],
  [0x1D670, 0x1D689, 0x41],
  [0x1D68A, 0x1D6A3, 0x61]
];
function mathLetterAscii(cp) {
  for (const [start, end, ascii] of MATH_LETTER_RANGES) {
    if (cp < start) return '';
    if (cp <= end) return String.fromCharCode(ascii + (cp - start));
  }
  return '';
}
function isMathLetter(cp) {
  return mathLetterAscii(cp) !== '';
}
function readEncodedMathLetter(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isMathLetter(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedMathLetters(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedMathLetter(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldMathLetters(text) {
  let out = '';
  for (const char of text) {
    out += mathLetterAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Enclosed letters that fold to one ASCII letter are host letters too.
// U+1F130 through U+1F149 are the squared capitals. U+1F12B and U+1F12C are
// the circled italic C and R. Their literal, percent-encoded, and numeric
// forms kept the password. Otherwise "user:secret@my\u{1F130}proxy:7890"
// keeps the password. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
const ENCLOSED_LETTER_RANGES = [
  [0x1F12B, 0x1F12B, 0x43],
  [0x1F12C, 0x1F12C, 0x52],
  [0x1F130, 0x1F149, 0x41]
];
function enclosedLetterAscii(cp) {
  for (const [start, end, ascii] of ENCLOSED_LETTER_RANGES) {
    if (cp < start) return '';
    if (cp <= end) return String.fromCharCode(ascii + (cp - start));
  }
  return '';
}
function isEnclosedLetter(cp) {
  return enclosedLetterAscii(cp) !== '';
}
function readEncodedEnclosedLetter(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isEnclosedLetter(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedEnclosedLetters(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedEnclosedLetter(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldEnclosedLetters(text) {
  let out = '';
  for (const char of text) {
    out += enclosedLetterAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Outlined Latin capitals U+1CCD6..U+1CCEF fold to A-Z under NFKC. A
// single-label or dotted host already allows those letters. Their literal,
// percent-encoded, and numeric forms kept the password too. Otherwise
// "user:secret@my\u{1CCD6}proxy:7890" and
// "user:secret@ex\u{1CCD6}mple.com:8080" keep the password. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
function outlinedLetterAscii(cp) {
  if (cp >= 0x1CCD6 && cp <= 0x1CCEF) return String.fromCharCode(0x41 + (cp - 0x1CCD6));
  return '';
}
function isOutlinedLetter(cp) {
  return outlinedLetterAscii(cp) !== '';
}
function readEncodedOutlinedLetter(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isOutlinedLetter(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedOutlinedLetters(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedOutlinedLetter(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldOutlinedLetters(text) {
  let out = '';
  for (const char of text) {
    out += outlinedLetterAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Outlined digits U+1CCF0..U+1CCF9 fold to 0-9 under NFKC. A single-label
// host, a dotted host, a numeric host, and a port already allow those digits.
// Their literal, percent-encoded, and numeric forms kept the password too.
// Otherwise "user:secret@my\u{1CCF0}proxy:7890" and
// "user:secret@ex\u{1CCF1}ample.com:8080" keep the password. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
function outlinedDigitAscii(cp) {
  if (cp >= 0x1CCF0 && cp <= 0x1CCF9) return String.fromCharCode(0x30 + (cp - 0x1CCF0));
  return '';
}
function isOutlinedDigit(cp) {
  return outlinedDigitAscii(cp) !== '';
}
function readEncodedOutlinedDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isOutlinedDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedOutlinedDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedOutlinedDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldOutlinedDigits(text) {
  let out = '';
  for (const char of text) {
    out += outlinedDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Circled digits U+24EA and U+2460..U+2468 fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// those digits. Their literal, percent-encoded, and numeric forms kept the
// password too. Otherwise "user:secret@my\u24EAproxy:7890" and
// "user:secret@ex\u2460ample.com:8080" keep the password. U+2469..U+2473
// expand to 10..20 and are folded separately. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
function circledDigitAscii(cp) {
  if (cp === 0x24EA) return '0';
  if (cp >= 0x2460 && cp <= 0x2468) return String.fromCharCode(0x31 + (cp - 0x2460));
  return '';
}
function isCircledDigit(cp) {
  return circledDigitAscii(cp) !== '';
}
function readEncodedCircledDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isCircledDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedCircledDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedCircledDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldCircledDigits(text) {
  let out = '';
  for (const char of text) {
    out += circledDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Circled numbers U+2469..U+2473 fold to 10..20 under NFKC. U+3251..U+325F
// fold to 21..35 and U+32B1..U+32BF fold to 36..50. A single-digit fold
// leaves the password in "user:secret@my\u2469proxy:7890" and
// "user:secret@my\u3251proxy:7890" because the host label never sees one
// ASCII digit. The same is true of a numeric host and of the percent-encoded
// and numeric forms. The redacted host uses ASCII digits. U+3250 folds to
// "PTE", and U+32C0 folds to a digit plus a month mark. Those stay as written.
function circledNumberAscii(cp) {
  if (cp >= 0x2469 && cp <= 0x2473) return String(10 + (cp - 0x2469));
  if (cp >= 0x3251 && cp <= 0x325F) return String(21 + (cp - 0x3251));
  if (cp >= 0x32B1 && cp <= 0x32BF) return String(36 + (cp - 0x32B1));
  return '';
}
function isCircledNumber(cp) {
  return circledNumberAscii(cp) !== '';
}
function readEncodedCircledNumber(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isCircledNumber(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedCircledNumbers(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const number = readEncodedCircledNumber(text, index);
    if (number) {
      out += number.char;
      index = number.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldCircledNumbers(text) {
  let out = '';
  for (const char of text) {
    out += circledNumberAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Parenthesized numbers U+2474..U+2487 fold to "(1)".."(20)" under NFKC.
// Keeping the parentheses ends the host, so "user:secret@my\u2474proxy:7890"
// would still keep the password. The digits inside are 1..20. Their literal,
// percent-encoded, and numeric forms kept the password too. The redacted
// host uses those ASCII digits. Digit full stops and parenthesized letters are
// folded separately. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
function parenthesizedNumberAscii(cp) {
  if (cp >= 0x2474 && cp <= 0x247C) return String(1 + (cp - 0x2474));
  if (cp >= 0x247D && cp <= 0x2487) return String(10 + (cp - 0x247D));
  return '';
}
function isParenthesizedNumber(cp) {
  return parenthesizedNumberAscii(cp) !== '';
}
function readEncodedParenthesizedNumber(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isParenthesizedNumber(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedParenthesizedNumbers(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const number = readEncodedParenthesizedNumber(text, index);
    if (number) {
      out += number.char;
      index = number.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldParenthesizedNumbers(text) {
  let out = '';
  for (const char of text) {
    out += parenthesizedNumberAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Digit full stops U+2488..U+249B fold to "1.".."20." under NFKC. Keeping the
// full stop ends a single-label host and splits a port, so
// "user:secret@my\u2488proxy:7890" and "user:secret@my-proxy:\u2488890" would
// still keep the password. The digits inside are 1..20. Their literal,
// percent-encoded, and numeric forms kept the password too. The redacted
// host uses those ASCII digits. Parenthesized letters and capitals, and a
// digit zero full stop, are folded separately. A dingbat circled sans-serif
// digit zero, such as U+1F10B, stays as written.
function digitFullStopAscii(cp) {
  if (cp >= 0x2488 && cp <= 0x2490) return String(1 + (cp - 0x2488));
  if (cp >= 0x2491 && cp <= 0x249B) return String(10 + (cp - 0x2491));
  return '';
}
function isDigitFullStop(cp) {
  return digitFullStopAscii(cp) !== '';
}
function readEncodedDigitFullStop(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isDigitFullStop(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedDigitFullStops(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const number = readEncodedDigitFullStop(text, index);
    if (number) {
      out += number.char;
      index = number.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldDigitFullStops(text) {
  let out = '';
  for (const char of text) {
    out += digitFullStopAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Parenthesized letters U+249C..U+24B5 fold to "(a)".."(z)" under NFKC.
// Keeping the parentheses ends the host, so "user:secret@my\u249Cproxy:7890"
// would still keep the password. The letters inside are a..z. Their literal,
// percent-encoded, and numeric forms kept the password too. The redacted
// host uses those ASCII letters. Parenthesized capitals are folded separately.
// A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
function parenthesizedLetterAscii(cp) {
  if (cp >= 0x249C && cp <= 0x24B5) return String.fromCharCode(0x61 + (cp - 0x249C));
  return '';
}
function isParenthesizedLetter(cp) {
  return parenthesizedLetterAscii(cp) !== '';
}
function readEncodedParenthesizedLetter(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isParenthesizedLetter(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedParenthesizedLetters(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedParenthesizedLetter(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldParenthesizedLetters(text) {
  let out = '';
  for (const char of text) {
    out += parenthesizedLetterAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Parenthesized capitals U+1F110..U+1F129 fold to "(A)".."(Z)" under NFKC.
// Keeping the parentheses ends the host, so "user:secret@my\u{1F110}proxy:7890"
// would still keep the password. The letters inside are A..Z. Their literal,
// percent-encoded, and numeric forms kept the password too. The redacted
// host uses those ASCII letters. A digit zero full stop is folded separately.
// A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
function parenthesizedCapitalAscii(cp) {
  if (cp >= 0x1F110 && cp <= 0x1F129) return String.fromCharCode(0x41 + (cp - 0x1F110));
  return '';
}
function isParenthesizedCapital(cp) {
  return parenthesizedCapitalAscii(cp) !== '';
}
function readEncodedParenthesizedCapital(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isParenthesizedCapital(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedParenthesizedCapitals(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedParenthesizedCapital(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldParenthesizedCapitals(text) {
  let out = '';
  for (const char of text) {
    out += parenthesizedCapitalAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Digit zero full stop U+1F100 folds to "0." under NFKC. Keeping the full
// stop ends a single-label host and splits a port, so
// "user:secret@my\u{1F100}proxy:7890" and "user:secret@my-proxy:\u{1F100}890"
// would still keep the password. The digit inside is 0. Its literal,
// percent-encoded, and numeric forms kept the password too. The redacted
// host uses that ASCII digit. Digit full stops one through twenty are folded
// separately. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
function digitZeroFullStopAscii(cp) {
  if (cp === 0x1F100) return '0';
  return '';
}
function isDigitZeroFullStop(cp) {
  return digitZeroFullStopAscii(cp) !== '';
}
function readEncodedDigitZeroFullStop(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isDigitZeroFullStop(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedDigitZeroFullStops(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedDigitZeroFullStop(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldDigitZeroFullStops(text) {
  let out = '';
  for (const char of text) {
    out += digitZeroFullStopAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Digit zero comma U+1F101 folds to "0," under NFKC. Keeping the comma ends a
// single-label host and splits a port, so "user:secret@my\u{1F101}proxy:7890"
// and "user:secret@my-proxy:\u{1F101}890" would still keep the password. The
// digit inside is 0. Its literal, percent-encoded, and numeric forms kept the
// password too. The redacted host uses that ASCII digit. A digit zero full
// stop is folded separately. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
function digitZeroCommaAscii(cp) {
  if (cp === 0x1F101) return '0';
  return '';
}
function isDigitZeroComma(cp) {
  return digitZeroCommaAscii(cp) !== '';
}
function readEncodedDigitZeroComma(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isDigitZeroComma(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedDigitZeroCommas(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedDigitZeroComma(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldDigitZeroCommas(text) {
  let out = '';
  for (const char of text) {
    out += digitZeroCommaAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Digit one comma U+1F102 folds to "1," under NFKC. Keeping the comma ends a
// single-label host and splits a port, so "user:secret@my\u{1F102}proxy:7890"
// and "user:secret@my-proxy:\u{1F102}890" would still keep the password. The
// digit inside is 1. Its literal, percent-encoded, and numeric forms kept the
// password too. The redacted host uses that ASCII digit. A digit zero comma
// is folded separately. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
function digitOneCommaAscii(cp) {
  if (cp === 0x1F102) return '1';
  return '';
}
function isDigitOneComma(cp) {
  return digitOneCommaAscii(cp) !== '';
}
function readEncodedDigitOneComma(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isDigitOneComma(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedDigitOneCommas(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedDigitOneComma(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldDigitOneCommas(text) {
  let out = '';
  for (const char of text) {
    out += digitOneCommaAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Digit commas U+1F103..U+1F10A fold to "2,".."9," under NFKC. Keeping the
// comma ends a single-label host and splits a port, so
// "user:secret@my\u{1F103}proxy:7890" and "user:secret@my-proxy:\u{1F10A}890"
// would still keep the password. The digits inside are 2..9. Their literal,
// percent-encoded, and numeric forms kept the password too. The redacted
// host uses those ASCII digits. Digit zero and one commas are folded
// separately. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
function digitCommaFromTwoAscii(cp) {
  if (cp >= 0x1F103 && cp <= 0x1F10A) return String.fromCharCode(0x32 + (cp - 0x1F103));
  return '';
}
function isDigitCommaFromTwo(cp) {
  return digitCommaFromTwoAscii(cp) !== '';
}
function readEncodedDigitCommaFromTwo(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isDigitCommaFromTwo(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedDigitCommasFromTwo(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedDigitCommaFromTwo(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldDigitCommasFromTwo(text) {
  let out = '';
  for (const char of text) {
    out += digitCommaFromTwoAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Tortoise shell bracketed S U+1F12A folds to U+3014, S, U+3015 under NFKC. Keeping
// the brackets ends the host, so "user:secret@my\u{1F12A}proxy:7890" would
// still keep the password. The letter inside is S. Its literal,
// percent-encoded, and numeric forms kept the password too. The redacted
// host uses that ASCII letter. Parenthesized capitals are folded separately.
// A squared CD is folded separately.
function tortoiseShellSAscii(cp) {
  if (cp === 0x1F12A) return 'S';
  return '';
}
function isTortoiseShellS(cp) {
  return tortoiseShellSAscii(cp) !== '';
}
function readEncodedTortoiseShellS(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isTortoiseShellS(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedTortoiseShellS(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedTortoiseShellS(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldTortoiseShellS(text) {
  let out = '';
  for (const char of text) {
    out += tortoiseShellSAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Squared CD U+1F12D folds to "CD" under NFKC. A single-label host and a
// dotted host already allow those letters. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\u{1F12D}proxy:7890" and
// "user:secret@ex\u{1F12D}ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A squared WZ is folded separately.
function squaredCdAscii(cp) {
  if (cp === 0x1F12D) return 'CD';
  return '';
}
function isSquaredCd(cp) {
  return squaredCdAscii(cp) !== '';
}
function readEncodedSquaredCd(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSquaredCd(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSquaredCd(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedSquaredCd(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSquaredCd(text) {
  let out = '';
  for (const char of text) {
    out += squaredCdAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Squared WZ U+1F12E folds to "WZ" under NFKC. A single-label host and a
// dotted host already allow those letters. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\u{1F12E}proxy:7890" and
// "user:secret@ex\u{1F12E}ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A squared HV is folded separately.
function squaredWzAscii(cp) {
  if (cp === 0x1F12E) return 'WZ';
  return '';
}
function isSquaredWz(cp) {
  return squaredWzAscii(cp) !== '';
}
function readEncodedSquaredWz(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSquaredWz(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSquaredWz(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedSquaredWz(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSquaredWz(text) {
  let out = '';
  for (const char of text) {
    out += squaredWzAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Squared HV U+1F14A folds to "HV" under NFKC. A single-label host and a
// dotted host already allow those letters. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\u{1F14A}proxy:7890" and
// "user:secret@ex\u{1F14A}ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A squared MV is folded separately.
function squaredHvAscii(cp) {
  if (cp === 0x1F14A) return 'HV';
  return '';
}
function isSquaredHv(cp) {
  return squaredHvAscii(cp) !== '';
}
function readEncodedSquaredHv(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSquaredHv(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSquaredHv(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedSquaredHv(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSquaredHv(text) {
  let out = '';
  for (const char of text) {
    out += squaredHvAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Squared MV U+1F14B folds to "MV" under NFKC. A single-label host and a
// dotted host already allow those letters. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\u{1F14B}proxy:7890" and
// "user:secret@ex\u{1F14B}ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A squared SD is folded separately.
function squaredMvAscii(cp) {
  if (cp === 0x1F14B) return 'MV';
  return '';
}
function isSquaredMv(cp) {
  return squaredMvAscii(cp) !== '';
}
function readEncodedSquaredMv(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSquaredMv(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSquaredMv(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedSquaredMv(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSquaredMv(text) {
  let out = '';
  for (const char of text) {
    out += squaredMvAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Squared SD U+1F14C folds to "SD" under NFKC. A single-label host and a
// dotted host already allow those letters. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\u{1F14C}proxy:7890" and
// "user:secret@ex\u{1F14C}ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A squared SS is folded separately.
function squaredSdAscii(cp) {
  if (cp === 0x1F14C) return 'SD';
  return '';
}
function isSquaredSd(cp) {
  return squaredSdAscii(cp) !== '';
}
function readEncodedSquaredSd(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSquaredSd(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSquaredSd(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedSquaredSd(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSquaredSd(text) {
  let out = '';
  for (const char of text) {
    out += squaredSdAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Squared SS U+1F14D folds to "SS" under NFKC. A single-label host and a
// dotted host already allow those letters. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\u{1F14D}proxy:7890" and
// "user:secret@ex\u{1F14D}ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A squared PPV is folded separately.
function squaredSsAscii(cp) {
  if (cp === 0x1F14D) return 'SS';
  return '';
}
function isSquaredSs(cp) {
  return squaredSsAscii(cp) !== '';
}
function readEncodedSquaredSs(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSquaredSs(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSquaredSs(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedSquaredSs(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSquaredSs(text) {
  let out = '';
  for (const char of text) {
    out += squaredSsAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Squared PPV U+1F14E folds to "PPV" under NFKC. A single-label host and a
// dotted host already allow those letters. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\u{1F14E}proxy:7890" and
// "user:secret@ex\u{1F14E}ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A squared WC is folded separately.
function squaredPpvAscii(cp) {
  if (cp === 0x1F14E) return 'PPV';
  return '';
}
function isSquaredPpv(cp) {
  return squaredPpvAscii(cp) !== '';
}
function readEncodedSquaredPpv(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSquaredPpv(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSquaredPpv(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedSquaredPpv(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSquaredPpv(text) {
  let out = '';
  for (const char of text) {
    out += squaredPpvAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Squared WC U+1F14F folds to "WC" under NFKC. A single-label host and a
// dotted host already allow those letters. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\u{1F14F}proxy:7890" and
// "user:secret@ex\u{1F14F}ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A raised MC sign is folded separately.
function squaredWcAscii(cp) {
  if (cp === 0x1F14F) return 'WC';
  return '';
}
function isSquaredWc(cp) {
  return squaredWcAscii(cp) !== '';
}
function readEncodedSquaredWc(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSquaredWc(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSquaredWc(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedSquaredWc(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSquaredWc(text) {
  let out = '';
  for (const char of text) {
    out += squaredWcAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Raised MC sign U+1F16A folds to "MC" under NFKC. A single-label host and a
// dotted host already allow those letters. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\u{1F16A}proxy:7890" and
// "user:secret@ex\u{1F16A}ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A raised MD sign is folded separately.
function raisedMcAscii(cp) {
  if (cp === 0x1F16A) return 'MC';
  return '';
}
function isRaisedMc(cp) {
  return raisedMcAscii(cp) !== '';
}
function readEncodedRaisedMc(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isRaisedMc(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedRaisedMc(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedRaisedMc(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldRaisedMc(text) {
  let out = '';
  for (const char of text) {
    out += raisedMcAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Raised MD sign U+1F16B folds to "MD" under NFKC. A single-label host and a
// dotted host already allow those letters. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\u{1F16B}proxy:7890" and
// "user:secret@ex\u{1F16B}ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A raised MR sign is folded separately.
function raisedMdAscii(cp) {
  if (cp === 0x1F16B) return 'MD';
  return '';
}
function isRaisedMd(cp) {
  return raisedMdAscii(cp) !== '';
}
function readEncodedRaisedMd(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isRaisedMd(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedRaisedMd(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedRaisedMd(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldRaisedMd(text) {
  let out = '';
  for (const char of text) {
    out += raisedMdAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Raised MR sign U+1F16C folds to "MR" under NFKC. A single-label host and a
// dotted host already allow those letters. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\u{1F16C}proxy:7890" and
// "user:secret@ex\u{1F16C}ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A squared DJ is folded separately.
function raisedMrAscii(cp) {
  if (cp === 0x1F16C) return 'MR';
  return '';
}
function isRaisedMr(cp) {
  return raisedMrAscii(cp) !== '';
}
function readEncodedRaisedMr(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isRaisedMr(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedRaisedMr(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedRaisedMr(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldRaisedMr(text) {
  let out = '';
  for (const char of text) {
    out += raisedMrAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Squared DJ U+1F190 folds to "DJ" under NFKC. A single-label host and a
// dotted host already allow those letters. Its literal, percent-encoded, and
// numeric forms kept the password too. Otherwise
// "user:secret@my\u{1F190}proxy:7890" and
// "user:secret@ex\u{1F190}ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A Latin capital ligature IJ is folded separately.
function squaredDjAscii(cp) {
  if (cp === 0x1F190) return 'DJ';
  return '';
}
function isSquaredDj(cp) {
  return squaredDjAscii(cp) !== '';
}
function readEncodedSquaredDj(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSquaredDj(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSquaredDj(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedSquaredDj(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSquaredDj(text) {
  let out = '';
  for (const char of text) {
    out += squaredDjAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Latin capital ligature IJ U+0132 folds to "IJ" under NFKC. A single-label
// host and a dotted host already allow those letters. Its literal,
// percent-encoded, and numeric forms kept the password too. Otherwise
// "user:secret@my\u0132proxy:7890" and
// "user:secret@ex\u0132ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A Latin small ligature ij is folded separately.
function capitalLigatureIjAscii(cp) {
  if (cp === 0x0132) return 'IJ';
  return '';
}
function isCapitalLigatureIj(cp) {
  return capitalLigatureIjAscii(cp) !== '';
}
function readEncodedCapitalLigatureIj(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 2; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xC2 || lead > 0xDF || bytes[1] < 0x80 || bytes[1] > 0xBF) return null;
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isCapitalLigatureIj(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedCapitalLigatureIj(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedCapitalLigatureIj(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldCapitalLigatureIj(text) {
  let out = '';
  for (const char of text) {
    out += capitalLigatureIjAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Latin small ligature ij U+0133 folds to "ij" under NFKC. A single-label
// host and a dotted host already allow those letters. Its literal,
// percent-encoded, and numeric forms kept the password too. Otherwise
// "user:secret@my\u0133proxy:7890" and
// "user:secret@ex\u0133ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A Latin capital letter LJ is folded separately.
function smallLigatureIjAscii(cp) {
  if (cp === 0x0133) return 'ij';
  return '';
}
function isSmallLigatureIj(cp) {
  return smallLigatureIjAscii(cp) !== '';
}
function readEncodedSmallLigatureIj(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 2; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xC2 || lead > 0xDF || bytes[1] < 0x80 || bytes[1] > 0xBF) return null;
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSmallLigatureIj(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSmallLigatureIj(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedSmallLigatureIj(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSmallLigatureIj(text) {
  let out = '';
  for (const char of text) {
    out += smallLigatureIjAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Latin capital letter LJ U+01C7 folds to "LJ" under NFKC. A single-label
// host and a dotted host already allow those letters. Its literal,
// percent-encoded, and numeric forms kept the password too. Otherwise
// "user:secret@my\u01C7proxy:7890" and
// "user:secret@ex\u01C7ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A Latin capital letter L with small letter J is folded separately.
function capitalLetterLjAscii(cp) {
  if (cp === 0x01C7) return 'LJ';
  return '';
}
function isCapitalLetterLj(cp) {
  return capitalLetterLjAscii(cp) !== '';
}
function readEncodedCapitalLetterLj(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 2; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xC2 || lead > 0xDF || bytes[1] < 0x80 || bytes[1] > 0xBF) return null;
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isCapitalLetterLj(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedCapitalLetterLj(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedCapitalLetterLj(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldCapitalLetterLj(text) {
  let out = '';
  for (const char of text) {
    out += capitalLetterLjAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Latin capital letter L with small letter J U+01C8 folds to "Lj" under NFKC.
// A single-label host and a dotted host already allow those letters. Its literal,
// percent-encoded, and numeric forms kept the password too. Otherwise
// "user:secret@my\u01C8proxy:7890" and
// "user:secret@ex\u01C8ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A Latin small letter LJ is folded separately.
function capitalLWithSmallJAscii(cp) {
  if (cp === 0x01C8) return 'Lj';
  return '';
}
function isCapitalLWithSmallJ(cp) {
  return capitalLWithSmallJAscii(cp) !== '';
}
function readEncodedCapitalLWithSmallJ(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 2; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xC2 || lead > 0xDF || bytes[1] < 0x80 || bytes[1] > 0xBF) return null;
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isCapitalLWithSmallJ(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedCapitalLWithSmallJ(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedCapitalLWithSmallJ(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldCapitalLWithSmallJ(text) {
  let out = '';
  for (const char of text) {
    out += capitalLWithSmallJAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Latin small letter LJ U+01C9 folds to "lj" under NFKC. A single-label
// host and a dotted host already allow those letters. Its literal,
// percent-encoded, and numeric forms kept the password too. Otherwise
// "user:secret@my\u01C9proxy:7890" and
// "user:secret@ex\u01C9ample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A Latin capital letter NJ is folded separately.
function smallLetterLjAscii(cp) {
  if (cp === 0x01C9) return 'lj';
  return '';
}
function isSmallLetterLj(cp) {
  return smallLetterLjAscii(cp) !== '';
}
function readEncodedSmallLetterLj(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 2; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xC2 || lead > 0xDF || bytes[1] < 0x80 || bytes[1] > 0xBF) return null;
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSmallLetterLj(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSmallLetterLj(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedSmallLetterLj(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSmallLetterLj(text) {
  let out = '';
  for (const char of text) {
    out += smallLetterLjAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Latin capital letter NJ U+01CA folds to "NJ" under NFKC. A single-label
// host and a dotted host already allow those letters. Its literal,
// percent-encoded, and numeric forms kept the password too. Otherwise
// "user:secret@my\u01CAproxy:7890" and
// "user:secret@ex\u01CAample.com:8080" keep the password. The redacted
// host uses those ASCII letters. A Latin capital letter N with small letter J, such as U+01CB, stays as written.
function capitalLetterNjAscii(cp) {
  if (cp === 0x01CA) return 'NJ';
  return '';
}
function isCapitalLetterNj(cp) {
  return capitalLetterNjAscii(cp) !== '';
}
function readEncodedCapitalLetterNj(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 2; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xC2 || lead > 0xDF || bytes[1] < 0x80 || bytes[1] > 0xBF) return null;
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isCapitalLetterNj(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedCapitalLetterNj(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const letter = readEncodedCapitalLetterNj(text, index);
    if (letter) {
      out += letter.char;
      index = letter.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldCapitalLetterNj(text) {
  let out = '';
  for (const char of text) {
    out += capitalLetterNjAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Mathematical digits U+1D7CE..U+1D7FF fold to 0-9 under NFKC. A single-label
// host, a dotted host, a numeric host, and a port already allow those digits.
// Their literal, percent-encoded, and numeric forms kept the password too.
// Otherwise "user:secret@my\u{1D7CE}proxy:7890" and
// "user:secret@ex\u{1D7CF}ample.com:8080" keep the password. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
function mathDigitAscii(cp) {
  if (cp >= 0x1D7CE && cp <= 0x1D7FF) return String.fromCharCode(0x30 + ((cp - 0x1D7CE) % 10));
  return '';
}
function isMathDigit(cp) {
  return mathDigitAscii(cp) !== '';
}
function readEncodedMathDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isMathDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedMathDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedMathDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldMathDigits(text) {
  let out = '';
  for (const char of text) {
    out += mathDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Segmented digits U+1FBF0..U+1FBF9 fold to 0-9 under NFKC. A single-label
// host, a dotted host, a numeric host, and a port already allow those digits.
// Their literal, percent-encoded, and numeric forms kept the password too.
// Otherwise "user:secret@my\u{1FBF0}proxy:7890" and
// "user:secret@ex\u{1FBF1}ample.com:8080" keep the password. A dingbat circled sans-serif digit zero, such as U+1F10B, stays as written.
function segmentedDigitAscii(cp) {
  if (cp >= 0x1FBF0 && cp <= 0x1FBF9) return String.fromCharCode(0x30 + (cp - 0x1FBF0));
  return '';
}
function isSegmentedDigit(cp) {
  return segmentedDigitAscii(cp) !== '';
}
function readEncodedSegmentedDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSegmentedDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSegmentedDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedSegmentedDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSegmentedDigits(text) {
  let out = '';
  for (const char of text) {
    out += segmentedDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Arabic-Indic digits U+0660..U+0669 and extended Arabic-Indic digits
// U+06F0..U+06F9 do not fold to 0-9 under NFKC. A single-label host, a
// dotted host, a numeric host, and a port already allow ASCII digits, so
// these marks kept the password. Their literal, percent-encoded, and numeric
// forms did too. Otherwise "user:secret@my\u0661proxy:7890" and
// "user:secret@\u0661\u0662\u0667.\u0660.\u0660.\u0661:7890" keep the password.
// The redacted host uses an ASCII digit. U+066A and other non-digit Arabic
// marks stay as written.
function arabicDigitAscii(cp) {
  if (cp >= 0x0660 && cp <= 0x0669) return String.fromCharCode(0x30 + (cp - 0x0660));
  if (cp >= 0x06F0 && cp <= 0x06F9) return String.fromCharCode(0x30 + (cp - 0x06F0));
  return '';
}
function isArabicDigit(cp) {
  return arabicDigitAscii(cp) !== '';
}
function readEncodedArabicDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 2; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xC2 || lead > 0xDF || bytes[1] < 0x80 || bytes[1] > 0xBF) return null;
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isArabicDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedArabicDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedArabicDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldArabicDigits(text) {
  let out = '';
  for (const char of text) {
    out += arabicDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// NKo digits U+07C0..U+07C9 do not fold to 0-9 under NFKC. A single-label
// host, a dotted host, a numeric host, and a port already allow ASCII digits,
// so these marks kept the password. Their literal, percent-encoded, and
// numeric forms did too. Otherwise "user:secret@my\u07C1proxy:7890" and
// "user:secret@\u07C1\u07C2\u07C7.\u07C0.\u07C0.\u07C1:7890" keep the
// password. The redacted host uses an ASCII digit. U+07BF, U+07CA, and other
// non-digit marks stay as written.
function nkoDigitAscii(cp) {
  if (cp >= 0x07C0 && cp <= 0x07C9) return String.fromCharCode(0x30 + (cp - 0x07C0));
  return '';
}
function isNkoDigit(cp) {
  return nkoDigitAscii(cp) !== '';
}
function readEncodedNkoDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 2; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xC2 || lead > 0xDF || bytes[1] < 0x80 || bytes[1] > 0xBF) return null;
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isNkoDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedNkoDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedNkoDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldNkoDigits(text) {
  let out = '';
  for (const char of text) {
    out += nkoDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Devanagari digits U+0966..U+096F do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u0967proxy:7890" and
// "user:secret@\u0967\u0968\u096D.\u0966.\u0966.\u0967:7890" keep the
// password. The redacted host uses an ASCII digit. U+0970 and other
// non-digit Devanagari marks stay as written.
function devanagariDigitAscii(cp) {
  if (cp >= 0x0966 && cp <= 0x096F) return String.fromCharCode(0x30 + (cp - 0x0966));
  return '';
}
function isDevanagariDigit(cp) {
  return devanagariDigitAscii(cp) !== '';
}
function readEncodedDevanagariDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isDevanagariDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedDevanagariDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedDevanagariDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldDevanagariDigits(text) {
  let out = '';
  for (const char of text) {
    out += devanagariDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Bengali digits U+09E6..U+09EF do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u09E7proxy:7890" and
// "user:secret@\u09E7\u09E8\u09ED.\u09E6.\u09E6.\u09E7:7890" keep the
// password. The redacted host uses an ASCII digit. U+09F0 and other
// non-digit Bengali marks stay as written.
function bengaliDigitAscii(cp) {
  if (cp >= 0x09E6 && cp <= 0x09EF) return String.fromCharCode(0x30 + (cp - 0x09E6));
  return '';
}
function isBengaliDigit(cp) {
  return bengaliDigitAscii(cp) !== '';
}
function readEncodedBengaliDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isBengaliDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedBengaliDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedBengaliDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldBengaliDigits(text) {
  let out = '';
  for (const char of text) {
    out += bengaliDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Gurmukhi digits U+0A66..U+0A6F do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u0A67proxy:7890" and
// "user:secret@\u0A67\u0A68\u0A6D.\u0A66.\u0A66.\u0A67:7890" keep the
// password. The redacted host uses an ASCII digit. U+0A5C, U+0A70, and other
// non-digit Gurmukhi marks stay as written.
function gurmukhiDigitAscii(cp) {
  if (cp >= 0x0A66 && cp <= 0x0A6F) return String.fromCharCode(0x30 + (cp - 0x0A66));
  return '';
}
function isGurmukhiDigit(cp) {
  return gurmukhiDigitAscii(cp) !== '';
}
function readEncodedGurmukhiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isGurmukhiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedGurmukhiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedGurmukhiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldGurmukhiDigits(text) {
  let out = '';
  for (const char of text) {
    out += gurmukhiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Gujarati digits U+0AE6..U+0AEF do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u0AE7proxy:7890" and
// "user:secret@\u0AE7\u0AE8\u0AED.\u0AE6.\u0AE6.\u0AE7:7890" keep the
// password. The redacted host uses an ASCII digit. U+0AE1, U+0AF0, and other
// non-digit Gujarati marks stay as written.
function gujaratiDigitAscii(cp) {
  if (cp >= 0x0AE6 && cp <= 0x0AEF) return String.fromCharCode(0x30 + (cp - 0x0AE6));
  return '';
}
function isGujaratiDigit(cp) {
  return gujaratiDigitAscii(cp) !== '';
}
function readEncodedGujaratiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isGujaratiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedGujaratiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedGujaratiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldGujaratiDigits(text) {
  let out = '';
  for (const char of text) {
    out += gujaratiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Oriya digits U+0B66..U+0B6F do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u0B67proxy:7890" and
// "user:secret@\u0B67\u0B68\u0B6D.\u0B66.\u0B66.\u0B67:7890" keep the
// password. The redacted host uses an ASCII digit. U+0B61, U+0B70, and other
// non-digit Oriya marks stay as written.
function oriyaDigitAscii(cp) {
  if (cp >= 0x0B66 && cp <= 0x0B6F) return String.fromCharCode(0x30 + (cp - 0x0B66));
  return '';
}
function isOriyaDigit(cp) {
  return oriyaDigitAscii(cp) !== '';
}
function readEncodedOriyaDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isOriyaDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedOriyaDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedOriyaDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldOriyaDigits(text) {
  let out = '';
  for (const char of text) {
    out += oriyaDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}
// Tamil digits U+0BE6..U+0BEF do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u0BE7proxy:7890" and
// "user:secret@\u0BE7\u0BE8\u0BED.\u0BE6.\u0BE6.\u0BE7:7890" keep the
// password. The redacted host uses an ASCII digit. U+0BD7, U+0BF0, and other
// non-digit Tamil marks stay as written.
function tamilDigitAscii(cp) {
  if (cp >= 0x0BE6 && cp <= 0x0BEF) return String.fromCharCode(0x30 + (cp - 0x0BE6));
  return '';
}
function isTamilDigit(cp) {
  return tamilDigitAscii(cp) !== '';
}
function readEncodedTamilDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isTamilDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedTamilDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedTamilDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldTamilDigits(text) {
  let out = '';
  for (const char of text) {
    out += tamilDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Telugu digits U+0C66..U+0C6F do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u0C67proxy:7890" and
// "user:secret@\u0C67\u0C68\u0C6D.\u0C66.\u0C66.\u0C67:7890" keep the
// password. The redacted host uses an ASCII digit. U+0C65, U+0C70, and other
// non-digit Telugu marks stay as written.
function teluguDigitAscii(cp) {
  if (cp >= 0x0C66 && cp <= 0x0C6F) return String.fromCharCode(0x30 + (cp - 0x0C66));
  return '';
}
function isTeluguDigit(cp) {
  return teluguDigitAscii(cp) !== '';
}
function readEncodedTeluguDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isTeluguDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedTeluguDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedTeluguDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldTeluguDigits(text) {
  let out = '';
  for (const char of text) {
    out += teluguDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Kannada digits U+0CE6..U+0CEF do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u0CE7proxy:7890" and
// "user:secret@\u0CE7\u0CE8\u0CED.\u0CE6.\u0CE6.\u0CE7:7890" keep the
// password. The redacted host uses an ASCII digit. U+0CE5, U+0CF0, and other
// non-digit Kannada marks stay as written.
function kannadaDigitAscii(cp) {
  if (cp >= 0x0CE6 && cp <= 0x0CEF) return String.fromCharCode(0x30 + (cp - 0x0CE6));
  return '';
}
function isKannadaDigit(cp) {
  return kannadaDigitAscii(cp) !== '';
}
function readEncodedKannadaDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isKannadaDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedKannadaDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedKannadaDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldKannadaDigits(text) {
  let out = '';
  for (const char of text) {
    out += kannadaDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Malayalam digits U+0D66..U+0D6F do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u0D67proxy:7890" and
// "user:secret@\u0D67\u0D68\u0D6D.\u0D66.\u0D66.\u0D67:7890" keep the
// password. The redacted host uses an ASCII digit. U+0D65, U+0D70, and other
// non-digit Malayalam marks stay as written.
function malayalamDigitAscii(cp) {
  if (cp >= 0x0D66 && cp <= 0x0D6F) return String.fromCharCode(0x30 + (cp - 0x0D66));
  return '';
}
function isMalayalamDigit(cp) {
  return malayalamDigitAscii(cp) !== '';
}
function readEncodedMalayalamDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isMalayalamDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedMalayalamDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedMalayalamDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldMalayalamDigits(text) {
  let out = '';
  for (const char of text) {
    out += malayalamDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Sinhala digits U+0DE6..U+0DEF do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u0DE7proxy:7890" and
// "user:secret@\u0DE7\u0DE8\u0DED.\u0DE6.\u0DE6.\u0DE7:7890" keep the
// password. The redacted host uses an ASCII digit. U+0DE5, U+0DF0, and other
// non-digit Sinhala marks stay as written.
function sinhalaDigitAscii(cp) {
  if (cp >= 0x0DE6 && cp <= 0x0DEF) return String.fromCharCode(0x30 + (cp - 0x0DE6));
  return '';
}
function isSinhalaDigit(cp) {
  return sinhalaDigitAscii(cp) !== '';
}
function readEncodedSinhalaDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSinhalaDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSinhalaDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedSinhalaDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSinhalaDigits(text) {
  let out = '';
  for (const char of text) {
    out += sinhalaDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Thai digits U+0E50..U+0E59 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u0E51proxy:7890" and
// "user:secret@\u0E51\u0E52\u0E57.\u0E50.\u0E50.\u0E51:7890" keep the
// password. The redacted host uses an ASCII digit. U+0E4F, U+0E5A, and other
// non-digit Thai marks stay as written.
function thaiDigitAscii(cp) {
  if (cp >= 0x0E50 && cp <= 0x0E59) return String.fromCharCode(0x30 + (cp - 0x0E50));
  return '';
}
function isThaiDigit(cp) {
  return thaiDigitAscii(cp) !== '';
}
function readEncodedThaiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isThaiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedThaiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedThaiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldThaiDigits(text) {
  let out = '';
  for (const char of text) {
    out += thaiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Lao digits U+0ED0..U+0ED9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u0ED1proxy:7890" and
// "user:secret@\u0ED1\u0ED2\u0ED7.\u0ED0.\u0ED0.\u0ED1:7890" keep the
// password. The redacted host uses an ASCII digit. U+0ECF, U+0EDA, and other
// non-digit Lao marks stay as written.
function laoDigitAscii(cp) {
  if (cp >= 0x0ED0 && cp <= 0x0ED9) return String.fromCharCode(0x30 + (cp - 0x0ED0));
  return '';
}
function isLaoDigit(cp) {
  return laoDigitAscii(cp) !== '';
}
function readEncodedLaoDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isLaoDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedLaoDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedLaoDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldLaoDigits(text) {
  let out = '';
  for (const char of text) {
    out += laoDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Tibetan digits U+0F20..U+0F29 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u0F21proxy:7890" and
// "user:secret@\u0F21\u0F22\u0F27.\u0F20.\u0F20.\u0F21:7890" keep the
// password. The redacted host uses an ASCII digit. U+0F1F, U+0F2A, and other
// non-digit Tibetan marks stay as written.
function tibetanDigitAscii(cp) {
  if (cp >= 0x0F20 && cp <= 0x0F29) return String.fromCharCode(0x30 + (cp - 0x0F20));
  return '';
}
function isTibetanDigit(cp) {
  return tibetanDigitAscii(cp) !== '';
}
function readEncodedTibetanDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isTibetanDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedTibetanDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedTibetanDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldTibetanDigits(text) {
  let out = '';
  for (const char of text) {
    out += tibetanDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Myanmar digits U+1040..U+1049 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u1041proxy:7890" and
// "user:secret@\u1041\u1042\u1047.\u1040.\u1040.\u1041:7890" keep the
// password. The redacted host uses an ASCII digit. U+103F, U+104A, and other
// non-digit Myanmar marks stay as written.
function myanmarDigitAscii(cp) {
  if (cp >= 0x1040 && cp <= 0x1049) return String.fromCharCode(0x30 + (cp - 0x1040));
  return '';
}
function isMyanmarDigit(cp) {
  return myanmarDigitAscii(cp) !== '';
}
function readEncodedMyanmarDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isMyanmarDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedMyanmarDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedMyanmarDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldMyanmarDigits(text) {
  let out = '';
  for (const char of text) {
    out += myanmarDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Myanmar Shan digits U+1090..U+1099 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u1091proxy:7890" and
// "user:secret@\u1091\u1092\u1097.\u1090.\u1090.\u1091:7890" keep the
// password. The redacted host uses an ASCII digit. U+108F, U+109A, and other
// non-digit Myanmar marks stay as written.
function myanmarShanDigitAscii(cp) {
  if (cp >= 0x1090 && cp <= 0x1099) return String.fromCharCode(0x30 + (cp - 0x1090));
  return '';
}
function isMyanmarShanDigit(cp) {
  return myanmarShanDigitAscii(cp) !== '';
}
function readEncodedMyanmarShanDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isMyanmarShanDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedMyanmarShanDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedMyanmarShanDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldMyanmarShanDigits(text) {
  let out = '';
  for (const char of text) {
    out += myanmarShanDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Khmer digits U+17E0..U+17E9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u17E1proxy:7890" and
// "user:secret@\u17E1\u17E2\u17E7.\u17E0.\u17E0.\u17E1:7890" keep the
// password. The redacted host uses an ASCII digit. U+17DF, U+17EA, and other
// non-digit Khmer marks stay as written.
function khmerDigitAscii(cp) {
  if (cp >= 0x17E0 && cp <= 0x17E9) return String.fromCharCode(0x30 + (cp - 0x17E0));
  return '';
}
function isKhmerDigit(cp) {
  return khmerDigitAscii(cp) !== '';
}
function readEncodedKhmerDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isKhmerDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedKhmerDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedKhmerDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldKhmerDigits(text) {
  let out = '';
  for (const char of text) {
    out += khmerDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Mongolian digits U+1810..U+1819 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u1811proxy:7890" and
// "user:secret@\u1811\u1812\u1817.\u1810.\u1810.\u1811:7890" keep the
// password. The redacted host uses an ASCII digit. U+180F, U+181A, and other
// non-digit Mongolian marks stay as written.
function mongolianDigitAscii(cp) {
  if (cp >= 0x1810 && cp <= 0x1819) return String.fromCharCode(0x30 + (cp - 0x1810));
  return '';
}
function isMongolianDigit(cp) {
  return mongolianDigitAscii(cp) !== '';
}
function readEncodedMongolianDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isMongolianDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedMongolianDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedMongolianDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldMongolianDigits(text) {
  let out = '';
  for (const char of text) {
    out += mongolianDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Limbu digits U+1946..U+194F do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u1947proxy:7890" and
// "user:secret@\u1947\u1948\u194D.\u1946.\u1946.\u1947:7890" keep the
// password. The redacted host uses an ASCII digit. U+1945, U+1950, and other
// non-digit Limbu marks stay as written.
function limbuDigitAscii(cp) {
  if (cp >= 0x1946 && cp <= 0x194F) return String.fromCharCode(0x30 + (cp - 0x1946));
  return '';
}
function isLimbuDigit(cp) {
  return limbuDigitAscii(cp) !== '';
}
function readEncodedLimbuDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isLimbuDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedLimbuDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedLimbuDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldLimbuDigits(text) {
  let out = '';
  for (const char of text) {
    out += limbuDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// New Tai Lue digits U+19D0..U+19D9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u19D1proxy:7890" and
// "user:secret@\u19D1\u19D2\u19D7.\u19D0.\u19D0.\u19D1:7890" keep the
// password. The redacted host uses an ASCII digit. U+19CF, U+19DA, and other
// non-digit New Tai Lue marks stay as written.
function newTaiLueDigitAscii(cp) {
  if (cp >= 0x19D0 && cp <= 0x19D9) return String.fromCharCode(0x30 + (cp - 0x19D0));
  return '';
}
function isNewTaiLueDigit(cp) {
  return newTaiLueDigitAscii(cp) !== '';
}
function readEncodedNewTaiLueDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isNewTaiLueDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedNewTaiLueDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedNewTaiLueDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldNewTaiLueDigits(text) {
  let out = '';
  for (const char of text) {
    out += newTaiLueDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Tai Tham Hora digits U+1A80..U+1A89 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u1A81proxy:7890" and
// "user:secret@\u1A81\u1A82\u1A87.\u1A80.\u1A80.\u1A81:7890" keep the
// password. The redacted host uses an ASCII digit. U+1A7F, U+1A8A, and other
// non-digit Tai Tham marks stay as written.
function taiThamHoraDigitAscii(cp) {
  if (cp >= 0x1A80 && cp <= 0x1A89) return String.fromCharCode(0x30 + (cp - 0x1A80));
  return '';
}
function isTaiThamHoraDigit(cp) {
  return taiThamHoraDigitAscii(cp) !== '';
}
function readEncodedTaiThamHoraDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isTaiThamHoraDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedTaiThamHoraDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedTaiThamHoraDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldTaiThamHoraDigits(text) {
  let out = '';
  for (const char of text) {
    out += taiThamHoraDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Tai Tham Tham digits U+1A90..U+1A99 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u1A91proxy:7890" and
// "user:secret@\u1A91\u1A92\u1A97.\u1A90.\u1A90.\u1A91:7890" keep the
// password. The redacted host uses an ASCII digit. U+1A8F, U+1A9A, and other
// non-digit Tai Tham marks stay as written.
function taiThamThamDigitAscii(cp) {
  if (cp >= 0x1A90 && cp <= 0x1A99) return String.fromCharCode(0x30 + (cp - 0x1A90));
  return '';
}
function isTaiThamThamDigit(cp) {
  return taiThamThamDigitAscii(cp) !== '';
}
function readEncodedTaiThamThamDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isTaiThamThamDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedTaiThamThamDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedTaiThamThamDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldTaiThamThamDigits(text) {
  let out = '';
  for (const char of text) {
    out += taiThamThamDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Balinese digits U+1B50..U+1B59 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u1B51proxy:7890" and
// "user:secret@\u1B51\u1B52\u1B57.\u1B50.\u1B50.\u1B51:7890" keep the
// password. The redacted host uses an ASCII digit. U+1B4F, U+1B5A, and other
// non-digit Balinese marks stay as written.
function balineseDigitAscii(cp) {
  if (cp >= 0x1B50 && cp <= 0x1B59) return String.fromCharCode(0x30 + (cp - 0x1B50));
  return '';
}
function isBalineseDigit(cp) {
  return balineseDigitAscii(cp) !== '';
}
function readEncodedBalineseDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isBalineseDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedBalineseDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedBalineseDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldBalineseDigits(text) {
  let out = '';
  for (const char of text) {
    out += balineseDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Sundanese digits U+1BB0..U+1BB9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u1BB1proxy:7890" and
// "user:secret@\u1BB1\u1BB2\u1BB7.\u1BB0.\u1BB0.\u1BB1:7890" keep the
// password. The redacted host uses an ASCII digit. U+1BAF, U+1BBA, and other
// non-digit Sundanese marks stay as written.
function sundaneseDigitAscii(cp) {
  if (cp >= 0x1BB0 && cp <= 0x1BB9) return String.fromCharCode(0x30 + (cp - 0x1BB0));
  return '';
}
function isSundaneseDigit(cp) {
  return sundaneseDigitAscii(cp) !== '';
}
function readEncodedSundaneseDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSundaneseDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSundaneseDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedSundaneseDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSundaneseDigits(text) {
  let out = '';
  for (const char of text) {
    out += sundaneseDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Lepcha digits U+1C40..U+1C49 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u1C41proxy:7890" and
// "user:secret@\u1C41\u1C42\u1C47.\u1C40.\u1C40.\u1C41:7890" keep the
// password. The redacted host uses an ASCII digit. U+1C3F, U+1C4A, and other
// non-digit Lepcha marks stay as written.
function lepchaDigitAscii(cp) {
  if (cp >= 0x1C40 && cp <= 0x1C49) return String.fromCharCode(0x30 + (cp - 0x1C40));
  return '';
}
function isLepchaDigit(cp) {
  return lepchaDigitAscii(cp) !== '';
}
function readEncodedLepchaDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isLepchaDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedLepchaDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedLepchaDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldLepchaDigits(text) {
  let out = '';
  for (const char of text) {
    out += lepchaDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Ol Chiki digits U+1C50..U+1C59 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u1C51proxy:7890" and
// "user:secret@\u1C51\u1C52\u1C57.\u1C50.\u1C50.\u1C51:7890" keep the
// password. The redacted host uses an ASCII digit. U+1C4F, U+1C5A, and other
// non-digit Ol Chiki marks stay as written.
function olChikiDigitAscii(cp) {
  if (cp >= 0x1C50 && cp <= 0x1C59) return String.fromCharCode(0x30 + (cp - 0x1C50));
  return '';
}
function isOlChikiDigit(cp) {
  return olChikiDigitAscii(cp) !== '';
}
function readEncodedOlChikiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isOlChikiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedOlChikiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedOlChikiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldOlChikiDigits(text) {
  let out = '';
  for (const char of text) {
    out += olChikiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Vai digits U+A620..U+A629 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\uA621proxy:7890" and
// "user:secret@\uA621\uA622\uA627.\uA620.\uA620.\uA621:7890" keep the
// password. The redacted host uses an ASCII digit. U+A61F, U+A62A, and other
// non-digit Vai marks stay as written.
function vaiDigitAscii(cp) {
  if (cp >= 0xA620 && cp <= 0xA629) return String.fromCharCode(0x30 + (cp - 0xA620));
  return '';
}
function isVaiDigit(cp) {
  return vaiDigitAscii(cp) !== '';
}
function readEncodedVaiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isVaiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedVaiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedVaiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldVaiDigits(text) {
  let out = '';
  for (const char of text) {
    out += vaiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Saurashtra digits U+A8D0..U+A8D9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\uA8D1proxy:7890" and
// "user:secret@\uA8D1\uA8D2\uA8D7.\uA8D0.\uA8D0.\uA8D1:7890" keep the
// password. The redacted host uses an ASCII digit. U+A8CF, U+A8DA, and other
// non-digit Saurashtra marks stay as written.
function saurashtraDigitAscii(cp) {
  if (cp >= 0xA8D0 && cp <= 0xA8D9) return String.fromCharCode(0x30 + (cp - 0xA8D0));
  return '';
}
function isSaurashtraDigit(cp) {
  return saurashtraDigitAscii(cp) !== '';
}
function readEncodedSaurashtraDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSaurashtraDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSaurashtraDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedSaurashtraDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSaurashtraDigits(text) {
  let out = '';
  for (const char of text) {
    out += saurashtraDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Kayah Li digits U+A900..U+A909 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\uA901proxy:7890" and
// "user:secret@\uA901\uA902\uA907.\uA900.\uA900.\uA901:7890" keep the
// password. The redacted host uses an ASCII digit. U+A8FF, U+A90A, and other
// non-digit Kayah Li marks stay as written.
function kayahLiDigitAscii(cp) {
  if (cp >= 0xA900 && cp <= 0xA909) return String.fromCharCode(0x30 + (cp - 0xA900));
  return '';
}
function isKayahLiDigit(cp) {
  return kayahLiDigitAscii(cp) !== '';
}
function readEncodedKayahLiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isKayahLiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedKayahLiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedKayahLiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldKayahLiDigits(text) {
  let out = '';
  for (const char of text) {
    out += kayahLiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Javanese digits U+A9D0..U+A9D9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\uA9D1proxy:7890" and
// "user:secret@\uA9D1\uA9D2\uA9D7.\uA9D0.\uA9D0.\uA9D1:7890" keep the
// password. The redacted host uses an ASCII digit. U+A9CF, U+A9DA, and other
// non-digit Javanese marks stay as written.
function javaneseDigitAscii(cp) {
  if (cp >= 0xA9D0 && cp <= 0xA9D9) return String.fromCharCode(0x30 + (cp - 0xA9D0));
  return '';
}
function isJavaneseDigit(cp) {
  return javaneseDigitAscii(cp) !== '';
}
function readEncodedJavaneseDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isJavaneseDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedJavaneseDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedJavaneseDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldJavaneseDigits(text) {
  let out = '';
  for (const char of text) {
    out += javaneseDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Myanmar Tai Laing digits U+A9F0..U+A9F9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\uA9F1proxy:7890" and
// "user:secret@\uA9F1\uA9F2\uA9F7.\uA9F0.\uA9F0.\uA9F1:7890" keep the
// password. The redacted host uses an ASCII digit. U+A9EF, U+A9FA, and other
// non-digit Myanmar Tai Laing marks stay as written.
function myanmarTaiLaingDigitAscii(cp) {
  if (cp >= 0xA9F0 && cp <= 0xA9F9) return String.fromCharCode(0x30 + (cp - 0xA9F0));
  return '';
}
function isMyanmarTaiLaingDigit(cp) {
  return myanmarTaiLaingDigitAscii(cp) !== '';
}
function readEncodedMyanmarTaiLaingDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isMyanmarTaiLaingDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedMyanmarTaiLaingDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedMyanmarTaiLaingDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldMyanmarTaiLaingDigits(text) {
  let out = '';
  for (const char of text) {
    out += myanmarTaiLaingDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Cham digits U+AA50..U+AA59 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\uAA51proxy:7890" and
// "user:secret@\uAA51\uAA52\uAA57.\uAA50.\uAA50.\uAA51:7890" keep the
// password. The redacted host uses an ASCII digit. U+AA4F, U+AA5A, and other
// non-digit Cham marks stay as written.
function chamDigitAscii(cp) {
  if (cp >= 0xAA50 && cp <= 0xAA59) return String.fromCharCode(0x30 + (cp - 0xAA50));
  return '';
}
function isChamDigit(cp) {
  return chamDigitAscii(cp) !== '';
}
function readEncodedChamDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isChamDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedChamDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedChamDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldChamDigits(text) {
  let out = '';
  for (const char of text) {
    out += chamDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Meetei Mayek digits U+ABF0..U+ABF9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\uABF1proxy:7890" and
// "user:secret@\uABF1\uABF2\uABF7.\uABF0.\uABF0.\uABF1:7890" keep the
// password. The redacted host uses an ASCII digit. U+ABEF, U+ABFA, and other
// non-digit Meetei Mayek marks stay as written.
function meeteiMayekDigitAscii(cp) {
  if (cp >= 0xABF0 && cp <= 0xABF9) return String.fromCharCode(0x30 + (cp - 0xABF0));
  return '';
}
function isMeeteiMayekDigit(cp) {
  return meeteiMayekDigitAscii(cp) !== '';
}
function readEncodedMeeteiMayekDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 3; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xE0 || lead > 0xEF) return null;
  for (let count = 1; count < 3; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isMeeteiMayekDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedMeeteiMayekDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedMeeteiMayekDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldMeeteiMayekDigits(text) {
  let out = '';
  for (const char of text) {
    out += meeteiMayekDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Osmanya digits U+104A0..U+104A9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{104A1}proxy:7890" and
// "user:secret@\u{104A1}\u{104A2}\u{104A7}.\u{104A0}.\u{104A0}.\u{104A1}:7890" keep the
// password. The redacted host uses an ASCII digit. U+1049F, U+104AA, and other
// non-digit Osmanya marks stay as written.
function osmanyaDigitAscii(cp) {
  if (cp >= 0x104A0 && cp <= 0x104A9) return String.fromCharCode(0x30 + (cp - 0x104A0));
  return '';
}
function isOsmanyaDigit(cp) {
  return osmanyaDigitAscii(cp) !== '';
}
function readEncodedOsmanyaDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isOsmanyaDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedOsmanyaDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedOsmanyaDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldOsmanyaDigits(text) {
  let out = '';
  for (const char of text) {
    out += osmanyaDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Hanifi Rohingya digits U+10D30..U+10D39 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{10D31}proxy:7890" and
// "user:secret@\u{10D31}\u{10D32}\u{10D37}.\u{10D30}.\u{10D30}.\u{10D31}:7890" keep the
// password. The redacted host uses an ASCII digit. U+10D2F, U+10D3A, and other
// non-digit Hanifi Rohingya marks stay as written.
function hanifiRohingyaDigitAscii(cp) {
  if (cp >= 0x10D30 && cp <= 0x10D39) return String.fromCharCode(0x30 + (cp - 0x10D30));
  return '';
}
function isHanifiRohingyaDigit(cp) {
  return hanifiRohingyaDigitAscii(cp) !== '';
}
function readEncodedHanifiRohingyaDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isHanifiRohingyaDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedHanifiRohingyaDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedHanifiRohingyaDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldHanifiRohingyaDigits(text) {
  let out = '';
  for (const char of text) {
    out += hanifiRohingyaDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Garay digits U+10D40..U+10D49 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{10D41}proxy:7890" and
// "user:secret@\u{10D41}\u{10D42}\u{10D47}.\u{10D40}.\u{10D40}.\u{10D41}:7890" keep the
// password. The redacted host uses an ASCII digit. U+10D3F, U+10D4A, and other
// non-digit Garay marks stay as written.
function garayDigitAscii(cp) {
  if (cp >= 0x10D40 && cp <= 0x10D49) return String.fromCharCode(0x30 + (cp - 0x10D40));
  return '';
}
function isGarayDigit(cp) {
  return garayDigitAscii(cp) !== '';
}
function readEncodedGarayDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isGarayDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedGarayDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedGarayDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}


// Brahmi digits U+11066..U+1106F do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{11067}proxy:7890" and
// "user:secret@\u{11067}\u{11068}\u{1106D}.\u{11066}.\u{11066}.\u{11067}:7890" keep the
// password. The redacted host uses an ASCII digit. U+11065, U+11070, and other
// non-digit Brahmi marks stay as written.
function brahmiDigitAscii(cp) {
  if (cp >= 0x11066 && cp <= 0x1106F) return String.fromCharCode(0x30 + (cp - 0x11066));
  return '';
}
function isBrahmiDigit(cp) {
  return brahmiDigitAscii(cp) !== '';
}
function readEncodedBrahmiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isBrahmiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedBrahmiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedBrahmiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldBrahmiDigits(text) {
  let out = '';
  for (const char of text) {
    out += brahmiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Sora Sompeng digits U+110F0..U+110F9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{110F1}proxy:7890" and
// "user:secret@\u{110F1}\u{110F2}\u{110F7}.\u{110F0}.\u{110F0}.\u{110F1}:7890" keep the
// password. The redacted host uses an ASCII digit. U+110EF, U+110FA, and other
// non-digit Sora Sompeng marks stay as written.
function soraSompengDigitAscii(cp) {
  if (cp >= 0x110F0 && cp <= 0x110F9) return String.fromCharCode(0x30 + (cp - 0x110F0));
  return '';
}
function isSoraSompengDigit(cp) {
  return soraSompengDigitAscii(cp) !== '';
}
function readEncodedSoraSompengDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSoraSompengDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSoraSompengDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedSoraSompengDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSoraSompengDigits(text) {
  let out = '';
  for (const char of text) {
    out += soraSompengDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Chakma digits U+11136..U+1113F do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{11137}proxy:7890" and
// "user:secret@\u{11137}\u{11138}\u{1113D}.\u{11136}.\u{11136}.\u{11137}:7890" keep the
// password. The redacted host uses an ASCII digit. U+11135, U+11140, and other
// non-digit Chakma marks stay as written.
function chakmaDigitAscii(cp) {
  if (cp >= 0x11136 && cp <= 0x1113F) return String.fromCharCode(0x30 + (cp - 0x11136));
  return '';
}
function isChakmaDigit(cp) {
  return chakmaDigitAscii(cp) !== '';
}
function readEncodedChakmaDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isChakmaDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedChakmaDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedChakmaDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldChakmaDigits(text) {
  let out = '';
  for (const char of text) {
    out += chakmaDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Sharada digits U+111D0..U+111D9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{111D1}proxy:7890" and
// "user:secret@\u{111D1}\u{111D2}\u{111D7}.\u{111D0}.\u{111D0}.\u{111D1}:7890" keep the
// password. The redacted host uses an ASCII digit. U+111CF, U+111DA, and other
// non-digit Sharada marks stay as written.
function sharadaDigitAscii(cp) {
  if (cp >= 0x111D0 && cp <= 0x111D9) return String.fromCharCode(0x30 + (cp - 0x111D0));
  return '';
}
function isSharadaDigit(cp) {
  return sharadaDigitAscii(cp) !== '';
}
function readEncodedSharadaDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSharadaDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSharadaDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedSharadaDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSharadaDigits(text) {
  let out = '';
  for (const char of text) {
    out += sharadaDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Khudawadi digits U+112F0..U+112F9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{112F1}proxy:7890" and
// "user:secret@\u{112F1}\u{112F2}\u{112F7}.\u{112F0}.\u{112F0}.\u{112F1}:7890" keep the
// password. The redacted host uses an ASCII digit. U+112EF, U+112FA, and other
// non-digit Khudawadi marks stay as written.
function khudawadiDigitAscii(cp) {
  if (cp >= 0x112F0 && cp <= 0x112F9) return String.fromCharCode(0x30 + (cp - 0x112F0));
  return '';
}
function isKhudawadiDigit(cp) {
  return khudawadiDigitAscii(cp) !== '';
}
function readEncodedKhudawadiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isKhudawadiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedKhudawadiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedKhudawadiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldKhudawadiDigits(text) {
  let out = '';
  for (const char of text) {
    out += khudawadiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Newa digits U+11450..U+11459 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{11451}proxy:7890" and
// "user:secret@\u{11451}\u{11452}\u{11457}.\u{11450}.\u{11450}.\u{11451}:7890" keep the
// password. The redacted host uses an ASCII digit. U+1144F, U+1145A, and other
// non-digit Newa marks stay as written.
function newaDigitAscii(cp) {
  if (cp >= 0x11450 && cp <= 0x11459) return String.fromCharCode(0x30 + (cp - 0x11450));
  return '';
}
function isNewaDigit(cp) {
  return newaDigitAscii(cp) !== '';
}
function readEncodedNewaDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isNewaDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedNewaDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedNewaDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldNewaDigits(text) {
  let out = '';
  for (const char of text) {
    out += newaDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Tirhuta digits U+114D0..U+114D9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{114D1}proxy:7890" and
// "user:secret@\u{114D1}\u{114D2}\u{114D7}.\u{114D0}.\u{114D0}.\u{114D1}:7890" keep the
// password. The redacted host uses an ASCII digit. U+114CF, U+114DA, and other
// non-digit Tirhuta marks stay as written.
function tirhutaDigitAscii(cp) {
  if (cp >= 0x114D0 && cp <= 0x114D9) return String.fromCharCode(0x30 + (cp - 0x114D0));
  return '';
}
function isTirhutaDigit(cp) {
  return tirhutaDigitAscii(cp) !== '';
}
function readEncodedTirhutaDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isTirhutaDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedTirhutaDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedTirhutaDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldTirhutaDigits(text) {
  let out = '';
  for (const char of text) {
    out += tirhutaDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Modi digits U+11650..U+11659 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{11651}proxy:7890" and
// "user:secret@\u{11651}\u{11652}\u{11657}.\u{11650}.\u{11650}.\u{11651}:7890" keep the
// password. The redacted host uses an ASCII digit. U+1164F, U+1165A, and other
// non-digit Modi marks stay as written.
function modiDigitAscii(cp) {
  if (cp >= 0x11650 && cp <= 0x11659) return String.fromCharCode(0x30 + (cp - 0x11650));
  return '';
}
function isModiDigit(cp) {
  return modiDigitAscii(cp) !== '';
}
function readEncodedModiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isModiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedModiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedModiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldModiDigits(text) {
  let out = '';
  for (const char of text) {
    out += modiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Takri digits U+116C0..U+116C9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{116C1}proxy:7890" and
// "user:secret@\u{116C1}\u{116C2}\u{116C7}.\u{116C0}.\u{116C0}.\u{116C1}:7890" keep the
// password. The redacted host uses an ASCII digit. U+116BF, U+116CA, and other
// non-digit Takri marks stay as written.
function takriDigitAscii(cp) {
  if (cp >= 0x116C0 && cp <= 0x116C9) return String.fromCharCode(0x30 + (cp - 0x116C0));
  return '';
}
function isTakriDigit(cp) {
  return takriDigitAscii(cp) !== '';
}
function readEncodedTakriDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isTakriDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedTakriDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedTakriDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldTakriDigits(text) {
  let out = '';
  for (const char of text) {
    out += takriDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Ahom digits U+11730..U+11739 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{11731}proxy:7890" and
// "user:secret@\u{11731}\u{11732}\u{11737}.\u{11730}.\u{11730}.\u{11731}:7890" keep the
// password. The redacted host uses an ASCII digit. U+1172F, U+1173A, and other
// non-digit Ahom marks stay as written.
function ahomDigitAscii(cp) {
  if (cp >= 0x11730 && cp <= 0x11739) return String.fromCharCode(0x30 + (cp - 0x11730));
  return '';
}
function isAhomDigit(cp) {
  return ahomDigitAscii(cp) !== '';
}
function readEncodedAhomDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isAhomDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedAhomDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedAhomDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldAhomDigits(text) {
  let out = '';
  for (const char of text) {
    out += ahomDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Warang Citi digits U+118E0..U+118E9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{118E1}proxy:7890" and
// "user:secret@\u{118E1}\u{118E2}\u{118E7}.\u{118E0}.\u{118E0}.\u{118E1}:7890" keep the
// password. The redacted host uses an ASCII digit. U+118DF, U+118EA, and other
// non-digit Warang Citi marks stay as written.
function warangCitiDigitAscii(cp) {
  if (cp >= 0x118E0 && cp <= 0x118E9) return String.fromCharCode(0x30 + (cp - 0x118E0));
  return '';
}
function isWarangCitiDigit(cp) {
  return warangCitiDigitAscii(cp) !== '';
}
function readEncodedWarangCitiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isWarangCitiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedWarangCitiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedWarangCitiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldWarangCitiDigits(text) {
  let out = '';
  for (const char of text) {
    out += warangCitiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Dives Akuru digits U+11950..U+11959 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{11951}proxy:7890" and
// "user:secret@\u{11951}\u{11952}\u{11957}.\u{11950}.\u{11950}.\u{11951}:7890" keep the
// password. The redacted host uses an ASCII digit. U+1194F, U+1195A, and other
// non-digit Dives Akuru marks stay as written.
function divesAkuruDigitAscii(cp) {
  if (cp >= 0x11950 && cp <= 0x11959) return String.fromCharCode(0x30 + (cp - 0x11950));
  return '';
}
function isDivesAkuruDigit(cp) {
  return divesAkuruDigitAscii(cp) !== '';
}
function readEncodedDivesAkuruDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isDivesAkuruDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedDivesAkuruDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedDivesAkuruDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldDivesAkuruDigits(text) {
  let out = '';
  for (const char of text) {
    out += divesAkuruDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Bhaiksuki digits U+11C50..U+11C59 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{11C51}proxy:7890" and
// "user:secret@\u{11C51}\u{11C52}\u{11C57}.\u{11C50}.\u{11C50}.\u{11C51}:7890" keep the
// password. The redacted host uses an ASCII digit. U+11C4F, U+11C5A, and other
// non-digit Bhaiksuki marks stay as written.
function bhaiksukiDigitAscii(cp) {
  if (cp >= 0x11C50 && cp <= 0x11C59) return String.fromCharCode(0x30 + (cp - 0x11C50));
  return '';
}
function isBhaiksukiDigit(cp) {
  return bhaiksukiDigitAscii(cp) !== '';
}
function readEncodedBhaiksukiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isBhaiksukiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedBhaiksukiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedBhaiksukiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldBhaiksukiDigits(text) {
  let out = '';
  for (const char of text) {
    out += bhaiksukiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Masaram Gondi digits U+11D50..U+11D59 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{11D51}proxy:7890" and
// "user:secret@\u{11D51}\u{11D52}\u{11D57}.\u{11D50}.\u{11D50}.\u{11D51}:7890" keep the
// password. The redacted host uses an ASCII digit. U+11D4F, U+11D5A, and other
// non-digit Masaram Gondi marks stay as written.
function masaramGondiDigitAscii(cp) {
  if (cp >= 0x11D50 && cp <= 0x11D59) return String.fromCharCode(0x30 + (cp - 0x11D50));
  return '';
}
function isMasaramGondiDigit(cp) {
  return masaramGondiDigitAscii(cp) !== '';
}
function readEncodedMasaramGondiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isMasaramGondiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedMasaramGondiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedMasaramGondiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldMasaramGondiDigits(text) {
  let out = '';
  for (const char of text) {
    out += masaramGondiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Gunjala Gondi digits U+11DA0..U+11DA9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{11DA1}proxy:7890" and
// "user:secret@\u{11DA1}\u{11DA2}\u{11DA7}.\u{11DA0}.\u{11DA0}.\u{11DA1}:7890" keep the
// password. The redacted host uses an ASCII digit. U+11D9F, U+11DAA, and other
// non-digit Gunjala Gondi marks stay as written.
function gunjalaGondiDigitAscii(cp) {
  if (cp >= 0x11DA0 && cp <= 0x11DA9) return String.fromCharCode(0x30 + (cp - 0x11DA0));
  return '';
}
function isGunjalaGondiDigit(cp) {
  return gunjalaGondiDigitAscii(cp) !== '';
}
function readEncodedGunjalaGondiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isGunjalaGondiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedGunjalaGondiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedGunjalaGondiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldGunjalaGondiDigits(text) {
  let out = '';
  for (const char of text) {
    out += gunjalaGondiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Tolong Siki digits U+11DE0..U+11DE9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{11DE1}proxy:7890" and
// "user:secret@\u{11DE1}\u{11DE2}\u{11DE7}.\u{11DE0}.\u{11DE0}.\u{11DE1}:7890" keep the
// password. The redacted host uses an ASCII digit. U+11DDF, U+11DEA, and other
// non-digit Tolong Siki marks stay as written.
function tolongSikiDigitAscii(cp) {
  if (cp >= 0x11DE0 && cp <= 0x11DE9) return String.fromCharCode(0x30 + (cp - 0x11DE0));
  return '';
}
function isTolongSikiDigit(cp) {
  return tolongSikiDigitAscii(cp) !== '';
}
function readEncodedTolongSikiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isTolongSikiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedTolongSikiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedTolongSikiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldTolongSikiDigits(text) {
  let out = '';
  for (const char of text) {
    out += tolongSikiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Kawi digits U+11F50..U+11F59 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{11F51}proxy:7890" and
// "user:secret@\u{11F51}\u{11F52}\u{11F57}.\u{11F50}.\u{11F50}.\u{11F51}:7890" keep the
// password. The redacted host uses an ASCII digit. U+11F4F, U+11F5A, and other
// non-digit Kawi marks stay as written.
function kawiDigitAscii(cp) {
  if (cp >= 0x11F50 && cp <= 0x11F59) return String.fromCharCode(0x30 + (cp - 0x11F50));
  return '';
}
function isKawiDigit(cp) {
  return kawiDigitAscii(cp) !== '';
}
function readEncodedKawiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isKawiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedKawiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedKawiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldKawiDigits(text) {
  let out = '';
  for (const char of text) {
    out += kawiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}


// Gurung Khema digits U+16130..U+16139 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{16131}proxy:7890" and
// "user:secret@\u{16131}\u{16132}\u{16137}.\u{16130}.\u{16130}.\u{16131}:7890" keep the
// password. The redacted host uses an ASCII digit. U+1612F, U+1613A, and other
// non-digit Gurung Khema marks stay as written.
function gurungKhemaDigitAscii(cp) {
  if (cp >= 0x16130 && cp <= 0x16139) return String.fromCharCode(0x30 + (cp - 0x16130));
  return '';
}
function isGurungKhemaDigit(cp) {
  return gurungKhemaDigitAscii(cp) !== '';
}
function readEncodedGurungKhemaDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isGurungKhemaDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedGurungKhemaDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedGurungKhemaDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldGurungKhemaDigits(text) {
  let out = '';
  for (const char of text) {
    out += gurungKhemaDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Mro digits U+16A60..U+16A69 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{16A61}proxy:7890" and
// "user:secret@\u{16A61}\u{16A62}\u{16A67}.\u{16A60}.\u{16A60}.\u{16A61}:7890" keep the
// password. The redacted host uses an ASCII digit. U+16A5F, U+16A6A, and other
// non-digit Mro marks stay as written.
function mroDigitAscii(cp) {
  if (cp >= 0x16A60 && cp <= 0x16A69) return String.fromCharCode(0x30 + (cp - 0x16A60));
  return '';
}
function isMroDigit(cp) {
  return mroDigitAscii(cp) !== '';
}
function readEncodedMroDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isMroDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedMroDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedMroDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldMroDigits(text) {
  let out = '';
  for (const char of text) {
    out += mroDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Tangsa digits U+16AC0..U+16AC9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{16AC1}proxy:7890" and
// "user:secret@\u{16AC1}\u{16AC2}\u{16AC7}.\u{16AC0}.\u{16AC0}.\u{16AC1}:7890" keep the
// password. The redacted host uses an ASCII digit. U+16ABF, U+16ACA, and other
// non-digit Tangsa marks stay as written.
function tangsaDigitAscii(cp) {
  if (cp >= 0x16AC0 && cp <= 0x16AC9) return String.fromCharCode(0x30 + (cp - 0x16AC0));
  return '';
}
function isTangsaDigit(cp) {
  return tangsaDigitAscii(cp) !== '';
}
function readEncodedTangsaDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isTangsaDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedTangsaDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedTangsaDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldTangsaDigits(text) {
  let out = '';
  for (const char of text) {
    out += tangsaDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Pahawh Hmong digits U+16B50..U+16B59 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{16B51}proxy:7890" and
// "user:secret@\u{16B51}\u{16B52}\u{16B57}.\u{16B50}.\u{16B50}.\u{16B51}:7890" keep the
// password. The redacted host uses an ASCII digit. U+16B4F, U+16B5A, and other
// non-digit Pahawh Hmong marks stay as written.
function pahawhHmongDigitAscii(cp) {
  if (cp >= 0x16B50 && cp <= 0x16B59) return String.fromCharCode(0x30 + (cp - 0x16B50));
  return '';
}
function isPahawhHmongDigit(cp) {
  return pahawhHmongDigitAscii(cp) !== '';
}
function readEncodedPahawhHmongDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isPahawhHmongDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedPahawhHmongDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedPahawhHmongDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldPahawhHmongDigits(text) {
  let out = '';
  for (const char of text) {
    out += pahawhHmongDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Kirat Rai digits U+16D70..U+16D79 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{16D71}proxy:7890" and
// "user:secret@\u{16D71}\u{16D72}\u{16D77}.\u{16D70}.\u{16D70}.\u{16D71}:7890" keep the
// password. The redacted host uses an ASCII digit. U+16D6F, U+16D7A, and other
// non-digit Kirat Rai marks stay as written.
function kiratRaiDigitAscii(cp) {
  if (cp >= 0x16D70 && cp <= 0x16D79) return String.fromCharCode(0x30 + (cp - 0x16D70));
  return '';
}
function isKiratRaiDigit(cp) {
  return kiratRaiDigitAscii(cp) !== '';
}
function readEncodedKiratRaiDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isKiratRaiDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedKiratRaiDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedKiratRaiDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldKiratRaiDigits(text) {
  let out = '';
  for (const char of text) {
    out += kiratRaiDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Nyiakeng Puachue Hmong digits U+1E140..U+1E149 do not fold to 0-9 under
// NFKC. A single-label host, a dotted host, a numeric host, and a port already
// allow ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{1E141}proxy:7890" and
// "user:secret@\u{1E141}\u{1E142}\u{1E147}.\u{1E140}.\u{1E140}.\u{1E141}:7890" keep the
// password. The redacted host uses an ASCII digit. U+1E13F, U+1E14A, and other
// non-digit Nyiakeng Puachue Hmong marks stay as written.
function nyiakengPuachueHmongDigitAscii(cp) {
  if (cp >= 0x1E140 && cp <= 0x1E149) return String.fromCharCode(0x30 + (cp - 0x1E140));
  return '';
}
function isNyiakengPuachueHmongDigit(cp) {
  return nyiakengPuachueHmongDigitAscii(cp) !== '';
}
function readEncodedNyiakengPuachueHmongDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isNyiakengPuachueHmongDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedNyiakengPuachueHmongDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedNyiakengPuachueHmongDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldNyiakengPuachueHmongDigits(text) {
  let out = '';
  for (const char of text) {
    out += nyiakengPuachueHmongDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Wancho digits U+1E2F0..U+1E2F9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{1E2F1}proxy:7890" and
// "user:secret@\u{1E2F1}\u{1E2F2}\u{1E2F7}.\u{1E2F0}.\u{1E2F0}.\u{1E2F1}:7890" keep the
// password. The redacted host uses an ASCII digit. U+1E2EF, U+1E2FA, and other
// non-digit Wancho marks stay as written.
function wanchoDigitAscii(cp) {
  if (cp >= 0x1E2F0 && cp <= 0x1E2F9) return String.fromCharCode(0x30 + (cp - 0x1E2F0));
  return '';
}
function isWanchoDigit(cp) {
  return wanchoDigitAscii(cp) !== '';
}
function readEncodedWanchoDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isWanchoDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedWanchoDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedWanchoDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldWanchoDigits(text) {
  let out = '';
  for (const char of text) {
    out += wanchoDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Nag Mundari digits U+1E4F0..U+1E4F9 do not fold to 0-9 under NFKC.
// A single-label host, a dotted host, a numeric host, and a port already
// allow ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{1E4F1}proxy:7890" and
// "user:secret@\u{1E4F1}\u{1E4F2}\u{1E4F7}.\u{1E4F0}.\u{1E4F0}.\u{1E4F1}:7890" keep the
// password. The redacted host uses an ASCII digit. U+1E4EF, U+1E4FA, and other
// non-digit Nag Mundari marks stay as written.
function nagMundariDigitAscii(cp) {
  if (cp >= 0x1E4F0 && cp <= 0x1E4F9) return String.fromCharCode(0x30 + (cp - 0x1E4F0));
  return '';
}
function isNagMundariDigit(cp) {
  return nagMundariDigitAscii(cp) !== '';
}
function readEncodedNagMundariDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isNagMundariDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedNagMundariDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedNagMundariDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldNagMundariDigits(text) {
  let out = '';
  for (const char of text) {
    out += nagMundariDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Ol Onal digits U+1E5F1..U+1E5FA do not fold to 0-9 under NFKC.
// U+1E5F1 is zero. A single-label host, a dotted host, a numeric host, and a
// port already allow ASCII digits, so these marks kept the password. Their
// literal, percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{1E5F2}proxy:7890" and
// "user:secret@\u{1E5F2}\u{1E5F3}\u{1E5F8}.\u{1E5F1}.\u{1E5F1}.\u{1E5F2}:7890" keep the
// password. The redacted host uses an ASCII digit. U+1E5F0, U+1E5FB, and other
// non-digit Ol Onal marks stay as written.
function olOnalDigitAscii(cp) {
  if (cp >= 0x1E5F1 && cp <= 0x1E5FA) return String.fromCharCode(0x30 + (cp - 0x1E5F1));
  return '';
}
function isOlOnalDigit(cp) {
  return olOnalDigitAscii(cp) !== '';
}
function readEncodedOlOnalDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isOlOnalDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedOlOnalDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedOlOnalDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldOlOnalDigits(text) {
  let out = '';
  for (const char of text) {
    out += olOnalDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Adlam digits U+1E950..U+1E959 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{1E951}proxy:7890" and
// "user:secret@\u{1E951}\u{1E952}\u{1E957}.\u{1E950}.\u{1E950}.\u{1E951}:7890" keep the
// password. The redacted host uses an ASCII digit. U+1E94F, U+1E95A, and other
// non-digit Adlam marks stay as written.
function adlamDigitAscii(cp) {
  if (cp >= 0x1E950 && cp <= 0x1E959) return String.fromCharCode(0x30 + (cp - 0x1E950));
  return '';
}
function isAdlamDigit(cp) {
  return adlamDigitAscii(cp) !== '';
}
function readEncodedAdlamDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isAdlamDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedAdlamDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedAdlamDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldAdlamDigits(text) {
  let out = '';
  for (const char of text) {
    out += adlamDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Myanmar Pao digits U+116D0..U+116D9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{116D1}proxy:7890" and
// "user:secret@\u{116D1}\u{116D2}\u{116D7}.\u{116D0}.\u{116D0}.\u{116D1}:7890" keep the
// password. The redacted host uses an ASCII digit. U+116CF, U+116E4, and other
// non-digit marks stay as written.
function myanmarPaoDigitAscii(cp) {
  if (cp >= 0x116D0 && cp <= 0x116D9) return String.fromCharCode(0x30 + (cp - 0x116D0));
  return '';
}
function isMyanmarPaoDigit(cp) {
  return myanmarPaoDigitAscii(cp) !== '';
}
function readEncodedMyanmarPaoDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isMyanmarPaoDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedMyanmarPaoDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedMyanmarPaoDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldMyanmarPaoDigits(text) {
  let out = '';
  for (const char of text) {
    out += myanmarPaoDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Myanmar Eastern Pwo Karen digits U+116DA..U+116E3 do not fold to 0-9 under
// NFKC. A single-label host, a dotted host, a numeric host, and a port already
// allow ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{116DB}proxy:7890" and
// "user:secret@\u{116DB}\u{116DC}\u{116E1}.\u{116DA}.\u{116DA}.\u{116DB}:7890" keep the
// password. The redacted host uses an ASCII digit. U+116CF, U+116E4, and other
// non-digit marks stay as written.
function easternPwoKarenDigitAscii(cp) {
  if (cp >= 0x116DA && cp <= 0x116E3) return String.fromCharCode(0x30 + (cp - 0x116DA));
  return '';
}
function isEasternPwoKarenDigit(cp) {
  return easternPwoKarenDigitAscii(cp) !== '';
}
function readEncodedEasternPwoKarenDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isEasternPwoKarenDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedEasternPwoKarenDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedEasternPwoKarenDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldEasternPwoKarenDigits(text) {
  let out = '';
  for (const char of text) {
    out += easternPwoKarenDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

// Sunuwar digits U+11BF0..U+11BF9 do not fold to 0-9 under NFKC. A
// single-label host, a dotted host, a numeric host, and a port already allow
// ASCII digits, so these marks kept the password. Their literal,
// percent-encoded, and numeric forms did too. Otherwise
// "user:secret@my\u{11BF1}proxy:7890" and
// "user:secret@\u{11BF1}\u{11BF2}\u{11BF7}.\u{11BF0}.\u{11BF0}.\u{11BF1}:7890" keep the
// password. The redacted host uses an ASCII digit. U+11BE1, U+11BFA, and other
// non-digit Sunuwar marks stay as written.
function sunuwarDigitAscii(cp) {
  if (cp >= 0x11BF0 && cp <= 0x11BF9) return String.fromCharCode(0x30 + (cp - 0x11BF0));
  return '';
}
function isSunuwarDigit(cp) {
  return sunuwarDigitAscii(cp) !== '';
}
function readEncodedSunuwarDigit(text, index) {
  if (text[index] !== '%') return null;
  const bytes = [];
  let cursor = index;
  for (let count = 0; count < 4; count += 1) {
    const next = readEncodedByte(text, cursor);
    if (!next) return null;
    bytes.push(next.value);
    cursor = next.next;
  }
  const lead = bytes[0];
  if (lead < 0xF0 || lead > 0xF4) return null;
  for (let count = 1; count < 4; count += 1) {
    if (bytes[count] < 0x80 || bytes[count] > 0xBF) return null;
  }
  const cp = decodeUtf8Scalar(bytes);
  if (cp == null || !isSunuwarDigit(cp)) return null;
  return { char: String.fromCodePoint(cp), next: cursor };
}
function decodeEncodedSunuwarDigits(text) {
  let out = '';
  for (let index = 0; index < text.length;) {
    const digit = readEncodedSunuwarDigit(text, index);
    if (digit) {
      out += digit.char;
      index = digit.next;
      continue;
    }
    out += text[index];
    index += 1;
  }
  return out;
}
function foldSunuwarDigits(text) {
  let out = '';
  for (const char of text) {
    out += sunuwarDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

function foldGarayDigits(text) {
  let out = '';
  for (const char of text) {
    out += garayDigitAscii(char.codePointAt(0)) || char;
  }
  return out;
}

function redactProxyCredentials(text) {
  const decoded = foldCapitalLetterNj(foldSmallLetterLj(foldCapitalLWithSmallJ(foldCapitalLetterLj(foldSmallLigatureIj(foldCapitalLigatureIj(foldSquaredDj(foldRaisedMr(foldRaisedMd(foldRaisedMc(foldSquaredWc(foldSquaredPpv(foldSquaredSs(foldSquaredSd(foldSquaredMv(foldSquaredHv(foldSquaredWz(foldSquaredCd(foldTortoiseShellS(foldDigitCommasFromTwo(foldDigitOneCommas(foldDigitZeroCommas(foldDigitZeroFullStops(foldParenthesizedCapitals(foldParenthesizedLetters(foldDigitFullStops(foldParenthesizedNumbers(foldCircledNumbers(foldSunuwarDigits(foldEasternPwoKarenDigits(foldMyanmarPaoDigits(foldAdlamDigits(foldOlOnalDigits(foldNagMundariDigits(foldWanchoDigits(foldNyiakengPuachueHmongDigits(foldKiratRaiDigits(foldPahawhHmongDigits(foldTangsaDigits(foldMroDigits(foldGurungKhemaDigits(foldKawiDigits(foldTolongSikiDigits(foldGunjalaGondiDigits(foldMasaramGondiDigits(foldBhaiksukiDigits(foldDivesAkuruDigits(foldWarangCitiDigits(foldAhomDigits(foldTakriDigits(foldModiDigits(foldTirhutaDigits(foldNewaDigits(foldKhudawadiDigits(foldSharadaDigits(foldChakmaDigits(foldSoraSompengDigits(foldBrahmiDigits(foldGarayDigits(foldHanifiRohingyaDigits(foldOsmanyaDigits(foldMeeteiMayekDigits(foldChamDigits(foldMyanmarTaiLaingDigits(foldJavaneseDigits(foldKayahLiDigits(foldSaurashtraDigits(foldVaiDigits(foldOlChikiDigits(foldLepchaDigits(foldSundaneseDigits(foldBalineseDigits(foldTaiThamThamDigits(foldTaiThamHoraDigits(foldNewTaiLueDigits(foldLimbuDigits(foldMongolianDigits(foldKhmerDigits(foldMyanmarShanDigits(foldMyanmarDigits(foldTibetanDigits(foldLaoDigits(foldThaiDigits(foldSinhalaDigits(foldMalayalamDigits(foldKannadaDigits(foldTeluguDigits(foldTamilDigits(foldOriyaDigits(foldGujaratiDigits(foldGurmukhiDigits(foldBengaliDigits(foldDevanagariDigits(foldNkoDigits(foldArabicDigits(foldSegmentedDigits(foldMathDigits(foldCircledDigits(foldOutlinedDigits(foldOutlinedLetters(foldEnclosedLetters(foldMathLetters(foldRomanLetters(foldSupSubLetters(foldModifierLetters(foldLatinCompatLetters(foldLetterlikeLetters(foldCircledLetters(foldFullwidthLetters(foldLabelHyphens(foldProxyInvisibles(decodeProxyHtml(foldProxyInvisibles(decodeEncodedProxyMarks(decodeEncodedSegmentedDigits(decodeEncodedMathDigits(decodeEncodedCircledDigits(decodeEncodedOutlinedDigits(decodeEncodedOutlinedLetters(decodeEncodedEnclosedLetters(decodeEncodedMathLetters(decodeEncodedRomanLetters(decodeEncodedSupSubLetters(decodeEncodedModifierLetters(decodeEncodedLatinCompatLetters(decodeEncodedLetterlikeLetters(decodeEncodedCircledLetters(decodeEncodedFullwidthLetters(decodeEncodedArabicDigits(decodeEncodedNkoDigits(decodeEncodedDevanagariDigits(decodeEncodedBengaliDigits(decodeEncodedGurmukhiDigits(decodeEncodedGujaratiDigits(decodeEncodedOriyaDigits(decodeEncodedTamilDigits(decodeEncodedTeluguDigits(decodeEncodedKannadaDigits(decodeEncodedMalayalamDigits(decodeEncodedSinhalaDigits(decodeEncodedThaiDigits(decodeEncodedLaoDigits(decodeEncodedTibetanDigits(decodeEncodedMyanmarDigits(decodeEncodedMyanmarShanDigits(decodeEncodedKhmerDigits(decodeEncodedMongolianDigits(decodeEncodedLimbuDigits(decodeEncodedNewTaiLueDigits(decodeEncodedTaiThamHoraDigits(decodeEncodedTaiThamThamDigits(decodeEncodedBalineseDigits(decodeEncodedSundaneseDigits(decodeEncodedLepchaDigits(decodeEncodedOlChikiDigits(decodeEncodedVaiDigits(decodeEncodedSaurashtraDigits(decodeEncodedKayahLiDigits(decodeEncodedJavaneseDigits(decodeEncodedMyanmarTaiLaingDigits(decodeEncodedChamDigits(decodeEncodedMeeteiMayekDigits(decodeEncodedOsmanyaDigits(decodeEncodedCapitalLetterNj(decodeEncodedSmallLetterLj(decodeEncodedCapitalLWithSmallJ(decodeEncodedCapitalLetterLj(decodeEncodedSmallLigatureIj(decodeEncodedCapitalLigatureIj(decodeEncodedSquaredDj(decodeEncodedRaisedMr(decodeEncodedRaisedMd(decodeEncodedRaisedMc(decodeEncodedSquaredWc(decodeEncodedSquaredPpv(decodeEncodedSquaredSs(decodeEncodedSquaredSd(decodeEncodedSquaredMv(decodeEncodedSquaredHv(decodeEncodedSquaredWz(decodeEncodedSquaredCd(decodeEncodedTortoiseShellS(decodeEncodedDigitCommasFromTwo(decodeEncodedDigitOneCommas(decodeEncodedDigitZeroCommas(decodeEncodedDigitZeroFullStops(decodeEncodedParenthesizedCapitals(decodeEncodedParenthesizedLetters(decodeEncodedDigitFullStops(decodeEncodedParenthesizedNumbers(decodeEncodedCircledNumbers(decodeEncodedSunuwarDigits(decodeEncodedEasternPwoKarenDigits(decodeEncodedMyanmarPaoDigits(decodeEncodedAdlamDigits(decodeEncodedOlOnalDigits(decodeEncodedNagMundariDigits(decodeEncodedWanchoDigits(decodeEncodedNyiakengPuachueHmongDigits(decodeEncodedKiratRaiDigits(decodeEncodedPahawhHmongDigits(decodeEncodedTangsaDigits(decodeEncodedMroDigits(decodeEncodedGurungKhemaDigits(decodeEncodedKawiDigits(decodeEncodedTolongSikiDigits(decodeEncodedGunjalaGondiDigits(decodeEncodedMasaramGondiDigits(decodeEncodedBhaiksukiDigits(decodeEncodedDivesAkuruDigits(decodeEncodedWarangCitiDigits(decodeEncodedAhomDigits(decodeEncodedTakriDigits(decodeEncodedModiDigits(decodeEncodedTirhutaDigits(decodeEncodedNewaDigits(decodeEncodedKhudawadiDigits(decodeEncodedSharadaDigits(decodeEncodedChakmaDigits(decodeEncodedSoraSompengDigits(decodeEncodedBrahmiDigits(decodeEncodedGarayDigits(decodeEncodedHanifiRohingyaDigits(decodeEncodedLabelPunct(text))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))));
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
