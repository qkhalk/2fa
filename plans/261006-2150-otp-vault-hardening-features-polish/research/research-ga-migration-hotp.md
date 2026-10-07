# Research: GA Migration QR Parser, HOTP, TOTP SHA-256/512

Date: 2026-10-07. For: `lib/otp.js` extension in the 2fa local-first vault.
Method: RFCs fetched directly from rfc-editor.org; proto schema cross-checked across 2+ independent reverse-engineering sources; wire format from protobuf.dev; app conventions checked against Aegis production code.

## 1. otpauth-migration protobuf wire format

URI: `otpauth-migration://offline?data=<base64 protobuf>`

Confirmed identically by two independent reverse-engineered schemas:

- Source A: [Parsing Google Authenticator export QR codes - Alex Bakker (Aegis author)](https://alexbakker.me/post/parsing-google-auth-export-qr-code.html)
- Source B: [qistoph/otp_export - OtpMigration.proto + README](https://github.com/qistoph/otp_export) (repo root `OtpMigration.proto`, MIT)

Neither author had Google's official `.proto` (format is undocumented), but field numbers and enum values agree between both. Bakker caveats: "not 100% sure if the types of the fields are exactly correct... they seem to match up well enough."

### MigrationPayload

| # | Field | Type |
|---|-------|------|
| 1 | otp_parameters | repeated OtpParameters (wire type 2, each entry length-prefixed) |
| 2 | version | int32 (observed value in the wild: 1) |
| 3 | batch_size | int32 |
| 4 | batch_index | int32 (0-based) |
| 5 | batch_id | int32 (unique id per export attempt; groups QRs of one export) |

### OtpParameters

| # | Field | Type |
|---|-------|------|
| 1 | secret | bytes - raw secret bytes, NOT base32 |
| 2 | name | string - account, may carry "Issuer:account" |
| 3 | issuer | string - may be empty |
| 4 | algorithm | enum Algorithm |
| 5 | digits | enum DigitCount |
| 6 | type | enum OtpType |
| 7 | counter | int64 - HOTP only |

### Enums (exact values; both sources agree)

| Algorithm (f4) | DigitCount (f5) | OtpType (f6) |
|---|---|---|
| 0 = ALGORITHM_UNSPECIFIED | 0 = DIGIT_COUNT_UNSPECIFIED | 0 = OTP_TYPE_UNSPECIFIED |
| 1 = SHA1 | 1 = SIX | 1 = HOTP |
| 2 = SHA256 | 2 = EIGHT | 2 = TOTP |
| 3 = SHA512 | - | - |
| 4 = MD5 | - | - |

### Gotchas (each sourced)

- **No period field.** The payload carries no period; GA assumes 30 s. Imported TOTP entries must default `period = 30` even though our vault supports 15-120 s. (Sources A+B: no field beyond 7 in OtpParameters.)
- **Base64 is standard, not URL-safe.** The `data` param is standard base64 (contains `+ / =`) percent-encoded inside the URI. qistoph README pipeline: percent-decode, then plain `base64 -d`; their `urldecode()` explicitly maps `+` and `%XX`. JS trap: `URLSearchParams` turns `+` into space - parse the query manually or restore `+`. Tolerate base64url anyway (map `-`>`+`, `_`>`/`, re-pad) for third-party producers.
- **Secret is raw bytes; no padding involved** in migration. Padding rules apply to base32 in `otpauth://` URIs (see section 5) and when re-encoding secrets for display.
- **Issuer-in-name:** GA often leaves `issuer` empty and stores `Issuer:account` in `name` (same convention as the otpauth:// label). Aegis' production GA importer splits on the first colon and takes part 2 as the account (see [Aegis GoogleAuthImporter.java](https://github.com/beemdevelopment/Aegis/blob/master/app/src/main/java/com/beemdevelopment/aegis/importers/GoogleAuthImporter.java)). Rule: if `issuer` is empty and `name` contains a colon, split at the FIRST colon; issuer = left, account = right with leading spaces stripped.
- **Unknown enum values:** proto3 must not fail on unknown enum numbers. Mapping: algorithm 0 > treat as SHA1 (proto3 default); 4 (MD5) > skip entry with warning (WebCrypto has no MD5; carrying MD5 is a security downgrade); >4 > skip with warning. digits 0 > default 6. type 0 > default TOTP. Never abort the batch on one bad entry.
- **Beware different numbering in GA's internal SQLite DB:** `TYPE_TOTP = 0, TYPE_HOTP = 1` (Aegis importer) - OPPOSITE order of the migration QR enum (HOTP=1, TOTP=2). Do not share one mapping.
- **Multi-QR batching** (Source A, matches B): large exports split across several QR codes shown sequentially. Each QR contains a complete, independently decodable MigrationPayload. Stitch: decode each QR, group by `batch_id`, merge all `otp_parameters`, order by `batch_index` (0..batch_size-1), dedupe by (secret, name). Partial scans are fine - import what was scanned; `batch_size` reports how many QRs exist.

## 2. Minimal protobuf wire-format decoding (no library)

Rules per [protobuf.dev - Proto Encoding](https://protobuf.dev/programming-guides/encoding/):

- A message is a sequence of key/value records. The key is a varint packing `(field_number << 3) | wire_type`.
- Wire types: 0 = varint; 1 = fixed64 (8 bytes little-endian); 2 = length-delimited (varint length + payload; used for bytes, strings, submessages); 5 = fixed32 (4 bytes LE); 3/4 = deprecated groups (throw in our parser).
- Varint: 1-10 bytes; low 7 bits are payload in little-endian order, MSB = continuation bit. Decode with BigInt (needed for int64 counter).
- int64: negatives use two's complement (10-byte varint); decode via `BigInt.asIntN(64, v)`. Counters are small in practice; convert to Number only if <= Number.MAX_SAFE_INTEGER.
- Unknown-field skipping (proto3 contract): use the wire type to hop over - wt 0: consume a varint; wt 1: +8 bytes; wt 5: +4 bytes; wt 2: read length varint, skip that many bytes. Fields may appear in any order; last scalar occurrence wins.

```js
// Dependency-free MigrationPayload decoder
const b64 = s => { s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };        // standard b64, tolerate base64url
const utf8 = b => new TextDecoder().decode(b);

function varint(b, p) { let v = 0n, sh = 0n;                        // -> [BigInt value, nextPos]
  for (;;) { if (p >= b.length) throw Error('truncated varint');
    const c = b[p++]; v |= BigInt(c & 0x7f) << sh;
    if (!(c & 0x80)) return [v, p];
    if ((sh += 7n) >= 70n) throw Error('bad varint'); } }

function skip(b, p, wt) {                                           // p is AFTER the tag
  if (wt === 0) return varint(b, p)[1];
  if (wt === 1) return p + 8;                                       // fixed64
  if (wt === 5) return p + 4;                                       // fixed32
  if (wt === 2) { const [n, q] = varint(b, p); return q + Number(n); }
  throw Error('unsupported wire type ' + wt); }                     // 3/4: groups

function lenBytes(b, p) { const [n, q] = varint(b, p);
  return [b.subarray(q, q + Number(n)), q + Number(n)]; }

function otpParams(b) { const o = { secret: null, name: '', issuer: '',
    alg: 1, digits: 1, type: 2, counter: 0n };                      // proto3 defaults
  let p = 0;
  while (p < b.length) { const [k, q] = varint(b, p);
    const f = Number(k >> 3n), wt = Number(k & 7n); p = q;
    if (f === 1 && wt === 2) { [o.secret, p] = lenBytes(b, p); }
    else if ((f === 2 || f === 3) && wt === 2) { const [s, r] = lenBytes(b, p); p = r;
      if (f === 2) o.name = utf8(s); else o.issuer = utf8(s); }
    else if (f >= 4 && f <= 6 && wt === 0) { const [v, r] = varint(b, p); p = r;
      if (f === 4) o.alg = Number(v);
      else if (f === 5) o.digits = Number(v); else o.type = Number(v); }
    else if (f === 7 && wt === 0) { const [v, r] = varint(b, p); p = r;
      o.counter = BigInt.asIntN(64, v); }
    else p = skip(b, p, wt); }
  return o; }

function migration(b) { const out = { entries: [], version: 0,
    batchSize: 1, batchIndex: 0, batchId: 0 };
  let p = 0;
  while (p < b.length) { const [k, q] = varint(b, p);
    const f = Number(k >> 3n), wt = Number(k & 7n); p = q;
    if (f === 1 && wt === 2) { const [s, r] = lenBytes(b, p); p = r;
      out.entries.push(otpParams(s)); }
    else if (f >= 2 && f <= 5 && wt === 0) { const [v, r] = varint(b, p); p = r;
      if (f === 2) out.version = Number(v);
      else if (f === 3) out.batchSize = Number(v);
      else if (f === 4) out.batchIndex = Number(v); else out.batchId = Number(v); }
    else p = skip(b, p, wt); }
  return out; }
```

Caller: `migration(b64(dataParam))`.

## 3. HOTP (RFC 4226)

Source: [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226.txt), fetched 2026-10-07.

- `HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))`; C is the 8-byte big-endian counter; K >= 128 bits (160 recommended). Steps: HMAC-SHA-1 > dynamic truncation DT(HS) (offset = low 4 bits of byte 19; take 4 bytes at offset, mask top bit with 0x7f, read big-endian 31-bit) > `D = Snum mod 10^Digit`. 6 digits minimum MUST; 7/8 optional.
- Byte-identical to our existing `generateTotp` truncation - only the HMAC input changes: `Uint8Array(8)` big-endian counter instead of `(unixMs / 1000 / period)`. WebCrypto path unchanged (`subtle.sign` HMAC-SHA1 already in place).

### Appendix D test vectors - verified from the RFC

Secret = ASCII "12345678901234567890" (hex `3132333435363738393031323334353637383930`).

| C | HMAC-SHA-1 (hex) | Truncated dec (31-bit) | HOTP |
|------|------------------------------------------|------------|--------|
| 0 | cc93cf18508d94934c64b65d8ba7667fb7cde4b0 | 1284755224 | 755224 |
| 1 | 75a48a19d4cbe100644e8ac1397eea747a2d33ab | 1094287082 | 287082 |
| 2 | 0bacb7fa082fef30782211938bc1c5e70416ff44 | 137359152  | 359152 |
| 3 | 66c28227d03a2d5529262ff016a1e6ef76557ece | 1726969429 | 969429 |
| 4 | a904c900a64b35909874b33e61c5938a8e15ed1c | 1640338314 | 338314 |
| 5 | a37e783d7b7233c083d4f62926c7a25f238d0316 | 868254676  | 254676 |
| 6 | bc9cd28561042c83f219324d3c607256c03272ae | 1918287922 | 287922 |
| 7 | a4fb960c0bc06e1eabb804e5b397cdc4b45596fa | 82162583   | 162583 |
| 8 | 1b3c89f65e6c9e883012052823443f048b4332db | 673399871  | 399871 |
| 9 | 1637409809a679dc698207310c8c7fc07290d9e5 | 645520489  | 520489 |

The RFC prints the truncated hex without leading zero nibbles (e.g. `82fef30` = 0x082fef30); the decimal and HOTP columns are unambiguous. Unit tests should assert the final HOTP column: `755224 287082 359152 969429 338314 254676 287922 162583 399871 520489` - matches the plan's expected list exactly.

### Counter semantics in authenticator apps

- Protocol ([RFC 4226 sec 7.2](https://www.rfc-editor.org/rfc/rfc4226.txt)): client increments its counter to produce each code; server increments its copy only on successful validation. Drift between the two is normal.
- Validation-side resync (sec 7.3-7.4): server checks counters `C_server .. C_server + s` (look-ahead window); `s` SHOULD be as low as usability allows; attacker success approx `s*v/10^Digit`; throttle attempts (parameter T), lock out across sessions. Appendix E.4 alternative: counter-based resync - if client sends its counter, `C_client >= C_server`, difference <= s, and the code validates, set `C_server = C_client + 1`. This matters to us only if we ever verify codes; for generation-only, it explains why app-side divergence is tolerated by servers.
- App convention (NOT standardized by any RFC; apps diverge): increment the persisted counter each time a code is revealed or copied - each reveal consumes one code, matching Google Authenticator's tap-to-advance behavior. Do NOT increment on list render or on a timer. Never decrement. Do not reset on app restart (counter is persisted state). Re-enrollment issues a fresh secret with counter 0. Recommendation for this vault: increment once per reveal AND once per copy, plus allow manual counter edit as a drift escape hatch; persist `counter` per HOTP entry; seed it from the migration payload's int64 field on import.

## 4. TOTP SHA-256 / SHA-512 (RFC 6238 Appendix B)

Source: [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.txt), fetched 2026-10-07. `TOTP = HOTP(K, T)`, `T = floor((unix - T0) / X)`, defaults `X = 30`, `T0 = 0`; SHA-256/SHA-512 are MAY options; T MUST exceed 32-bit range (past 2038) - our time math must use Number/BigInt, not int32.

**Critical gotcha - seed sizes.** Appendix B's seeds are the ASCII string "12345678901234567890" extended to the HMAC block size per algorithm: 20 bytes for SHA-1 (`3132...3930`), 32 bytes for SHA-256 ("12345678901234567890123456789012"), 64 bytes for SHA-512 ("1234567890" x6 + "1234"). The SHA-256/SHA-512 columns below are NOT reproducible with a 20-byte secret; each column uses its own seed. Tests must build the three distinct seeds. (WebCrypto HMAC accepts any key length, so runtime code needs no seed handling - this affects only test fixtures.)

8-digit values, X = 30, T0 = 0 (verified from the RFC table):

| Unix T | T (hex) | SHA1 (seed 20B) | SHA256 (seed 32B) | SHA512 (seed 64B) |
|------------|------------------|----------|----------|----------|
| 59 | 0000000000000001 | 94287082 | 46119246 | 90693936 |
| 1111111109 | 00000000023523ec | 07081804 | 68084774 | 25091201 |
| 1111111111 | 00000000023523ed | 14050471 | 67062674 | 99943326 |
| 1234567890 | 000000000273ef07 | 89005924 | 91819424 | 93441116 |
| 2000000000 | 0000000003f940aa | 69279037 | 90698825 | 38618901 |
| 20000000000 | 0000000027bc86aa | 65353130 | 77737706 | 47863826 |

Implementation delta for `lib/otp.js`: the only change to `generateTotp` is the hash parameter on `subtle.importKey`/`subtle.sign` ("SHA-1" > "SHA-256"/"SHA-512"); truncation, digits, and T computation are hash-agnostic.

## 5. Edge cases: extending parseOtpAuthUri for otpauth://hotp

Source: [google-authenticator wiki - Key-Uri-Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

- Form: `otpauth://TYPE/LABEL?PARAMS`; TYPE in {hotp, totp} (spec uses lowercase; recommend case-insensitive compare).
- **counter**: wiki says "Required if provisioning a key for use with HOTP. It will set the initial counter value." No default is specified - decision: default 0 when missing (proto3 default, GA/Aegis practice, RFC enrollment convention). Accept non-negative integers only; reject values above Number.MAX_SAFE_INTEGER (real counters stay < 2^32).
- **period**: spec marks it "totp only". Meaningless for HOTP > ignore silently if present; never store; never error (tolerant parsing beats strictness for third-party QR generators).
- **digits**: 6 (default) or 8 only; anything else > reject the entry (vault supports 6/8; wiki notes some clients ignore this param entirely).
- **algorithm**: SHA1 default; SHA256/SHA512 listed; MD5 is NOT in the spec > skip with warning. For type=hotp + SHA256/512: technically outside RFC 4226 (HOTP is defined over SHA-1); the HMAC path is hash-agnostic so support it, but comment it as a non-RFC extension (the wiki's algorithm param applies to both types).
- **label/issuer**: ABNF `label = accountname / issuer (":" / "%3A") *"%20" accountname`; neither half may contain a colon; the wiki recommends using BOTH the label prefix and the issuer parameter, which should match. Parse order: percent-decode label > split at first ":" > trim leading spaces off account. If the issuer param conflicts with the label prefix > prefer the explicit issuer param, warn softly.
- **secret**: RFC 3548 base32, padding omitted by convention > `base32ToBytes` must accept missing `=` padding and lowercase input; strip internal whitespace (some generators emit grouped secrets).
- Unknown query parameters: ignore (forward compatibility). Fail only on semantic violations: bad counter, bad digits, undecodable secret, unknown type.
- Scheme routing: `otpauth-migration://` must NOT enter `parseOtpAuthUri` - separate `parseMigrationUri` returning a batch (section 1).

## 6. Recommendation (ranked)

1. **HOTP first.** Smallest delta: reuse the HMAC + dynamic-truncation path, add an 8-byte BE counter encoder, persist `counter` per entry, increment on reveal/copy. Validated against 10 exact RFC vectors. Zero new crypto.
2. **TOTP SHA-256/512 second.** One-parameter change (hash alg on importKey/sign) + plumbing the algorithm field through vault records and backup migration. Tests need three distinct seed lengths (section 4 gotcha).
3. **Migration parser third.** Self-contained ~60-line decoder (section 2), enum mapping and skip-with-warning rules from section 1, batch stitching via batch_id/batch_index, default period 30, default digits 6.

All three are additive to `lib/otp.js`, dependency-free, and unit-testable in Node via Vitest exactly like the existing lib tests. Risk notes: the parser must be bounds-checked and total (never throw on unknown fields) since it consumes untrusted QR input; HOTP counter persistence must go through the same encrypted-vault path as secrets.

## 7. Limitations

- The `.proto` is reverse-engineered (Google never published it). Two independent sources agree on every field, but the decoder must stay defensive and entries must be validated before persisting.
- Bakker's scalar types (int32/int64) are best guesses; on the wire all scalars are varints, so decoding is unaffected - only semantic bounds checks (e.g., counter range) rely on the declared types.
- App-side HOTP increment conventions are not standardized anywhere authoritative; section 3 records convention + rationale, not an RFC citation.
- Did not verify Google Authenticator's current 2026 app release against 2019-2021 reverse engineering; recommend round-tripping one real export QR through the new parser as an acceptance test.
- Playwright e2e for the migration import (camera/QR decode) is out of scope here - that needs a fixture QR image and was not researched.

## Sources

- [RFC 4226 - HOTP (rfc-editor.org)](https://www.rfc-editor.org/rfc/rfc4226.txt) - algorithm, Appendix D vectors, sec 7.2-7.4 + E.4 counter/resync
- [RFC 6238 - TOTP (rfc-editor.org)](https://www.rfc-editor.org/rfc/rfc6238.txt) - T computation, Appendix B vectors/seeds, X/T0 defaults
- [Parsing Google Authenticator export QR codes - Alex Bakker](https://alexbakker.me/post/parsing-google-auth-export-qr-code.html) - MigrationPayload/OtpParameters schema, batching (batch_size/batch_index/batch_id)
- [qistoph/otp_export](https://github.com/qistoph/otp_export) - OtpMigration.proto, README decode pipeline (urldecode > base64 -d > protoc --decode)
- [protobuf.dev - Proto Encoding](https://protobuf.dev/programming-guides/encoding/) - wire types, varint rules, key packing, unknown-field skipping
- [google-authenticator wiki - Key-Uri-Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) - otpauth URI params/defaults, label ABNF, counter required for hotp
- [Aegis GoogleAuthImporter.java](https://github.com/beemdevelopment/Aegis/blob/master/app/src/main/java/com/beemdevelopment/aegis/importers/GoogleAuthImporter.java) - issuer-in-name colon split, GA DB type enum (TOTP=0/HOTP=1), counter persistence
