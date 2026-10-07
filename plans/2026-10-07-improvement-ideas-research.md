# Research & Brainstorm: Hướng cải tiến cho Personal OTP Vault

- **Thời gian research:** 2026-10-07
- **Scope:** Dựa trên code hiện tại (v0.1.1, main @ d38ab18) + research bên ngoài (OWASP, đối thủ 2FAS/Aegis/Ente Auth, Chrome MV3 docs, format otpauth-migration).
- **Phương pháp:** Đọc trực tiếp `lib/otp.js`, `lib/vault.js`, `app.js`, `extension/*`, `sw.js`, `index.html` + web research. Mọi nhận định về code đều đã xác minh trong source.

## Mục lục

1. [Tóm tắt nhanh](#tóm-tắt-nhanh)
2. [Hardening — gia cố bảo mật](#1-hardening)
3. [Features — tính năng mới](#2-features)
4. [Polish — trải nghiệm](#3-polish)
5. [Không nên làm (YAGNI)](#4-không-nên-làm-yagni)
6. [Đề xuất thứ tự ưu tiên](#5-đề-xuất-thứ-tự-ưu-tiên)
7. [Nguồn tham khảo](#nguồn-tham-khảo)
8. [Câu hỏi chưa giải quyết](#câu-hỏi-chưa-giải-quyết)

---

## Tóm tắt nhanh

Dự án nền tảng tốt: tách domain logic sạch (`lib/`), render entry dùng `textContent` (chống XSS đúng cách), strict parsing, backup có checksum + migration, test 3 tầng. Ba lỗ hổng thực tế lớn nhất tìm thấy:

1. **jsQR load từ CDN không có SRI** (`index.html:467`) — rủi ro supply-chain + phá tính offline.
2. **PBKDF2 chỉ 150k iterations** (`lib/vault.js:50`) — dưới mức OWASP khuyến nghị hiện tại (600k cho SHA-256).
3. **Không có auto-lock** — passphrase nằm trong bộ nhớ vô thời hạn sau khi unlock (`app.js`, `extension/popup.js`).

## 1. Hardening

### H1. Vendor jsQR vào bundle + thêm CSP ⛔ Ưu tiên cao nhất
`index.html:467` nạp `<script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js">` **không có thuộc tính `integrity`**. Hệ quả:
- CDN bị compromise → code độc chạy trong trang giữ toàn bộ secrets 2FA.
- Camera QR scan cần mạng — mâu thuẫn trực tiếp với "local-first, offline-capable" trong README.
- Lộ IP/thói quen dùng cho jsdelivr.

**Fix:** `npm i jsqr`, import trong `app.js` (esbuild bundle sẵn), xóa tag CDN. Sau đó thêm `<meta http-equiv="Content-Security-Policy">` với `default-src 'self'; img-src 'self' data: blob:; camera qua Permissions Policy`. Lưu ý: visual/e2e test có thể đang chặn SW nhưng không mock CDN — kiểm tra `offline.spec.js`. *Effort: S–M.*

### H2. Nâng PBKDF2 lên 600k iterations + lưu KDF params trong envelope
OWASP Password Storage Cheat Sheet (bản 2023, vẫn chuẩn 2025/2026): **PBKDF2-HMAC-SHA256 tối thiểu 600.000 iterations**. Hiện tại hard-code 150k tại `lib/vault.js:50`.

Quan trọng hơn con số: hiện không lưu KDF params nào trong payload, nên bất kỳ thay đổi nào về iterations/hash/salt-length sau này đều làm hỏng decrypt các vault cũ. **Fix gộp:** thêm `kdf: { algorithm, iterations, hash, saltBytes }` vào encrypted envelope; derive key theo params lưu sẵn; vault mới tạo dùng 600k; vault cũ vẫn decrypt được (params mặc định 150k khi thiếu) và tự nâng cấp khi user save lại. *Effort: M. Cần update unit test + e2e.*

### H3. Auto-lock theo thời gian không hoạt động
`currentPassphrase` giữ trong biến JS sau khi unlock, không có idle timer (`grep` không thấy bất kỳ auto-lock/timeout nào ở cả app lẫn extension). Ai mượn/vượt qua màn hình máy đang mở là đọc được vault.

**Fix:** settings "Lock after N minutes inactivity" (mặc định 10–15 phút cho web app; extension popup tự unmount khi đóng nên mức ưu tiên thấp hơn nhưng nên có lock-on-idle khi popup mở lâu). Optional: khóa khi `visibilitychange` → hidden quá X phút. *Effort: S–M.*

### H4. Throttle unlock attempts
Không có rate limit khi nhập sai passphrase (app.js/popup.js đều không có). Offline brute-force chặn bằng KDF (H2), nhưng throttle in-app (backoff tăng dần sau 3–5 lần sai) vẫn nâng đáng kể rào cản với kẻ có tay tại máy. Lưu counter trong settings key, reset khi unlock thành công. *Effort: S.*

### H5. Passphrase strength check
`normalizePassphrase` chỉ yêu cầu ≥8 ký tự (`lib/vault.js:38`). Với vault chứa **toàn bộ seeds 2FA**, 8 ký tự là mỏng. Thêm strength meter thuần local (độ dài + lớp ký tự + blacklist pattern phổ biến — không cần zxcvbn), cảnh báo mạnh khi yếu, cân nhắc khuyến nghị ≥12. *Effort: S.*

### H6. `clipboardRead` → optional permission (extension)
`clipboardRead` là permission mức cảnh báo cao trong Chrome Web Store ("Read data you copy and paste"). Extension chỉ dùng `readText()` cho tính năng clipboard-import. Chuyển sang `optional_permissions` + `chrome.permissions.request()` tại thời điểm user bấm import — bớt rào cản cài đặt và qua review dễ hơn. *Effort: S.*

### H7. Backup checksum ≠ chống giả mạo
Checksum SHA-256 (`lib/vault.js:155`) chỉ chống hỏng dữ liệu do tai nạn — ai sửa được file backup đều có thể tính lại checksum. Không phải bug, nhưng nên: (a) ghi rõ giới hạn này trong docs, (b) khi làm Backup v3 (đã có trong roadmap), dùng HMAC với key derive từ backup passphrase. *Effort: S (docs) / gộp vào v3.*

### H8. Entry ID dùng `Math.random()`
`lib/otp.js:36` — ID không phải thông tin bảo mật, nhưng đổi sang `crypto.getRandomValues()` là 2 dòng, xóa luôn một câu hỏi trong security review. *Effort: XS.*

## 2. Features

### F1. Import từ Google Authenticator (`otpauth-migration://`) 💎 giá trị nhất
URI format: `otpauth-migration://offline?data=<base64-protobuf>`, chứa repeated `OtpParameters` (secret, name, issuer, algorithm, digits, type; có batch index/size khi export nhiều QR). Decode thuần JS không cần dependency nào (~100–150 dòng cho đúng schema này) — hợp triết lý no-deps của dự án. Đây là dòng chảy user lớn nhất: ai đang dùng GA muốn chuyển sang vault riêng. Tham khảo chuẩn: bài viết của tác giả Aegis (alexbakker.me) và tool `qistoph/otp_export`. *Effort: M (parser + UI import preview + tests với vector thật).*

### F2. Import/export 2FAS & Aegis
Cùng lý do F1 theo hướng ngược lại và chéo-app: 2FAS export JSON (có bản encrypted), Aegis export JSON (plain/encrypted). Làm được cả hai chiều → vault này thành "hub" migration. Bắt đầu bằng Aegis plain + 2FAS plain (JSON đơn giản), encrypted variant sau. *Effort: M mỗi format.*

### F3. TOTP SHA-256 / SHA-512
WebCrypto `subtle.sign` HMAC hỗ trợ sẵn SHA-256/512 — hiện `parseOtpAuthUri` từ chối mọi algorithm ≠ SHA1 (`lib/otp.js:167`). Một số dịch vụ doanh nghiệp/ngân hàng dùng SHA256. Mở rộng `normalizeEntry` + enum algorithm + hiển thị badge thuật toán trên entry. *Effort: S.*

### F4. Xuất 1 entry ra QR
Cần đổi thiết bị/đăng ký lại? Generate QR từ otpauth URI ngay trong app (cần QR **encoder** vendor — khác jsQR decoder). Local-first hoàn toàn, không share qua mạng. *Effort: M.*

### F5. Backup reminder + "last backup" badge
Rủi ro số 1 của vault local là **mất dữ liệu**, không phải bị hack. Hiển thị "Last backup: X days ago" trong Settings + toast nhắc khi >30 ngày (lưu timestamp vào settings). Rẻ mà cứu giá trị. *Effort: S.*

### F6. Undo/Trash cho xóa entry
Xóa nhầm một seed 2FA = mất vĩnh viễn quyền truy cập service đó. Đơn giản nhất: toast "Undo" 10s sau khi xóa, hoặc soft-delete flag + auto-purge. *Effort: S–M.*

### F7. Biometric unlock qua WebAuthn PRF
Roadmap đã có ý này — lưu ý triển khai đúng: dùng **extension `prf`** của WebAuthn để derive AES key từ platform authenticator (Touch ID/Windows Hello), không lưu bất kỳ dữ liệu sinh trắc nào. Feature-detect (cần Chrome 128+/Safari 18+/Firefox 135+, cao hơn baseline hiện tại của dự án) + fallback passphrase luôn hoạt động. *Effort: L — làm sau khi các mục trên ổn.*

### F8. Cảnh báo lệch giờ (time drift)
TOTP sai nếu đồng hồ máy lệch. Opt-in: khi online, HEAD request 1 endpoint và so `Date` header — cảnh báo nếu lệch >5s. Tôn trọng local-first vì chỉ chạy khi user bật và có mạng. *Effort: S.*

### F9. Keyboard shortcut mở popup (extension)
`commands` API + `_execute_action` — vài dòng trong manifest. *Effort: XS.*

## 3. Polish

| Mục | Hiện trạng | Đề xuất | Effort |
|---|---|---|---|
| **P1. Dark mode** | `styles.css` không có `prefers-color-scheme`/theme nào | CSS variables + toggle + system default; cập nhật visual snapshots | M |
| **P2. Drag & drop reorder** | Hiện chỉ có nút move-up/down | Pointer-based drag (HTML5 DnD khó trên mobile) | M |
| **P3. Countdown ring từng entry** | Chỉ có 1 timer bar global (theo period nhỏ nhất) | Ring/đường tiến trình trên mỗi card — hữu ích khi period khác nhau | S–M |
| **P4. Accessibility audit** | Chưa audit | axe-core vào Playwright, fix contrast/focus/aria | M |
| **P5. Haptic khi copy (mobile)** | Không có | `navigator.vibrate(20)` | XS |
| **P6. i18n (vi/en)** | Toàn bộ hard-coded English | Chỉ làm nếu có audience thật — thêm từ PDR trước | M–L |

## 4. Không nên làm (YAGNI)

- **Cross-device sync / cloud backup** — giữ nguyên non-goal trong roadmap. Mọi đề xuất "sync" phá local-first và kéo theo key management + attack surface. F1/F2 (import/export) giải quyết 90% nhu cầu thực tế của sync.
- **HOTP** — rất ít service còn dùng; chờ có yêu cầu thật (kết hợp F1: GA migration có thể trả về type=HOTP — lúc đó chỉ import được sau khi hỗ trợ, cân nhắc kỹ).
- **Advanced search regex** — vault cá nhân hiếm khi >200 entry, search substring hiện tại đủ.
- **Audit log/analytics** (roadmap proposal) — với app cá nhân 1 user, chi phí UI/storage cao hơn giá trị.

## 5. Đề xuất thứ tự ưu tiên

| Lần | Nhóm | Lý do |
|---|---|---|
| **Đợt 1 (bảo mật nền)** | H1, H2, H3, H4, H5 | Đóng 3 lỗ hổng thật + 2 rào cản rẻ tiền. H1 phải làm trước cả feature nào. |
| **Đợt 2 (giá trị user)** | F1, F5, F6, F9 | Migration từ GA + chống mất dữ liệu = 2 điều user cảm nhận nhất. |
| **Đợt 3 (mở rộng)** | F3, H6, P1, P2 | Tương thích rộng hơn + trải nghiệm. |
| **Đợt 4 (lớn, cân nhắc)** | F7, F2, F4, còn lại | Mỗi cái một PR riêng, theo demand. |

## Nguồn tham khảo

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — PBKDF2 600k (SHA-256) / 210k (SHA-512)
- [Parsing Google Authenticator export QR codes — alexbakker.me](https://alexbakker.me/post/parsing-google-auth-export-qr-code.html) — format otpauth-migration
- [qistoph/otp_export](https://github.com/qistoph/otp_export) — tool tham khảo parse GA export
- [NVD CVE-2023-3823](https://nvd.nist.gov/vuln/detail/CVE-2023-3823) — Google Authenticator export gửi secrets không mã hóa (bài học: mọi export flow phải local-only)
- [Chrome: Permission warning guidelines](https://developer.chrome.com/docs/extensions/reference/permissions-list) — clipboardRead là permission cảnh báo cao
- So sánh đối thủ: [PrivacyGuides discussion](https://discuss.privacyguides.net) (2FAS/Aegis/Ente Auth 2025)

## Câu hỏi chưa giải quyết

1. Baseline browser (Chrome 114+/Safari 16+) có nên nâng để dùng WebAuthn PRF không, hay giữ baseline + feature-detect?
2. i18n tiếng Việt có phải mục tiêu thật không (PDR hiện ghi English-only ngầm định)?
3. Có muốn support HOTP cho import từ GA không, hay chỉ import token TOTP và báo rõ với user?
