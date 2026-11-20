# Security Specification — 나의 AI 프롬프트 창고

## 1. Application Context & Data Invariants
- This is a single-page, login-free ("로그인 화면 없이 한 페이지") beginner AI prompt library backed by Firestore collection `prompts`.
- No PII (emails, phone numbers, addresses, user accounts) is stored in Firestore.
- **Invariants**:
  1. Every document in `/prompts/{promptId}` must have a valid ID (`^[a-zA-Z0-9_-]+$`, max 128 chars).
  2. Every document must contain **only** the 4 schema keys: `title`, `category`, `content`, `createdAt`.
  3. `title` must be a non-empty string (`1 <= size <= 200`).
  4. `category` must be one of `'사진 합성'`, `'스타일 변환'`, `'캐릭터·포스터'`.
  5. `content` must be a non-empty string (`1 <= size <= 20000`) so long prompts over 1,000 characters are supported while preventing abuse.
  6. `createdAt` must equal `request.time` on creation and remain immutable on updates.
  7. All other paths in the database are denied by default (`match /{document=**} { allow read, write: if false; }`), except read-only `/test/connection` for connectivity checks.

## 2. Adversarial Payloads ("Dirty Dozen")
1. **Shadow Field Injection**: `{ title: "A", category: "사진 합성", content: "B", createdAt: serverTimestamp, isAdmin: true }` -> Rejected (`hasOnly` check).
2. **Missing Required Field**: `{ title: "A", category: "사진 합성", createdAt: serverTimestamp }` -> Rejected (`hasAll` check).
3. **Invalid Category Enum**: `{ title: "A", category: "기타", content: "B", createdAt: serverTimestamp }` -> Rejected.
4. **Empty Title**: `{ title: "", category: "사진 합성", content: "B", createdAt: serverTimestamp }` -> Rejected.
5. **Oversized Title (>200 chars)**: Rejected.
6. **Empty Content**: `{ title: "A", category: "사진 합성", content: "", createdAt: serverTimestamp }` -> Rejected.
7. **Oversized Content (>20,000 chars)**: Rejected (Denial of Wallet protection).
8. **Type Poisoning (Non-string content)**: `{ title: "A", category: "사진 합성", content: 12345, createdAt: serverTimestamp }` -> Rejected.
9. **Client-Spoofed Timestamp on Create**: `createdAt: Timestamp(2000-01-01)` -> Rejected (`createdAt == request.time`).
10. **Immutable `createdAt` Tampering on Update**: Updating `createdAt` -> Rejected (`affectedKeys().hasOnly(['title', 'category', 'content'])` and `incoming().createdAt == existing().createdAt`).
11. **ID Poisoning**: Creating `/prompts/invalid id with spaces` or 200-char ID -> Rejected (`isValidId`).
12. **Unauthorized Collection Write**: Writing to `/users/1` or `/admins/1` -> Rejected by global deny catch-all.
