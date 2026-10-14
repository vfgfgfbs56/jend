# JEND — Security Risk Register & Release Blockers

> **Дата пересмотра:** 2026-10-14. **Ветка:** `feat/m8.5.15.6b1-file-open-denial-security-register`. **Стадия:** sandbox experiment, not a production security acceptance.  
> **Контекст и планы:** [JEND-PROJECT-CONTEXT.md](JEND-PROJECT-CONTEXT.md).  
> **Критическое правило:** отсутствие найденных багов **не доказывает отсутствие уязвимостей**. Каждое существенное изменение server/client/crypto/native/deployment требует повторного анализа угроз и негативных тестов. Никакой промо-формулировки «100% безопасно».

## Security release policy

- **Critical/High**: незакрытые обязательные угрозы, отсутствие проверенных mitigation, новые регрессии, либо неработающая изоляция = **NO-GO** для передачи реального E2EE plaintext/токенов в AI worker и для `Backend & Security Ready`. `NO-GO` означает остановку релизного пути, не блокирует написание тестов/неисполняемых прототипов.
- Каждая закрытая строка требует ссылку на **код + отрицательный тест/CI + подтверждённую ОС**, желательно отдельное ревью. Документация без защитного механизма не переводит статус в CLOSED.
- Нужны независимый review критических границ, отслеживание advisories/зависимостей, code scanning, фуззинг C++/GGUF и Rust IPC, release подписей, обновления и план реагирования. Сканер не заменяет аудит.
- Пользовательские сообщения, E2EE-ключи, HF/BYOK токены, подписи и приватные модели **не должны попадать** в CI-артефакты, stdout, stderr, дампы, crash reports и незащищённые процессы.
- Desktop baseline и отдельно заявленные мобильные platform gates **не смешивать**. Успешный Linux seccomp-test не подтверждает Mac sandbox или Windows AppContainer.
- Фронтенд: переход от backend к основной UI-разработке после gate `Backend & Security Ready`. UX-макеты возможны раньше, но не предоставляют угрозам разрешение на production.

## Risk register

`CONFIRMED GAP` = недостаток защитного механизма явно следует из текущего экспериментального кода, **не обязательно эксплуатируемая уязвимость рабочей системы**. `REVIEW REQUIRED` = риск требует проверки и не утверждается как существующая уязвимость. `MITIGATED IN PROBE` = проверено лишь в указанном тестовом режиме.

| ID | Severity | Boundary / scenario | Status & evidence | Required before backend-ready |
|---|---|---|---|---|
| JSEC-001 | Critical | Утечка E2EE/plaintext через нативный worker: чтение файлов, сеть, унаследованные FD | **CONFIRMED GAP**: `--infer-dev` не имеет production sandbox; Linux `--sandbox-probe` экспериментальный. PR #17 проверяет запрет новых `openat`, но не унаследованных FD. | Отдельная ОС identity; проверенный список FD; файловая изоляция (Linux namespaces/Landlock/allowlist, Apple sandbox, Windows AppContainer), сеть off, соответствующие негативные тесты |
| JSEC-002 | Critical | Подмена исполняемого worker между hash-check и `exec` | **CONFIRMED GAP**: M8.5.15.6a проверяет digest по пути, но не race-free OS attestation | Независимый подписанный worker release, immutable deployment/verified OS loader identity и revalidation/sandbox на final exec |
| JSEC-003 | Critical | Подмена GGUF между проверкой и загрузкой C++ | **CONFIRMED GAP**: M8.5.15.5 фиксирует открытый дескриптор, но inode допускает запись | OS-enforced immutable/sealed artifact и точный same-byte handoff, проверка отказов при одновременной модификации |
| JSEC-004 | High | Источник сам выбирает подписывающий ключ, rollback старого выпуска | **CONFIRMED DEPLOYMENT GAP**: offline тестовые ключи, ещё нет закреплённого production publisher/distributor root | Отдельная процедура trust-enrollment, rotation, revocation, rollback/freeze prevention и тесты |
| JSEC-005 | High | Supply-chain вредоносный GGUF/tokenizer / нативный parser | **CONFIRMED VALIDATION GAP**: GGUF проверен только по 24-байтовому заголовку + digest; это не полная проверка формата | Bounded parser для полного формата, архитектура/токенизатор/operator allowlist, fuzz ASan/UBSan и реальная легальная тест-модель |
| JSEC-006 | High | Source worker может делать SSRF/redirect, signed URL misuse, ресурсное истощение | **REVIEW REQUIRED**: есть staged Xet, но целостность на входе не доказывает сетевую безопасность | Проверка redirect/TLS/signed URL scope, loopback/private-IP denial, time/byte/ratio budgets, timeout, retry/backpressure |
| JSEC-007 | Critical | IDOR/BOLA аккаунтов и устройств, обход auth, replay/device binding | **REVIEW REQUIRED**: серверные smoke и атомарный JREQ есть, нужен full endpoint authz test matrix | Review handlers/DB row ownership, проверка всех sensitive mutations, replay/nonces, privilege boundary tests |
| JSEC-008 | Critical | Раскрытие chat/E2EE ключей или BYOK токена в логах, исключениях, network fallback | **REVIEW REQUIRED**: модельный worker пока model-free, будущий frontend/API увеличит поверхность | Sensitive data flow map, redaction tests, controlled outbound access, no silent cloud fallback, explicit capability/consent |
| JSEC-009 | High | Cache poisoning, traversal, symlinks, Windows ACL, incorrect hardlink trust | **CONFIRMED HARDENING GAP**: snapshot использует private Unix dirs, но остаётся Windows ACL/ancestor ownership/TOCTOU | OS-specific nofollow/owner/DACL checks, safe directory handles, atomic CAS, concurrency/crash tests |
| JSEC-010 | High | CPU/RAM/FD/timeout abuse, archive/compression bombs, denial of service | **REVIEW REQUIRED**: лимиты есть в отдельных tests, но не end-to-end native service | Per-device budgets, cancellation, process trees/cgroups/jobs, memory/cpu tests, disconnection handling |
| JSEC-011 | High | XSS/CSRF/unsafe render/unsafe URLs в будущем UI и модельном markdown output | **DESIGN BLOCKER**: полноценный frontend не реализован | Renderer escaping/sanitization/CSP, link allowlist, action confirmation, permission separation and tests before UI release |
| JSEC-012 | High | Dependency compromise, CI runner credentials, missing updates/vuln response | **REVIEW REQUIRED**: manifest integrity/checks и pinned build exist, advisories need regular monitoring | `cargo audit`, C/C++ dependency review, pinned CI actions/permissions, SBOM, secrets scanning, reproducible/signing pipeline |
| JSEC-013 | High | Peer delivery deanonymization/abuse, malicious peers | **DEFERRED / NOT IMPLEMENTED**: future optional opt-in peer transport | License/public-only sharing, opt-in, origin/IP warning, independently signed bytes, quotas and abuse controls before peer launch |

## Security proof inventory

- **Mac ARM64 user-confirmed:** M8.5.15.4–15.5 **10 PASS**, M8.5.15.6a **6 PASS**, M8.5.15.6b **4 PASS**. The last four confirm that an unsupported Linux sandbox is refused on Mac, **not** Mac OS process isolation.
- **Linux CI baseline:** M8.5.15.6b actual x64+ARM64 seccomp/no-new-privs network-denial/rlimits pass. M8.5.15.6b.1 extends this to actual **new file-open EPERM and fork EPERM** test once CI confirmed. Until then mark pending.
- **Windows/macOS CI baseline:** protocol tests pass and Linux-only `--sandbox-probe` refuses. Production native isolation is still unproven.
- **Android/iOS:** standalone Rust IPC parser cross-compiles; mobile native execution/isolation has **not** been tested.

## Process for each security-sensitive PR

1. Look for adversarial input: authn/authz, network endpoints, model manifests, GGUF parser, native code, IPC, FS paths/handles, shell, frontend markdown, secrets and storage.
2. Record the risk ID in PR and this register. State whether an issue is **proven, suspected, or mitigated only in tests**. Update controls, platform, test and remaining blockers.
3. Add **negative** regression cases: bad signature/key, tampered/truncated/corrupt payload, traversal, size/CPU/RAM exhaustion, replay/IDOR, stdout/stderr leaks, symlink races, cross-platform refusal.
4. Run static preflight, full Rust/SQL and desktop/native matrix. Where available run fuzzers/sanitizers/dependency advisories as separate gates. Verify CI SHA for the exact proposed PR.
5. Update `JEND-PROJECT-CONTEXT.md`, this file and `PROJECT-MANIFEST.sha256` with each security-sensitive source PR; do NOT fabricate PASS. Maintain stack; no merging without user approval.
6. Never claim `Backend & Security Ready` while any Critical/High gate included in the target desktop release is unresolved or an untrusted worker can access plaintext/secrets.

**No claim of zero vulnerabilities is made or implied by this register.**
