# JEND — PROJECT CONTEXT & ROADMAP (памятка для нового чата)

> **Обновлено:** 2026-10-15. **Текущий этап:** M8.5.15.6d.1 — убрать платформенные предупреждения и добавить desktop compile gate; M8.5.15.6d Linux 9 data + 11 launch PASS, пользовательский Mac 2 data refusal/no-inference PASS; production BLOCKED.
> **Основная ветка разработки:** `fix/m8.5.15.6d-desktop-warning-gate`; новый stacked PR поверх draft [#20](https://github.com/vfgfgfbs56/jend/pull/20), который основан на [#19](https://github.com/vfgfgfbs56/jend/pull/19). CI нового head ещё не подтверждён.
> **Статус:** прототипы проверки/хранения моделей и взаимодействия Rust/C++; **реальный безопасный инференс сторонней модели в Jend пока НЕ реализован**.  
> **Важно:** этот файл — редактируемый снимок на момент коммита, не автоматически обновляемые сведения о GitHub. Перед новым действием перечитать его и **проверить актуальное состояние PR, веток и CI**.

## Как продолжать в новом чате (прочитать прежде, чем действовать)

1. Открыть **именно этот файл из последней рабочей ветки**:
   [JEND-PROJECT-CONTEXT.md — актуальная ветка](https://github.com/vfgfgfbs56/jend/blob/fix/m8.5.15.6d-desktop-warning-gate/JEND-PROJECT-CONTEXT.md).
   После слияния прочитать версию на `main`:
   `https://github.com/vfgfgfbs56/jend/blob/main/JEND-PROJECT-CONTEXT.md`.
2. Проверить [открытые PR](https://github.com/vfgfgfbs56/jend/pulls), их **базы**, последние SHA, CI и отсутствие конфликтов. Не предполагать, что все ранее открытые PR уже слиты.
3. Воспринимать раздел «Подтверждено» как факты, «План» — как **не реализованные** задачи. Не считать PASS для синтетического теста доказательством настоящей нейросети.
4. При разработке: создать отдельную ветку от **актуального верхнего PR**, внести код и tests, обновить **этот** файл и [JEND-SECURITY-REGISTER.md](JEND-SECURITY-REGISTER.md) при изменении security-sensitive кода, обновить `PROJECT-MANIFEST.sha256`, прогнать CI, открыть новый stacked PR; **ничего не сливать без прямого разрешения пользователя**.
5. Пользователь тестирует на Mac, обычно в `~/Downloads`; нужны точные копируемые команды (`zsh`/иногда Bash), закреплённый SHA, и явные ожидаемые строки PASS. В выводе пользователя **нельзя домысливать непоказанные PASS**.

**Текст для вставки в новый чат:**

> Продолжаем разработку Jend в https://github.com/vfgfgfbs56/jend. Сначала прочитай https://github.com/vfgfgfbs56/jend/blob/feat/m8.5.15.6b1-file-open-denial-security-register/JEND-PROJECT-CONTEXT.md и проверь текущие GitHub PR/CI. Это основной контекст целей, уже выполненных тестов, ограничений безопасности, очереди работ и критериев завершения архитектуры. Продолжай от актуальной верхней ветки, обнови этот файл вместе с изменениями; не сливай PR без моего разрешения.

## 1. Что мы строим и чего НЕ строим

**Jend = универсальный безопасный интерфейс для множества существующих узнаваемых AI-моделей**, которые пользователь выбирает, устанавливает и переключает из одного приложения. **Не создавать собственную foundation model**, не привязываться навсегда к Hugging Face и не содержать центральный склад терабайтов всех моделей.

- Локальные модели — если доступны веса, совместимый backend, аппаратные ресурсы и допустимая лицензия. Закрытые модели без весов **не могут честно рекламироваться как локальные**; будущий optional remote/BYOK режим потребует явного согласия и отдельной политики приватности/оплаты.
- Поддерживаемые платформы по плану: **Windows x64/ARM64, Linux x64/ARM64, macOS Intel/Apple Silicon, Android ARM64, iOS/iPadOS ARM64**. Пока подтверждён лишь **IPC protocol proof на пяти desktop CI** и кросс-компиляция parser на Android/iOS. Это **не доказательство готового инференса или мобильного приложения**.
- Слабые устройства: выбирать совместимую **существующую** модель/квантование, ограничивать контекст, KV-cache, RAM/VRAM и потоковые задачи. SSD и маленький WeightVM cache **не превращают большую плотную модель в быструю маленькую модель**.
- C/C++ для нативных движков и вычислительных ядер; Rust для доверия, сети, подписей, управления и политик; Objective-C/Objective-C++ для Apple APIs/Metal; ARM NEON/SIMD/Assembly — **после измерений**, в изолированных hot loops. Собственный полный язык программирования **не нужен**; возможен только ограниченный декларативный формат совместимости.
- Hugging Face/Xet — **необязательный источник**, не обязательная платная API-инфраструктура. Реальные скачивания могут иметь расходы/лимиты и лицензии; не использовать один личный HF token для миллионов пользователей. Проверенные страницы могут приходить от разных разрешённых источников, но проверка всегда идёт по **одному независимо подписанному** ожидаемому хешу.
- Никакой внезапной передачи приватных чатов в сеть; никакой «тихой» подмены локального инференса удалённым API; E2EE ключи/чаты и пользовательские секреты недоступны source-worker, скачанным моделям и нативным вычислительным backend.

Базовый архитектурный ADR: [ADR-0014 Universal Model Runtime and WeightFabric](docs/ADR-0014-UNIVERSAL-MODEL-RUNTIME-AND-WEIGHTFABRIC.md). Старое направление M7.13 «только Jend-native models» **продуктово заменено**, но существующие закрытые режимы и security gates не отключать без отдельной проверки.

## 2. Архитектура — целевые границы

```text
Единый Jend UI: каталог / установка / чат / переключение моделей
  -> Rust Orchestrator: device profiler, лицензии, RAM/budget, consent
      -> Signed model/catalog release metadata + pinned trust roots
      -> WeightFabric resolver: проверенный CAS -> разрешённый upstream
           -> ограниченные seeds -> OPTIONAL, opt-in public-weight peers
      -> Source-worker: TLS/HTTP/Xet, bounded bytes, никакой власти над хешами
      -> Existing Jend release signatures + exact SHA-256/length
      -> Local verified CAS / WeightVM / approved read-only artifact handles
      -> Attested and OS-sandboxed runtime (GGUF/llama.cpp CPU first)
      -> Streamed local output -> Jend UI
OPTIONAL REMOTE: только отдельная явная сессия BYOK/провайдера и согласие
```

**Неприкосновенные границы:**
1. Signing key/trust root должен быть утверждён **независимо от скачанного файла**; нельзя просто скачать модель, самим вычислить SHA-256 и подписать тестовым ключом, затем объявить её достоверной.
2. Подписанные SourceMap/VirtualMap/ModelManifest, полный и покусковой SHA-256, точный размер и проверка после копирования; скачанный транспорт не решает, что считать доверенным.
3. Проверенные байты **не дают права исполнять нативный код**. Требуются неподменяемый источник байтов/handle, заверенный worker binary, sandbox, квоты CPU/RAM/времени и полноценная проверка GGUF структур/архитектуры.
4. `safetensors` = безопасный формат тензоров, **не** готовый runtime; GGUF не гарантирует поддержку любой архитектуры; ONNX — отдельный движок и набор операторов.
5. P2P только добровольно, только **публичные** веса, с предупреждением об IP-адресе, мобильном трафике и батарее. Без P2P доступность моделей потребует хотя бы одну полную доступную копию где-то; нельзя обещать нулевые расходы на трафик.
6. Реальная портируемость = собственные native адаптеры и профили безопасности по OS, не один desktop executable на iPhone/Android.

## 3. Подтверждено (никогда не повышать статус без доказательств)

**Mac M8.5.15.6c — пользователь подтвердил 2026-10-14:** ровно 2 показанные PASS: `unsupported platform refused before worker access` и `grants no production inference capability`. Это корректный отказ, **не macOS sandbox**.

**Mac M8.5.15.6d — пользователь подтвердил 2026-10-15:** ровно 2 показанные строки: `Jend sealed GGUF handoff unsupported host refused: PASS` и `Jend sealed GGUF handoff still grants no inference: PASS`. Проверка дана для инструкций на `4f96e06d3b086e06dd1a0346d3dcb7c42a2ccf11`; пользователь также прислал 6 Rust warnings о Linux-only imports/переменной. Это отказ Linux-only handoff, не доказательство macOS isolation или inference.

**M8.5.15.6d.1 — текущая поправка:** Linux-only imports и чтение argv перенесены в Linux scope обоих smoke binaries; snapshot receipt явно освобождается на пути отказа. Desktop matrix компилирует каждый бинарник с `-D unused-imports -D unused-variables`; warnings не подавляются. Gate покрывает Linux x64/ARM64, macOS Intel/Apple Silicon и Windows x64. Поведение запуска/изоляции не расширяется. CI нового кода пока ожидается; следующий архитектурный этап остаётся M8.5.15.6e.

**PR #19 финальный head `c594803bfd542bbb66b58a86e336f128eb25f265`:** все 8 CI checks повторно проверены PASS: [Rust](https://github.com/vfgfgfbs56/jend/actions/runs/38605609540), [platform](https://github.com/vfgfgfbs56/jend/actions/runs/38605609537), [PostgreSQL](https://github.com/vfgfgfbs56/jend/actions/runs/38605609498). Draft, не слит.

**Текущий M8.5.15.6d:** immutable NX/O_RDONLY GGUF data capability, final signed header/chunk/whole rehash, fixed FD 4 handoff, no executable mappings. Только synthetic data / no inference. Финальный код `f8dd341f3391c323681fd71645dc2ba471206df5` проверен: [Rust + copy-race tests](https://github.com/vfgfgfbs56/jend/actions/runs/38614413677), [platform matrix](https://github.com/vfgfgfbs56/jend/actions/runs/38614413779), [PostgreSQL](https://github.com/vfgfgfbs56/jend/actions/runs/38614413840) — 8/8 checks PASS. Linux по 9 sealed-data PASS + 11 launch PASS, Mac/Windows по 2 data refusal PASS. NX GNU_STACK, personality reset/query-only и запрет READ_IMPLIES_EXEC подтверждены constructor + signed ELF negative tests. Receipt header теперь получен из того же signed hash stream без повторного чтения; deceptive-reader и copy-race regressions PASS, 88 model-store unit tests PASS. Следующий commit меняет только docs/manifest; код совпадает с проверенным SHA. Проверять текущий head CI. [Design](docs/M8.5.15.6D-SEALED-GGUF-DATA-HANDOFF.md), [очередь security gates](docs/JEND-NATIVE-SECURITY-PLAN.md).

**M8.5.15.6c / PR #19 — подтверждённый CI baseline `ee6135b024e545ce03b915eebefd5a55cabf74a6`:** все 8 checks PASS: [Rust + workspace/security](https://github.com/vfgfgfbs56/jend/actions/runs/38604828773), [desktop matrix + mobile parser](https://github.com/vfgfgfbs56/jend/actions/runs/38604829162), [PostgreSQL](https://github.com/vfgfgfbs56/jend/actions/runs/38604829068). Linux x64/ARM64 — **10 trusted launch PASS**, 6 smoke unit tests: signed accepted head/profile, sealed FD exec, атаки в constructor до main, env/FD/parent mapping removal, RAM/CPU/time/output bounds и kill/reap. macOS Intel/Apple Silicon и Windows — **2 refusal PASS**, не sandbox этих OS. Усиления тестов ET_EXEC + PT_INTERP, portable synthetic canary, exact CPU kill и ECHILD handling также подтверждены на этом SHA. Последующий коммит обновляет только документы/manifest; исходники launcher совпадают с проверенным кодом. Перед новым действием проверить CI текущего head. [Design / blockers](docs/M8.5.15.6C-TRUSTED-NATIVE-LAUNCH.md). Пользовательский Mac 6c refusal 2 PASS теперь подтверждён; реального inference нет.

**PR #18, актуальный SHA `a2409472ff8564d0eb83338f00cdd145ac1fb81b`:** проверено 2026-10-14 — все 8 checks PASS: [Rust](https://github.com/vfgfgfbs56/jend/actions/runs/38598965075), [desktop + mobile parser CI](https://github.com/vfgfgfbs56/jend/actions/runs/38598965204), [PostgreSQL](https://github.com/vfgfgfbs56/jend/actions/runs/38598964967). Это предыдущий worker-side scrub, а не ограничения до запуска C++. Все 19 milestone PR открыты; merge не выполнен.

**Mac Apple Silicon — пользователь сообщил:**
- M8.5.12: реальный HF/Xet singleton HTTP 206 + физическая→логическая реконструкция 1 МиБ и отсутствие непроверенных данных в WeightVM — **3 PASS**. Сетевой multipart и более одного signed entry — **NOT_EXERCISED**.
- M8.5.13: офлайн signed Xet page admission — **6 PASS** (эпhemeral test signing key / synthetic bytes).
- M8.5.14: планировщик RAM/SSD/форматов — **6 PASS**; это оценка ресурсов, не inference.
- M8.5.15: протокольный C++ worker — **5 PASS**; real GGUF НЕ исполнялся.
- M8.5.15.1: пользователь прислал **6 Rust supervisor PASS**; строка C++ trailing-data в этом сообщении не показана, не подменять её фактом персонального Mac-теста.
- M8.5.15.2: переносимый C++/Rust protocol proof на `Darwin arm64 Python 3.14.8` — **7 PASS**. CI: Linux x64/ARM64, macOS Intel/Apple Silicon, Windows x64 protocol — PASS; iOS/Android ARM64 **только parser cross-compile**.
- M8.5.15.3: independently signed complete GGUF stream/hash inspection — **6 PASS**.
- M8.5.15.4 + M8.5.15.5: пользователь выполнил общий smoke на Mac — **10 PASS**, включая независимую подпись и snapshot (6), открытый дескриптор и повторное хеширование (4). **Это тест синтетического GGUF и не реальный инференс.**

**PR #18 / M8.5.15.6b.2** — GitHub CI **PASS**, Mac ещё НЕ тестировался:
- [Rust workspace и Linux native seccomp smoke](https://github.com/vfgfgfbs56/jend/actions/runs/38598108598) — PASS.
- [Native IPC portability](https://github.com/vfgfgfbs56/jend/actions/runs/38598108555) — все 6 jobs PASS: Linux x64/ARM64 реально подтвердили закрытие synthetic FD через `close_range`, очистку synthetic env, отказ fake FD; оба Mac и Windows отказали в Linux sandbox.
- [PostgreSQL security](https://github.com/vfgfgfbs56/jend/actions/runs/38598108461) — PASS.
- **JSEC-001 НЕ закрыт:** это эксперимент внутри запущенного бинарника, не безопасный trusted parent launcher и не OS enforcement на Mac/Windows.

**PR #17 / M8.5.15.6b.1** — GitHub CI **PASS** и Mac **5 PASS** подтверждены пользователем:
- Linux x64/ARM64 kernel-filter smoke реально подтвердил `EPERM` для новых файлов и fork; Windows/macOS отказали в неподдерживаемом Linux sandbox.
- Пять Mac PASS: компиляция, unsupported sandbox refused, отсутствие canary denied, native model execution disabled, отсутствие полной E2EE isolation.
- [JEND-SECURITY-REGISTER.md](JEND-SECURITY-REGISTER.md) — риски Critical/High и требование NO-GO до backend security acceptance.

**PR #16 / M8.5.15.6b** — GitHub CI **PASS**, Mac **4 PASS** подтверждены пользователем:
- [Rust и Linux seccomp smoke](https://github.com/vfgfgfbs56/jend/actions/runs/38456389618) — PASS. На Ubuntu реально установлены seccomp/no-new-privs/rlimits и сетевой socket отказал с EPERM.
- [Native IPC portability matrix](https://github.com/vfgfgfbs56/jend/actions/runs/38456389587) — все 6 jobs PASS: Linux x64/ARM64 kernel-probe, Windows и оба Mac корректно отклоняют неподдерживаемый Linux sandbox, iOS/Android только cross-compile протокола.
- [PostgreSQL security](https://github.com/vfgfgfbs56/jend/actions/runs/38456389693) — PASS.
- ВАЖНО: seccomp **не изолирует filesystem/E2EE**, не применяется к настоящему GGUF inference, не реализует полноценный OS sandbox на Mac/Windows и не делает worker production-ready.

**PR #15 / M8.5.15.6a** — CI **PASS**, Mac 6 PASS подтверждены пользователем:
- [Rust + 6 native binary integrity smoke PASS](https://github.com/vfgfgfbs56/jend/actions/runs/38453537643) — прошли exact SHA-256, чужой digest, изменённый бинарник, size/path preflight, model-free IPC и отсутствие права production execution.
- [Native IPC platform CI](https://github.com/vfgfgfbs56/jend/actions/runs/38453537749) — 6 jobs PASS (desktop и мобильная cross-compile).
- [PostgreSQL security](https://github.com/vfgfgfbs56/jend/actions/runs/38453537545) — PASS.
- **Mac M8.5.15.6a: 6 PASS подтверждены пользователем**: exact worker SHA-256, неверный pin, испорченный бинарник, размер/путь, protocol-only IPC и отсутствие production sandbox. Для теста expected digest получен из локально собранного бинарника — это НЕ выпуск, подписанный доверенным Jend distributor. Полный OS sandbox, race-free exec и реальный инференс остаются BLOCKED.

**PR #14 / M8.5.15.5**: GitHub CI уже **PASS**:
- [Rust + pinned open-handle smoke](https://github.com/vfgfgfbs56/jend/actions/runs/38451463930) — 10 PASS в CI.
- [Native IPC platform CI](https://github.com/vfgfgfbs56/jend/actions/runs/38451463874) — 6 jobs PASS (5 desktop + mobile compile).
- [PostgreSQL smoke](https://github.com/vfgfgfbs56/jend/actions/runs/38451463814) — PASS.
- **Mac M8.5.15.4–15.5: 10 PASS от пользователя подтверждены**. Но нельзя считать дескриптор неизменяемым при записи в тот же inode, native OS sandbox или инференсом реальной модели.

Проверенный тест M8.5.15.4–15.5 на Mac:

```bash
cd ~/Downloads
git clone --branch feat/m8.5.15.5-pinned-gguf-file-handle --single-branch https://github.com/vfgfgfbs56/jend.git jend-m8.5.15.5-test
cd jend-m8.5.15.5-test
cargo generate-lockfile
bash scripts/dev-verified-gguf-snapshot-smoke.sh
```

Ожидаемые 6 строк snapshot (дополнительно 4 pinned-handle PASS):
```text
Jend GGUF independent release signature to private snapshot: PASS
Jend GGUF source mutation cannot modify verified copy: PASS
Jend GGUF different release key rejected before staging: PASS
Jend GGUF corrupted copy leaves no published or staged file: PASS
Jend GGUF explicit snapshot size budget enforced: PASS
Jend GGUF snapshot grants no native execution capability: PASS
```

## 4. GitHub PR stack (ВСЕ открыты на 2026-10-14; проверить заново)

Все PR **stacked**, каждый зависит от предыдущего; без разрешения пользователя **не merge**.

| Очередь | PR | Что содержит |
|---|---|---|
| 1 | [#1](https://github.com/vfgfgfbs56/jend/pull/1) | восстановить Rust workspace, manifest, CI (base main) |
| 2 | [#2](https://github.com/vfgfgfbs56/jend/pull/2) | M8.5.9 строгий Xet multipart |
| 3 | [#4](https://github.com/vfgfgfbs56/jend/pull/4) | M8.5.10 bounded signed HTTP multi-range |
| 4 | [#5](https://github.com/vfgfgfbs56/jend/pull/5) | M8.5.11 Xorb decode, live multipart не проверен |
| 5 | [#6](https://github.com/vfgfgfbs56/jend/pull/6) | M8.5.12 live singleton fetch |
| 6 | [#7](https://github.com/vfgfgfbs56/jend/pull/7) | M8.5.13 signed WeightPage gate |
| 7 | [#8](https://github.com/vfgfgfbs56/jend/pull/8) | M8.5.14 универсальные модели + feasibility |
| 8 | [#9](https://github.com/vfgfgfbs56/jend/pull/9) | M8.5.15 C++/llama.cpp dev worker |
| 9 | [#10](https://github.com/vfgfgfbs56/jend/pull/10) | M8.5.15.1 Rust IPC supervisor |
| 10 | [#11](https://github.com/vfgfgfbs56/jend/pull/11) | M8.5.15.2 portability |
| 11 | [#12](https://github.com/vfgfgfbs56/jend/pull/12) | M8.5.15.3 signed GGUF intake |
| 12 | [#13](https://github.com/vfgfgfbs56/jend/pull/13) | M8.5.15.4 private verified snapshot — предыдущий этап |
| 13 | [#14](https://github.com/vfgfgfbs56/jend/pull/14) | M8.5.15.5 same-open-handle signed GGUF rehash, Mac 10 PASS; ещё не immutable OS backing |
| 14 | [#15](https://github.com/vfgfgfbs56/jend/pull/15) | M8.5.15.6a worker SHA-256, CI и Mac 6 PASS; NO production attestation / sandbox |
| 15 | [#16](https://github.com/vfgfgfbs56/jend/pull/16) | M8.5.15.6b Linux-only seccomp/rlimit protocol probe; macOS/Windows reject; никакого реального GGUF запуска |
| 16 | [#17](https://github.com/vfgfgfbs56/jend/pull/17) | M8.5.15.6b.1 deny new file opens / fork EPERM + Security Register, Mac 5 PASS; НЕ production sandbox |
| 17 | [#18](https://github.com/vfgfgfbs56/jend/pull/18) | M8.5.15.6b.2 закрытие унаследованных synthetic FDs и environment в Linux dev-only probe; НЕ production sandbox |
| 18 | [#19](https://github.com/vfgfgfbs56/jend/pull/19) | M8.5.15.6c trusted Rust до exec + signed sealed static binary; Linux 10 PASS, Mac/Windows refusal; draft, production BLOCKED |
| 19 | [#20](https://github.com/vfgfgfbs56/jend/pull/20) | M8.5.15.6d sealed signed GGUF DATA FD 4, final hash/copy-race tests; draft, no inference |

## 5. Очередь задач — последовательность и условия допуска

### СЕЙЧАС
- [x] M8.5.15.6d: Linux x64/ARM64 — 9 sealed-data + 11 launch PASS, constructor/read-only/mmap/stack/personality, copy race/source mutation; Mac/Windows refusal 2 PASS. Synthetic DATA only, не настоящая модель. Пользовательский Mac 6d: ровно 2 refusal/no-inference PASS подтверждены 2026-10-15.
- [ ] M8.5.15.6d.1: проверить строгую компиляцию двух smoke binaries на пяти desktop runners, прежние launch/data tests и workspace/security CI; не считать новую поправку подтверждённой до лога CI.
- [ ] Далее M8.5.15.6e: bounded full GGUF pre-parser + IPC fuzz; trust enrollment/OS compartments/other-OS adapters — отдельные обязательные gates. [План](docs/JEND-NATIVE-SECURITY-PLAN.md).
- [x] M8.5.15.6c model-free Linux baseline: signed accepted release + sealed static ELF + trusted pre-exec Landlock/seccomp, constructor attacks и bound/kill/reap — Linux x64/ARM64 CI 10 PASS, Mac/Windows отказ 2 PASS; проверить CI последнего head. Реальный GGUF, production trust, отдельная OS identity и fuzz ещё BLOCKED.
- [x] M8.5.15.3: signed whole GGUF + тест Mac 6 PASS.
- [x] M8.5.15.4: private snapshot — CI PASS и Mac 6 PASS в составе общего теста.
- [x] M8.5.15.5: Mac **10 PASS** (включая 4 дескрипторные проверки) и GitHub CI PASS.
- [ ] Сверить текущие PR CI, review, mergeability; не путать PR #14/#15 с main.
- [ ] Проверить fail-closed snapshot store под **Windows ACL**, непредвиденные права родителей, TOCTOU/cache poisoning, падения и конкуренцию, fuzz/path traversal.
- [ ] Не включать нативную загрузку GGUF до прочного trust/sandbox gate.
- [x] M8.5.15.6a: CI SHA-256 binary integrity smoke 6 PASS, portability и PostgreSQL PASS.
- [x] M8.5.15.6a: Mac **6 PASS** подтверждены пользователем; это не OS sandbox и не production exec.
- [x] M8.5.15.6b: Linux x64/ARM64 seccomp kernel probe и macOS/Windows fail-closed refusal в CI PASS.
- [x] M8.5.15.6b: пользовательский Mac smoke **4 PASS** — компиляция, корректный отказ Linux sandbox на Mac, блокировка native inference, явное отсутствие FS/E2EE isolation.
- [x] M8.5.15.6b.1: Linux x64/ARM64 CI EPERM на openat/fork PASS и Mac **5 PASS** подтверждены пользователем (Mac sandbox отсутствует).
- [x] M8.5.15.6b.2: Linux x64/ARM64 `close_range`, `clearenv`, fake-FD rejection, seccomp проверены GitHub CI PASS; desktop matrix и PostgreSQL PASS.
- [ ] M8.5.15.6b.2: пользовательский Mac smoke — ещё не подтверждён; на Mac требуется fail-closed отказ в Linux sandbox, не поддержка sandbox.
- [ ] Модель рисков [JEND-SECURITY-REGISTER.md](JEND-SECURITY-REGISTER.md): проверить все Critical/High до `Backend & Security Ready`; протоколы и CI PASS не доказывают отсутствие остальных уязвимостей.
- [ ] Backend & Security Ready gate: завершить отдельно после Architecture v1 freeze, перед основным frontend; детали в §6.

### СЛЕДУЮЩИЕ ИНЖЕНЕРНЫЕ ЭТАПЫ (план, названия предварительные)
- **M8.5.15.5 — pinned open-file identity (Mac 10 PASS):** один открытый дескриптор с подписью/повторным хешем; Unix inode/dev check, отклонение pathname substitution, same-inode mutation rehash. **Не immutable**: OS-protected sealed backing + safe native handoff остаются в дальнейшем security gate; Windows ACL/handle sharing, Android/iOS отдельно.
- **M8.5.15.6a — native executable integrity preflight (в работе):** bounded streaming SHA-256 native worker binary против *независимо закреплённой* ожидаемой суммы; offline synthetic/dev fixture only, **не** доверенная подпись дистрибутива и **не** race-free exec.
- **M8.5.15.6b — Linux restricted-process security probe (в работе):** Linux C++ prototype actually applies no-new-privs/seccomp for test-only command, denies AF_INET sockets and new child processes, caps CPU/RAM/fds/core. macOS and Windows MUST refuse rather than advertise a sandbox. Это только ограниченная syscall изоляция, доступ к файлам/E2EE НЕ изолирован.
- **M8.5.15.6b.1 — ограниченный Linux file-open denial (в работе):** тестовый seccomp отвергает новые `open/openat/openat2`, некоторые операции изменения путей и fork; реальный `EPERM` нужен в CI. Унаследованные FD, E2EE и доступ к filesystem до установки фильтра остаются проблемой. Новые Critical/High риски фиксировать в `JEND-SECURITY-REGISTER.md`.
- **M8.5.15.6b.2 — inherited test FD and environment scrub (в работе):** Linux test mode требует реально переданный безвредный FD, использует `close_range` и `clearenv` до seccomp, fail-closed без syscall/FD; Linux kernel security proof, Mac/Windows refusal. **Не является trusted launcher:** исполняемый файл может прочитать данные до очистки, stdio остаётся; секреты не передавать. JSEC-001 остаётся Critical.
- **M8.5.15.6c — trusted pre-exec launch (текущий Linux model-free этап):** существующий signed Jend release gate (builder + approver, exact accepted head/kind/host profile), immutable sealed executable memfd и FD exec; Rust устанавливает clean stdio/empty env, Landlock, default-deny seccomp и quotas до C++ constructor. CI baseline подтверждён, проверять актуальный head; [design / ограничения](docs/M8.5.15.6C-TRUSTED-NATIVE-LAUNCH.md). **Следующий gate:** независимые production root enrollment/revocation, отдельная OS identity и защита от same-UID debugger, sealed GGUF handoff, fuzz IPC/GGUF и native Apple/Windows/mobile adapters. Linux syscall proof не даёт права production inference.
- **M8.5.15.6d — sealed GGUF DATA (в работе):** проверенные same-open bytes копируются в sealed NX backing, финально проверяются и передаются только через O_RDONLY FD 4 под pre-exec policy; synthetic header-only, no inference.
- **M8.5.15.6e — следующий этап:** полный bounded GGUF structural parser, FD-native backend contract и IPC/GGUF fuzz, отдельная проверка моделей/ресурсов; не ослаблять sandbox ради запуска backend.
- **M8.5.15.7 — первый реальный GGUF CPU fixture:** законно полученная маленькая **сторонняя** модель, независимо опубликованный digest + проверенные лицензия и цепочка подписанного Jend release metadata; реальная локальная генерация, токены/s, first-token latency, peak RSS на ARM64 и x64, не использовать секреты.
- **M8.5.16 — architecture v1 freeze + multi-model catalog:** утверждённый signed variant schema, versioned backend ABI, раздельные runtime adapters, 2+ существующие model families, multi-source WeightFabric/cache/mirror fallback (по лицензии), trust-root enrollment, rollback/revocation/update policy, ясный UI local/remote и требования ко всем целевым платформам. **Не заявлять поддержку формата без рабочего backend.**
- **M8.6 — backend/security integration:** настоящий проверенный GGUF execution baseline, модельные lifecycle API, OS isolation, persisted release trust, multi-origin download quotas и отказоустойчивость, кроссплатформенные тесты. GPU/Metal/ONNX/мобильное расширение выполняются по приоритету, не должны искусственно блокировать базовый API-контракт.
- **M8.7 — Backend & Security Ready (плановый checkpoint):** security review, интеграционные тесты и acceptance report; после этого начинаем основную реализацию frontend. Номер предварительный, календарной даты нет; незакрытый обязательный blocker = NO-GO.
- **Позже** — opt-in P2P/public-weight sharing, BYOK/remote provider, availability/cost analysis, feature flags and audits.

## 6. Когда именно заканчиваем backend и переходим к frontend?

**Уточнение цели от владельца проекта (2026-10-13):** «закончить разработку» означает **довести безопасность, backend и основные архитектурные механизмы до проверенной готовности, ЧТОБЫ ПЕРЕЙТИ К полноценной frontend-разработке**. НЕ означает закончить весь Jend, обучить свою модель или выпустить production-продукт.

Нужно различать **три** рубежа:

1. **Architecture v1 Design Freeze** — ориентир **M8.5.16**: принято решение о форматах подписанных моделей, протоколах, runtime adapter ABI, безопасной доставке, разрешениях, поддерживаемых OS и устройстве UI/API контрактов. *Дизайн зафиксирован, backend ещё не объявлен готовым.*
2. **Backend & Security Ready (frontend start gate)** — отдельный checkpoint после реально работающих backend-потоков, закрытия обязательных security blockers и проверки интеграционных контрактов (предварительно M8.7 после интеграции M8.6). Только после его PASS начинаем **основную** реализацию frontend пользовательского сервиса. Ранние UX-макеты, прототипы и совместное проектирование API **разрешены раньше**.
3. **Product Release** — после frontend, end-to-end пользовательских сценариев, полевых и мобильных тестов, эксплуатационной подготовки и независимого внешнего аудита по требованиям релиза. Не смешивать с backend gate.

**Перед переходом к frontend все критические/высокие риски из [JEND-SECURITY-REGISTER.md](JEND-SECURITY-REGISTER.md), включённые в релизный scope, должны быть закрыты проверяемыми mitigation и тестами; обещание «нулевые уязвимости» некорректно.**

**Обязательные условия Backend & Security Ready** (каждое подтверждено тестом, ревью и ссылкой; незакрытый пункт блокирует переход):
- [ ] Доверенные publisher/Jend-distributor root keys зарегистрированы независимо от источника байтов; подписи catalog/variant/model, key rotation, revocation, rollback/freeze защита и проверенный алгоритм обновлений.
- [ ] Безопасная доставка signed pages/models и локальный verified CAS: source-worker без E2EE ключей, защита SSRF/redirect/grants, resume, immutable artifact identity, quotas/timeouts, crash recovery, cache poisoning & TOCTOU negative tests.
- [ ] Настоящая licensed сторонняя GGUF-модель и tokenizer/config проверены независимо от сети и генерируют токены локально через **OS-sandboxed, binary-attested** CPU native engine; сеть запрещена, RAM/CPU/fd/timeout/cancel ограничены; нет произвольного загружаемого кода.
- [ ] Backend API/IPC контракты для model list/install/status/cancel/delete/select/generate, модельных ресурсов, контекстов, прав на чаты/инструменты, ошибок и событий описаны, версионированы и покрыты контрактными тестами. Frontend может использовать тестовый backend/stub, не ломая безопасность.
- [ ] Безопасность E2EE и vault на границе AI подтверждена: нет тихого remote inference, приватный plaintext не попадает в registry/logs/peers, действия AI требуют явных user capabilities, критические тесты и threat model актуальны.
- [ ] Реальные интеграционные тесты на поддерживаемой минимальной desktop конфигурации (Linux, Windows, macOS x64/ARM64 — с честно указанным coverage); строгие compatibility и low-RAM ограничения; реальные измерения качества/latency/RSS; для неподдержанной platform отдельный отказ и путь расширения. Android/iOS не рекламировать как готовые до приложения, подписи и реальных device-tests.
- [ ] Независимая security-review процедура для ключевых trust boundaries, dependency/worker pin, supply-chain, CI, отказоустойчивость, recovery/updates; high/critical findings устранены или release scope явно заблокирован.
- [ ] Все предыдущие milestone PR пересмотрены, integration plan записан, безопасность подтверждена на том коде, с которым будет соединяться frontend.

**НЕ должны блокировать ранний основной frontend для desktop v1, если не включены в v1:** собственная foundation model, собственный язык программирования, P2P, платный remote API, тысячи моделей, каждый GPU/ISA backend, все мобильные устройства сразу. Они могут поставляться позже как подписанные/версионированные дополнительные адаптеры. Но их **не включать и не рекламировать как готовые**, пока не реализованы и не протестированы.

**Дата завершения пока не установлена.** Следующий PR должен показывать закрытые/открытые blockers и следующий gate, а не назначать необоснованный дедлайн. Перейти к frontend по факту доказанной готовности backend/security, а не по номеру M8.x или количеству PASS на синтетических файлах.

## 7. Как ОБЯЗАТЕЛЬНО поддерживать этот файл актуальным

Этот документ должен быть **единственным стартовым контекстом нового чата**. Автор каждого следующего PR/существенного коммита:
1. Обновляет дату и текущую рабочую ветку/PR; факты о CI только после проверки на GitHub.
2. Переносит реальные завершённые пункты из **«План» в «Подтверждено»** с указанием платформы и типа проверки. Не ставит PASS без лога или сообщения пользователя.
3. Добавляет/переупорядочивает следующий шаг, исправляет blockers, сроки/gates, ссылки на решения и PR chain.
4. Обновляет `JEND-SECURITY-REGISTER.md` для security-sensitive изменений и `PROJECT-MANIFEST.sha256` после всех изменений.
5. Проверяет `scripts/check-project-context-update.py`, `scripts/static-preflight.py`, `scripts/verify-manifest.py` и CI. **Любой security-sensitive PR обязан также обновить `JEND-SECURITY-REGISTER.md`; CI должен блокировать забытый review.** **Новый PR с исходниками/CI/docs без изменения этого файла должен блокироваться CI**. Если изменений только в памятке/манифесте, gate допускает.
6. После слияния stacked веток обновляет ссылку на активную версию (`main` или верхний текущий PR), статус PR и порядок merge.

**Ограничение:** GitHub CI может требовать документ при изменениях, но **не напишет правильные факты и план самостоятельно**. Следующий ассистент/разработчик должен актуализировать содержимое, проверять PR и запускать тесты. Файл не является фоновым агентом.

## 8. Чего избегать

Не вводить токены HF/GitHub в чат, git, stdout или логи. Не сливать без просьбы. Не объявлять модель «доверенной» на основании хеша, который она принесла сама. Не обещать 7B на 64 MiB RAM из-за подкачки. Не выдавать synthetic/header-only PASS за реальный inference. Не подразумевать что протокол на Windows = безопасный production sandbox или что Rust parser cross-compile = iPhone приложение.

Исторические технические источники в репозитории: [ADR-0014](docs/ADR-0014-UNIVERSAL-MODEL-RUNTIME-AND-WEIGHTFABRIC.md), [M8.5.15.3 signed GGUF](docs/M8.5.15.3-SIGNED-GGUF-WHOLE-INPUT.md), [M8.5.15.4 verified snapshot](docs/M8.5.15.4-VERIFIED-GGUF-SNAPSHOT.md).
