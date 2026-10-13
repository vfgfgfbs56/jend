# JEND — PROJECT CONTEXT & ROADMAP (памятка для нового чата)

> **Обновлено:** 2026-10-13. **Текущий этап:** M8.5.15.4.  
> **Основная ветка разработки:** `feat/m8.5.15.4-verified-gguf-snapshot`, [PR #13](https://github.com/vfgfgfbs56/jend/pull/13).  
> **Статус:** прототипы проверки/хранения моделей и взаимодействия Rust/C++; **реальный безопасный инференс сторонней модели в Jend пока НЕ реализован**.  
> **Важно:** этот файл — редактируемый снимок на момент коммита, не автоматически обновляемые сведения о GitHub. Перед новым действием перечитать его и **проверить актуальное состояние PR, веток и CI**.

## Как продолжать в новом чате (прочитать прежде, чем действовать)

1. Открыть **именно этот файл из последней рабочей ветки**:
   [JEND-PROJECT-CONTEXT.md — актуальная ветка](https://github.com/vfgfgfbs56/jend/blob/feat/m8.5.15.4-verified-gguf-snapshot/JEND-PROJECT-CONTEXT.md).
   После слияния прочитать версию на `main`:
   `https://github.com/vfgfgfbs56/jend/blob/main/JEND-PROJECT-CONTEXT.md`.
2. Проверить [открытые PR](https://github.com/vfgfgfbs56/jend/pulls), их **базы**, последние SHA, CI и отсутствие конфликтов. Не предполагать, что все ранее открытые PR уже слиты.
3. Воспринимать раздел «Подтверждено» как факты, «План» — как **не реализованные** задачи. Не считать PASS для синтетического теста доказательством настоящей нейросети.
4. При разработке: создать отдельную ветку от **актуального верхнего PR**, внести код и tests, обновить **этот** файл, обновить `PROJECT-MANIFEST.sha256`, прогнать CI, открыть новый stacked PR; **ничего не сливать без прямого разрешения пользователя**.
5. Пользователь тестирует на Mac, обычно в `~/Downloads`; нужны точные копируемые команды (`zsh`/иногда Bash), закреплённый SHA, и явные ожидаемые строки PASS. В выводе пользователя **нельзя домысливать непоказанные PASS**.

**Текст для вставки в новый чат:**

> Продолжаем разработку Jend в https://github.com/vfgfgfbs56/jend. Сначала прочитай https://github.com/vfgfgfbs56/jend/blob/feat/m8.5.15.4-verified-gguf-snapshot/JEND-PROJECT-CONTEXT.md и проверь текущие GitHub PR/CI. Это основной контекст целей, уже выполненных тестов, ограничений безопасности, очереди работ и критериев завершения архитектуры. Продолжай от актуальной верхней ветки, обнови этот файл вместе с изменениями; не сливай PR без моего разрешения.

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

**Mac Apple Silicon — пользователь сообщил:**
- M8.5.12: реальный HF/Xet singleton HTTP 206 + физическая→логическая реконструкция 1 МиБ и отсутствие непроверенных данных в WeightVM — **3 PASS**. Сетевой multipart и более одного signed entry — **NOT_EXERCISED**.
- M8.5.13: офлайн signed Xet page admission — **6 PASS** (эпhemeral test signing key / synthetic bytes).
- M8.5.14: планировщик RAM/SSD/форматов — **6 PASS**; это оценка ресурсов, не inference.
- M8.5.15: протокольный C++ worker — **5 PASS**; real GGUF НЕ исполнялся.
- M8.5.15.1: пользователь прислал **6 Rust supervisor PASS**; строка C++ trailing-data в этом сообщении не показана, не подменять её фактом персонального Mac-теста.
- M8.5.15.2: переносимый C++/Rust protocol proof на `Darwin arm64 Python 3.14.8` — **7 PASS**. CI: Linux x64/ARM64, macOS Intel/Apple Silicon, Windows x64 protocol — PASS; iOS/Android ARM64 **только parser cross-compile**.
- M8.5.15.3: independently signed complete GGUF stream/hash inspection — **6 PASS**, и пользователь **повторно прислал эти же 6 PASS** в последнем сообщении. Они **НЕ означают выполнение M8.5.15.4**.

**Последний верхний PR #13 / M8.5.15.4**: GitHub CI уже **PASS**:
- [Rust + новый snapshot smoke](https://github.com/vfgfgfbs56/jend/actions/runs/38446569781) — 6 новых PASS.
- [Native IPC platform CI](https://github.com/vfgfgfbs56/jend/actions/runs/38446569729) — 6 jobs PASS (5 desktop + mobile compile).
- [PostgreSQL smoke](https://github.com/vfgfgfbs56/jend/actions/runs/38446569592) — PASS.
- **Mac M8.5.15.4 snapshot smoke пользователем ПОКА НЕ подтверждён.** Программа копирует, проверяет и публикует под SHA-256 синтетическую копию GGUF, но **не выдаёт её за immutable ОС handle и не запускает модель**.

Тест M8.5.15.4 на Mac:

```bash
cd ~/Downloads
git clone --branch feat/m8.5.15.4-verified-gguf-snapshot --single-branch https://github.com/vfgfgfbs56/jend.git jend-m8.5.15.4-test
cd jend-m8.5.15.4-test
cargo generate-lockfile
bash scripts/dev-verified-gguf-snapshot-smoke.sh
```

Ожидаемые 6 строк:
```text
Jend GGUF independent release signature to private snapshot: PASS
Jend GGUF source mutation cannot modify verified copy: PASS
Jend GGUF different release key rejected before staging: PASS
Jend GGUF corrupted copy leaves no published or staged file: PASS
Jend GGUF explicit snapshot size budget enforced: PASS
Jend GGUF snapshot grants no native execution capability: PASS
```

## 4. GitHub PR stack (ВСЕ открыты на 2026-10-13; проверить заново)

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
| 12 | [#13](https://github.com/vfgfgfbs56/jend/pull/13) | M8.5.15.4 private verified snapshot — текущий верх |

## 5. Очередь задач — последовательность и условия допуска

### СЕЙЧАС
- [x] M8.5.15.3: signed whole GGUF + тест Mac 6 PASS.
- [x] M8.5.15.4: private snapshot — CI PASS.
- [ ] M8.5.15.4: **Mac 6 PASS** ещё не подтверждён пользователем.
- [ ] Сверить текущие PR CI, review, mergeability; не путать PR #13 с main.
- [ ] Проверить fail-closed snapshot store под **Windows ACL**, непредвиденные права родителей, TOCTOU/cache poisoning, падения и конкуренцию, fuzz/path traversal.
- [ ] Не включать нативную загрузку GGUF до прочного trust/sandbox gate.

### СЛЕДУЮЩИЕ ИНЖЕНЕРНЫЕ ЭТАПЫ (план, названия предварительные)
- **M8.5.15.5 — stable verified artifact handle:** достоверный read-only file descriptor / OS handle, повторная проверка именно этих байтов, защита от смены файла между проверкой и загрузкой; fail-closed на каждом OS. Android/iOS — отдельные mobile capability contracts.
- **M8.5.15.6 — sandboxed attested native worker:** pinned/verified worker binary, OS sandbox без сети и доступа к E2EE, ограничения RAM/CPU/fds/времени, kill descendants, fuzz IPC и GGUF pre-parser.
- **M8.5.15.7 — первый реальный GGUF CPU fixture:** законно полученная маленькая **сторонняя** модель, независимо опубликованный digest + проверенные лицензия и цепочка подписанного Jend release metadata; реальная локальная генерация, токены/s, first-token latency, peak RSS на ARM64 и x64, не использовать секреты.
- **M8.5.16 — architecture v1 freeze + multi-model catalog:** утверждённый signed variant schema, versioned backend ABI, раздельные runtime adapters, 2+ существующие model families, multi-source WeightFabric/cache/mirror fallback (по лицензии), trust-root enrollment, rollback/revocation/update policy, ясный UI local/remote и требования ко всем целевым платформам. **Не заявлять поддержку формата без рабочего backend.**
- **M8.6** — проверенная реальная execution/integration на поддерживаемых desktop OS, затем ускорение Apple Metal/Objective-C++, ARM NEON/Vulkan/CUDA и мобильные отдельные приложения; добавлять ONNX/safetensors-adapter по результатам совместимости, а не "поддерживаем всё".
- **Позже** — opt-in P2P/public-weight sharing, BYOK/remote provider, availability/cost analysis, feature flags and audits.

## 6. Когда архитектуру нужно закончить?

**Целевая точка «Architecture v1 / design freeze» — НЕ ПОЗЖЕ ЗАВЕРШЕНИЯ M8.5.16, ДО начала расширения M8.6 на множество моделей, GPU и мобильные релизы.** Это **плановый gate**, а не обещание календарной даты: точная дата ещё не согласована и **не должна выдумываться**. Если gate не выполнен — оставаться на безопасном прототипе, не объявлять архитектуру законченной.

Критерии завершения **дизайна v1** (каждый пункт должен иметь ADR, тест, ревью/CI или явное `BLOCKED`):
- [ ] Окончательно описаны доверенные корни, обновление/ротация ключей, отзыв, защита от rollback/freeze и подписи всех вариантов.
- [ ] Единый signed model catalog/variant contract: лицензия, provenance, format, architecture, quantization, tokenizer, memory budget, device/backend compatibility.
- [ ] Специфицированы и проверены immutable artifact handoff, source-worker и native worker OS-sandbox, отсутствие доступа к E2EE/сети.
- [ ] Заданы адаптеры Windows, Linux, macOS, Android, iOS и их ограничения, отдельно CPU baseline и SIMD/GPU dispatch.
- [ ] Спроектированы локальный verified CAS, multi-origin delivery, optional mirror/peer rules и эксплуатационный budget для миллиона пользователей; минимальный центральный storage без нереалистичного «0 bytes / 0 bandwidth».
- [ ] Описаны единый model switch/chat UI, разрешения на инструменты/файлы, explicit remote/BYOK privacy + cost boundary.
- [ ] Есть реальные end-to-end тесты не менее одной лицензированной внешней GGUF-модели с измерениями на ARM64/x64; все критические security gates проверены.
- [ ] Разобрана цепочка PR и архитектурные решения задокументированы, нет невыполненных blockers в заявленной v1 scope.

**«Архитектура зафиксирована» ≠ «продукт готов».** Production release разрешён только после реальных поддержанных модельных сценариев, независимого security review, мобильных/desktop OS тестов, настройки обновлений и эксплуатационных процедур.

## 7. Как ОБЯЗАТЕЛЬНО поддерживать этот файл актуальным

Этот документ должен быть **единственным стартовым контекстом нового чата**. Автор каждого следующего PR/существенного коммита:
1. Обновляет дату и текущую рабочую ветку/PR; факты о CI только после проверки на GitHub.
2. Переносит реальные завершённые пункты из **«План» в «Подтверждено»** с указанием платформы и типа проверки. Не ставит PASS без лога или сообщения пользователя.
3. Добавляет/переупорядочивает следующий шаг, исправляет blockers, сроки/gates, ссылки на решения и PR chain.
4. Обновляет `PROJECT-MANIFEST.sha256` после всех изменений.
5. Проверяет `scripts/check-project-context-update.py`, `scripts/static-preflight.py`, `scripts/verify-manifest.py` и CI. **Новый PR с исходниками/CI/docs без изменения этого файла должен блокироваться CI**. Если изменений только в памятке/манифесте, gate допускает.
6. После слияния stacked веток обновляет ссылку на активную версию (`main` или верхний текущий PR), статус PR и порядок merge.

**Ограничение:** GitHub CI может требовать документ при изменениях, но **не напишет правильные факты и план самостоятельно**. Следующий ассистент/разработчик должен актуализировать содержимое, проверять PR и запускать тесты. Файл не является фоновым агентом.

## 8. Чего избегать

Не вводить токены HF/GitHub в чат, git, stdout или логи. Не сливать без просьбы. Не объявлять модель «доверенной» на основании хеша, который она принесла сама. Не обещать 7B на 64 MiB RAM из-за подкачки. Не выдавать synthetic/header-only PASS за реальный inference. Не подразумевать что протокол на Windows = безопасный production sandbox или что Rust parser cross-compile = iPhone приложение.

Исторические технические источники в репозитории: [ADR-0014](docs/ADR-0014-UNIVERSAL-MODEL-RUNTIME-AND-WEIGHTFABRIC.md), [M8.5.15.3 signed GGUF](docs/M8.5.15.3-SIGNED-GGUF-WHOLE-INPUT.md), [M8.5.15.4 verified snapshot](docs/M8.5.15.4-VERIFIED-GGUF-SNAPSHOT.md).
