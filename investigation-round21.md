# Раунд 21: bearer-токен без поколения, гонка `/init` с границей tenant, механизм remap узла

Дата: 2026-10-18 по часовому поясу Europe/Moscow; приведённые события гостя помечены UTC. Главный новый источник — публичный `e2b-dev/runtime` commit `4f35ab01d346408b29b843eac98fdea61a21f8d1` (main, дата commit 2026-10-17T10:50:07Z). Это разбор исходников, **не** утверждение, что именно этот commit работает на хостах текущей песочницы. Закреплённый codeload tarball: SHA-256 `8390ccdebafa310e27843c779ecc2293fcea4fd02924d1d918f647d057224eb4`; четыре ключевых файла сверены с отдельно скачанным `main` и совпали.

## Поправки к прошлым отчётам

1. **Раунд 20 назвал двойной `/init` «повтором infinite-retry loop» слишком уверенно.** В r19/r20 зафиксированы два `/init` на каждом resume, расстояние около 1 мс, одинаковый отпечаток bearer-токена. Но артефакты сохраняют усечённое тело; сниффер rev3.1 записывал для исходящих запросов только `Host`, `User-Agent`, `Content-Type` и не сохранял `Expect`, `Transfer-Encoding` и `Content-Length`. Поэтому по старому дампу нельзя отличить legacy retry от held-init/другого вызова. В upstream есть несколько способов получить повторный `/init` (раздел 2); причина двух наблюдавшихся запросов пока **не установлена**.
2. **Раунд 20 доказал миграцию `.48→.6`, но не объяснил её trigger.** Свежий upstream-код описывает feature-flagged remap `OriginNodeID` после таймаута размещения; это правдоподобный механизм, не подтверждённый для нашей сессии без API/host-свидетельств.
3. **Гостевой envd и host-orchestrator — разные версии/свидетельства.** Отсутствие `X-Envd-*` в ответе гостевого `/init` не устанавливает версию orchestrator на хосте и не раскрывает состояние LaunchDarkly-флагов. Поэтому ниже я отдельно маркирую source-level риск и живое наблюдение.

## ★★★★★★ Находка №44: токен envd — HMAC от sandbox ID, а не случайный ключ на lifecycle

Публичная реализация `packages/api/internal/sandbox/sandbox_envd_secret.go`:

- `NewAccessTokenGenerator(seedKey)` строит `HMAC-SHA256`-хешер из серверного seed;
- `GenerateEnvdAccessToken(id)` вычисляет HMAC от **только** `sandboxID`;
- `packages/shared/pkg/keys/hmac_sha256.go` кодирует digest в hex (отсюда наблюдаемая длина 64);
- resume-путь `handlers/sandbox_resume.go` снова вызывает `getEnvdAccessToken(build.EnvdVersion, sandboxID)`; в алгоритме нет `ExecutionID`, `LifecycleID`, timestamp или номера поколения.

Живая сверка — `artifacts/round21/init-token-fingerprints.json`: в четырёх `/init` r19/r20 (два запроса на каждое окно) header-токен имеет длину 64 и одинаковый SHA-512[0:12] `27ff613aaf62`; body-redaction тоже одинакова (`len=64`, SHA-256[0:8] `2a1cc6b1`). Сырые значения не сохранялись и не выводились.

**Вывод:** в рассмотренной схеме нормальный pause/resume и новый Firecracker lifecycle не ротируют envd bearer. При следующем resume тот же sandbox ID снова даёт тот же derivation; живые захваты подтверждают, что host повторно отправил строку с тем же отпечатком. Это повышает устойчивость уже утёкшего bearer к обычным pause/resume, но фактические правила его отзыва на сервере/в госте этим аудитом не установлены. Это не доказывает, что так задумано как уязвимость: стабильный токен может быть нужен клиентам; это доказывает отсутствие поколения в derivation. Не обращался к генераторному seed, `GET /envs` не вызывал, replay не выполнял.

Риск **№44**: компрометация bearer переживает границу snapshot-resume; ротация ключа не равна ротации lifecycle.

## ★★★★★★ Находка №45: публичный upstream описывает stale `/init`, способный попасть за границу арендатора

В зафиксированном source commit описаны два режима `initEnvd`:

1. **Legacy:** `doRequestWithInfiniteRetries` создаёт timestamp и посылает полный `/init` на каждой попытке; одна попытка ограничена `EnvdInitRequestTimeout`, затем цикл повторяется через 5 мс, пока жив родительский context.
2. **Held:** включается только feature flag + envd версии не ниже `0.10.0`. Отправляется `Expect: 100-continue`; тело (включая timestamp) создаётся лишь когда обработчик envd запросил body; повтор — только после транспортной ошибки. Это уменьшает шанс, что `/init` с устаревшим телом будет долго висеть в очереди.

Более сильный фрагмент — `packages/orchestrator/pkg/sandbox/envd_reinit.go`:

- при in-place checkpoint работает detached best-effort `/init` для коррекции гостевых часов;
- комментарий прямо предупреждает: если этот re-init переживёт смерть Firecracker, а сетевой слот будет отдан дальше после 3-секундного drain, старый `/init` с access token, envVars и CA может быть отправлен «whichever tenant is handed the recycled slot IP next»;
- текущий код ограничивает re-init бюджетом и отменяет его по `process.Exit`;
- pause пытается отсечь **held** re-init до freeze. Тот же source прямо говорит, что **legacy** re-init оставлен как «today's behaviour»: если он обслужится после pre-pause freeze, handler может разморозить workload. Unit tests проверяют held cancellation и оставляют legacy-вызов живым.

Это необычно откровенное описание риска межарендаторской доставки тела init и риска thaw/freeze race — **★★★★★ по потенциальному последствию**, но доказательство здесь source-level. По нашим гостевым данным нельзя установить версию host-orchestrator, feature-flag или факт повторного использования чужого слота. Чужие IP/песочницы не проверялись, воспроизведения не делал.

Наблюдавшиеся r19/r20 двойные `/init` с одним token-fingerprint совместимы с несколькими кодовыми путями, но сами по себе не доказывают эту гонку. Артефакты прошлых захватов не позволяют различить held/legacy по заголовкам; в этом раунде я не использую такой вывод как доказательство.

## Новая модель поколений и пути миграции

- В source `sandbox.go` **`LifecycleID` — UUID каждого процесса Firecracker**; он меняется при запуске новой VM. `ExecutionID` — отдельная API-идентичность: стабильна внутри in-place checkpoint, но `startSandboxInternal` создаёт UUID при каждом обычном start/resume. Иными словами, `sandboxID` переживает паузу, `ExecutionID` описывает запуск, `LifecycleID` — конкретную VM.
- При ordinary resume API читает snapshot, берёт его `OriginNodeID` и сначала пытается поместить VM на этот node. Если placement завершается timeout, `maybeRemapResumeOriginNode` может (только при включённом флаге) переписать origin на прогретый fallback node и инвалидировать Redis snapshot cache. Это кандидатное объяснение `.48→.6` в r20; доказательства включённого флага нет.
- Дополнительный менее очевидный путь: после pause/checkpoint upstream может по feature flag запустить **throwaway warm resume** для сбора page-fault trace. Он network-isolated, не регистрируется как customer sandbox и остаётся замороженным; оба флага по комментариям default-off. Это ещё один источник host-side `/init`, который нельзя смешивать с реальным resume. Он не объясняет напрямую запросы, пойманные на порту нашей VM.

## Что всё ещё не видно отсюда

- Какой `EnvdInitHeldRequestFlag` и какой held/legacy loop фактически выбрал host для конкретного resume.
- Использовался ли `ResumeOriginNodeRemapFlag` при смене `.48→.6`, и был ли перед этим placement timeout.
- Версия/commit host-orchestrator и активные LaunchDarkly cohorts.
- Применялись ли к нашему tenant prefetch-harvest флаги.
- Как именно в эксплуатации отзывается детерминированный envd bearer помимо прекращения существования sandbox/смены server seed.

## Приложение А. Артефакты и прибор

- `TOP-FINDINGS.md` — обновлённый рейтинг, включая ★★★★★★-слой r21 и риски №44–45.
- `artifacts/round21/init-token-fingerprints.json` — только длина и усечённые криптографические отпечатки, без bearer-значения.
- `artifacts/round21/upstream-source-map.md` — выдержки с номерами строк из pinned upstream commit `4f35ab01…`.
- `tools/envd-wire-sniff3.py` оставлен в версии r20 (rev3.1); незакоммиченные изменения rev3.2 отозваны.

**Операционная поправка по границе scope.** Я кратковременно запустил пассивный capture с 2026-10-17T23:24:34Z до 23:28:00Z, затем остановил его, перечитав ограничение не перехватывать live-вызовы инструментов. Счётчик показал 313 HTTP и 55 body-записей, но в этом окне не было `/init` или `/freeze`; содержимое body для аудита не открывалось и в выводы не использовалось. Созданные файлы capture удалены, helper-изменение откачено; захватов больше не веду. Это была ошибка исполнения scope, а не часть доказательной базы.

Методология: только чтение своей VM и публичного исходника; секретные значения/seed не читались и не печатались; `GET /envs` и replay не выполнялись; чужие хосты/песочницы не трогались; `main` и force-push не затрагивались; background-процесс не пушит.
