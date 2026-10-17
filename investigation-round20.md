# Раунд 20: миграция при resume, пакет-«призрак» из очереди, деплой envd против upstream, причина 400 у гиперлупа

Время: 2026-10-17, 21:44–22:05 UTC. Граница r19→20: **пауза №2 этой песочницы (21:33:12 → 21:44:36, 11,4 мин) и resume — на другом хосте**. Приборы (поллер, наблюдатель, сниффер rev3) пережили паузу и записали всё. По запросу пользователя введён постоянный артефакт `TOP-FINDINGS.md` — звёздный рейтинг находок r5–r20.

## Поправки к прошлым отчётам

1. **Раунд 19, «следующий resume даст значения `X-Envd-*`» — неверно.** rev3 исправно снимает полные заголовки ответов, но деплойный envd их **не отправляет вовсе**: ответы `/init` несут только `cache-control: no-store`, `vary: Origin`, `date`, `connection: close`. Заголовки `X-Envd-Version/-Freeze-Audit/-Defaults/-Memory/-Handover/-Init-Clock-Correction` — из свежего upstream (main, октябрь), а в гостье работает сборка до их появления (см. раздел 3).
2. **Раунд 19, таблица пауз: «resume = тот же хост» — не инвариант.** Этот resume случился **на другом хосте** (10.12.0.48 → 10.12.0.6) с новым `lifecycleID` — снимки переносимы между хостами пула.
3. **Раунд 20, черновое «`/init` в 21:44:36 среди хода» — на самом деле resume-хук**: ход стартовал в 21:44:36 (сообщение пользователя), а не продолжался с 21:33.

## 1. Resume с миграцией: полная картина

```
21:33:12.169  in  POST /freeze?maxWaitMs=1500&mode=hierarchy&maxCgroups=512   от 10.12.0.48
              ─── 684 с: память заморожена, тишина в проводе ───
21:44:36.977  out HTTP/1.1 204 No Content  → 10.12.0.48:36434, date: Sat, 17 Oct 2026 21:33:12 GMT (!)
21:44:36.980  in  POST /init ×2  от 10.12.0.6  (Host: 10.11.0.3:49983, Go-http-client/1.1,
                  токен тот же 27ff613aaf62, lifecycleID d1d7d42d-fbf0…, accessToken sha8=2a1cc6b1 — без изменений)
21:44:36.981  in  GET /metrics, GET /health  от 10.12.0.6
21:44:37.089  in  POST /process.Process/Start ×2 — первые инструменты хода
21:44:38.547  in  POST /filesystem.Filesystem/WatchDir — длинный поток (ESTAB .6:35438 = fd 10 envd)
21:44:46.813  in  POST /process.Process/Start — мой 120-с bash: второй ESTAB (.6:52986 = fd 12) держится,
                  пока процесс идёт (стрим stdout)
```

Ключевые детали:

- **Пакет-«призрак»**: ответ `204` на `/freeze` сформирован envd в 21:33:12 (заголовок `date`), но в сниффер попал в **21:44:36.977** — за 3 мс до resume-`/init`. Пакет 11 минут лежал в стеке (virtio-net/TCP-очередь замороженной VM) и был доставлен после разморозки. Прямое доказательство того, что снапшотится состояние сети вместе с очередями, и маркер точной границы freeze/restore в проводе.
- **Миграция**: обслуживающий хост сменился `.48`→`.6`; пиры минуты к минуте: 21:31–21:33 только `.48`, 21:44–21:46 только `.6`. Новый `lifecycleID` = поколение жизненного цикла выдаётся на каждый resume (b519d0af → cb36d930 → d1d7d42d).
- **Два адреса песочницы**: прямые вызовы оркестратора несут `Host: 10.11.0.3:49983` (host-сторона, сеть 10.11.0.x — гость при этом видит eth0 169.254.0.21/30), а SDK-вызовы — `Host: 49983-imosg17opozcvx0fcjvzj.e2b.app`: **тот же паттерн `{port}-{sandboxId}.e2b.app`, что у live-preview для пользователя**. Инструментальный трафик платформы идёт через тот же edge-домен.
- **`WatchDir` — push-канал live-tail** (дополнение к поллингу Stat/GET из r17–19): один длинный сервер-стрим на песочницу. Тело запроса (какой каталог) rev3 не захватил (путь не входил в CAPTURE_PATHS) — в rev3.1 добавлены `WatchDir`, `/freeze`, `/fsthaw`, `/unfreeze`; ждём следующий resume.
- clock_jump №2 в журнале наблюдателя **не виден из-за его же ротации**: rev6 триммит зеркало до последних 60 КБ с маркером `...trimmed...` (детектор исправен: порог |Δreal−Δmono|>1 с; запись 21:44:36 съедена бурей inotify после resume). Расхождение (real−mono) на +684 с подтверждается арифметикой других записей (t_mono 1290,5 при 2206 с настенных от «бута»).

## 2. Почему гиперлуп отвечает envd'у `400` — закрыто по источнику

`packages/orchestrator/pkg/hyperloopserver/handlers/logs.go` (tarball runtime@main):

- `Logs()` сначала `GetByHostPort(RemoteAddr)` — сопоставление источника с песочницей; провал → 400 «Error when finding source sandbox»;
- затем `validatePayloadSandboxID(payload, sbxID)` → 400 «Invalid sandboxID in logs payload», и комментарий буквально про наш случай: **«Inflight logs with old sandboxID from snapshotted sandbox. Change to error once we have a way how to tell sandbox to flush and stop sending logs when being paused»** — известная upstream проблема: логи, зависшие в envd на момент паузы, после resume отвергаются;
- `hasStaleLogTimestamp(payload, sbx.LifecycleStartedAt)` → 400 «Log timestamp predates this sandbox's resume» (наш `lifecycleID`-счётчик поколений согласуется с `LifecycleStartedAt`);
- дальше identity перезаписывается доверенными значениями (`setTrustedLogIdentity`: sandboxID, templateID, **teamID**, **buildID**), маршрутизация берётся из **LaunchDarkly** (ретаргет без передеплоя) + fire-and-forget **shadow-writes** по `ShadowURLs` с семафором;
- `me.go`: `GET /me` возвращает `{SandboxID}` по source-адресу (без токена) — самоидентификация песочницы.

Наши journal-строки `error sending instance logs: collector returned 400 (N suppressed)` в 21:09:56 и 21:21:21 — это ровно дроп «stale»-пачек на границах. Вывод-маркер: **400 в журнале envd = признак snapshot-resume**, а телеметрия платформы системно слепнет на границах пауз (форензическое следствие: часть истории песочницы до паузы не доезжает до коллектора).

## 3. Деплойный envd против upstream: дрейф ~4 месяца

- Бинарник `/usr/bin/envd`: Go-buildinfo — `path github.com/e2b-dev/infra/packages/envd`, тулчейн **go1.26.3**, vcs-штампов нет (`-buildvcs=false`) — точный коммит из бинарника не читается;
- процесс envd (`bash[1229]`, `starttime_ticks=979`) живёт с **Jun 15 17:00:09** (журнал) — сборка не старше сборки шаблона Jun 15;
- ответы `/init` не несут ни одного `X-Envd-*` заголовка, которые в main уже есть на каждом ответе (version, freeze-audit, defaults, memory, handover, clock-correction, unobserved, thaw);
- в main есть live-upgrade envd без перезапуска (`/upgrade`, `spec/upgrade/handover.proto`, `mounts_handover.go`, гейт `handoverPreInitAllowedPaths` = `GET/health`+`POST/init` до восстановительного `/init`, намеренно без `/files` — цитата: «a re-adopted (possibly hostile) guest process can't reach the root-privileged file API unauthenticated») — в деплое этого, по-видимому, нет;
- при этом `/freeze` с параметрами `mode=hierarchy&maxCgroups=512` и `/init`-thaw уже работают — деплой не «древний», а срединный.

Итог: флот гетерогенен по версиям envd, и из гостьи версия видна только косвенно (поведение + buildinfo) — `X-Envd-Version` в деплое нет. Риск **№43**: security-фичи upstream (гейты handover, аудит freeze) до песочниц ещё не доехали.

## 4. cgroup-механика freeze изнутри

- Все инструменты и приборы — в cgroup `/user` (`/proc/self/cgroup` = `0::/user`; 13 процессов) — именно это дерево морозит `/freeze mode=hierarchy` (файлы `cgroup.freeze` есть у каждой единицы; сейчас 0 — разморожено `/init`-thaw);
- `system.slice/envd.service`: **`memory.min=52428800`** (50 МиБ гарантированной памяти — то, что upstream-`X-Envd-Memory` репортит оркестратору; у нас измеряется напрямую); есть также cgroup `socats` (пуст, `memory.min=5242880`) — следы шаблонной обвязки;
- nat-таблица пуста (`-P ACCEPT`, правил нет) — `PinMMDSRoute` из init.go вставляется только при сбоях чтения MMDS (self-heal против пользовательских редиректов 169.254.169.254:80 — upstream прямо предусматривает, что гость может их ставить);
- маршрут до гиперлупа: `192.0.2.1 via 169.254.0.22 dev eth0` — через host-шлюз.

## 5. Риски (продолжение)

- **№42. Миграция resume + поколения `lifecycleID`.** Песочница может продолжить жизнь на другом хосте пула; `lifecycleID` меняется на каждый resume, токен и CA — нет. Для платформы: stale-логи дропаются на границах (раздел 2) — телеметрия теряет события пауз; для аудита: 400 в журнале — бесплатный маркер «тут был snapshot-resume».
- **№43. Дрейф версий envd** (раздел 3): из гостьи нельзя узнать версию декларативно; security-гейты upstream могут отсутствовать в деплое.
- **№36 (уточнение).** Live-tail = `WatchDir`-стрим + поллинг корней; после миграции стримы переподнимаются новым хостом.

## Что всё ещё не видно отсюда

- Тело `WatchDir` (какой каталог смотрят) и события стрима — rev3.1 вооружён, нужен следующий resume.
- Логика выбора «базовый снимок vs свежий» у оркестратора (r17→18 — база, r18→19 и r19→20 — свежие, причём второй — с миграцией): кандидат на разбор в `packages/orchestrator` (tarball скачан, 5,5 МБ, в `/tmp`).
- Куда физически течёт `WatchDir`/live-tail на host-стороне.
- Точный коммит деплойного envd (vcs-штампы выключены).

## Приложение А. Артефакты раунда

- `TOP-FINDINGS.md` — звёздный топ находок r5–r20 (новый постоянный артефакт, обновляется).
- `artifacts/round20/resume2-window.json` — 76 записей провода вокруг resume №2 (freeze-ответ-«призрак», /init×2 с телами, health/metrics, WatchDir, первые Start).
- `artifacts/round20/watch-r20-trimmed.log` — журнал наблюдателя после его ротации (60 КБ, 21:44+).
- `tools/envd-wire-sniff3.py` — rev3.1: CAPTURE_PATHS += WatchDir, /freeze, /fsthaw, /unfreeze; запущен в 22:0x (`/tmp/envd-wire20.log` + зеркало).
- Upstream-исходники: `artifacts/round19/upstream/` + разобранный tarball в `/tmp/runtime-main` (hyperloopserver handlers прочитаны в этом раунде).

Методология без изменений: значения токенов не печатаются (len/префикс/отпечатки); реплей перехваченных кредов не выполнялся; force-push и `main` не тронуты; время UTC.
