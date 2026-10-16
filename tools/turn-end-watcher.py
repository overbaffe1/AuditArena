#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Наблюдатель конца хода (редакция 6, исправленная по итогам раунда 9).

Зачем: платформа в конце хода собирает патчсет сессии, запуская git ВНУТРИ песочницы
(см. investigation-round9.md, приложение Б). Этот скрипт фиксирует момент сборки:
  * инотифи на каталог репозитория, .git, /tmp/arena-workspace, /home/user;
  * счётчик форков /proc/stat:processes с периодом 0,01 с (короткоживущие git-процессы
    видны как приращение счётчика, даже если дифф /proc не успел снять командную строку);
  * дифф снапшота /proc с командными строками (дедупликация повторяющихся);
  * агрегированный счётчик чтений (ACCESS/OPEN/CLOSE) — признак массовой сборки;
  * содержимое мелких файлов и md5 крупных;
  * детектор скачка часов (пауза/возобновление песочницы).

Метрология (важно): метка времени ставится в момент ОБРАБОТКИ события наблюдателем,
а не в момент события. На всплесках отставание достигало 84–105 мс (вычисление md5
файлов по 0,5–0,6 МБ плюс запись каждой строки в два файла). Абсолютное время следует
брать из mtime файлов, порядок событий из лога достоверен.

Скрипт не запускает внешних процессов, чтобы не загрязнять собственный счётчик форков.
Лог пишется в рабочую папку репозитория — так он переживает пересоздание песочницы
(платформа переносит неотслеживаемые и незакоммиченные файлы через coding.patch).

Запуск:  python3 -u tools/turn-end-watcher.py     (от обычного пользователя, sudo не нужен)
"""
import ctypes
import errno
import hashlib
import json
import os
import struct
import time

REV = 6
REPO = '/home/user/AuditArena'
WS = '/tmp/arena-workspace'
LOG_REPO = os.path.join(REPO, '.arena-watch-rev6.log')
LOG_TMP = '/tmp/arena-watch-rev6.log'
SELF_NAMES = {'.arena-watch-rev6.log', 'arena-watch-rev6.log'}  # собственные записи (репо и зеркало в /tmp)
MAX_LOG = 400000                                 # байт, затем урезаем хвост
INLINE_MAX = 4000                                # байт содержимого мелкого файла в лог
POLL = 0.01                                      # период опроса /proc и inotify
TICK = 30.0                                      # период служебной отметки

# ---- inotify через ctypes --------------------------------------------------
libc = ctypes.CDLL('libc.so.6', use_errno=True)
libc.inotify_init1.argtypes = [ctypes.c_int]
libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
libc.inotify_add_watch.restype = ctypes.c_int
libc.read.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
libc.read.restype = ctypes.c_ssize_t
libc.close.argtypes = [ctypes.c_int]

IN_NONBLOCK = 0o4000
IN_ACCESS, IN_MODIFY, IN_ATTRIB = 0x1, 0x2, 0x4
IN_CLOSE_WRITE, IN_CLOSE_NOWRITE, IN_OPEN = 0x8, 0x10, 0x20
IN_MOVED_FROM, IN_MOVED_TO, IN_CREATE, IN_DELETE = 0x40, 0x80, 0x100, 0x200
IN_DELETE_SELF, IN_MOVE_SELF, IN_Q_OVERFLOW, IN_ISDIR = 0x400, 0x800, 0x4000, 0x40000000
ALL = (IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | IN_OPEN |
       IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF)
NAMES = [(IN_ACCESS, 'ACCESS'), (IN_MODIFY, 'MODIFY'), (IN_ATTRIB, 'ATTRIB'),
         (IN_CLOSE_WRITE, 'CLOSE_WRITE'), (IN_CLOSE_NOWRITE, 'CLOSE_NOWRITE'), (IN_OPEN, 'OPEN'),
         (IN_MOVED_FROM, 'MOVED_FROM'), (IN_MOVED_TO, 'MOVED_TO'), (IN_CREATE, 'CREATE'),
         (IN_DELETE, 'DELETE'), (IN_DELETE_SELF, 'DELETE_SELF'), (IN_MOVE_SELF, 'MOVE_SELF'),
         (IN_Q_OVERFLOW, 'Q_OVERFLOW')]

fd = libc.inotify_init1(IN_NONBLOCK)
if fd < 0:
    raise SystemExit('inotify_init1 failed: %d' % ctypes.get_errno())
wd2path = {}


def watch(path, mask=ALL):
    if not os.path.isdir(path):
        return
    wd = libc.inotify_add_watch(fd, path.encode(), mask)
    if wd >= 0:
        wd2path[wd] = path


def mask_str(mask):
    out = [n for b, n in NAMES if mask & b]
    if mask & IN_ISDIR:
        out.append('ISDIR')
    return '|'.join(out) or hex(mask)


def log(obj):
    obj['rev'] = REV
    obj['t_real'] = round(time.time(), 6)
    obj['t_mono'] = round(time.monotonic(), 6)
    obj['utc'] = time.strftime('%H:%M:%S', time.gmtime()) + '.%03d' % (int(time.time() * 1000) % 1000)
    line = json.dumps(obj, ensure_ascii=False) + '\n'
    for p in (LOG_REPO, LOG_TMP):
        try:
            with open(p, 'a', encoding='utf-8') as f:
                f.write(line)
            try:
                if os.path.getsize(p) > MAX_LOG:
                    data = open(p, 'rb').read()[-100000:]
                    with open(p, 'wb') as f:
                        f.write(b'...trimmed...\n' + data)
            except OSError:
                pass
        except OSError:
            pass


def inline(path):
    """Содержимое мелкого файла — чтобы coding-numstat.txt был виден целиком."""
    try:
        sz = os.path.getsize(path)
        if sz > INLINE_MAX:
            h = hashlib.md5(open(path, 'rb').read()).hexdigest()
            return {'size': sz, 'md5': h}
        raw = open(path, 'rb').read()
        return {'size': sz, 'md5': hashlib.md5(raw).hexdigest(),
                'text': raw.decode('utf-8', 'replace')}
    except OSError as e:
        return {'error': str(e)}


def forks_total():
    with open('/proc/stat') as f:
        for ln in f:
            if ln.startswith('processes'):
                return int(ln.split()[1])
    return -1


def proc_snapshot():
    """pid -> (ppid, cmdline)"""
    out = {}
    for d in os.listdir('/proc'):
        if not d.isdigit():
            continue
        try:
            with open('/proc/%s/stat' % d) as f:
                st = f.read()
            ppid = int(st[st.rindex(')') + 2:].split()[1])
            cmd = open('/proc/%s/cmdline' % d, 'rb').read().replace(b'\0', b' ').decode('utf-8', 'replace').strip()
            out[int(d)] = (ppid, cmd[:6000])
        except (OSError, ValueError, IndexError):
            continue
    return out


watch(WS)
watch(os.path.join(WS, 'procs'))
for p in ('/tmp/arena-workspace/procs',):
    if os.path.isdir(p):
        for name in os.listdir(p):
            watch(os.path.join(p, name))
watch(REPO)
watch(os.path.join(REPO, '.git'))
watch('/home/user')
# /tmp целиком не наблюдаем: зеркало лога вызывало самоусиление (рев.6, исправлено)
watch(os.path.join(REPO, 'probe-r8-sub'))

log({'event': 'start', 'pid': os.getpid(), 'uid': os.getuid(),
     'watches': sorted(wd2path.values()), 'sandbox': os.environ.get('E2B_SANDBOX_ID'),
     'template': os.environ.get('E2B_TEMPLATE_ID'),
     'forks_at_start': forks_total(),
     'ws_listing': sorted(os.listdir(WS)) if os.path.isdir(WS) else None,
     'repo_status_note': 'git не вызывается из наблюдателя намеренно'})

cmd_ids = {}              # командная строка -> короткий id (опросы платформы повторяются)


def cmd_id(cmd):
    """Повторяющиеся командные строки пишем один раз: иначе лог съедают опросы статуса."""
    if cmd not in cmd_ids:
        cmd_ids[cmd] = len(cmd_ids)
        log({'event': 'cmdline_new', 'id': cmd_ids[cmd], 'cmd': cmd[:8000]})
    return cmd_ids[cmd]


open_counts = {}          # (путь, ACCESS|OPEN|CLOSE_NOWRITE) -> сколько раз прочитали
inline_at = {}            # путь -> время последнего чтения содержимого (защита от петли)
prev_forks = forks_total()
prev_procs = proc_snapshot()
prev_real = time.time()
prev_mono = time.monotonic()
last_tick = prev_mono
last_flush = prev_mono
buf = ctypes.create_string_buffer(1 << 20)

while True:
    now_real, now_mono = time.time(), time.monotonic()
    d_real, d_mono = now_real - prev_real, now_mono - prev_mono
    if d_real - d_mono > 1.0 or d_real - d_mono < -1.0:
        log({'event': 'clock_jump', 'd_real': round(d_real, 6), 'd_mono': round(d_mono, 6),
             'note': 'real ушёл от monotonic: пауза/возобновление песочницы либо перевод часов'})
    prev_real, prev_mono = now_real, now_mono

    f = forks_total()
    if f != prev_forks:
        delta = f - prev_forks
        prev_forks = f
        cur = proc_snapshot()
        new = sorted(set(cur) - set(prev_procs))
        gone = sorted(set(prev_procs) - set(cur))
        rec = {'event': 'forks', 'delta': delta, 'total': f, 'new_pids': len(new),
               'gone_pids': len(gone), 'procs': []}
        for pid in new[:40]:
            ppid, cmd = cur[pid]
            rec['procs'].append({'pid': pid, 'ppid': ppid, 'c': cmd_id(cmd)})
            if os.path.basename(cmd.split(' ')[0]) in ('git', 'tar', 'gtar', 'git-remote-https'):
                log({'event': 'GIT_OR_TAR_IN_VM', 'pid': pid, 'ppid': ppid, 'cmd': cmd[:8000],
                     'note': 'в VM запущен git/tar — патчсет считается внутри песочницы'})
        prev_procs = cur
        log(rec)

    n = libc.read(fd, buf, 1 << 20)
    if n > 0:
        off = 0
        raw = buf.raw[:n]
        while off + 16 <= n:
            wd_, mask, cookie, length = struct.unpack_from('iIII', raw, off)
            name = raw[off + 16:off + 16 + length].split(b'\0')[0].decode('utf-8', 'replace')
            off += 16 + length
            if name in SELF_NAMES or 'arena-watch-rev6' in name:
                continue
            base = wd2path.get(wd_, '?wd%d' % wd_)
            full = os.path.join(base, name) if name else base
            if mask & IN_CREATE and mask & IN_ISDIR:
                watch(full)
            # Чтения (OPEN/ACCESS/CLOSE_NOWRITE) только считаем: их порождает и само
            # наблюдательское inline(), иначе возникает петля самоусиления (баг первой сборки рев.6).
            if not mask & (IN_MODIFY | IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MOVED_FROM |
                           IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF):
                key = full + '|' + ('OPEN' if mask & IN_OPEN else 'ACCESS' if mask & IN_ACCESS else 'CLOSE')
                open_counts[key] = open_counts.get(key, 0) + 1
                continue
            rec = {'event': 'inotify', 'mask': mask_str(mask), 'path': full, 'cookie': cookie}
            if name and not mask & IN_ISDIR:
                hot = base == WS or '/arena-workspace' in base or name.startswith('coding')
                if (hot or inline_at.get(full, 0) < now_mono - 1.0):
                    try:
                        if os.path.isfile(full) and (hot or os.path.getsize(full) < 4000):
                            rec['content'] = inline(full)
                            inline_at[full] = now_mono
                    except OSError:
                        pass
            if full.endswith('/.git/index') or full.endswith('/.git/index.lock'):
                log({'event': 'GIT_INDEX_WRITE_IN_VM', 'mask': mask_str(mask), 'path': full,
                     'note': 'в VM пишут индекс git — признак git add/git reset внутри песочницы'})
            if base == WS and name.startswith('coding'):
                log({'event': 'ARTIFACT_WRITTEN', 'mask': mask_str(mask), 'path': full,
                     'content': inline(full) if os.path.isfile(full) else None})
            log(rec)
    elif n < 0 and ctypes.get_errno() not in (errno.EAGAIN, errno.EWOULDBLOCK):
        log({'event': 'read_error', 'errno': ctypes.get_errno()})

    if open_counts and (len(open_counts) > 60 or now_mono - last_flush > 5.0):
        last_flush = now_mono
        top = sorted(open_counts.items(), key=lambda kv: -kv[1])[:40]
        repo_reads = {k: v for k, v in open_counts.items() if k.startswith(REPO)}
        if len(repo_reads) > 40 or sum(repo_reads.values()) > 200:
            log({'event': 'COLLECTION_BURST', 'distinct_repo': len(repo_reads),
                 'total_repo': sum(repo_reads.values()),
                 'note': 'массовое чтение файлов репозитория ВНУТРИ VM — снимок/патч собирается в песочнице',
                 'sample': list(repo_reads)[:25]})
        log({'event': 'reads', 'total': sum(open_counts.values()), 'distinct': len(open_counts),
             'top': [{'path': k, 'n': v} for k, v in top]})
        open_counts.clear()

    if now_mono - last_tick >= TICK:
        last_tick = now_mono
        ws = sorted(os.listdir(WS)) if os.path.isdir(WS) else None
        rec = {'event': 'tick', 'forks': prev_forks, 'real_minus_mono': round(now_real - now_mono, 3),
               'ws': ws}
        for nm in ('coding.patch', 'coding.diff', 'coding-numstat.txt'):
            p = os.path.join(WS, nm)
            if os.path.exists(p):
                st = os.stat(p)
                rec[nm] = {'size': st.st_size, 'mtime_ns': st.st_mtime_ns}
        log(rec)

    time.sleep(POLL)
