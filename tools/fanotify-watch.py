#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fanotify-наблюдатель: кто открывает файлы в отмеченных каталогах (раунд 16).

inotify не сообщает PID открывшего; fanotify сообщает. Это закрывает два
вопроса раунда 15:
  * кто опрашивает /tmp/arena-workspace каждые ~30 с (pid 1229 = envd, значит
    опрос приходит с хоста через RPC, а не от скрытого процесса в госте);
  * кто открывает целевой файл при резервом чтении read_file (ожидание: pid
    1229, то есть сам envd, а не порождённый процесс).

Отмечаются каталоги /tmp/arena-workspace, /opt и /etc: событие приходит на
открытие/закрытие файла или каталога внутри них. В журнал пишутся pid, uid,
маска и путь; для pid 1229 путь берётся из /proc/self/fd события.

Значения секретов не читаются и не печатаются. Требует CAP_SYS_ADMIN:
запускается через sudo. Журнал: /tmp + (FAN_REPO_LOG=1) файл репозитория.
"""

import ctypes
import ctypes.util
import datetime
import json
import os
import select
import struct
import time

PATHS = ['/tmp/arena-workspace', '/opt', '/etc']
ENVD = os.environ.get('ARENA_ENVD_PID', '1229')
LOG_TMP = os.environ.get('FAN_LOG', '/tmp/fanotify16.log')
LOG_REPO = (os.path.join(os.environ.get('ARENA_REPO', '/home/user/AuditArena'),
                         '.fanotify16.log')
            if os.environ.get('FAN_REPO_LOG', '0') == '1' else None)

FAN_CLASS_NOTIF = 0
FAN_CLOEXEC = 1
FAN_NONBLOCK = 2
FAN_MARK_ADD = 1
FAN_OPEN = 0x20
FAN_CLOSE_WRITE = 0x08
FAN_CLOSE_NOWRITE = 0x10
FAN_ACCESS = 0x01
AT_FDCWD = -100

MASK_NAMES = {FAN_OPEN: 'OPEN', FAN_CLOSE_WRITE: 'CLOSE_WRITE',
              FAN_CLOSE_NOWRITE: 'CLOSE_NOWRITE', FAN_ACCESS: 'ACCESS'}

PROC_CACHE = {}


def utc(now):
    return datetime.datetime.utcfromtimestamp(now).strftime('%H:%M:%S.%f')[:-3]


def emit(record):
    line = json.dumps(record, ensure_ascii=False)
    for path in [p for p in (LOG_REPO, LOG_TMP) if p]:
        try:
            with open(path, 'a', encoding='utf-8') as handle:
                handle.write(line + '\n')
        except Exception:
            pass


def proc_info(pid):
    info = PROC_CACHE.get(pid)
    if info is None:
        cmd = ''
        uid = None
        try:
            raw = open('/proc/%d/cmdline' % pid, 'rb').read()
            cmd = raw.replace(b'\0', b' ').decode('utf-8', 'replace').strip()[:90]
        except Exception:
            cmd = '<gone>'
        try:
            for line in open('/proc/%d/status' % pid, encoding='utf-8'):
                if line.startswith('Uid:'):
                    uid = line.split()[1]
                    break
        except Exception:
            pass
        info = {'cmd': cmd, 'uid': uid}
        PROC_CACHE[pid] = info
    return info


def main():
    libc = ctypes.CDLL(ctypes.util.find_library('c') or 'libc.so.6',
                       use_errno=True)
    fd = libc.fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK,
                            os.O_RDONLY)
    if fd < 0:
        raise OSError(ctypes.get_errno(), 'fanotify_init')
    marked = []
    for path in PATHS:
        rc = libc.fanotify_mark(fd, FAN_MARK_ADD,
                                FAN_OPEN | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE,
                                AT_FDCWD, path.encode('utf-8'))
        marked.append({'path': path, 'ok': rc == 0,
                       'errno': None if rc == 0 else ctypes.get_errno()})
    emit({'event': 'start', 'pid': os.getpid(), 'marked': marked,
          'utc': utc(time.time()), 't_real': time.time()})
    poll = select.poll()
    poll.register(fd, select.POLLIN)
    while True:
        poll.poll(200)
        try:
            data = os.read(fd, 65536)
        except OSError:
            continue
        now = time.time()
        offset = 0
        while offset + 16 <= len(data):
            event_len, _vers, _res, mask, evfd, pid = struct.unpack_from(
                '<IBBHii', data, offset)
            if event_len < 16:
                break
            path = None
            if evfd >= 0:
                try:
                    path = os.readlink('/proc/self/fd/%d' % evfd)
                except Exception:
                    path = None
                try:
                    os.close(evfd)
                except Exception:
                    pass
            offset += event_len
            pid_s = str(pid)
            interesting = pid_s == ENVD or (
                path is not None and
                any(path == p or path.startswith(p + '/') for p in PATHS))
            if not interesting:
                continue
            names = [n for bit, n in MASK_NAMES.items() if mask & bit]
            info = proc_info(pid)
            emit({'event': 'open', 'pid': pid, 'uid': info['uid'],
                  'mask': '+'.join(names) or hex(mask), 'path': path,
                  'cmd': info['cmd'], 'utc': utc(now), 't_real': now})


if __name__ == '__main__':
    main()
