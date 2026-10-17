#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Поллер детей envd, рев.2 (раунд 15).

Задача прежняя: снять реализации инструментов платформы, которые исполняются
внутри VM короткоживущими процессами. Наблюдатель с периодом 10 мс их пропускает
(раунд 14: три вилки edit_file за 135 мс не были сняты), поэтому опрос идёт с
периодом 1 мс.

Новое в рев.2:
  * несколько замеров cmdline одного и того же PID (0/2/5/10/20/40 мс) — видно
    переход fork -> exec. В раунде 14 две записи имели cmdline '/usr/bin/envd'
    (13 символов); гипотеза: это снимок ребёнка до exec, а не отдельный процесс
    envd. Рев.2 её проверяет;
  * uid/gid/ppid из /proc/<pid>/status. Значения переменных окружения
    (/proc/<pid>/environ) НЕ читаются намеренно: в окружении платформенных
    процессов встречается GH_TOKEN, а методология аудита запрещает печатать
    значения секретов;
  * момент исчезновения PID — грубая длительность жизни процесса;
  * контроль пропусков по счётчику /proc/stat:processes.

Журнал пишется в /tmp (переживает только resume существующей песочницы) и, при
ARENA_POLL_REPO_LOG=1, в файл внутри репозитория: неотслеживаемые файлы уходят в
coding.patch и переживают пересоздание песочницы. В раунде 15 это проверено —
журналы раунда 14 вернулись обратно, а файлы из исключённых путей (*.db-wal,
build/) не вернулись.
"""

import datetime
import json
import os
import time

ENVD = os.environ.get('ARENA_ENVD_PID', '1229')
REPO = os.environ.get('ARENA_REPO', '/home/user/AuditArena')
LOG_TMP = os.environ.get('ARENA_POLL_LOG', '/tmp/envd-children2.log')
LOG_REPO = (os.path.join(REPO, '.envd-children2.log')
            if os.environ.get('ARENA_POLL_REPO_LOG', '0') == '1' else None)
PERIOD = float(os.environ.get('ARENA_POLL_PERIOD', '0.001'))
MAX_LOG = int(os.environ.get('ARENA_POLL_MAX_LOG', '200000'))
TAIL = 80000
# Замеры cmdline относительно первого обнаружения PID, секунды.
SAMPLES = (0.0, 0.002, 0.005, 0.010, 0.020, 0.040)
SELF_MARKERS = ('envd-children-poller', 'turn-end-watcher')


def utc(now=None):
    return datetime.datetime.utcfromtimestamp(
        now if now is not None else time.time()).strftime('%H:%M:%S.%f')[:-3]


def emit(record):
    line = json.dumps(record, ensure_ascii=False)
    for path in [p for p in (LOG_REPO, LOG_TMP) if p]:
        try:
            with open(path, 'a', encoding='utf-8') as handle:
                handle.write(line + '\n')
            if os.path.getsize(path) > MAX_LOG:
                data = open(path, 'rb').read()[-TAIL:]
                with open(path, 'wb') as handle:
                    handle.write(data)
        except Exception:
            pass


def envd_children():
    """Прямые дети всех потоков envd — именно так платформа запускает инструменты."""
    out = set()
    task_dir = '/proc/%s/task' % ENVD
    try:
        tasks = os.listdir(task_dir)
    except Exception:
        return out
    for task in tasks:
        try:
            raw = open(os.path.join(task_dir, task, 'children'),
                       encoding='utf-8').read()
        except Exception:
            continue
        for item in raw.split():
            if item.isdigit():
                out.add(int(item))
    return out


def proc_total():
    try:
        for line in open('/proc/stat', encoding='utf-8'):
            if line.startswith('processes'):
                return int(line.split()[1])
    except Exception:
        pass
    return -1


def read_cmdline(pid):
    """None — PID исчез; '' — cmdline пуст (зомби илиkernel thread)."""
    try:
        raw = open('/proc/%d/cmdline' % pid, 'rb').read()
    except Exception:
        return None
    if not raw:
        return ''
    return raw.replace(b'\0', b' ').decode('utf-8', 'replace').strip()


def read_ids(pid):
    uid = gid = ppid = None
    try:
        for line in open('/proc/%d/status' % pid, encoding='utf-8'):
            if line.startswith('Uid:'):
                uid = line.split()[1]
            elif line.startswith('Gid:'):
                gid = line.split()[1]
            elif line.startswith('PPid:'):
                ppid = line.split()[1]
    except Exception:
        return None
    return {'uid': uid, 'gid': gid, 'ppid': ppid}


def main():
    tracked = {}
    seen = envd_children()
    base = proc_total()
    caught = 0
    emit({'event': 'start', 'rev': 2, 'pid': os.getpid(), 'envd': ENVD,
          'period_ms': PERIOD * 1000.0, 'samples_ms': [s * 1000 for s in SAMPLES],
          'seen_children': len(seen), 'proc_total': base,
          'log_repo': bool(LOG_REPO), 'log_tmp': LOG_TMP,
          'max_log': MAX_LOG, 'utc': utc(), 't_real': time.time()})
    while True:
        time.sleep(PERIOD)
        now = time.time()
        current = envd_children()
        fresh = current - seen
        if fresh:
            for pid in sorted(fresh):
                cmd = read_cmdline(pid)
                if cmd is None:
                    continue
                if any(marker in cmd for marker in SELF_MARKERS):
                    continue
                ids = read_ids(pid)
                tracked[pid] = {'t0': now, 'cmdlines': [(0.0, cmd)],
                                'ids': ids, 'next': 1, 'last_seen': now,
                                'self': False}
                caught += 1
                emit({'event': 'child_new', 'pid': pid, 'len': len(cmd),
                      'ids': ids, 'utc': utc(now), 't_real': now,
                      'cmd': cmd[:600]})
        seen = current

        for pid in sorted(tracked):
            entry = tracked[pid]
            cmd = read_cmdline(pid)
            if cmd is None:
                emit({'event': 'child_done', 'pid': pid,
                      'life_ms': round((entry['last_seen'] - entry['t0']) * 1000, 2),
                      'ids': entry['ids'],
                      'distinct': len(entry['cmdlines']),
                      'cmdlines': [{'dt_ms': round(dt * 1000, 1),
                                    'len': len(text), 'text': text[:4000]}
                                   for dt, text in entry['cmdlines']],
                      'utc': utc(now), 't_real': now})
                del tracked[pid]
                continue
            entry['last_seen'] = now
            index = entry['next']
            if index < len(SAMPLES) and (now - entry['t0']) >= SAMPLES[index]:
                if cmd != entry['cmdlines'][-1][1]:
                    entry['cmdlines'].append((now - entry['t0'], cmd))
                entry['next'] = index + 1
                if entry['ids'] is None:
                    entry['ids'] = read_ids(pid)

        total = proc_total()
        if total - base > 0 and (fresh or total - base > caught):
            pass
        if total != base:
            emit({'event': 'forks', 'total': total, 'delta': total - base,
                  'caught': caught, 'missed': max(0, total - base - caught),
                  'tracked': len(tracked), 't_real': now, 'utc': utc(now)})
            base = total


if __name__ == '__main__':
    main()
