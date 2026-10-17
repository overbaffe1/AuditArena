#!/usr/bin/env python3
"""Быстрый опрос детей envd: ловит короткоживущие процессы инструментов платформы.

Зачем. Наблюдатель tools/turn-end-watcher.py опрашивает /proc с периодом 10 мс и потому
пропускает процессы, живущие меньше. В раунде 14 это стоило данных: правка edit_file
породила три вилки за 135 мс (счётчик forks 1684 -> 1687), а в журнал попала только
одна командная строка - проверка каталога. Реализация write_file/edit_file так и не
была снята.

Как. Этот инструмент читает /proc/<envd>/task/*/children с периодом ~1 мс и снимает
cmdline каждого нового PID. Все инструменты платформы - прямые дети envd (раунд 12),
поэтому список детей даёт полную выборку без перебора всей таблицы процессов.
Полнота контролируется по счётчику /proc/stat:processes - если он вырос, а новых детей
не появилось, значит процесс родился и умер между опросами; такие пропуски считаются.

Журнал. По умолчанию только /tmp (переживает возобновление песочницы, но НЕ переживает
пересоздание). Зеркало в репозиторий включается ARENA_POLL_REPO_LOG=1: тогда журнал
попадает в патчсет конца хода и возвращается после пересоздания - ценой самоцитирования
(раунды 9-11). Размер ограничен MAX_LOG, при превышении сохраняется хвост.

Запуск:  python3 -u tools/envd-children-poller.py
Переменные: ARENA_ENVD_PID (1229), ARENA_POLL_LOG (/tmp/envd-children.log),
            ARENA_POLL_REPO_LOG (0), ARENA_POLL_PERIOD (0.001)
"""
import glob
import json
import os
import time

REPO = '/home/user/AuditArena'
ENVD = os.environ.get('ARENA_ENVD_PID', '1229')
LOG_TMP = os.environ.get('ARENA_POLL_LOG', '/tmp/envd-children.log')
LOG_REPO = os.path.join(REPO, '.envd-children.log') if os.environ.get('ARENA_POLL_REPO_LOG', '0') == '1' else None
PERIOD = float(os.environ.get('ARENA_POLL_PERIOD', '0.001'))
MAX_LOG = 150000
SELF = '.envd-children.log'


def log(obj):
    """Одна запись JSON во все журналы, с ротацией по размеру."""
    now = time.time()
    obj['t_real'] = round(now, 6)
    obj['t_mono'] = round(time.monotonic(), 6)
    obj['utc'] = time.strftime('%H:%M:%S', time.gmtime()) + '.%03d' % (int(now * 1000) % 1000)
    line = json.dumps(obj, ensure_ascii=False) + '\n'
    for path in [x for x in (LOG_REPO, LOG_TMP) if x]:
        try:
            with open(path, 'a', encoding='utf-8') as handle:
                handle.write(line)
            if os.path.getsize(path) > MAX_LOG:
                tail = open(path, 'rb').read()[-60000:]
                with open(path, 'wb') as handle:
                    handle.write(b'...trimmed...\n' + tail)
        except OSError:
            pass


def child_pids():
    """PID-ы детей всех потоков envd."""
    out = []
    for path in glob.glob('/proc/%s/task/*/children' % ENVD):
        try:
            out.extend(open(path, encoding='utf-8').read().split())
        except OSError:
            continue
    return out


def processes_total():
    """Счётчик созданных процессов из /proc/stat - для контроля полноты."""
    try:
        for line in open('/proc/stat', encoding='utf-8'):
            if line.startswith('processes'):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def main():
    seen = set()
    missed = 0
    log({'event': 'start', 'pid': os.getpid(), 'envd': ENVD, 'period': PERIOD,
         'repo_log': bool(LOG_REPO)})
    total = processes_total()
    while True:
        for pid in child_pids():
            if pid in seen:
                continue
            seen.add(pid)
            cmd = ''
            try:
                raw = open('/proc/%s/cmdline' % pid, 'rb').read()
                cmd = raw.replace(b'\x00', b' ').decode('utf-8', 'replace').strip()
            except OSError:
                pass
            rec = {'event': 'child', 'pid': int(pid), 'len': len(cmd)}
            if cmd and SELF not in cmd:
                rec['cmd'] = cmd
            elif cmd:
                rec['note'] = 'собственная команда поллера, текст пропущен'
            else:
                rec['note'] = 'cmdline недоступен: процесс уже завершился'
                missed += 1
            log(rec)
        new_total = processes_total()
        if new_total is not None and total is not None and new_total != total:
            log({'event': 'forks', 'total': new_total, 'delta': new_total - total,
                 'caught': len(seen), 'missed': missed})
            total = new_total
        time.sleep(PERIOD)


if __name__ == '__main__':
    main()
