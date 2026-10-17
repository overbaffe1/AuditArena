#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сниффер канала платформа↔envd, рев.2 (раунд 17): маленькие тела RPC.

Рев.1 (раунд 16) держал только заголовки. Рев.2 дополнительно сохраняет тела
ЗАПРОСОВ длиной до SNIFF_BODY_MAX байт и только для узкого списка путей:
  * /process.Process/Start  — конфигурация процесса (cwd, user, envs?): что
    именно платформа передаёт на каждый вызов инструмента;
  * /filesystem.Filesystem/Stat — какие пути stat'ятся всплесками;
  * /init — рукопожатие при boot/resume (несёт токен и envVars).
Перед записью тело проходит редактацию: любые строки, похожие на токены
(arena-…, ghp_/gho_/ghu_/ghs_/ghr_, github_pat_, v1_, длинные hex), заменяются
на метку с длиной и SHA-256[0:8]; значение секрета в журнал и в контекст не
попадает. Тела /files (содержимое файлов агента) не сохраняются вовсе.

Захват пассивный (AF_PACKET), поток разбирается до конца заголовков, затем
досчитывается Content-Length. Требует CAP_NET_RAW: запуск через sudo.
Журнал: /tmp + (SNIFF_REPO_LOG=1 через `sudo env …`) зеркало в репозитории.
"""

import datetime
import hashlib
import json
import os
import re
import socket
import struct
import time

IFACE = os.environ.get('SNIFF_IFACE', 'eth0')
PORT = int(os.environ.get('SNIFF_PORT', '49983'))
LOG_TMP = os.environ.get('SNIFF_LOG', '/tmp/envd-wire17.log')
LOG_REPO = (os.path.join(os.environ.get('ARENA_REPO', '/home/user/AuditArena'),
                         '.envd-wire17.log')
            if os.environ.get('SNIFF_REPO_LOG', '0') == '1' else None)
BODY_MAX = int(os.environ.get('SNIFF_BODY_MAX', '4096'))
CAPTURE_PATHS = ('/process.Process/Start', '/filesystem.Filesystem/Stat',
                 '/init', '/process.Process/List', '/process.Process/Connect',
                 '/filesystem.Filesystem/WatchDir', '/freeze', '/fsthaw', '/unfreeze')
MAX_HDR = 65536

REDACT = [re.compile(p) for p in (
    r'arena-[A-Za-z0-9_\-]{6,}',
    r'gh[pousr]_[A-Za-z0-9]{6,}',
    r'github_pat_[A-Za-z0-9_]{6,}',
    r'v1_[A-Za-z0-9]{6,}',
    r'[0-9a-fA-F]{40,}',
    r'eyJ[A-Za-z0-9_\-]{20,}',
)]

STREAMS = {}


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


def redact(text):
    for pattern in REDACT:
        text = pattern.sub(
            lambda m: '<REDACTED len=%d sha8=%s>' % (
                len(m.group(0)),
                hashlib.sha256(m.group(0).encode('latin1')).hexdigest()[:8]),
            text)
    return text


def token_fingerprint(value):
    digest = hashlib.sha512(value.encode('latin1')).hexdigest()
    return {'len': len(value), 'prefix4': value[:4], 'sha512_12': digest[:12]}


def finish_head(head, direction, now, peer, state):
    lines = head.split(b'\r\n')
    first = lines[0].decode('latin1', 'replace')[:220]
    record = {'event': 'http', 'dir': direction, 'peer': peer, 'first': first,
              'utc': utc(now), 't_real': now, 'headers': {}}
    skip = 0
    chunked = False
    want_body = False
    path = first.split(' ')[1].split('?')[0] if ' ' in first else ''
    for raw in lines[1:]:
        if b':' not in raw:
            continue
        name, _, value = raw.partition(b':')
        name = name.decode('latin1', 'replace').strip().lower()
        value = value.decode('latin1', 'replace').strip()
        if name == 'x-access-token':
            record['token'] = token_fingerprint(value)
        elif name in ('authorization', 'set-cookie', 'x-envd-access-token'):
            record['headers'][name] = '<REDACTED len=%d>' % len(value)
        elif direction == 'in':
            record['headers'][name] = value[:200]
        elif name in ('host', 'user-agent', 'content-type'):
            record['headers'][name] = value[:100]
        elif name == 'content-length':
            try:
                skip = int(value)
            except ValueError:
                skip = 0
            if direction == 'out' and path in CAPTURE_PATHS \
                    and 0 < skip <= BODY_MAX:
                want_body = True
        elif name == 'transfer-encoding' and 'chunked' in value.lower():
            chunked = True
    record['body_skip'] = skip
    state['want_body'] = want_body and not chunked
    state['cap_left'] = skip if state['want_body'] else 0
    state['body'] = bytearray()
    emit(record)
    return skip, chunked


def main():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.bind((IFACE, 0))
    emit({'event': 'start', 'pid': os.getpid(), 'iface': IFACE, 'port': PORT,
          'body_max': BODY_MAX, 'utc': utc(time.time()), 't_real': time.time()})
    while True:
        packet = sock.recvfrom(65536)[0]
        now = time.time()
        if len(packet) < 54 or packet[12:14] != b'\x08\x00':
            continue
        ihl = (packet[14] & 0x0F) * 4
        if packet[23] != 6:
            continue
        src_ip = socket.inet_ntoa(packet[26:30])
        dst_ip = socket.inet_ntoa(packet[30:34])
        toff = 14 + ihl
        sport, dport = struct.unpack('!HH', packet[toff:toff + 4])
        if sport != PORT and dport != PORT:
            continue
        doff = (packet[toff + 12] >> 4) * 4
        payload = packet[toff + doff:]
        if not payload:
            continue
        direction = 'out' if dport == PORT else 'in'
        peer = '%s:%d>%s:%d' % (src_ip, sport, dst_ip, dport)
        key = (src_ip, sport, dst_ip, dport, direction)
        state = STREAMS.get(key)
        if state is None:
            state = {'buf': bytearray(), 'phase': 'head', 'skip': 0,
                     'last': now, 'want_body': False, 'cap_left': 0,
                     'body': bytearray()}
            STREAMS[key] = state
        state['last'] = now
        if state['phase'] == 'body':
            take = min(len(payload), state['cap_left'])
            state['body'] += payload[:take]
            state['cap_left'] -= take
            if state['cap_left'] == 0:
                text = redact(bytes(state['body']).decode('latin1', 'replace'))
                emit({'event': 'body', 'dir': direction, 'peer': peer,
                      'body_red': text[:1500], 'utc': utc(now), 't_real': now})
                state['phase'] = 'head'
                state['buf'] = bytearray()
                rest = payload[take:]
                if rest:
                    state['buf'] += rest
            continue
        if state['phase'] == 'skip':
            take = min(len(payload), state['skip'])
            state['skip'] -= take
            if state['skip'] == 0:
                state['phase'] = 'head'
                rest = payload[take:]
                if rest:
                    state['buf'] += rest
            continue
        state['buf'] += payload
        if payload[:1] == b'\x16' and not state['buf'][:4] in (b'POST', b'GET ', b'PUT ', b'HEAD'):
            state['phase'] = 'skip'
            state['skip'] = 10 ** 9
            continue
        index = state['buf'].find(b'\r\n\r\n')
        if index == -1:
            if len(state['buf']) > MAX_HDR:
                state['phase'] = 'skip'
                state['skip'] = 10 ** 9
            continue
        head = bytes(state['buf'][:index])
        tail = state['buf'][index + 4:]
        skip, chunked = finish_head(head, direction, now, peer, state)
        state['buf'] = bytearray()
        if chunked or direction == 'in':
            state['phase'] = 'skip'
            state['skip'] = 10 ** 9 if chunked else 0
            if state['skip'] == 0:
                state['phase'] = 'head'
                state['buf'] = tail
        elif state['want_body']:
            take = min(len(tail), state['cap_left'])
            state['body'] += tail[:take]
            state['cap_left'] -= take
            state['phase'] = 'body'
            if state['cap_left'] == 0:
                text = redact(bytes(state['body']).decode('latin1', 'replace'))
                emit({'event': 'body', 'dir': direction, 'peer': peer,
                      'body_red': text[:1500], 'utc': utc(now), 't_real': now})
                state['phase'] = 'head'
                state['body'] = bytearray()
                rest = tail[take:]
                if rest:
                    state['buf'] += rest
        else:
            state['skip'] = skip
            state['phase'] = 'skip' if skip else 'head'
            if not skip:
                state['buf'] = tail
        if len(STREAMS) > 400:
            for stale in [k for k, v in STREAMS.items()
                          if now - v['last'] > 120]:
                del STREAMS[stale]


if __name__ == '__main__':
    main()
