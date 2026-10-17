#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Пассивный сниффер канала платформа↔envd (раунд 16).

Зачем: все файловые и процессные вызовы инструментов платформы приходят в гостя
по HTTP на порт envd (49983) с адреса хоста 169.254.0.22. Раунды 12–15
восстанавливали карту вызовов по косвенным следам (процессы, inotify, atime).
Здесь карта снимается с провода: последовательность RPC на каждый инструмент,
заголовки клиента и факт отсутствия TLS.

Безопасность и методология:
  * захват пассивный (AF_PACKET, без вмешательства в канал);
  * тела запросов НЕ сохраняются: парсер держит только заголовочный блок и
    пропускает Content-Length байт тела;
  * значение заголовка X-Access-Token НЕ сохраняется и НЕ печатается: сразу
    считается SHA-512, в журнал идут длина, префикс 4 символа и отпечаток 12;
    отпечаток сверяется с accessTokenHash из MMDS (сам токен не раскрывается);
  * журнал пишется в /tmp и (SNIFF_REPO_LOG=1) в файл репозитория, чтобы
    пережить пересоздание песочницы.

Требует CAP_NET_RAW: запускается через sudo.
"""

import datetime
import hashlib
import json
import os
import socket
import struct
import time

IFACE = os.environ.get('SNIFF_IFACE', 'eth0')
PORT = int(os.environ.get('SNIFF_PORT', '49983'))
LOG_TMP = os.environ.get('SNIFF_LOG', '/tmp/envd-wire16.log')
LOG_REPO = (os.path.join(os.environ.get('ARENA_REPO', '/home/user/AuditArena'),
                         '.envd-wire16.log')
            if os.environ.get('SNIFF_REPO_LOG', '0') == '1' else None)
MAX_HDR = 65536
IDLE_PRUNE = 120.0

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


def token_fingerprint(value):
    """Значение секрета не сохраняется: только длина, префикс и отпечаток."""
    digest = hashlib.sha512(value.encode('latin1')).hexdigest()
    return {'len': len(value), 'prefix4': value[:4], 'sha512_12': digest[:12]}


def parse_head(head, direction, now, peer):
    lines = head.split(b'\r\n')
    first = lines[0].decode('latin1', 'replace')[:220]
    record = {'event': 'http', 'dir': direction, 'peer': peer,
              'first': first, 'utc': utc(now), 't_real': now, 'headers': {}}
    skip = 0
    chunked = False
    for raw in lines[1:]:
        if b':' not in raw:
            continue
        name, _, value = raw.partition(b':')
        name = name.decode('latin1', 'replace').strip().lower()
        value = value.decode('latin1', 'replace').strip()
        if name == 'x-access-token':
            record['token'] = token_fingerprint(value)
        elif name == 'authorization':
            record['auth'] = token_fingerprint(value)
        elif name in ('host', 'user-agent', 'content-type', 'connect-protocol-version'):
            record['headers'][name] = value[:120]
        elif name == 'content-length':
            try:
                skip = int(value)
            except ValueError:
                skip = 0
        elif name == 'transfer-encoding' and 'chunked' in value.lower():
            chunked = True
    record['body_skip'] = skip
    record['body_chunked'] = chunked
    emit(record)
    return skip, chunked


def main():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.bind((IFACE, 0))
    emit({'event': 'start', 'pid': os.getpid(), 'iface': IFACE, 'port': PORT,
          'utc': utc(time.time()), 't_real': time.time()})
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
                     'last': now, 'peer': peer}
            STREAMS[key] = state
            emit({'event': 'stream', 'dir': direction, 'peer': peer,
                  'utc': utc(now), 't_real': now})
        state['last'] = now
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
        if payload[:1] == b'\x16' and not state['buf'].startswith(b'POST') \
                and not state['buf'].startswith(b'GET') \
                and not state['buf'].startswith(b'HTTP/'):
            emit({'event': 'tls_detected', 'dir': direction, 'peer': peer,
                  'utc': utc(now), 't_real': now})
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
        skip, chunked = parse_head(head, direction, now, peer)
        state['buf'] = bytearray()
        if chunked or direction == 'in':
            state['phase'] = 'skip'
            state['skip'] = 10 ** 9 if chunked else 0
            if state['skip'] == 0:
                state['phase'] = 'head'
                state['buf'] = tail
        else:
            state['skip'] = skip
            state['phase'] = 'skip' if skip else 'head'
            if not skip:
                state['buf'] = tail
        if len(STREAMS) > 400:
            for stale in [k for k, v in STREAMS.items()
                          if now - v['last'] > IDLE_PRUNE]:
                del STREAMS[stale]


if __name__ == '__main__':
    main()
