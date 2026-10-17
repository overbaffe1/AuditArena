#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Зонд предупреждений платформы (раунд 15).

Описание start_process обещает: если платформа обнаружит ответ, ломающий
предпросмотр (отказ по host/origin или блокировку встраивания в iframe), она
сообщит об этом в поле warnings. В раунде 10 предупреждений получить не удалось
(пять подтверждений), но тогда зонды отвечали 200 на любой запрос.

Этот сервер намеренно отвечает 403 на любой Host, кроме localhost/127.0.0.1, и
добавляет оба заголовка блокировки встраивания: X-Frame-Options: DENY и
Content-Security-Policy: frame-ancestors 'none'. Задача — проверить, сформирует
ли платформа warnings и какие именно запросы она шлёт в песочницу при старте
процесса (Host, User-Agent, метод, путь).

Журнал пишется в stderr: обёртка порождения процессов направляет и stdout, и
stderr в out.log, который платформа читает через get_process_output.
"""

import datetime
import http.server
import os
import socketserver
import sys

PORT = int(os.environ.get('PROBE_PORT', '8097'))
BIND = os.environ.get('PROBE_BIND', '0.0.0.0')


def note(text):
    stamp = datetime.datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]
    sys.stderr.write('%s %s\n' % (stamp, text))
    sys.stderr.flush()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def handle_one(self):
        host = (self.headers.get('Host') or '').split(':')[0]
        allowed = host in ('localhost', '127.0.0.1')
        note('%s %s host=%s allowed=%s ua=%s headers=%s' % (
            self.command, self.path, self.headers.get('Host'), allowed,
            self.headers.get('User-Agent'), sorted(self.headers.keys())))
        body = b'ok\n' if allowed else b'host not allowed\n'
        self.send_response(200 if allowed else 403)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "frame-ancestors 'none'")
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    do_GET = handle_one
    do_HEAD = handle_one
    do_POST = handle_one
    do_OPTIONS = handle_one

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    with Server((BIND, PORT), Handler) as httpd:
        note('listening %s:%d pid=%d' % (BIND, PORT, os.getpid()))
        httpd.serve_forever()


if __name__ == '__main__':
    main()
