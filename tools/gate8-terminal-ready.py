#!/usr/bin/env python3

import fcntl
import os
import random
import select
import signal
import struct
import sys
import termios
import time


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


if len(sys.argv) != 6:
    fail("usage: gate8-terminal-ready.py TARGET TRANSPORT SESSION LABEL RAW_OUTPUT")

target, transport, session, label, output_path = sys.argv[1:]
left = random.SystemRandom().randrange(100_000, 900_000)
right = random.SystemRandom().randrange(100_000, 900_000)
expected = f"GATE8_READY:{left + right}".encode()
probe = f"printf 'GATE8_READY:%s\\n' \"$(({left}+{right}))\"\n".encode()
deadline = time.monotonic() + 40
next_probe = 0.0
observed = bytearray()
background_replied = False
cursor_replied = False
remote_attached = False
child_pid, master = os.forkpty()

if child_pid == 0:
    os.execvp(
        "pb",
        [
            "pb",
            target,
            "--transport",
            transport,
            "--name",
            session,
            "--status-bar",
            "off",
        ],
    )

fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))

try:
    with open(output_path, "wb", buffering=0) as output:
        while time.monotonic() < deadline:
            now = time.monotonic()
            if remote_attached and now >= next_probe:
                os.write(master, probe)
                next_probe = now + 0.5
            readable, _, _ = select.select([master], [], [], 0.1)
            if not readable:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError:
                chunk = b""
            if not chunk:
                _, status = os.waitpid(child_pid, 0)
                fail(
                    "terminal attach exited before readiness "
                    f"for {label}: exit={os.waitstatus_to_exitcode(status)}"
                )
                break
            output.write(chunk)
            observed.extend(chunk)
            if len(observed) > 1 << 20:
                del observed[: len(observed) - (1 << 20)]
            if not background_replied and (
                b"\x1b]11;?\x07" in observed or b"\x1b]11;?\x1b\\" in observed
            ):
                os.write(master, b"\x1b]11;rgb:0000/0000/0000\x1b\\")
                background_replied = True
            if not cursor_replied and b"\x1b[6n" in observed:
                os.write(master, b"\x1b[1;1R")
                cursor_replied = True
            if not remote_attached and b"\x1b[2J\x1b[H" in observed:
                remote_attached = True
            if expected in observed:
                os.write(master, b"exit\n")
                _, status = os.waitpid(child_pid, 0)
                if os.waitstatus_to_exitcode(status) != 0:
                    fail(f"terminal exited nonzero after readiness for {label}")
                print(expected.decode())
                raise SystemExit(0)
finally:
    try:
        os.kill(child_pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        os.close(master)
    except OSError:
        pass

fail(f"terminal readiness canary was not observed for {label}")
