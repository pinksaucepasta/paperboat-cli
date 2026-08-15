#!/usr/bin/env python3

import argparse
import base64
import errno
import fcntl
import hashlib
import json
import os
import random
import re
import select
import shlex
import signal
import statistics
import struct
import subprocess
import sys
import termios
import time
from dataclasses import dataclass
from typing import Callable


ATTACHED = b"\x1b[2J\x1b[H"
RAW_RESPONDER = (
    "env TERM=xterm-256color python3 -u -c "
    "\"import os,tty;tty.setraw(0);"
    "[(lambda b:os.write(1,b'PBIN'+b))(os.read(0,1)) for _ in iter(int,1)]\""
)


@dataclass(frozen=True)
class Cell:
    name: str
    entrypoint: str
    transport: str | None


def cells() -> list[Cell]:
    result = [Cell("direct_ssh", "direct_ssh", None)]
    for entrypoint in ("pb_ssh", "openssh_alias", "pb_terminal"):
        for transport in ("d", "q", "w"):
            result.append(Cell(f"{entrypoint}_{transport}", entrypoint, transport))
    return result


def session_delete_command(pb: str, target: str, session_name: str) -> list[str]:
    return [pb, "session", "delete", target, session_name, "--yes"]


def percentile(values: list[float], percent: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(1, (len(ordered) * percent + 99) // 100)
    return ordered[index - 1]


def gaps_ms(events: list[tuple[float, bytes]]) -> list[float]:
    return [(events[index][0] - events[index - 1][0]) * 1000 for index in range(1, len(events))]


def payload(kind: str, records: int, width: int) -> bytes:
    lines = []
    for sequence in range(records):
        prefix = f"PBSEQ{sequence:06d}|".encode()
        available = width - len(prefix) - 1
        if kind == "compressible":
            body = b"X" * available
        else:
            blocks = []
            block = 0
            while sum(map(len, blocks)) < available:
                digest = hashlib.sha256(struct.pack(">II", sequence, block)).digest()
                blocks.append(base64.b64encode(digest))
                block += 1
            body = b"".join(blocks)[:available]
        lines.append(prefix + body + b"\n")
    return b"".join(lines)


def bulk_command(kind: str, records: int, width: int, begin_parts: tuple[int, int], end_parts: tuple[int, int]) -> str:
    if kind == "compressible":
        body = "b'X'*n"
    else:
        body = (
            "b''.join(base64.b64encode(hashlib.sha256(struct.pack('>II',i,j)).digest()) "
            "for j in range((n+43)//44))[:n]"
        )
    program = (
        "import base64,hashlib,struct,sys;"
        f"print('PB_BULK_'+str({begin_parts[0]}+{begin_parts[1]}));"
        f"r={records};w={width};"
        "[(lambda p,n:sys.stdout.buffer.write(p+" + body + "+b'\\n'))"
        "(f'PBSEQ{i:06d}|'.encode(),w-len(f'PBSEQ{i:06d}|')-1) for i in range(r)];"
        "sys.stdout.flush();"
        f"print('PB_BULK_'+str({end_parts[0]}+{end_parts[1]}),flush=True)"
    )
    return "python3 -u -c " + shlex.quote(program)


class PTYSession:
    def __init__(self, argv: list[str], environment: dict[str, str], native: bool):
        self.argv = argv
        self.environment = environment
        self.native = native
        self.pid = -1
        self.master = -1
        self.pending = bytearray()
        self.waited = False

    def start(self) -> None:
        self.pid, self.master = os.forkpty()
        if self.pid == 0:
            os.execvpe(self.argv[0], self.argv, self.environment)
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))

    def write(self, value: bytes) -> None:
        os.write(self.master, value)

    def read_once(self, timeout: float) -> tuple[float, bytes] | None:
        readable, _, _ = select.select([self.master], [], [], max(0.0, timeout))
        if not readable:
            return None
        try:
            chunk = os.read(self.master, 65536)
        except OSError as error:
            if error.errno == errno.EIO:
                return None
            raise
        if not chunk:
            return None
        at = time.monotonic()
        self.pending.extend(chunk)
        if len(self.pending) > 8 << 20:
            del self.pending[: len(self.pending) - (8 << 20)]
        return at, chunk

    def consume(self, marker: bytes) -> bool:
        index = self.pending.find(marker)
        if index < 0:
            return False
        del self.pending[: index + len(marker)]
        return True

    def wait_marker(self, marker: bytes, timeout: float, on_tick: Callable[[float], None] | None = None) -> float:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.consume(marker):
                return time.monotonic()
            now = time.monotonic()
            if on_tick is not None:
                on_tick(now)
            self.read_once(min(0.1, deadline - now))
        raise TimeoutError(f"marker not observed: {marker!r}")

    def read_for(self, duration: float) -> list[tuple[float, bytes]]:
        deadline = time.monotonic() + duration
        events = []
        while time.monotonic() < deadline:
            event = self.read_once(min(0.1, deadline - time.monotonic()))
            if event is not None:
                events.append(event)
        return events

    def wait(self, timeout: float) -> int | None:
        if self.waited:
            return None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid == self.pid:
                self.waited = True
                return os.waitstatus_to_exitcode(status)
            time.sleep(0.02)
        return None

    def close(self) -> None:
        if self.master >= 0:
            try:
                self.write(b"\x03exit\n")
            except OSError:
                pass
        if self.pid > 0 and self.wait(2.0) is None:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            if self.wait(1.0) is None:
                try:
                    os.kill(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.wait(1.0)
        if self.master >= 0:
            try:
                os.close(self.master)
            except OSError:
                pass
            self.master = -1


class Runner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.random = random.SystemRandom()

    def command(self, cell: Cell, session_name: str) -> tuple[list[str], dict[str, str], bool]:
        environment = os.environ.copy()
        ssh_options = [
            "-tt",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={self.args.connect_timeout}",
            "-o", "ConnectionAttempts=1",
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
        ]
        if cell.entrypoint == "direct_ssh":
            return (["ssh", *ssh_options, "-i", self.args.direct_key, self.args.direct_host], environment, False)
        if cell.entrypoint == "pb_ssh":
            return ([self.args.pb, "ssh", self.args.target, "--transport", cell.transport], environment, False)
        if cell.entrypoint == "openssh_alias":
            environment["PAPERBOAT_TRANSPORT"] = cell.transport or ""
            return (["ssh", *ssh_options, f"{self.args.ssh_user}@{self.args.target}.pprbt.dev"], environment, False)
        return (
            [self.args.pb, self.args.target, "new", "--transport", cell.transport or "", "--name", session_name, "--status-bar", "off"],
            environment,
            True,
        )

    def cleanup_session(self, session_name: str) -> None:
        command = session_delete_command(self.args.pb, self.args.target, session_name)
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
                text=True,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"session delete timed out for {session_name}") from error
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            if len(detail) > 500:
                detail = detail[:500] + "..."
            raise RuntimeError(
                f"session delete failed for {session_name}: exit={completed.returncode} output={detail!r}"
            )

    def open_ready(self, cell: Cell, run: int, workload: str) -> tuple[PTYSession, str, float]:
        session_name = f"bench-{workload}-{cell.name}-{run}-{time.time_ns()}"
        argv, environment, native = self.command(cell, session_name)
        terminal = PTYSession(argv, environment, native)
        started = time.monotonic()
        terminal.start()
        left = self.random.randrange(100_000, 900_000)
        right = self.random.randrange(100_000, 900_000)
        expected = f"PB_READY:{left + right}".encode()
        probe = f"printf 'PB_READY:%s\\n' \"$(({left}+{right}))\"\n".encode()
        sent = False
        next_probe = started
        background_replied = False
        cursor_replied = False

        def tick(now: float) -> None:
            nonlocal sent, next_probe, background_replied, cursor_replied
            if not background_replied and (b"\x1b]11;?\x07" in terminal.pending or b"\x1b]11;?\x1b\\" in terminal.pending):
                terminal.write(b"\x1b]11;rgb:0000/0000/0000\x1b\\")
                background_replied = True
            if not cursor_replied and b"\x1b[6n" in terminal.pending:
                terminal.write(b"\x1b[1;1R")
                cursor_replied = True
            if now < next_probe:
                return
            if native and ATTACHED not in terminal.pending:
                return
            if not native and not terminal.pending:
                return
            terminal.write(probe)
            sent = True
            next_probe = now + 0.5

        try:
            ready_at = terminal.wait_marker(expected, self.args.ready_timeout, tick)
            if not sent:
                raise RuntimeError("readiness probe was not sent")
            terminal.pending.clear()
            return terminal, session_name, (ready_at - started) * 1000
        except BaseException as error:
            terminal.close()
            if native:
                try:
                    self.cleanup_session(session_name)
                except Exception as cleanup_error:
                    raise cleanup_error from error
            raise

    def finish(self, terminal: PTYSession, session_name: str) -> None:
        native = terminal.native
        terminal.close()
        if native:
            self.cleanup_session(session_name)

    def startup(self, cell: Cell, run: int) -> dict:
        terminal, session_name, startup_ms = self.open_ready(cell, run, "startup")
        self.finish(terminal, session_name)
        return {"startup_ms": startup_ms}

    def confirm_shell(self, terminal: PTYSession) -> None:
        left = self.random.randrange(100_000, 900_000)
        right = self.random.randrange(100_000, 900_000)
        marker = f"PB_SHELL:{left + right}".encode()
        probe = f"printf 'PB_SHELL:%s\\n' \"$(({left}+{right}))\"\n".encode()
        next_probe = 0.0

        def tick(now: float) -> None:
            nonlocal next_probe
            if now >= next_probe:
                terminal.write(probe)
                next_probe = now + 0.5

        terminal.wait_marker(marker, self.args.ready_timeout, tick)
        terminal.pending.clear()

    def cmatrix_on(self, terminal: PTYSession) -> dict:
        terminal.write(b"env TERM=xterm-256color cmatrix -n -u 2\n")
        terminal.read_for(self.args.cmatrix_warmup)
        terminal.pending.clear()
        events = terminal.read_for(self.args.cmatrix_duration)
        if len(events) < 2:
            raise RuntimeError("cmatrix produced fewer than two read events")
        gaps = gaps_ms(events)
        byte_count = sum(len(chunk) for _, chunk in events)
        terminal.write(b"\x03")
        self.confirm_shell(terminal)
        return {
            "duration_ms": self.args.cmatrix_duration * 1000,
            "bytes": byte_count,
            "events": len(events),
            "bytes_per_second": byte_count / self.args.cmatrix_duration,
            "gap_p50_ms": percentile(gaps, 50),
            "gap_p95_ms": percentile(gaps, 95),
            "gap_p99_ms": percentile(gaps, 99),
            "max_gap_ms": max(gaps),
            "gaps_over_33_ms": sum(value > 33 for value in gaps),
            "gaps_over_50_ms": sum(value > 50 for value in gaps),
            "gaps_over_100_ms": sum(value > 100 for value in gaps),
        }

    def cmatrix(self, cell: Cell, run: int) -> dict:
        terminal, session_name, startup_ms = self.open_ready(cell, run, "cmatrix")
        try:
            return {"startup_ms": startup_ms, **self.cmatrix_on(terminal)}
        finally:
            self.finish(terminal, session_name)

    def input_on(self, terminal: PTYSession) -> dict:
        terminal.write((RAW_RESPONDER + "\n").encode())
        deadline = time.monotonic() + self.args.ready_timeout
        next_probe = 0.0
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_probe:
                terminal.write(b"W")
                next_probe = now + 0.5
            if terminal.consume(b"PBINW"):
                break
            terminal.read_once(0.1)
        else:
            raise TimeoutError("raw responder did not become ready")
        values = []
        for index in range(self.args.input_samples):
            key = bytes([ord("a") + index % 26])
            started = time.monotonic()
            terminal.write(key)
            terminal.wait_marker(b"PBIN" + key, self.args.input_timeout)
            values.append((time.monotonic() - started) * 1000)
            if self.args.input_interval > 0:
                time.sleep(self.args.input_interval)
        return {
            "samples": len(values),
            "input_p50_ms": percentile(values, 50),
            "input_p95_ms": percentile(values, 95),
            "input_p99_ms": percentile(values, 99),
            "input_max_ms": max(values),
            "responses_over_200_ms": sum(value > 200 for value in values),
            "responses_over_500_ms": sum(value > 500 for value in values),
            "values_ms": values,
        }

    def input(self, cell: Cell, run: int) -> dict:
        terminal, session_name, startup_ms = self.open_ready(cell, run, "input")
        try:
            return {"startup_ms": startup_ms, **self.input_on(terminal)}
        finally:
            self.finish(terminal, session_name)

    def bulk_on(self, terminal: PTYSession, kind: str) -> dict:
        expected = payload(kind, self.args.bulk_records, self.args.bulk_width)
        left = self.random.randrange(100_000, 400_000)
        right = self.random.randrange(100_000, 400_000)
        end_left = self.random.randrange(500_000, 700_000)
        end_right = self.random.randrange(500_000, 700_000)
        begin = f"PB_BULK_{left + right}".encode()
        end = f"PB_BULK_{end_left + end_right}".encode()
        command = bulk_command(kind, self.args.bulk_records, self.args.bulk_width, (left, right), (end_left, end_right))
        command_started = time.monotonic()
        terminal.write((command + "\n").encode())
        begin_at = terminal.wait_marker(begin + b"\r\n", self.args.bulk_timeout)
        collected = bytearray()
        events = []
        deadline = time.monotonic() + self.args.bulk_timeout
        while time.monotonic() < deadline:
            marker_index = terminal.pending.find(end)
            if marker_index >= 0:
                collected.extend(terminal.pending[:marker_index])
                end_at = time.monotonic()
                break
            if terminal.pending:
                keep = max(0, len(end) - 1)
                take = max(0, len(terminal.pending) - keep)
                if take:
                    collected.extend(terminal.pending[:take])
                    del terminal.pending[:take]
            event = terminal.read_once(0.1)
            if event is not None:
                events.append(event)
        else:
            raise TimeoutError("bulk end marker was not observed")
        normalized = bytes(collected).replace(b"\r\n", b"\n")
        actual_hash = hashlib.sha256(normalized).hexdigest()
        expected_hash = hashlib.sha256(expected).hexdigest()
        sequences = [int(value) for value in re.findall(rb"PBSEQ(\d{6})\|", normalized)]
        integrity = actual_hash == expected_hash and sequences == list(range(self.args.bulk_records))
        if not integrity:
            raise RuntimeError(
                f"bulk integrity mismatch actual={actual_hash} expected={expected_hash} "
                f"sequences={len(sequences)}/{self.args.bulk_records}"
            )
        transfer_seconds = max(0.000001, end_at - begin_at)
        self.confirm_shell(terminal)
        return {
            "kind": kind,
            "records": self.args.bulk_records,
            "logical_bytes": len(expected),
            "received_bytes": len(collected),
            "sha256": actual_hash,
            "integrity": True,
            "command_to_end_ms": (end_at - command_started) * 1000,
            "first_to_last_ms": transfer_seconds * 1000,
            "logical_bytes_per_second": len(expected) / transfer_seconds,
            "events": len(events),
        }

    def bulk(self, cell: Cell, run: int, kind: str) -> dict:
        terminal, session_name, startup_ms = self.open_ready(cell, run, f"bulk-{kind}")
        try:
            return {"startup_ms": startup_ms, **self.bulk_on(terminal, kind)}
        finally:
            self.finish(terminal, session_name)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="hn-byod-ready")
    parser.add_argument("--pb", default="pb")
    parser.add_argument("--ssh-user", default="root")
    parser.add_argument("--direct-host", default="root@157.180.74.88")
    parser.add_argument("--direct-key", default=os.path.expanduser("~/.ssh/gate8_hetzner"))
    parser.add_argument("--workload", choices=("startup", "cmatrix", "input", "bulk-compressible", "bulk-entropy", "combined", "all"), default="all")
    parser.add_argument("--cell", action="append", default=[])
    parser.add_argument("--startup-runs", type=int, default=50)
    parser.add_argument("--cmatrix-runs", type=int, default=50)
    parser.add_argument("--input-runs", type=int, default=1)
    parser.add_argument("--bulk-runs", type=int, default=50)
    parser.add_argument("--cmatrix-duration", type=float, default=5.0)
    parser.add_argument("--cmatrix-warmup", type=float, default=1.0)
    parser.add_argument("--input-samples", type=int, default=100)
    parser.add_argument("--input-interval", type=float, default=0.02)
    parser.add_argument("--input-timeout", type=float, default=3.0)
    parser.add_argument("--bulk-records", type=int, default=512)
    parser.add_argument("--bulk-width", type=int, default=1024)
    parser.add_argument("--bulk-timeout", type=float, default=30.0)
    parser.add_argument("--ready-timeout", type=float, default=30.0)
    parser.add_argument("--connect-timeout", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20260815)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def self_test() -> None:
    assert percentile([4, 1, 3, 2], 50) == 2
    assert percentile([4, 1, 3, 2], 95) == 4
    assert len(cells()) == 10
    assert session_delete_command("/pb", "machine", "bench-1") == [
        "/pb", "session", "delete", "machine", "bench-1", "--yes",
    ]
    for kind in ("compressible", "entropy"):
        value = payload(kind, 5, 80)
        assert len(value) == 400
        assert len(re.findall(rb"PBSEQ(\d{6})\|", value)) == 5
        command = bulk_command(kind, 5, 80, (11, 22), (33, 44))
        completed = subprocess.run(["sh", "-c", command], check=True, stdout=subprocess.PIPE)
        assert completed.stdout == value.replace(b"PBSEQ000000", b"PB_BULK_33\nPBSEQ000000", 1) + b"PB_BULK_77\n"
    print("self-test: pass")


def emit(value: dict) -> None:
    print(json.dumps(value, separators=(",", ":")), flush=True)


def interrupt(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    signal.signal(signal.SIGTERM, interrupt)
    if min(args.startup_runs, args.cmatrix_runs, args.input_runs, args.bulk_runs, args.input_samples, args.bulk_records, args.bulk_width) < 1:
        raise SystemExit("run and sample counts must be positive")
    selected = cells()
    if args.cell:
        requested = set(args.cell)
        selected = [cell for cell in selected if cell.name in requested]
        unknown = requested - {cell.name for cell in selected}
        if unknown:
            raise SystemExit(f"unknown cells: {', '.join(sorted(unknown))}")
    workloads = [args.workload] if args.workload != "all" else ["startup", "cmatrix", "input", "bulk-compressible", "bulk-entropy"]
    counts = {
        "startup": args.startup_runs,
        "cmatrix": args.cmatrix_runs,
        "input": args.input_runs,
        "bulk-compressible": args.bulk_runs,
        "bulk-entropy": args.bulk_runs,
        "combined": args.startup_runs,
    }
    emit({
        "schema": "paperboat.terminal-comparison/v1",
        "type": "metadata",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": args.target,
        "cells": [cell.name for cell in selected],
        "workloads": workloads,
        "counts": {workload: counts[workload] for workload in workloads},
        "cmatrix_duration_seconds": args.cmatrix_duration,
        "input_samples_per_run": args.input_samples,
        "bulk_records": args.bulk_records,
        "bulk_width": args.bulk_width,
        "rotation_seed": args.seed,
    })
    runner = Runner(args)
    failures = 0
    rng = random.Random(args.seed)
    for workload in workloads:
        for run in range(1, counts[workload] + 1):
            order = selected.copy()
            rng.shuffle(order)
            for cell in order:
                if workload == "combined":
                    session_name = ""
                    terminal = None
                    startup_ms = 0.0
                    stages = [
                        ("cmatrix", lambda: runner.cmatrix_on(terminal)),
                        ("bulk-compressible", lambda: runner.bulk_on(terminal, "compressible")),
                        ("bulk-entropy", lambda: runner.bulk_on(terminal, "entropy")),
                    ]
                    try:
                        terminal, session_name, startup_ms = runner.open_ready(cell, run, "combined")
                        common = {
                            "schema": "paperboat.terminal-comparison/v1",
                            "type": "sample",
                            "cell": cell.name,
                            "entrypoint": cell.entrypoint,
                            "transport": cell.transport or "tcp",
                            "run": run,
                        }
                        emit({**common, "workload": "startup", "ok": True, "startup_ms": startup_ms})
                        for stage, operation in stages:
                            stage_started = time.monotonic()
                            try:
                                emit({**common, "workload": stage, "ok": True, "startup_ms": startup_ms, **operation()})
                            except Exception as error:
                                failures += 1
                                emit({**common, "workload": stage, "ok": False, "startup_ms": startup_ms, "elapsed_ms": (time.monotonic() - stage_started) * 1000, "error": f"{type(error).__name__}: {error}"})
                                break
                    except Exception as error:
                        failures += 1
                        emit({
                            "schema": "paperboat.terminal-comparison/v1",
                            "type": "sample",
                            "workload": "startup",
                            "cell": cell.name,
                            "entrypoint": cell.entrypoint,
                            "transport": cell.transport or "tcp",
                            "run": run,
                            "ok": False,
                            "error": f"{type(error).__name__}: {error}",
                        })
                    finally:
                        if terminal is not None:
                            runner.finish(terminal, session_name)
                    continue
                started = time.monotonic()
                base = {
                    "schema": "paperboat.terminal-comparison/v1",
                    "type": "sample",
                    "workload": workload,
                    "cell": cell.name,
                    "entrypoint": cell.entrypoint,
                    "transport": cell.transport or "tcp",
                    "run": run,
                }
                try:
                    if workload == "startup":
                        result = runner.startup(cell, run)
                    elif workload == "cmatrix":
                        result = runner.cmatrix(cell, run)
                    elif workload == "input":
                        result = runner.input(cell, run)
                    else:
                        result = runner.bulk(cell, run, workload.removeprefix("bulk-"))
                    emit({**base, "ok": True, **result})
                except Exception as error:
                    failures += 1
                    emit({**base, "ok": False, "elapsed_ms": (time.monotonic() - started) * 1000, "error": f"{type(error).__name__}: {error}"})
    emit({
        "schema": "paperboat.terminal-comparison/v1",
        "type": "complete",
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "failures": failures,
    })
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
