#!/usr/bin/env python3
import os
import sys
import time


def frame(index: int) -> bytes:
    header = (
        f"\x1b[2K\r[agent] step={index:04d} analyzing src/module_{index % 37:02d}.go "
        f"tests={index * 13 % 997:03d} patch=@@ -{index % 211},7 +{index % 223},9 @@\n"
    ).encode("ascii")
    line = (
        f"+ result_{index % 53:02d} := verify(operation_{index % 29:02d}, "
        f"status_{index % 17:02d}) // deterministic agent workload\n"
    ).encode("ascii")
    body = (line * ((32 << 10) // len(line) + 1))[: (32 << 10) - len(header)]
    return header + body


def main() -> int:
    frames = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    interval = float(sys.argv[2]) if len(sys.argv) > 2 else 0.02
    for index in range(frames):
        os.write(sys.stdout.fileno(), frame(index))
        time.sleep(interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
