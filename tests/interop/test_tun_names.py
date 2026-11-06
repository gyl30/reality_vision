#!/usr/bin/env python3
"""在独立 user/network/mount namespace 中验收 TUN 名称；不安装路由。"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
import run_xray_interop as interop  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("RV_TUN_NAMES_NAMESPACE") != "1":
        os.environ["RV_TUN_NAMES_NAMESPACE"] = "1"
        os.execvp("unshare", ["unshare", "-Urnm", sys.executable, *sys.argv])
    args.work_dir.mkdir(parents=True, exist_ok=True)
    failures = []
    for label, name in (
        ("default", None),
        ("auto", ""),
        ("15-bytes", "rv1234567890123"),
        ("16-bytes", "rv12345678901234"),
        ("long", "rv" + "x" * 40),
    ):
        command = [
            str(args.client.resolve()),
            "--server",
            "127.0.0.1",
            "--port",
            "1",
            "--server_name",
            interop.SERVER_NAME,
            "--server_public_key",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "--short_id",
            interop.SHORT_ID,
            "--uuid",
            interop.USER_ID,
            "--tun",
        ]
        if name is not None:
            command += ["--tun_name", name]
        log_path = args.work_dir / f"{label}.log"
        with log_path.open("wb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 4
                while (
                    process.poll() is None
                    and "TUN inbound " not in log_path.read_text()
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.02)
                output = log_path.read_text()
                links = json.loads(
                    subprocess.check_output(["ip", "-j", "link", "show"], text=True)
                )
                devices = [link["ifname"] for link in links if link["ifname"] != "lo"]
                invalid = name is not None and len(name.encode()) >= 16
                if invalid:
                    if process.poll() != 1 or devices or "--tun_name" not in output:
                        failures.append(
                            f"{label}: expected configuration exit 1 and no device; exit={process.poll()} devices={devices} log={output!r}"
                        )
                else:
                    match = re.search(r"TUN inbound (\S+) started", output)
                    actual = match.group(1) if match else None
                    expected = "rv-tun" if name is None else name
                    if (
                        process.poll() is not None
                        or devices != [actual]
                        or not actual
                        or (expected and actual != expected)
                    ):
                        failures.append(
                            f"{label}: requested={name!r} actual={actual!r} devices={devices} log={output!r}"
                        )
                    if actual:
                        subprocess.run(["ip", "link", "delete", actual], check=True)
                        process.wait(timeout=5)
                print(
                    json.dumps(
                        {
                            "case": label,
                            "requested": name,
                            "bytes": None if name is None else len(name.encode()),
                            "devices": devices,
                            "exit": process.poll(),
                        }
                    ),
                    flush=True,
                )
            finally:
                interop.stop_process(process)
                links = json.loads(
                    subprocess.check_output(["ip", "-j", "link", "show"], text=True)
                )
                if any(link["ifname"] != "lo" for link in links):
                    failures.append(f"{label}: device remained after process exit")
    if failures:
        raise RuntimeError("\n".join(failures))
    print("TUN name boundaries and device cleanup passed")


if __name__ == "__main__":
    main()
