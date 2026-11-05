"""Exercise built executables with synthetic data and no external model or API."""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    bin_dir = args.bin_dir.resolve(strict=True)
    suffix = ".exe" if os.name == "nt" else ""
    service = bin_dir / f"dhaba-triage{suffix}"
    evaluate = bin_dir / f"evaluate{suffix}"
    evaluate_live = bin_dir / f"evaluate-live{suffix}"
    rereview = bin_dir / f"rereview{suffix}"
    require(all(path.is_file() for path in (service, evaluate, evaluate_live, rereview)), "Missing built executables")

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    # Do not use proxy settings inherited from a workstation or runner.
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(path, payload=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            base + path, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with client.open(req, timeout=5) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as error:
            with error:
                return error.code, error.read(), error.headers

    ticket = {
        "id": "ci-synthetic-ticket",
        "received_at": "2026-09-02T12:00:00Z",
        "subject": "Synthetic build verification",
        "body": "Please help with this synthetic CI question.",
        "purchases": [],
        "app_opens_since_renewal": 0,
    }
    with tempfile.TemporaryDirectory(prefix="dhaba-ci-") as temporary:
        work = Path(temporary)
        env = os.environ.copy()
        env.update(
            TRIAGE_MODE="replay",
            TRIAGE_ADDR=f"127.0.0.1:{port}",
            TRIAGE_DB=str(work / "triage.redb"),
            HTTP_CONCURRENCY="4",
        )
        subprocess.run(
            [str(rereview), "--help"],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
            check=True,
        )
        subprocess.run(
            [str(evaluate_live), "--validate-only"],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
            check=True,
        )
        with (work / "service.log").open("w+", encoding="utf-8") as log:

            def start():
                process = subprocess.Popen(
                    [str(service)], cwd=work, env=env, stdout=log, stderr=log
                )
                try:
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        require(process.poll() is None, "Service exited during startup")
                        try:
                            status, body, _ = request("/health")
                            if status == 200 and json.loads(body) == {"status": "ok"}:
                                return process
                        except (OSError, urllib.error.URLError):
                            pass
                        time.sleep(0.1)
                    raise RuntimeError("Service did not become healthy within 20 seconds")
                except BaseException:
                    stop(process)
                    raise

            process = None
            try:
                process = start()
                status, first, headers = request("/triage", ticket)
                require(status == 200, "Synthetic triage failed")
                require(bool(headers.get("X-Request-Id")), "Missing request correlation ID")
                result = json.loads(first)
                require(result["ticket_id"] == ticket["id"], "Incorrect ticket ID")
                require(result["needs_human"] is True, "Unknown replay must require review")
                require(result["refund"]["amount_inr"] == 0, "Unknown replay approved money")
                require(result["meta"]["source"] == "fallback", "Expected replay fallback")
                status, repeated, _ = request("/triage", ticket)
                require(status == 200 and repeated == first, "Repeated delivery changed the result")
                changed = dict(ticket, body="A different synthetic question.")
                require(request("/triage", changed)[0] == 409, "Changed payload did not conflict")
                require(request("/metrics")[0] == 200, "Metrics endpoint failed")

                fixture = work / "synthetic.json"
                fixture.write_text(json.dumps({"tickets": [ticket]}), encoding="utf-8")
                evaluation = subprocess.run(
                    [str(evaluate), str(fixture), base],
                    cwd=work,
                    env=env,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=40,
                    check=True,
                )
                require(json.loads(evaluation.stdout) == [result], "Evaluation CLI result differs")

                stop(process)
                process = start()
                status, persisted, _ = request("/triage", ticket)
                require(status == 200 and persisted == first, "Restart lost the stored decision")
            except BaseException:
                if process is not None:
                    stop(process)
                log.flush()
                log.seek(0)
                print(log.read(6000))
                raise
            finally:
                if process is not None:
                    stop(process)
    print("Replay smoke passed: health, triage, replay/conflict, metrics, evaluate, live fixtures, rereview help, restart.")


if __name__ == "__main__":
    main()
