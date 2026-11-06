"""Reproduce bounded Task 3 degradation using only Python's standard library.

Build: cargo build --locked --bin dhaba-triage
Run:   python scripts/load-demo.py --report .runtime/load-demo.json

Default: 100 distinct tickets scheduled at 50/second; local mock latency 1000 ms.
A separate three-request probe forces HTTP 503, checks Retry-After, then retries.
No external model, API key, paid call, or existing database is used.
"""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

SENTINEL = "PRIVATE_SYNTHETIC_LOAD_SENTINEL_8326"
MODEL_LIMIT, HTTP_LIMIT = 4, 64
ANALYSIS = {
    "category": "technical", "severity": "medium", "language": "english",
    "confidence": 0.99, "refund_requested": False,
    "details": {"secondary_intent": None, "additional_intents": [],
                "refund_target": "unspecified", "unsupported_language": False,
                "reported": ["device_provided", "app_version_provided", "error_details_provided"],
                "missing": []},
}
MODEL_REPLY = json.dumps({"message": {"role": "assistant", "content": json.dumps(ANALYSIS)},
                         "done": True, "done_reason": "stop"}).encode("utf-8")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def http_json(base, path, payload=None, timeout=5):
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(base + path, data, {"Content-Type": "application/json"})
    try:
        response = client.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.load(response), response.headers


class MockOllama:
    """Fixed classifier fixture, deliberately not a real language model."""

    def __init__(self, latency_seconds, gated=False):
        self.latency, self.lock = latency_seconds, threading.Lock()
        self.entered, self.release = threading.Event(), threading.Event()
        self.active = self.peak = self.calls = self.errors = 0
        if not gated:
            self.release.set()
        state = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_POST(self):
                size = int(self.headers.get("Content-Length", "0"))
                if self.path != "/api/chat" or not 0 < size <= 65_536:
                    self.send_error(400)
                    return
                self.rfile.read(size)
                with state.lock:
                    state.calls += 1
                    state.active += 1
                    state.peak = max(state.peak, state.active)
                state.entered.set()
                try:
                    require(state.release.wait(timeout=10), "HTTP probe gate timed out")
                    time.sleep(state.latency)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(MODEL_REPLY)))
                    self.end_headers()
                    self.wfile.write(MODEL_REPLY)
                except (OSError, RuntimeError):
                    with state.lock:
                        state.errors += 1
                finally:
                    with state.lock:
                        state.active -= 1

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.05), daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def snapshot(self):
        with self.lock:
            return {"calls": self.calls, "peak_concurrency": self.peak, "errors": self.errors}


@contextmanager
def service(executable, work, mock, name, http_limit=HTTP_LIMIT):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    base, log_path = f"http://127.0.0.1:{port}", work / f"{name}.log"
    env = {key: value for key, value in os.environ.items() if not key.startswith("DEEPSEEK_")}
    env.update(TRIAGE_MODE="ollama", TRIAGE_ADDR=f"127.0.0.1:{port}",
               TRIAGE_DB=str(work / f"{name}.redb"), OLLAMA_URL=mock.base,
               OLLAMA_MODEL="synthetic-local-load-fixture", MODEL_CONCURRENCY=str(MODEL_LIMIT),
               MODEL_TIMEOUT_MS="8000", HTTP_CONCURRENCY=str(http_limit),
               ANALYSIS_CACHE_NAMESPACE=f"load-demo-{name}",
               ANALYSIS_CACHE_CAPACITY="256", ANALYSIS_CACHE_TTL_SECS="300")
    with log_path.open("wb") as log:
        # Fresh cwd ignores the project's .env; the copied executable never locks target/.
        process = subprocess.Popen([str(executable)], cwd=work, env=env, stdout=log, stderr=log,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                require(process.poll() is None, "Service exited during startup")
                try:
                    if http_json(base, "/health", timeout=0.3)[:2] == (200, {"status": "ok"}):
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.05)
            else:
                raise RuntimeError("Service startup exceeded 15 seconds")
            yield base, log_path
        finally:
            # Stop only this script's own child, never processes selected by name.
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def inspect_logs(path, requests, decisions):
    log = path.read_text(encoding="utf-8", errors="replace")
    require(bool(log.strip()), "Empty logs would make the privacy check vacuous")
    require(all(text not in log for text in
                (SENTINEL, "Synthetic control number", "synthetic-load-ticket-")),
            "Operational logs exposed synthetic customer data")
    events = Counter(json.loads(line).get("fields", {}).get("event") for line in log.splitlines())
    require(events["triage_request"] == requests, "Request-log count differs from HTTP attempts")
    require(events["triage_decision"] == decisions, "Decision-log count differs from triage results")
    return {"privacy_passed": True, "request_events": requests, "decision_events": decisions}


def ticket(index, phase):
    return {"id": f"synthetic-load-ticket-{phase}-{index}",
            "received_at": "2033-07-21T12:00:00Z", "subject": "Synthetic local outage exercise",
            "body": f"Synthetic control number {index} freezes in app version 5.0 on an invented Android 15 device. {SENTINEL}",
            "purchases": [], "app_opens_since_renewal": 0}


def send(base, payload, scheduled_at):
    started = time.monotonic()
    status, body, headers = http_json(base, "/triage", payload, timeout=8)
    require(bool(headers.get("x-request-id")), "Handled response lacks a request ID")
    if status == 503:
        require(body == {"error": "service_busy", "retryable": True}, "Unexpected 503 response")
        require(headers.get("Retry-After") == "1", "Missing Retry-After: 1")
        source = "http_rejected"
    else:
        require(status == 200 and body["ticket_id"] == payload["id"], "Unexpected triage response")
        refund, meta = body["refund"], body["meta"]
        require(refund["amount_inr"] == 0 and refund["purchase_id"] is None and
                refund["decision"] in ("not_requested", "review_required"), "Unexpected money authorization")
        require(body["needs_human"] is True and meta["language"] == "english", "Incorrect routing/language")
        require(SENTINEL not in body["reply_draft"], "Draft exposed the private sentinel")
        source = meta["source"]
        require(source in ("ollama", "fallback"), "Unexpected or paid analysis source")
        if source == "fallback":
            require(body["confidence"] == 0 and meta["degraded_reason"] == "model_busy" and
                    meta["model_attempts"] == 0, "Fallback did not safely represent model pressure")
        else:
            require(meta["model_attempts"] == 1, "Local fixture unexpectedly required retries")
    return {"status": status, "source": source, "body": body, "started_at": started,
            "latency_ms": (time.monotonic() - started) * 1_000,
            "dispatch_lag_ms": max(0, (started - scheduled_at) * 1_000)}


def percentile(rows, percent):
    ordered = sorted(row["latency_ms"] for row in rows)
    return round(ordered[math.ceil(len(ordered) * percent / 100) - 1], 2)


def example(row):
    body = row["body"]
    return {key: body[key] for key in ("category", "refund", "reply_draft", "needs_human", "confidence", "meta")}


def run_arrivals(executable, work, args):
    with MockOllama(args.latency_ms / 1_000) as mock:
        with service(executable, work, mock, "arrivals") as (base, log):
            started = time.monotonic()
            with ThreadPoolExecutor(max_workers=min(128, args.requests)) as pool:
                futures = []
                for index in range(args.requests):
                    scheduled = started + index / args.rate
                    time.sleep(max(0, scheduled - time.monotonic()))
                    futures.append(pool.submit(send, base, ticket(index, "arrivals"), scheduled))
                dispatch_seconds = time.monotonic() - started
                rows = [future.result() for future in futures]
            elapsed = time.monotonic() - started
            status, metrics, _ = http_json(base, "/metrics")
            require(status == 200 and http_json(base, "/health")[:2] == (200, {"status": "ok"}),
                    "Service unhealthy after load")
        counts, statuses, stats = Counter(row["source"] for row in rows), Counter(str(row["status"]) for row in rows), mock.snapshot()
    require(counts["ollama"] > 0 and counts["fallback"] > 0, "Both model success and pressure must be exercised")
    require(stats["peak_concurrency"] == MODEL_LIMIT and stats["errors"] == 0, "Model bound not reached or exceeded, or mock failed")
    require(stats["calls"] == counts["ollama"], "Mock-call accounting differs from successful model replies")
    require(metrics["triage_evaluated_total"] == statuses["200"] and
            metrics["triage_degraded_total"] == counts["fallback"] and
            metrics["triage_http_overload_total"] == statuses["503"], "HTTP and stored-result counters differ")
    require(metrics["model_usage"]["calls"] == 0, "A paid-provider call was recorded")
    span = max(row["started_at"] for row in rows) - min(row["started_at"] for row in rows)
    return {"requests": len(rows), "requested_arrival_rate_per_second": args.rate,
            "dispatch_seconds": round(dispatch_seconds, 3), "total_elapsed_seconds": round(elapsed, 3),
            "observed_arrival_rate_per_second": round((len(rows) - 1) / span, 2),
            "http_completions_per_second": round(len(rows) / elapsed, 2),
            "http_200_results_per_second": round(statuses["200"] / elapsed, 2),
            "model_classified_results_per_second": round(counts["ollama"] / elapsed, 2),
            "status_counts": dict(statuses), "analysis_source_counts": dict(counts), "mock_model": stats,
            "p50_latency_ms": percentile(rows, 50), "p95_latency_ms": percentile(rows, 95),
            "max_dispatch_lag_ms": round(max(row["dispatch_lag_ms"] for row in rows), 2),
            "model_pressure_exercised": True, "all_fallbacks_require_human": True, "no_money_authorized": True,
            "operational_logs": inspect_logs(log, len(rows), statuses["200"]),
            "policy_versions": sorted({row["body"]["meta"]["policy_version"] for row in rows if row["status"] == 200}),
            "response_examples": {source: example(next(row for row in rows if row["source"] == source))
                                  for source in ("ollama", "fallback")}, "service_metrics": metrics}


def run_admission_probe(executable, work):
    with MockOllama(0, gated=True) as mock:
        with service(executable, work, mock, "admission", http_limit=1) as (base, log):
            with ThreadPoolExecutor(max_workers=1) as pool:
                first = pool.submit(send, base, ticket(0, "admission"), time.monotonic())
                try:
                    require(mock.entered.wait(timeout=5), "Admission probe did not reach the model")
                    rejected = send(base, ticket(1, "admission"), time.monotonic())
                    require(rejected["status"] == 503 and mock.snapshot()["calls"] == 1,
                            "Occupied HTTP slot did not reject without another model call")
                finally:
                    mock.release.set()
                require(first.result(timeout=5)["status"] == 200, "Admitted request did not finish")
            require(send(base, ticket(1, "admission"), time.monotonic())["status"] == 200, "Retry failed")
            status, metrics, _ = http_json(base, "/metrics")
            require(status == 200 and metrics["triage_evaluated_total"] == 2 and
                    metrics["triage_http_overload_total"] == 1, "Rejected request was stored or counts differ")
            require(http_json(base, "/health")[:2] == (200, {"status": "ok"}), "Probe left service unhealthy")
        stats = mock.snapshot()
    require(stats == {"calls": 2, "peak_concurrency": 1, "errors": 0}, "Admission retry made extra calls")
    return {"requests": 3, "http_concurrency": 1, "status_counts": {"200": 2, "503": 1},
            "retry_after": "1", "rejected_request_recorded": False, "retry_succeeded": True,
            "mock_model": stats, "operational_logs": inspect_logs(log, 3, 2), "rejection_body": rejected["body"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bin-dir", type=Path, default=Path(__file__).resolve().parents[1] / "target/debug")
    parser.add_argument("--requests", type=int, default=100, help="Arrival-phase tickets, 20..500")
    parser.add_argument("--rate", type=float, default=50, help="Scheduled arrivals/second, 5..200")
    parser.add_argument("--latency-ms", type=int, default=1_000, help="Fixed local-model delay, 50..2000 ms")
    parser.add_argument("--report", type=Path, help="Also export the JSON report to this path")
    args = parser.parse_args()
    if not (20 <= args.requests <= 500 and math.isfinite(args.rate) and 5 <= args.rate <= 200
            and 50 <= args.latency_ms <= 2_000 and args.requests / args.rate <= 10
            and args.rate * args.latency_ms / 1_000 > MODEL_LIMIT):
        parser.error("Use bounded counts/rate/delay; duration <=10s and rate*delay must exceed four model permits")
    executable = (args.bin_dir / ("dhaba-triage.exe" if os.name == "nt" else "dhaba-triage")).resolve()
    if not executable.is_file():
        parser.error("Build first: cargo build --locked --bin dhaba-triage")
    report = {"schema_version": 1, "scenario": "local_mock_outage_degradation",
              "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
              "service_binary_sha256": sha256_file(executable), "script_sha256": sha256_file(Path(__file__)),
              "external_api_calls": 0, "external_api_cost_usd": 0, "mock_latency_ms": args.latency_ms,
              "configured_model_concurrency": MODEL_LIMIT, "configured_http_concurrency": HTTP_LIMIT,
              "limitation": "Short local-mock exercise, not live LLM quality, sustained capacity, or a circuit breaker. HTTP results/fallbacks are distinct from model-classified replies."}
    try:
        temporary_root = Path(tempfile.gettempdir()).resolve()
        with tempfile.TemporaryDirectory(prefix="dhaba-load-", dir=temporary_root) as temporary:
            work = Path(temporary).resolve()
            require(work.parent == temporary_root and work.name.startswith("dhaba-load-"), "Unexpected temporary directory")
            copied = work / executable.name
            shutil.copy2(executable, copied)  # Only this new owned directory is later cleaned up.
            report["arrival_phase"] = run_arrivals(copied, work, args)
            report["http_admission_probe"] = run_admission_probe(copied, work)
        report.update(owned_processes_stopped=True, passed=True)
    except (RuntimeError, OSError, ValueError, KeyError) as error:
        report.update(passed=False, failure=str(error))
    rendered = json.dumps(report, indent=2) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

