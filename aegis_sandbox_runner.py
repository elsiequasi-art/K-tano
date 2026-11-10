"""Bounded test coordinator for the Aegis Docker Desktop VM runner.

This module is copied read-only into a Linux container hosted by Docker Desktop.
It launches one fresh Python process per test case, so imports and module globals
do not leak between cases. The host invokes this file only inside the VM-backed
container with networking disabled.
"""

import argparse
import contextlib
import importlib
import io
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path


REPORT_MARKER = "AEGIS_REPORT:"
CASE_MARKER = "AEGIS_CASE:"
MAX_SUITE_BYTES = 128 * 1024
MAX_TESTS = 16
MAX_CASE_OUTPUT_BYTES = 64 * 1024
MAX_CAPTURE_CHARACTERS = 2_000
MAX_TRACE_CHARACTERS = 4_000
CASE_TIMEOUT_SECONDS = 5
TOTAL_TIMEOUT_SECONDS = 105
MAX_REPORT_BYTES = 128 * 1024
NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,79}$")


class CappedText(io.TextIOBase):
    def __init__(self, limit):
        self.limit = limit
        self.parts = []
        self.length = 0
        self.truncated = False

    def write(self, value):
        text = str(value)
        remaining = self.limit - self.length
        if remaining > 0:
            kept = text[:remaining]
            self.parts.append(kept)
            self.length += len(kept)
        if len(text) > remaining:
            self.truncated = True
        return len(text)

    def getvalue(self):
        return "".join(self.parts)

    def flush(self):
        return None

    def isatty(self):
        return False


def _valid_json_value(value, depth=0):
    if depth > 32:
        return False
    if value is None or isinstance(value, (bool, int, float, str)):
        return not isinstance(value, str) or len(value) <= 32_000
    if isinstance(value, list):
        return len(value) <= 2_000 and all(_valid_json_value(item, depth + 1) for item in value)
    if isinstance(value, dict):
        return len(value) <= 2_000 and all(
            isinstance(key, str) and len(key) <= 256 and _valid_json_value(item, depth + 1)
            for key, item in value.items()
        )
    return False


def _validate_suite(suite):
    if not isinstance(suite, dict) or set(suite) != {"tests"}:
        raise ValueError("Suite JSON must contain only a top-level tests array.")
    cases = suite["tests"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_TESTS:
        raise ValueError(f"Suite must contain between 1 and {MAX_TESTS} test cases.")
    allowed_case_keys = {
        "name", "function", "class", "method", "constructor_args",
        "constructor_kwargs", "args", "kwargs", "expect",
    }
    names = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) - allowed_case_keys:
            raise ValueError(f"Test {index + 1} has an invalid shape or unknown fields.")
        name = case.get("name")
        if not isinstance(name, str) or not name.strip() or len(name) > 100:
            raise ValueError(f"Test {index + 1} needs a short name.")
        if name in names:
            raise ValueError(f"Test names must be unique; {name!r} is repeated.")
        names.add(name)
        function = case.get("function")
        class_name = case.get("class")
        method = case.get("method")
        if bool(function) == bool(class_name):
            raise ValueError(f"Test {index + 1} must specify either function or class and method.")
        if function is not None and (not isinstance(function, str) or not NAME_PATTERN.fullmatch(function)):
            raise ValueError(f"Test {index + 1} has an invalid function name.")
        if class_name is not None:
            if not isinstance(class_name, str) or not NAME_PATTERN.fullmatch(class_name):
                raise ValueError(f"Test {index + 1} has an invalid class name.")
            if not isinstance(method, str) or not NAME_PATTERN.fullmatch(method):
                raise ValueError(f"Test {index + 1} has an invalid method name.")
        elif "method" in case or "constructor_args" in case or "constructor_kwargs" in case:
            raise ValueError(f"Test {index + 1} uses class-only fields with a function call.")
        for key in ("args", "constructor_args"):
            value = case.get(key, [])
            if not isinstance(value, list) or len(value) > 32:
                raise ValueError(f"Test {index + 1} {key} must be an array of at most 32 values.")
        for key in ("kwargs", "constructor_kwargs"):
            value = case.get(key, {})
            if not isinstance(value, dict) or len(value) > 32 or any(
                not isinstance(argument, str) or not NAME_PATTERN.fullmatch(argument)
                for argument in value
            ):
                raise ValueError(f"Test {index + 1} {key} must be an object with simple argument names.")
        if not all(_valid_json_value(case.get(key, [] if key in ("args", "constructor_args") else {})) for key in (
            "args", "kwargs", "constructor_args", "constructor_kwargs"
        )):
            raise ValueError(f"Test {index + 1} contains an oversized or deeply nested payload.")
        expectation = case.get("expect", {})
        if not isinstance(expectation, dict) or set(expectation) - {"exception", "return_type", "return_equals"}:
            raise ValueError(f"Test {index + 1} has an invalid expect object.")
        if len(expectation) > 1:
            raise ValueError(f"Test {index + 1} may specify one expectation at a time.")
        if "exception" in expectation and (
            not isinstance(expectation["exception"], str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]{0,159}", expectation["exception"])
        ):
            raise ValueError(f"Test {index + 1} has an invalid expected exception name.")
        if "return_type" in expectation and (
            not isinstance(expectation["return_type"], str)
            or not NAME_PATTERN.fullmatch(expectation["return_type"])
        ):
            raise ValueError(f"Test {index + 1} has an invalid expected return type.")
        if not _valid_json_value(expectation):
            raise ValueError(f"Test {index + 1} contains an invalid expectation value.")
    return cases


def _run_case_worker(index, module_name, suite_path, workspace):
    command = [
        sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
        "--case-index", str(index), "--entry-module", module_name,
        "--suite", suite_path, "--workspace", workspace,
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        close_fds=True,
        start_new_session=True,
    )
    output = bytearray()
    overflow = False
    timed_out = False
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + CASE_TIMEOUT_SECONDS
    try:
        while process.poll() is None or selector.get_map():
            if time.monotonic() >= deadline:
                timed_out = True
                break
            ready = selector.select(timeout=0.1)
            for key, _ in ready:
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(chunk) > MAX_CASE_OUTPUT_BYTES:
                    overflow = True
                    break
                output.extend(chunk)
            if overflow:
                break
        if timed_out or overflow:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
    finally:
        selector.close()
        process.stdout.close()
    if timed_out:
        return {"status": "timeout", "elapsed_ms": CASE_TIMEOUT_SECONDS * 1_000, "error": f"Case exceeded {CASE_TIMEOUT_SECONDS} seconds."}
    if overflow:
        return {"status": "output_limit", "error": "Case output exceeded the 32 KiB worker limit."}
    text = output.decode("utf-8", errors="replace")
    result_lines = [line[len(CASE_MARKER):] for line in text.splitlines() if line.startswith(CASE_MARKER)]
    if not result_lines:
        return {
            "status": "runner_error",
            "error": f"Case worker exited with status {process.returncode} without a result record.",
            "worker_output": text[-2_000:],
        }
    try:
        result = json.loads(result_lines[-1])
    except json.JSONDecodeError:
        return {"status": "runner_error", "error": "Case worker returned an unreadable result record."}
    return result if isinstance(result, dict) else {"status": "runner_error", "error": "Invalid case result."}


def _run_case(index, module_name, suite_path, workspace):
    started = time.monotonic()
    cases = _validate_suite(json.loads(Path(suite_path).read_text(encoding="utf-8")))
    case = cases[index]
    sys.path.insert(0, workspace)
    stdout_capture = CappedText(MAX_CAPTURE_CHARACTERS)
    stderr_capture = CappedText(MAX_CAPTURE_CHARACTERS)
    result = None
    caught = None
    trace = ""
    try:
        with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
            module = importlib.import_module(module_name)
            if "function" in case:
                target = getattr(module, case["function"])
                call_args = case.get("args", [])
                call_kwargs = case.get("kwargs", {})
            else:
                target_class = getattr(module, case["class"])
                instance = target_class(
                    *case.get("constructor_args", []),
                    **case.get("constructor_kwargs", {}),
                )
                target = getattr(instance, case["method"])
                call_args = case.get("args", [])
                call_kwargs = case.get("kwargs", {})
            result = target(*call_args, **call_kwargs)
    except BaseException as error:
        caught = error
        trace = traceback.format_exc()[-MAX_TRACE_CHARACTERS:]

    expectation = case.get("expect", {})
    status = "passed"
    message = "Call completed as expected."
    exception_name = None
    if caught is not None:
        exception_name = f"{type(caught).__module__}.{type(caught).__name__}"
        expected_exception = expectation.get("exception")
        if expected_exception and expected_exception in (type(caught).__name__, exception_name):
            message = f"Observed expected exception {exception_name}."
        else:
            status = "failed"
            message = f"Unexpected exception: {exception_name}: {caught}"
    elif "exception" in expectation:
        status = "failed"
        message = f"Expected exception {expectation['exception']} was not raised."
    elif "return_type" in expectation and type(result).__name__ != expectation["return_type"]:
        status = "failed"
        message = f"Expected return type {expectation['return_type']}, got {type(result).__name__}."
    elif "return_equals" in expectation and result != expectation["return_equals"]:
        status = "failed"
        message = "Return value did not match the expected JSON value."
    try:
        preview = json.dumps(result, ensure_ascii=False)
    except (TypeError, ValueError, RecursionError):
        try:
            preview = repr(result)
        except BaseException:
            preview = f"<{type(result).__name__} result>"
    return {
        "name": case["name"],
        "status": status,
        "message": message[:1_000],
        "elapsed_ms": int((time.monotonic() - started) * 1_000),
        "exception_type": exception_name,
        "traceback": trace,
        "stdout": stdout_capture.getvalue(),
        "stderr": stderr_capture.getvalue(),
        "stdout_truncated": stdout_capture.truncated,
        "stderr_truncated": stderr_capture.truncated,
        "return_preview": preview[:1_000],
    }


def _write_report(report):
    serialized = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > MAX_REPORT_BYTES:
        for case in report.get("cases", []):
            case["traceback"] = str(case.get("traceback", ""))[-600:]
            case["stdout"] = str(case.get("stdout", ""))[:128]
            case["stderr"] = str(case.get("stderr", ""))[:128]
            case["return_preview"] = str(case.get("return_preview", ""))[:128]
            case["message"] = str(case.get("message", ""))[:300]
        serialized = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > MAX_REPORT_BYTES:
        report = {
            "error": "The structured report exceeded the 128 KiB report limit.",
            "cases": [
                {"name": str(case.get("name", "test"))[:100], "status": str(case.get("status", "error"))[:40]}
                for case in report.get("cases", [])
            ],
        }
        serialized = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write(REPORT_MARKER + serialized + "\n")
    sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--entry-module", required=True)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--case-index", type=int)
    args = parser.parse_args()
    if args.case_index is not None:
        result = _run_case(args.case_index, args.entry_module, args.suite, args.workspace)
        sys.stdout.write(CASE_MARKER + json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
        return 0

    signal.alarm(TOTAL_TIMEOUT_SECONDS)
    try:
        suite_path = Path(args.suite)
        suite_bytes = suite_path.read_bytes()
        if len(suite_bytes) > MAX_SUITE_BYTES:
            raise ValueError("Suite JSON exceeds 128 KiB.")
        suite = json.loads(suite_bytes.decode("utf-8"))
        cases = _validate_suite(suite)
        module_parts = args.entry_module.split(".")
        if not module_parts or any(not NAME_PATTERN.fullmatch(part) for part in module_parts):
            raise ValueError("Selected entry module name is invalid.")
        entry_file = Path(args.workspace).joinpath(*module_parts).with_suffix(".py")
        package_file = Path(args.workspace).joinpath(*module_parts, "__init__.py")
        if not entry_file.is_file() and not package_file.is_file():
            raise ValueError("Selected entry module was not present in the staged source tree.")
        results = []
        for index, case in enumerate(cases):
            result = _run_case_worker(index, args.entry_module, args.suite, args.workspace)
            result.setdefault("name", case["name"])
            results.append(result)
        _write_report({"entry_module": args.entry_module, "cases": results})
        return 0
    except BaseException as error:
        _write_report({"error": f"{type(error).__name__}: {error}", "cases": []})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

