"""Tests for read-only SIEM attribution (`strix siem`)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from strix.interface.siem_cli import run_siem
from strix.report.siem import (
    SiemError,
    SiemEvent,
    SiemReadOnlyError,
    _guard_request,
    anchor_finding,
    attribute_run,
    correlate,
    fetch_events,
    parse_detector,
    parse_event_time,
    redact_dsn,
    render_markdown,
)


if TYPE_CHECKING:
    from pathlib import Path


NOW = datetime(2026, 11, 24, 8, 26, 0, tzinfo=UTC)


def _finding(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "vuln-1",
        "title": "SQL injection in /login",
        "severity": "high",
        "finding_class": "sqli",
        "target": "https://app.example.com",
        "endpoint": "/login",
        "method": "POST",
        "timestamp": "2026-11-24 08:26:00 UTC",
    }
    payload.update(overrides)
    return payload


def _event(seconds: float, **overrides: Any) -> SiemEvent:
    payload: dict[str, Any] = {
        "time": NOW + timedelta(seconds=seconds),
        "rule": "sqli-detection",
        "host": "app.example.com",
        "path": "/login",
        "source": "test",
    }
    payload.update(overrides)
    return SiemEvent(**payload)


class _Response:
    def __init__(self, text: str = "", payload: Any = None) -> None:
        self.text = text
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self._payload


def test_redact_dsn_hides_password() -> None:
    assert redact_dsn("splunk://admin:hunter2@siem.internal:8089?index=main") == (
        "splunk://admin:***@siem.internal:8089?index=main"
    )
    assert redact_dsn("jsonl:///tmp/events.jsonl") == "jsonl:///tmp/events.jsonl"


def test_parse_detector_rejects_unknown_scheme() -> None:
    with pytest.raises(SiemError, match="unsupported detector scheme"):
        parse_detector("wazuh://host:55000")


def test_parse_detector_refuses_mutating_elastic_index() -> None:
    with pytest.raises(SiemReadOnlyError, match="_bulk"):
        parse_detector("elastic://user:pw@es:9200/_bulk")


def test_parse_detector_refuses_splunk_admin_path() -> None:
    with pytest.raises(SiemReadOnlyError, match="services/auth"):
        parse_detector("splunk://u:p@siem:8089/services/auth/login")


def test_parse_detector_sentinel_needs_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_TOKEN", raising=False)
    with pytest.raises(SiemError, match="SENTINEL_TOKEN"):
        parse_detector("sentinel://workspace-123")
    monkeypatch.setenv("SENTINEL_TOKEN", "tok")
    config = parse_detector("sentinel://workspace-123?table=SigninLogs")
    assert config.kind == "sentinel"
    assert config.table == "SigninLogs"
    assert "tok" not in config.display


def test_guard_request_blocks_writes() -> None:
    _guard_request("elastic", "POST", "/winlogbeat/_search", "{}")
    with pytest.raises(SiemReadOnlyError):
        _guard_request("elastic", "POST", "/winlogbeat/_bulk")
    with pytest.raises(SiemReadOnlyError):
        _guard_request("elastic", "POST", "/winlogbeat/_doc/1")
    with pytest.raises(SiemReadOnlyError):
        _guard_request("elastic", "DELETE", "/winlogbeat/_search")


def test_parse_event_time_shapes() -> None:
    assert parse_event_time("2026-11-24 08:26:00 UTC") == NOW
    assert parse_event_time("2026-11-24T08:26:00Z") == NOW
    assert parse_event_time(NOW.timestamp()) == NOW
    assert parse_event_time(int(NOW.timestamp() * 1000)) == NOW
    assert parse_event_time("not a time") is None


def test_jsonl_fetch_filters_window(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    rows = [
        {"_time": "2026-11-24T08:00:00Z", "rule_name": "before", "host": "app.example.com"},
        {"_time": "2026-11-24T08:26:00Z", "rule_name": "inside", "host": "app.example.com"},
        {"broken": True},
        {"_time": "2026-11-24T09:00:00Z", "rule_name": "after", "host": "app.example.com"},
    ]
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    config = parse_detector(f"jsonl://{path}")
    events = fetch_events(config, NOW - timedelta(minutes=1), NOW + timedelta(minutes=1))
    assert [event.rule for event in events] == ["inside"]


def test_splunk_adapter_only_exports(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs: Any) -> _Response:
        calls.append({"url": url, **kwargs})
        body = "\n".join(
            [
                json.dumps({"result": {"_time": "2026-11-24T08:26:05Z", "rule_name": "r1"}}),
                json.dumps({"result": {"_time": "2026-11-24T08:26:06Z", "search_name": "r2"}}),
            ],
        )
        return _Response(text=body)

    monkeypatch.setattr("strix.report.siem.requests.post", fake_post)
    config = parse_detector("splunk://admin:pw@siem:8089?index=main")
    events = fetch_events(config, NOW - timedelta(minutes=5), NOW + timedelta(minutes=5))
    assert [event.rule for event in events] == ["r1", "r2"]
    assert calls[0]["url"].endswith("/services/search/jobs/export")
    assert calls[0]["data"]["search"] == "search index=main"
    assert calls[0]["auth"] == ("admin", "pw")


def test_elastic_adapter_parses_hits(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_post(url: str, **_kwargs: Any) -> _Response:
        assert url.endswith("/winlogbeat-*/_search")
        payload = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "@timestamp": "2026-11-24T08:26:07Z",
                            "rule.name": "elastic-rule",
                            "url.path": "/login",
                        },
                    },
                ],
            },
        }
        return _Response(payload=payload)

    monkeypatch.setattr("strix.report.siem.requests.post", fake_post)
    config = parse_detector("elastic://elastic:pw@es:9200/winlogbeat-*")
    events = fetch_events(config, NOW - timedelta(minutes=5), NOW + timedelta(minutes=5))
    assert [(event.rule, event.path) for event in events] == [("elastic-rule", "/login")]


def test_correlate_attributes_on_endpoint_and_time() -> None:
    summary = correlate([_finding()], [_event(30)], window_seconds=600)
    assert summary.attributed == 1
    assert summary.attributions[0].rules == ["sqli-detection"]
    assert summary.attributions[0].match_quality == "path"
    assert summary.attributions[0].latency_ms == 30_000
    assert summary.unmatched_events == 0


def test_correlate_never_assigns_nearest_event() -> None:
    """A nearby event on another endpoint must not be borrowed for the finding."""

    summary = correlate(
        [_finding()],
        [_event(5, path="/search"), _event(10, host="other.example.com")],
        window_seconds=600,
    )
    assert summary.attributed == 0
    assert summary.unattributed == 1
    assert summary.unmatched_events == 2
    assert summary.silent_classes == ["sqli"]


def test_correlate_marks_unanchored_without_timestamp() -> None:
    summary = correlate([_finding(timestamp="not a time")], [_event(0)], window_seconds=60)
    assert summary.unanchored == 1
    assert summary.attributed == 0


def test_correlate_host_only_match_is_labelled() -> None:
    summary = correlate(
        [_finding(endpoint="/login", target="https://app.example.com")],
        [_event(0, path=None)],
        window_seconds=60,
    )
    assert summary.attributions[0].status == "attributed"
    assert summary.attributions[0].match_quality == "host"


def test_unnamed_rule_still_counts_as_seen_but_heads_blind_spots() -> None:
    summary = correlate([_finding()], [_event(0, rule=None)], window_seconds=60)
    assert summary.attributed == 1
    assert summary.classes["sqli"].rules == {"unnamed"}
    assert summary.blind_classes == ["sqli"]


def test_anchor_finding_reads_target_and_endpoint() -> None:
    anchored = anchor_finding(_finding())
    assert anchored.host == "app.example.com"
    assert anchored.path == "/login"
    assert anchored.anchor == NOW


def test_attribute_run_uses_one_window_for_all_detectors(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        json.dumps(
            {"_time": "2026-11-24T08:26:10Z", "rule_name": "r", "host": "app.example.com"},
        )
        + "\n",
        encoding="utf-8",
    )
    summary = attribute_run(
        [_finding(timestamp="2026-11-24 08:26:00 UTC")],
        [parse_detector(f"jsonl://{path}")],
        window_seconds=600,
    )
    assert summary.attributed == 1
    assert summary.detectors == [f"jsonl://{path}"]


def test_render_markdown_reports_blind_spots() -> None:
    summary = correlate([_finding()], [], window_seconds=60)
    markdown = render_markdown(summary)
    assert "Classes the SIEM never saw: sqli" in markdown
    assert "0 of 1 findings were seen by a detector." in markdown


def _make_run(root: Path, findings: list[dict[str, Any]]) -> Path:
    run_dir = root / "strix_runs" / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(json.dumps({"run_name": "run-1"}), encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(findings),
        encoding="utf-8",
    )
    return run_dir


def test_cli_writes_attribution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    run_dir = _make_run(tmp_path, [_finding()])
    events = tmp_path / "events.jsonl"
    events.write_text(
        json.dumps({"_time": "2026-11-24T08:26:00Z", "rule_name": "r", "host": "app.example.com"})
        + "\n",
        encoding="utf-8",
    )
    code = run_siem(["--run", str(run_dir), "--detector", f"jsonl://{events}", "--write"])
    assert code == 0
    assert (run_dir / "siem_attribution.json").is_file()
    payload = json.loads((run_dir / "siem_attribution.json").read_text(encoding="utf-8"))
    assert payload["findings"]["attributed"] == 1


def test_cli_fails_on_blind_without_named_rule(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    run_dir = _make_run(tmp_path, [_finding()])
    events = tmp_path / "events.jsonl"
    events.write_text(
        json.dumps({"_time": "2026-11-24T08:26:00Z", "host": "app.example.com"}) + "\n",
        encoding="utf-8",
    )
    code = run_siem(
        ["--run", str(run_dir), "--detector", f"jsonl://{events}", "--fail-on-blind"],
    )
    assert code == 3


def test_cli_requires_a_detector(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    run_dir = _make_run(tmp_path, [_finding()])
    assert run_siem(["--run", str(run_dir)]) == 2
