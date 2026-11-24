"""Read-only SIEM attribution for finished scans.

The detection-validation layer: take the findings a scan filed and ask your
SIEM which of them it actually saw. Every adapter here is read-only - only
search requests are ever built, and a path that could mutate the store is
refused before a request exists. Credentials in a DSN are redacted from every
artifact this module writes.

Attribution rules, in the order that matters:

* A finding is only attributed when an event falls inside its time window *and*
  its endpoint matches. There is no nearest-class assignment: an event that
  does not satisfy both constraints is counted as unmatched, and a finding
  with no event is reported as unattributed rather than given a plausible
  neighbour.
* A finding with no parseable timestamp is counted as unanchored, never placed
  in a window.
* An event whose rule name is missing is reported as ``unnamed``; it still
  counts as having seen the finding, because the detection fired.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, unquote, urlsplit

import requests


if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

logger = logging.getLogger(__name__)


class SiemError(RuntimeError):
    """A detector could not be used, or its output could not be understood."""


class SiemReadOnlyError(SiemError):
    """A request was refused because it could mutate the SIEM."""


# Prefixes each adapter may talk to. Anything else is refused, so a crafted
# index name or DSN path cannot turn a search into a write.
_ALLOWED_PATH_PREFIXES: dict[str, tuple[str, ...]] = {
    "splunk": ("/services/search/jobs/export", "/services/search/jobs"),
    "elastic": (),
    "sentinel": (),
}

_ELASTIC_ALLOWED_SUFFIXES = ("/_search", "/_count")

# Checked against every path and body before the request exists.
_FORBIDDEN_FRAGMENTS = (
    "_bulk",
    "_update_by_query",
    "_delete_by_query",
    "_reindex",
    "_snapshot",
    "_scripts",
    "_cluster/settings",
    "_ilm",
    "_security",
    "_sql",
    "/services/auth",
    "/services/admin",
    "/services/data/inputs",
    "/services/receivers",
)

_TIME_KEYS = (
    "_time",
    "@timestamp",
    "TimeGenerated",
    "timestamp",
    "event_time",
    "time",
)
_HOST_KEYS = (
    "host",
    "host.name",
    "host_name",
    "url.host",
    "destination.host",
    "dest",
    "url.domain",
)
_PATH_KEYS = (
    "url.path",
    "url.original",
    "request.uri",
    "uri",
    "path",
    "request_path",
    "cs_uri_stem",
)
_RULE_KEYS = (
    "rule_name",
    "rule.name",
    "rule",
    "search_name",
    "alert.signature",
    "detection_rule",
    "signature",
    "sigma_rule",
    "title",
)

_EPOCH_MILLIS_THRESHOLD = 1e11
_DEFAULT_MAX_EVENTS = 5000
_DEFAULT_TIMEOUT = 20.0


@dataclass(frozen=True)
class DetectorConfig:
    """A parsed, display-safe detector DSN."""

    kind: str
    dsn: str
    display: str
    base_url: str | None = None
    index: str | None = None
    username: str | None = None
    password: str | None = None
    token: str | None = None
    host: str | None = None
    port: int | None = None
    workspace: str | None = None
    table: str | None = None
    query: str | None = None
    path: Path | None = None


@dataclass(frozen=True)
class SiemEvent:
    """One detection, normalised across sources."""

    time: datetime | None
    rule: str | None
    host: str | None
    path: str | None
    source: str


@dataclass(frozen=True)
class AnchoredFinding:
    """The fields correlation needs from a filed finding."""

    finding_id: str
    title: str
    vuln_class: str
    severity: str
    host: str | None
    path: str | None
    anchor: datetime | None


@dataclass
class FindingAttribution:
    finding: AnchoredFinding
    status: str
    rules: list[str] = field(default_factory=list)
    first_event_time: datetime | None = None
    latency_ms: int | None = None
    match_quality: str | None = None
    events: int = 0


@dataclass
class ClassCoverage:
    vuln_class: str
    findings: int = 0
    attributed: int = 0
    rules: set[str] = field(default_factory=set)

    @property
    def named(self) -> bool:
        return any(rule != "unnamed" for rule in self.rules)

    def as_dict(self) -> dict[str, Any]:
        return {
            "class": self.vuln_class,
            "findings": self.findings,
            "attributed": self.attributed,
            "rules": sorted(self.rules),
            "named_by_rule": self.named,
        }


@dataclass
class AttributionSummary:
    generated_at: datetime
    window_seconds: int
    detectors: list[str]
    events_fetched: int
    findings_total: int
    attributed: int
    unattributed: int
    unanchored: int
    unmatched_events: int
    classes: dict[str, ClassCoverage]
    attributions: list[FindingAttribution] = field(default_factory=list)

    @property
    def blind_classes(self) -> list[str]:
        """Classes with attributed findings that no named rule covered."""

        return sorted(name for name, cov in self.classes.items() if cov.findings and not cov.named)

    @property
    def silent_classes(self) -> list[str]:
        """Classes with findings the SIEM never saw at all."""

        return sorted(
            name for name, cov in self.classes.items() if cov.findings and not cov.attributed
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "window_seconds": self.window_seconds,
            "detectors": self.detectors,
            "events_fetched": self.events_fetched,
            "findings": {
                "total": self.findings_total,
                "attributed": self.attributed,
                "unattributed": self.unattributed,
                "unanchored": self.unanchored,
            },
            "unmatched_events": self.unmatched_events,
            "classes": [cov.as_dict() for cov in self.classes.values()],
            "blind_classes": self.blind_classes,
            "silent_classes": self.silent_classes,
            "attributions": [
                {
                    "id": item.finding.finding_id,
                    "title": item.finding.title,
                    "class": item.finding.vuln_class,
                    "severity": item.finding.severity,
                    "status": item.status,
                    "rules": item.rules,
                    "events": item.events,
                    "match_quality": item.match_quality,
                    "first_event_time": (
                        item.first_event_time.isoformat() if item.first_event_time else None
                    ),
                    "latency_ms": item.latency_ms,
                }
                for item in self.attributions
            ],
        }


def parse_detector(dsn: str) -> DetectorConfig:
    """Parse a detector DSN, refusing anything this module cannot talk to."""

    raw = (dsn or "").strip()
    if not raw:
        raise SiemError("detector DSN is empty")
    scheme, _, rest = raw.partition("://")
    scheme = scheme.lower()
    if not rest:
        raise SiemError(f"detector DSN has no payload: {redact_dsn(raw)}")
    parser = _DETECTOR_PARSERS.get(scheme)
    if parser is None:
        raise SiemError(
            f"unsupported detector scheme {scheme!r}; use jsonl, splunk, elastic or sentinel",
        )
    return parser(raw, rest)


def _split_auth(rest: str) -> tuple[str | None, str | None, str]:
    userinfo, sep, tail = rest.rpartition("@")
    if not sep:
        return None, None, rest
    username, _, password = userinfo.partition(":")
    return unquote(username) or None, unquote(password) or None, tail


def _parse_jsonl(raw: str, rest: str) -> DetectorConfig:
    path = Path(unquote(rest))
    display = f"jsonl://{path}"
    return DetectorConfig(kind="jsonl", dsn=raw, display=display, path=path)


def _parse_splunk(raw: str, rest: str) -> DetectorConfig:
    username, password, tail = _split_auth(rest)
    query = parse_qs(urlsplit("//" + tail).query.lstrip("?"))
    netloc_path = tail.split("?", 1)[0]
    netloc, _, path = netloc_path.partition("/")
    host, _, port_text = netloc.partition(":")
    index = (query.get("index") or ["main"])[0]
    if path.strip("/"):
        # The adapter only ever posts to the export endpoint; a path in the DSN
        # is either a mistake or an attempt to reach an admin route.
        raise SiemReadOnlyError(
            f"refused splunk path {path!r}: only /services/search/jobs/export is used",
        )
    _guard_fragments(index)
    try:
        port = int(port_text) if port_text else 8089
    except ValueError as exc:
        raise SiemError("splunk port must be a number") from exc
    token = os.environ.get("SPLUNK_TOKEN") or None
    display = redact_dsn(raw)
    return DetectorConfig(
        kind="splunk",
        dsn=raw,
        display=display,
        base_url=f"https://{host}:{port}",
        index=index,
        username=username,
        password=password,
        token=token,
        host=host,
        port=port,
    )


def _parse_elastic(raw: str, rest: str) -> DetectorConfig:
    username, password, tail = _split_auth(rest)
    netloc, _, index = tail.partition("/")
    host, _, port_text = netloc.partition(":")
    if not index:
        raise SiemError("elastic DSN needs an index: elastic://user:pw@host:9200/winlogbeat-*")
    _guard_fragments(index)
    try:
        port = int(port_text) if port_text else 9200
    except ValueError as exc:
        raise SiemError("elastic port must be a number") from exc
    return DetectorConfig(
        kind="elastic",
        dsn=raw,
        display=redact_dsn(raw),
        base_url=f"https://{host}:{port}",
        index=index,
        username=username,
        password=password,
        token=os.environ.get("ELASTIC_TOKEN") or None,
        host=host,
        port=port,
    )


def _parse_sentinel(raw: str, rest: str) -> DetectorConfig:
    workspace, _, query_text = rest.partition("?")
    params = parse_qs(query_text)
    table = (params.get("table") or ["SecurityEvent"])[0]
    clause = (params.get("query") or [""])[0]
    _guard_fragments(table, clause)
    token = os.environ.get("SENTINEL_TOKEN") or None
    if not token:
        raise SiemError("sentinel needs a token in $SENTINEL_TOKEN")
    return DetectorConfig(
        kind="sentinel",
        dsn=raw,
        display=f"sentinel://{unquote(workspace)}",
        base_url="https://api.loganalytics.io",
        workspace=unquote(workspace),
        table=table,
        query=clause or None,
        token=token,
    )


_DETECTOR_PARSERS: dict[str, Callable[[str, str], DetectorConfig]] = {
    "jsonl": _parse_jsonl,
    "splunk": _parse_splunk,
    "elastic": _parse_elastic,
    "sentinel": _parse_sentinel,
}


def redact_dsn(dsn: str) -> str:
    """Return *dsn* with any password or token replaced by ``***``."""

    scheme, sep, rest = dsn.partition("://")
    if not sep:
        return dsn
    userinfo, at, tail = rest.rpartition("@")
    if at:
        username, colon, _ = userinfo.partition(":")
        userinfo = f"{username}:{'***' if colon else ''}"
        rest = f"{userinfo}{at}{tail}"
    return f"{scheme}://{rest}"


def _guard_fragments(*values: str | None) -> None:
    lowered = tuple((value or "").lower() for value in values)
    for fragment in _FORBIDDEN_FRAGMENTS:
        if any(fragment in value for value in lowered):
            raise SiemReadOnlyError(
                f"refused read-only detector: {fragment} is not a search path",
            )


def _guard_request(kind: str, method: str, path: str, body: str = "") -> None:
    if method.upper() not in {"GET", "POST"}:
        raise SiemReadOnlyError(f"{kind} adapters may only GET or POST searches")
    _guard_fragments(path, body)
    if kind == "splunk":
        prefixes = _ALLOWED_PATH_PREFIXES["splunk"]
        if not any(path.startswith(prefix) for prefix in prefixes):
            raise SiemReadOnlyError(f"refused splunk path {path!r}: not a search endpoint")
    if kind == "elastic" and not path.endswith(_ELASTIC_ALLOWED_SUFFIXES):
        raise SiemReadOnlyError(f"refused elastic path {path!r}: not a search endpoint")


def parse_event_time(value: Any) -> datetime | None:
    """Parse a timestamp in any of the shapes the supported SIEMs emit."""

    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        return _from_epoch(float(value))
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d+(\.\d+)?", text):
        return _from_epoch(float(text))
    return _from_text(text)


def _from_epoch(number: float) -> datetime | None:
    seconds = number / 1000.0 if number > _EPOCH_MILLIS_THRESHOLD else number
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _from_text(text: str) -> datetime | None:
    for candidate in (text.replace("Z", "+00:00"), text):
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _first(source: dict[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in source and source[key] not in (None, ""):
            return source[key]
    return None


def normalise_event(raw: dict[str, Any], source: str) -> SiemEvent:
    """Turn a source-specific record into a :class:`SiemEvent`."""

    return SiemEvent(
        time=parse_event_time(_first(raw, _TIME_KEYS)),
        rule=_string_or_none(_first(raw, _RULE_KEYS)),
        host=_string_or_none(_first(raw, _HOST_KEYS)),
        path=_string_or_none(_first(raw, _PATH_KEYS)),
        source=source,
    )


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def fetch_events(
    config: DetectorConfig,
    start: datetime,
    end: datetime,
    *,
    max_events: int = _DEFAULT_MAX_EVENTS,
    timeout: float = _DEFAULT_TIMEOUT,
) -> list[SiemEvent]:
    """Fetch the events of one detector that fall inside ``[start, end]``."""

    if config.kind == "jsonl":
        return _fetch_jsonl(config, start, end, max_events=max_events)
    fetcher = {
        "splunk": _fetch_splunk,
        "elastic": _fetch_elastic,
        "sentinel": _fetch_sentinel,
    }.get(config.kind)
    if fetcher is None:
        raise SiemError(f"unsupported detector kind {config.kind!r}")
    return fetcher(config, start, end, max_events=max_events, timeout=timeout)


def _fetch_jsonl(
    config: DetectorConfig,
    start: datetime,
    end: datetime,
    *,
    max_events: int,
) -> list[SiemEvent]:
    if config.path is None or not config.path.is_file():
        raise SiemError(f"jsonl detector path does not exist: {config.path}")
    events: list[SiemEvent] = []
    with config.path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            payload = line.strip()
            if not payload:
                continue
            try:
                record = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise SiemError(
                    f"{config.path}:{line_number} is not JSON: {exc.msg}",
                ) from exc
            if not isinstance(record, dict):
                continue
            event = normalise_event(record, "jsonl")
            if event.time is None or not start <= event.time <= end:
                continue
            events.append(event)
            if len(events) >= max_events:
                logger.warning("jsonl detector hit the event cap (%d)", max_events)
                break
    return events


def _auth_kwargs(config: DetectorConfig) -> dict[str, Any]:
    headers: dict[str, str] = {"Accept": "application/json"}
    kwargs: dict[str, Any] = {"headers": headers}
    if config.token and config.kind == "elastic":
        headers["Authorization"] = f"ApiKey {config.token}"
    elif config.token:
        headers["Authorization"] = f"Bearer {config.token}"
    if config.username:
        kwargs["auth"] = (config.username, config.password or "")
    return kwargs


def _fetch_splunk(
    config: DetectorConfig,
    start: datetime,
    end: datetime,
    *,
    max_events: int,
    timeout: float,
) -> list[SiemEvent]:
    path = "/services/search/jobs/export"
    _guard_request("splunk", "POST", path)
    url = f"{config.base_url}{path}"
    data = {
        "search": f"search index={config.index}",
        "earliest_time": start.timestamp(),
        "latest_time": end.timestamp(),
        "output_mode": "json",
        "max_count": max_events,
    }
    logger.info("querying splunk detector %s", config.display)
    response = requests.post(
        url,
        data=data,
        timeout=timeout,
        **_auth_kwargs(config),
    )
    response.raise_for_status()
    events: list[SiemEvent] = []
    for line in response.text.splitlines():
        payload = line.strip()
        if not payload:
            continue
        try:
            row = json.loads(payload)
        except json.JSONDecodeError:
            continue
        result = row.get("result") if isinstance(row, dict) else None
        if isinstance(result, dict):
            events.append(normalise_event(result, "splunk"))
        if len(events) >= max_events:
            break
    return events


def _fetch_elastic(
    config: DetectorConfig,
    start: datetime,
    end: datetime,
    *,
    max_events: int,
    timeout: float,
) -> list[SiemEvent]:
    path = f"/{config.index}/_search"
    body: dict[str, Any] = {
        "size": max_events,
        "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}],
        "query": {
            "range": {
                "@timestamp": {
                    "gte": start.isoformat().replace("+00:00", "Z"),
                    "lte": end.isoformat().replace("+00:00", "Z"),
                },
            },
        },
    }
    _guard_request("elastic", "POST", path, json.dumps(body))
    logger.info("querying elastic detector %s", config.display)
    response = requests.post(
        f"{config.base_url}{path}",
        json=body,
        timeout=timeout,
        **_auth_kwargs(config),
    )
    response.raise_for_status()
    payload = response.json()
    hits = ((payload or {}).get("hits") or {}).get("hits") or []
    events: list[SiemEvent] = []
    for hit in hits:
        source = hit.get("_source") if isinstance(hit, dict) else None
        if isinstance(source, dict):
            events.append(normalise_event(source, "elastic"))
    return events


def _fetch_sentinel(
    config: DetectorConfig,
    start: datetime,
    end: datetime,
    *,
    max_events: int,
    timeout: float,
) -> list[SiemEvent]:
    path = f"/v1/workspaces/{config.workspace}/query"
    query = (
        f"{config.table} "
        f"| where TimeGenerated between (datetime({start:%Y-%m-%dT%H:%M:%SZ}) "
        f".. datetime({end:%Y-%m-%dT%H:%M:%SZ}))"
    )
    if config.query:
        query = f"{query}\n| where {config.query}"
    query = f"{query}\n| take {max_events}"
    _guard_request("sentinel", "POST", path, query)
    logger.info("querying sentinel detector %s", config.display)
    response = requests.post(
        f"{config.base_url}{path}",
        json={"query": query, "timespan": f"{start.isoformat()}/{end.isoformat()}"},
        timeout=timeout,
        **_auth_kwargs(config),
    )
    response.raise_for_status()
    payload = response.json()
    tables = (payload or {}).get("tables") or []
    if not tables:
        return []
    table = tables[0]
    columns = [column.get("name") for column in table.get("columns") or []]
    events: list[SiemEvent] = []
    for row in table.get("rows") or []:
        record = dict(zip(columns, row, strict=False))
        events.append(normalise_event(record, "sentinel"))
    return events


def _host_matches(finding_host: str, event_host: str) -> bool:
    left = finding_host.lower().strip(".")
    right = event_host.lower().strip(".")
    if not left or not right:
        return False
    return left == right or left.endswith("." + right) or right.endswith("." + left)


def _path_matches(finding_path: str, event_path: str) -> bool:
    left = finding_path.split("?", 1)[0].rstrip("/").lower() or "/"
    right = event_path.split("?", 1)[0].rstrip("/").lower() or "/"
    if not left or not right:
        return False
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def _anchor_from(report: dict[str, Any]) -> datetime | None:
    return parse_event_time(report.get("timestamp")) or parse_event_time(report.get("filed_at"))


def anchor_finding(report: dict[str, Any]) -> AnchoredFinding:
    """Extract the correlation fields from a filed finding."""

    target = str(report.get("target") or "")
    endpoint = str(report.get("endpoint") or "")
    host: str | None = None
    path: str | None = None
    for candidate in (endpoint, target):
        if not candidate:
            continue
        if "://" in candidate:
            parts = urlsplit(candidate)
            host = host or parts.hostname
            path = path or parts.path or "/"
        elif candidate.startswith("/"):
            path = path or candidate
        else:
            host = host or candidate.split("/", 1)[0]
    if not path and endpoint.startswith("/"):
        path = endpoint
    return AnchoredFinding(
        finding_id=str(report.get("id") or "unknown"),
        title=str(report.get("title") or "untitled"),
        vuln_class=str(
            report.get("finding_class")
            or report.get("cwe")
            or report.get("severity")
            or "unclassified",
        ),
        severity=str(report.get("severity") or "info"),
        host=host,
        path=path,
        anchor=_anchor_from(report),
    )


def _match_quality(
    finding: AnchoredFinding,
    event: SiemEvent,
    window: timedelta,
) -> str | None:
    """Return the match quality, or ``None`` when the event does not qualify.

    Both a time overlap and an endpoint match are required. A missing host or
    path is never treated as a wildcard.
    """

    if event.time is None or finding.anchor is None:
        return None
    if abs(event.time - finding.anchor) > window:
        return None
    host_paired = bool(finding.host and event.host)
    if finding.host and event.host and not _host_matches(finding.host, event.host):
        return None
    if finding.path and event.path:
        return "path" if _path_matches(finding.path, event.path) else None
    return "host" if host_paired else None


def correlate(
    reports: Iterable[dict[str, Any]],
    events: Iterable[SiemEvent],
    *,
    window_seconds: int = 600,
    detectors: Sequence[str] = (),
) -> AttributionSummary:
    """Attribute findings to the events that saw them, without guessing."""

    window = timedelta(seconds=abs(window_seconds))
    event_list = [event for event in events if event.time is not None]
    findings = [anchor_finding(report) for report in reports]

    used: set[int] = set()
    attributions: list[FindingAttribution] = []
    for finding in findings:
        if finding.anchor is None:
            attributions.append(FindingAttribution(finding=finding, status="unanchored"))
            continue
        matched: list[tuple[datetime, SiemEvent, str]] = []
        for index, event in enumerate(event_list):
            quality = _match_quality(finding, event, window)
            if quality is None or event.time is None:
                continue
            matched.append((event.time, event, quality))
            used.add(index)
        if not matched:
            attributions.append(FindingAttribution(finding=finding, status="unattributed"))
            continue
        matched.sort(key=lambda pair: pair[0])
        first_time, _first_event, first_quality = matched[0]
        rules = sorted({event.rule or "unnamed" for _, event, _ in matched})
        latency = int((first_time - finding.anchor).total_seconds() * 1000)
        attributions.append(
            FindingAttribution(
                finding=finding,
                status="attributed",
                rules=rules,
                first_event_time=first_time,
                latency_ms=latency,
                match_quality=first_quality,
                events=len(matched),
            ),
        )

    classes: dict[str, ClassCoverage] = {}
    for item in attributions:
        coverage = classes.setdefault(
            item.finding.vuln_class,
            ClassCoverage(vuln_class=item.finding.vuln_class),
        )
        coverage.findings += 1
        if item.status == "attributed":
            coverage.attributed += 1
            coverage.rules.update(item.rules)

    return AttributionSummary(
        generated_at=datetime.now(UTC),
        window_seconds=int(window.total_seconds()),
        detectors=list(detectors),
        events_fetched=len(event_list),
        findings_total=len(attributions),
        attributed=sum(1 for item in attributions if item.status == "attributed"),
        unattributed=sum(1 for item in attributions if item.status == "unattributed"),
        unanchored=sum(1 for item in attributions if item.status == "unanchored"),
        unmatched_events=len(event_list) - len(used),
        classes=classes,
        attributions=attributions,
    )


def attribute_run(
    reports: Sequence[dict[str, Any]],
    detectors: Sequence[DetectorConfig],
    *,
    window_seconds: int = 600,
    max_events: int = _DEFAULT_MAX_EVENTS,
    timeout: float = _DEFAULT_TIMEOUT,
) -> AttributionSummary:
    """Fetch one window from every detector and attribute *reports* against it."""

    anchors = [anchor for anchor in (_anchor_from(report) for report in reports) if anchor]
    if not anchors:
        return correlate(
            reports,
            [],
            window_seconds=window_seconds,
            detectors=[config.display for config in detectors],
        )
    window = timedelta(seconds=abs(window_seconds))
    start = min(anchors) - window
    end = max(anchors) + window
    events: list[SiemEvent] = []
    for config in detectors:
        try:
            events.extend(
                fetch_events(config, start, end, max_events=max_events, timeout=timeout),
            )
        except requests.RequestException as exc:
            raise SiemError(f"detector {config.display} failed: {exc}") from exc
    return correlate(
        reports,
        events,
        window_seconds=window_seconds,
        detectors=[config.display for config in detectors],
    )


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def render_markdown(summary: AttributionSummary) -> str:
    """Render the attribution summary as a human-readable report section."""

    lines = [
        "# SIEM detection attribution",
        "",
        f"**Generated:** {summary.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Window:** ±{summary.window_seconds}s per finding  ",
        f"**Detectors:** {', '.join(summary.detectors) or 'none'}  ",
        f"**Events fetched:** {summary.events_fetched}",
        "",
        "## Findings",
        "",
        (f"- {summary.attributed} of {summary.findings_total} findings were seen by a detector."),
        (
            f"- {_plural(summary.unattributed, 'finding')} fell inside the window "
            "but matched no event."
        ),
        (
            f"- {_plural(summary.unanchored, 'finding')} had no usable timestamp "
            "and were never placed in a window."
        ),
        (
            f"- {_plural(summary.unmatched_events, 'event')} matched no finding "
            "and were left unassigned."
        ),
        "",
        "## Per class",
        "",
        "| Class | Findings | Attributed | Rules that saw it |",
        "| --- | --- | --- | --- |",
    ]
    for coverage in sorted(
        summary.classes.values(),
        key=lambda cov: (-cov.findings, cov.vuln_class),
    ):
        rules = ", ".join(sorted(coverage.rules)) or "-"
        lines.append(
            f"| {coverage.vuln_class} | {coverage.findings} | {coverage.attributed} | {rules} |",
        )
    lines.extend(["", "## Blind spots", ""])
    blind = summary.blind_classes
    silent = summary.silent_classes
    lines.append(
        "- Classes no rule named: " + (", ".join(blind) if blind else "none"),
    )
    lines.append(
        "- Classes the SIEM never saw: " + (", ".join(silent) if silent else "none"),
    )
    unattributed = [item for item in summary.attributions if item.status == "unattributed"]
    if unattributed:
        lines.extend(["", "## Unattributed findings", ""])
        lines.extend(
            f"- `{item.finding.finding_id}` {item.finding.title} ({item.finding.vuln_class})"
            for item in unattributed
        )
    lines.append("")
    return "\n".join(lines)


def write_attribution(
    run_dir: Path,
    summary: AttributionSummary,
    *,
    stem: str = "siem_attribution",
) -> tuple[Path, Path]:
    """Write the attribution JSON and markdown into *run_dir*."""

    json_path = run_dir / f"{stem}.json"
    md_path = run_dir / f"{stem}.md"
    json_path.write_text(
        json.dumps(summary.as_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(summary), encoding="utf-8")
    return json_path, md_path
