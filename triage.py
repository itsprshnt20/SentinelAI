
"""Validated CSV ingestion, deterministic detection, and incident reports."""
import csv
import hashlib
import io
import ipaddress
import json
import re
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

MAX_BYTES = 2 * 1024 * 1024
MAX_ROWS = 20_000
REQUIRED = {"timestamp", "user", "source_ip", "outcome"}
STATUSES = ("Open", "Investigating", "Closed")
TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)?"
)


class InputError(ValueError):
    """The input cannot be processed as a supported login CSV."""


@dataclass(frozen=True)
class Event:
    row: int
    timestamp: datetime
    user: str
    source_ip: str
    outcome: str

    def export(self):
        return {**asdict(self), "timestamp": utc(self.timestamp)}


@dataclass(frozen=True)
class Rejection:
    row: int
    reason: str


@dataclass(frozen=True)
class Settings:
    threshold: int = 3
    failure_minutes: int = 10
    success_minutes: int = 15

    def __post_init__(self):
        if not all(type(value) is int for value in asdict(self).values()):
            raise ValueError("Detection settings must be whole numbers.")
        if not 2 <= self.threshold <= 100:
            raise ValueError("Failure threshold must be between 2 and 100.")
        if not 1 <= self.failure_minutes <= 1440 or not 1 <= self.success_minutes <= 1440:
            raise ValueError("Detection windows must be between 1 and 1440 minutes.")


@dataclass(frozen=True)
class Alert:
    id: str
    failures: tuple[Event, ...]
    success: Event | None

    @property
    def events(self):
        return self.failures + ((self.success,) if self.success else ())


def utc(timestamp):
    return timestamp.isoformat().replace("+00:00", "Z")


def parse_time(value):
    if not TIMESTAMP.fullmatch(value):
        raise ValueError("timestamp must be ISO 8601 with seconds and an optional timezone")
    try:
        timestamp = datetime.fromisoformat(value)
        return (timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc)).astimezone(
            timezone.utc
        )
    except (ValueError, OverflowError) as exc:
        raise ValueError("timestamp is not a valid date, time, or UTC offset") from exc


def parse_csv(raw):
    if len(raw) > MAX_BYTES:
        raise InputError("CSV exceeds 2 MiB. Export a smaller date range and retry.")
    if b"\x00" in raw:
        raise InputError("CSV contains binary data. Export a UTF-8 login CSV.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InputError("CSV must use UTF-8 encoding. Re-export the file as UTF-8.") from exc
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = [field.strip().lower() for field in next(reader)]
    except (StopIteration, csv.Error) as exc:
        raise InputError("CSV must start with a readable header row.") from exc
    if len(set(header)) != len(header) or not REQUIRED.issubset(header):
        raise InputError("Use unique CSV headers including timestamp, user, source_ip, and outcome.")
    events, rejected = [], []
    while True:
        row = reader.line_num + 1
        try:
            fields = next(reader)
        except StopIteration:
            break
        except csv.Error:
            rejected.append(Rejection(row, "Malformed CSV quoting or field size. Reading stopped at this record."))
            break
        if len(events) + len(rejected) >= MAX_ROWS:
            raise InputError("CSV exceeds 20,000 records. Export a smaller date range.")
        if len(fields) != len(header):
            rejected.append(Rejection(row, f"Expected {len(header)} columns, found {len(fields)}."))
            continue
        event, errors = parse_record(dict(zip(header, fields)), row)
        if errors:
            rejected.append(Rejection(row, "; ".join(errors)))
        else:
            events.append(event)
    return sorted(events, key=lambda event: (event.timestamp, event.row)), rejected


def parse_record(record, row):
    errors = []
    user = record["user"].strip()
    if not user or len(user) > 128 or not user.isprintable():
        errors.append("user must contain 1–128 printable characters")
    outcome = record["outcome"].strip().lower()
    if outcome not in {"failure", "success"}:
        errors.append("outcome must be failure or success")
    try:
        source = record["source_ip"].strip()
        if "%" in source:
            raise ValueError("Zone identifiers are unsupported")
        ip = str(ipaddress.ip_address(source))
    except ValueError:
        errors.append("source_ip must be a valid IPv4 or IPv6 address without a zone ID")
    try:
        timestamp = parse_time(record["timestamp"].strip())
    except ValueError as exc:
        errors.append(str(exc))
    return (None, errors) if errors else (Event(row, timestamp, user, ip, outcome), [])


def detect(events, settings):
    groups = defaultdict(list)
    for event in sorted(events, key=lambda item: (item.timestamp, item.row)):
        groups[event.user, event.source_ip].append(event)
    alerts = []
    failure_window = timedelta(minutes=settings.failure_minutes)
    success_window = timedelta(minutes=settings.success_minutes)
    for group in groups.values():
        failures = deque()
        next_success = following_successes(group)
        for event, following in zip(group, next_success):
            if event.outcome != "failure":
                continue
            while failures and event.timestamp - failures[0].timestamp > failure_window:
                failures.popleft()
            failures.append(event)
            if len(failures) != settings.threshold:
                continue
            success = following if following and following.timestamp - event.timestamp <= success_window else None
            matches = tuple(failures)
            evidence = (*matches, success) if success else matches
            fingerprint = json.dumps([asdict(settings), [item.export() for item in evidence]], sort_keys=True)
            alert_id = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
            alerts.append(Alert(alert_id, matches, success))
            failures.clear()
    return sorted(alerts, key=lambda alert: (alert.failures[-1].timestamp, alert.failures[-1].row))


def following_successes(group):
    """Index the first success strictly later in UTC than each event."""
    next_success = None
    later_success = None
    timestamp = None
    result = []
    for event in reversed(group):
        if event.timestamp != timestamp:
            later_success = next_success
            timestamp = event.timestamp
        result.append(later_success)
        if event.outcome == "success":
            next_success = event
    return reversed(result)


def summarize(alert):
    first, last = alert.failures[0], alert.failures[-1]
    rows = ", ".join(str(event.row) for event in alert.failures)
    observations = [
        f"{len(alert.failures)} failures for {first.user} from {first.source_ip}, "
        f"from {utc(first.timestamp)} through {utc(last.timestamp)} (source rows {rows})."
    ]
    if alert.success:
        observations.append(f"A success followed at {utc(alert.success.timestamp)} "
                            f"(source row {alert.success.row}).")
    else:
        observations.append(f"No subsequent success met the correlation rule after source row {last.row}.")
    return {
        "Observed behavior": observations,
        "Possible explanations": [
            "Repeated failures could come from mistyped credentials, a stale integration, or unauthorized attempts.",
            ("The success could be a legitimate retry or an unauthorized sign-in." if alert.success else
             "Inspect additional logs before drawing a conclusion about account access."),
        ],
        "Manual review steps": [
            "Verify expected activity with the account owner through a trusted channel.",
            "Review identity-provider logs for MFA, device, and session details around the evidence window.",
        ],
    }


def export_incident(alert, settings, status):
    if status not in STATUSES:
        raise ValueError("Unknown incident status.")
    first = alert.failures[0]
    payload = {
        "alert_id": alert.id,
        "status": status,
        "user": first.user,
        "source_ip": first.source_ip,
        "detection_settings": asdict(settings),
        "matching_row_ids": [event.row for event in alert.events],
        "evidence": [event.export() for event in alert.events],
        "summary": summarize(alert),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
