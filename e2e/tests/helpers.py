import json
import os
from typing import Optional

import jsonschema

# Load schema once
SCHEMA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "docs", "schema.json"
)

_schema = None


def get_schema():
    global _schema
    if _schema is None:
        with open(SCHEMA_PATH) as f:
            _schema = json.load(f)
    return _schema


def validate_event(event: dict) -> None:
    """Validate a single event against the BehaviorEvent schema."""
    jsonschema.validate(instance=event, schema=get_schema())


def validate_all_events(events: list[dict]) -> None:
    """Validate all events against the schema."""
    for i, event in enumerate(events):
        try:
            validate_event(event)
        except jsonschema.ValidationError as e:
            raise AssertionError(
                f"Event #{i} failed schema validation: {e.message}\n"
                f"Event: {json.dumps(event, indent=2)}"
            )


def filter_events(
    events: list[dict],
    event_type: Optional[str] = None,
    name: Optional[str] = None,
    layer: Optional[str] = None,
    pid: Optional[int] = None,
    comm: Optional[str] = None,
) -> list[dict]:
    """Filter events by criteria."""
    result = events
    if event_type:
        result = [e for e in result if e.get("event", {}).get("type") == event_type]
    if name:
        result = [e for e in result if e.get("event", {}).get("name") == name]
    if layer:
        result = [e for e in result if e.get("event", {}).get("layer") == layer]
    if pid:
        result = [e for e in result if e.get("header", {}).get("pid") == pid]
    if comm:
        result = [e for e in result if e.get("header", {}).get("comm") == comm]
    return result


def assert_event_exists(
    events: list[dict],
    event_type: Optional[str] = None,
    name: Optional[str] = None,
    layer: Optional[str] = None,
    msg: str = "",
) -> dict:
    """Assert at least one event matching criteria exists. Return the first match."""
    matches = filter_events(events, event_type=event_type, name=name, layer=layer)
    assert len(matches) > 0, (
        f"Expected event (type={event_type}, name={name}, layer={layer}) "
        f"not found. {msg}\n"
        f"Available events: {[e.get('event') for e in events[:20]]}"
    )
    return matches[0]


def assert_no_event(
    events: list[dict],
    event_type: Optional[str] = None,
    name: Optional[str] = None,
    layer: Optional[str] = None,
    msg: str = "",
) -> None:
    """Assert no events match the criteria."""
    matches = filter_events(events, event_type=event_type, name=name, layer=layer)
    assert len(matches) == 0, (
        f"Unexpected event found (type={event_type}, name={name}, layer={layer}). "
        f"{msg}\nFound: {json.dumps(matches[0], indent=2)}"
    )


def assert_auid_filter(events: list[dict], target_auid: int) -> None:
    """Assert all events have the correct auid, with documented exceptions.

    - PACKET events may legitimately carry auid=0 when packet→process
      correlation fails (the socket tracking table has no match for the
      5-tuple, e.g., short-lived processes).
    - HEARTBEAT events carry auid=0 as a sentinel: the event is a
      daemon-scoped pulse not attributable to any user process.
    - LIFECYCLE events forward the triggering event's auid and therefore
      match `target_auid` in normal operation.
    """
    for event in events:
        auid = event.get("header", {}).get("auid", -1)
        event_type = event.get("event", {}).get("type", "")
        if event_type == "PACKET":
            assert auid in (target_auid, 0), (
                f"PACKET event has unexpected auid={auid}"
            )
        elif event_type == "HEARTBEAT":
            # HEARTBEAT is a daemon-scoped pulse; auid=0 is the
            # documented sentinel (see docs/output-schema.md).
            assert auid == 0, (
                f"HEARTBEAT event has unexpected auid={auid} "
                f"(expected 0 sentinel)"
            )
        else:
            assert auid == target_auid, (
                f"Event has wrong auid={auid}, expected {target_auid}: "
                f"{json.dumps(event.get('event'), indent=2)}"
            )
