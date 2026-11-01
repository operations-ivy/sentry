from __future__ import annotations

from unittest import mock

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from overwatch import tracing
from overwatch.hub import Hub
from overwatch.watch import Watch


def spans():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return exporter, provider.get_tracer("test")


def test_an_alert_has_no_traceparent_without_a_span():
    assert tracing.carried() == {}


def test_a_relayed_alert_joins_the_watchs_trace_once_with_no_address():
    exporter, tracer = spans()
    with tracer.start_as_current_span("overwatch alert") as parent:
        alert = {"kind": "findmy", "at": 100.0, "detail": "AA:BB:CC", **tracing.carried()}
    with mock.patch.object(tracing, "tracer", tracer):
        seen = tracing.relayed("scanner", {"alerts": [alert]}, set(), 2)
        seen = tracing.relayed("scanner", {"alerts": [alert]}, seen, 2)  # still in the next snapshot
    [_, relay] = exporter.get_finished_spans()
    assert relay.name == "relay alert"
    assert relay.context.trace_id == parent.get_span_context().trace_id
    assert relay.parent.span_id == parent.get_span_context().span_id
    assert dict(relay.attributes) == {"overwatch.feed": "scanner", "overwatch.kind": "findmy", "overwatch.listeners": 2}
    assert tracing.relayed("scanner", {"alerts": []}, seen, 2) == set()


def test_old_snapshots_without_alerts_or_traceparents_are_fine():
    assert tracing.relayed("wifi", {"scanner": None}, set(), 0) == set()
    assert tracing.relayed("wifi", {"alerts": [{"kind": "deauth", "at": 1.0}]}, set(), 0) == set()


def test_alerts_stay_json_for_the_hub():
    watch = Watch(learn_seconds=0, linger_seconds=0)
    watch.advert("AA", "findmy", -60, now=100)
    watch.tick(now=100)
    watch.tick(now=101)
    assert Hub().publish(watch.get())
