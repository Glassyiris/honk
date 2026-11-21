"""Analyzer rules on plain sample lists and a fake trace, and the trace queries on a tiny
synthetic Perfetto trace."""

from types import SimpleNamespace

import pytest
from perfetto.protos.perfetto.trace.perfetto_trace_pb2 import Trace as TraceProto

from analyze import (
    Invalid,
    Trace,
    analyze_record,
    count_wakeups,
    poll_interval_ns,
    window_joules,
)

MS = 1_000_000
GAP = 500 * MS


def rail(*points):
    """(ms, µWs) pairs as the (ns, µWs) samples of a counter."""
    return [(ms * MS, uws) for ms, uws in points]


STEADY = rail((0, 0), (250, 250_000), (500, 500_000), (750, 750_000), (1000, 1_000_000))


def test_joules_interpolate_between_samples():
    # 1 W over 0.5 s; the boundaries lie between samples, so nearest-sample would be 0 or 1 J
    sparse = rail((0, 0), (1000, 1_000_000))
    assert window_joules(sparse, 250 * MS, 750 * MS, 2000 * MS) == pytest.approx(0.5)
    assert window_joules(STEADY, 100 * MS, 600 * MS, GAP) == pytest.approx(0.5)


def test_missing_rail_is_invalid():
    with pytest.raises(Invalid, match="no samples"):
        window_joules([], 0, MS, GAP)


@pytest.mark.parametrize("start, end", [(-1, 500 * MS), (500 * MS, 1001 * MS)])
def test_unbracketed_boundary_is_invalid(start, end):
    with pytest.raises(Invalid, match="outside the samples"):
        window_joules(STEADY, start, end, GAP)


def test_counter_reset_in_the_window_is_invalid_but_before_it_is_not():
    reset = rail((0, 900_000), (250, 100), (500, 250_100), (750, 500_100), (1000, 750_100))
    with pytest.raises(Invalid, match="reset"):
        window_joules(reset, 100 * MS, 600 * MS, GAP)
    assert window_joules(reset, 300 * MS, 900 * MS, GAP) > 0


def test_sample_gap_above_the_threshold_is_invalid_and_equal_is_not():
    gapped = rail((0, 0), (250, 250_000), (1000, 1_000_000))
    assert window_joules(gapped, 0, 1000 * MS, 750 * MS) == pytest.approx(1.0)
    with pytest.raises(Invalid, match="gap of 750 ms"):
        window_joules(gapped, 0, 1000 * MS, 749 * MS)


def test_adjacent_windows_sum_to_the_whole_across_a_repeated_timestamp():
    # two samples at 500 ms: the 0.1 J step between them belongs to exactly one of the windows
    split = rail((0, 0), (500, 500_000), (500, 600_000), (1000, 1_100_000))
    whole = window_joules(split, 0, 1000 * MS, GAP)
    assert whole == pytest.approx(1.1)
    halves = window_joules(split, 0, 500 * MS, GAP) + window_joules(split, 500 * MS, 1000 * MS, GAP)
    assert halves == pytest.approx(whole)


def test_wakeups_count_runnable_after_sleep_not_preemption_or_yield():
    rows = [
        (0, "S"),
        (100, "R"),  # woken: counts
        (110, "Running"),
        (200, "R+"),  # preempted, not a wakeup
        (210, "Running"),
        (300, "R"),  # yielded, not a wakeup
        (310, "Running"),
        (400, "D"),
        (500, "R"),  # woken from uninterruptible sleep: counts
        (510, "Running"),
        (600, "S"),
        (700, "R"),  # woken after the window
    ]
    assert count_wakeups(rows, 50, 650) == 2
    assert count_wakeups(rows, 100, 101) == 1  # the window start is included
    assert count_wakeups(rows, 0, 100) == 0  # the window end is not


def test_running_straight_from_sleep_is_a_wakeup():
    # the waker ran before the sleeper's switch-out was recorded, so there is no R row
    woken = [(0, "S"), (100, "R"), (110, "Running"), (200, "S"), (300, "R"), (310, "Running")]
    direct = [(0, "S"), (100, "Running"), (200, "D"), (300, "Running")]
    assert count_wakeups(woken, 50, 650) == count_wakeups(direct, 50, 650) == 2
    assert count_wakeups(direct, 250, 650) == 1
    assert count_wakeups(direct, 0, 100) == 0


class FakeTrace:
    def __init__(self, states, sched_loss=None, sched_span=(0, 10**12)):
        self.states = states
        self.sched_loss = sched_loss or {}
        self.sched_span = sched_span

    def thread_states(self, tids, start, end):
        return {t: self.states[t] for t in tids if t in self.states}


def test_record_gets_joules_wakeups_and_the_reason_for_each_null():
    rec = {"status": "ok", "boottime_start_ns": 250 * MS, "boottime_end_ns": 750 * MS}
    rec |= {"scan_start_ns": 3 * MS, "scan_end_ns": 5 * MS}
    rec["roles"] = {"engine": {"threads": [{"tid": 7}, {"tid": 8}]}, "relay": None}
    rails = {"CPU": STEADY, "GPU": []}
    out = analyze_record(rec, rails, FakeTrace({7: [(0, "S"), (300 * MS, "R")]}), GAP)
    assert (out["scan_start_ns"], out["scan_end_ns"]) == (
        3 * MS,
        5 * MS,
    )  # the record passes through
    assert out["joules"] == {"CPU": pytest.approx(0.5), "GPU": None}
    assert out["wakeups"] == {"engine": {"total": None, "threads": {7: 1}}}
    assert set(out["invalid"]) == {"joules.GPU", "wakeups.engine.8"}


def test_record_without_a_window_is_marked_not_dropped():
    rec = {"seq": 3, "status": "ok", "boottime_start_ns": None}
    out = analyze_record(rec, {"CPU": STEADY}, FakeTrace({}), GAP)
    assert out["seq"] == 3 and out["joules"] == {"CPU": None} and "window" in out["invalid"]


ENGINE_7 = {"engine": {"threads": [{"tid": 7}]}}
WOKEN_7 = {7: [(0, "S"), (300 * MS, "R")]}


def test_rejected_record_gets_only_nulls_and_the_runner_reason():
    rec = {"status": "rejected", "reason": "no payload reached the receiver", "roles": ENGINE_7}
    rec |= {"boottime_start_ns": 250 * MS, "boottime_end_ns": 750 * MS, "unreadable": ["cpu"]}
    out = analyze_record(rec, {"CPU": STEADY}, FakeTrace(WOKEN_7), GAP)
    assert out["joules"] == {"CPU": None}
    assert out["wakeups"] == {"engine": {"total": None, "threads": {}}}
    assert out["invalid"] == {"status": "rejected: no payload reached the receiver"}
    assert out["unreadable"] == ["cpu"]


@pytest.mark.parametrize(
    "trace, why",
    [
        (FakeTrace(WOKEN_7, sched_loss={"ftrace_cpu_overrun_delta": 3}), "overrun_delta=3"),
        (FakeTrace(WOKEN_7, sched_span=(0, 700 * MS)), "does not cover"),  # ends in the window
        (FakeTrace(WOKEN_7, sched_span=None), "does not cover"),
    ],
)
def test_wakeups_are_invalid_when_the_trace_lost_scheduler_data(trace, why):
    rec = {"status": "ok", "boottime_start_ns": 250 * MS, "boottime_end_ns": 750 * MS}
    out = analyze_record(rec | {"roles": ENGINE_7}, {"CPU": STEADY}, trace, GAP)
    assert out["wakeups"] == {"engine": {"total": None, "threads": {}}}
    assert why in out["invalid"]["wakeups"]
    assert out["joules"] == {"CPU": pytest.approx(0.5)}  # the rails do not depend on ftrace


def test_a_thread_run_straight_from_sleep_counts_in_its_role_total():
    rec = {"status": "ok", "boottime_start_ns": 250 * MS, "boottime_end_ns": 750 * MS}
    trace = FakeTrace({7: [(0, "S"), (300 * MS, "Running")], 8: [(0, "S"), (300 * MS, "R")]})
    roles = {"engine": {"threads": [{"tid": 7}, {"tid": 8}]}}
    out = analyze_record(rec | {"roles": roles}, {"CPU": STEADY}, trace, GAP)
    assert out["wakeups"] == {"engine": {"total": 2, "threads": {7: 1, 8: 1}}}
    assert out["invalid"] == {}


def test_poll_interval_is_the_median_spacing():
    assert poll_interval_ns({"A": rail((0, 0), (200, 1), (400, 2), (1000, 3))}) == 200 * MS
    assert poll_interval_ns({"A": []}) is None


def test_tracks_of_one_name_are_separate_rails_told_apart_by_id():
    # perfetto's own power-rail parser folds equal rail names into one track, so feed the rows a
    # track-id grouped query returns: A and B interleave in time, each monotonic on its own
    rows = [
        SimpleNamespace(id=1, name="power.CPU_uws", ts=0, value=0.0),
        SimpleNamespace(id=1, name="power.CPU_uws", ts=2 * MS, value=25.0),
        SimpleNamespace(id=2, name="power.CPU_uws", ts=MS, value=20.0),
        SimpleNamespace(id=2, name="power.CPU_uws", ts=3 * MS, value=50.0),
        SimpleNamespace(id=3, name="power.GPU_uws", ts=MS, value=7.0),
    ]
    trace = Trace.__new__(Trace)
    trace._tp = SimpleNamespace(query=lambda _sql: rows)
    assert trace.rails() == {
        "CPU#1": [(0, 0.0), (2 * MS, 25.0)],
        "CPU#2": [(MS, 20.0), (3 * MS, 50.0)],
        "GPU": [(MS, 7.0)],
    }


def synthetic_trace(path, overrun):
    """Rail S4M_VDD_CPU with three samples, rail S9_EMPTY declared without any, tid 7 asleep,
    woken at 1200 ms and asleep again at 1400 ms on CPU 0, and the ftrace overrun counter."""
    trace = TraceProto()

    def packet(seq, ts_ms):
        p = trace.packet.add()
        p.trusted_packet_sequence_id, p.timestamp = seq, ts_ms * MS
        return p

    rails = packet(1, 1000).power_rails
    for i, name in enumerate(["S4M_VDD_CPU", "S9_EMPTY"]):
        rails.rail_descriptor.add(index=i, rail_name=name, subsys_name="X", sampling_rate=4)
    for ts, uws in [(1000, 0), (1250, 250_000), (1500, 500_000)]:
        packet(1, ts).power_rails.energy_data.add(index=0, timestamp_ms=ts, energy=uws)
    events = packet(2, 1100).ftrace_events
    events.cpu = 0
    for ts, prev, state, nxt in [(1100, 7, 1, 0), (1210, 0, 0, 7), (1400, 7, 1, 0)]:
        e = events.event.add(timestamp=ts * MS, pid=prev).sched_switch
        e.prev_comm, e.prev_pid, e.prev_state, e.next_comm, e.next_pid = "a", prev, state, "b", nxt
        if ts == 1100:
            events.event.add(timestamp=1200 * MS, pid=0).sched_waking.pid = 7
    for phase, ts, value in [(1, 1000, 0), (2, 1500, overrun)]:
        stats = packet(3, ts).ftrace_stats
        stats.phase = phase
        stats.cpu_stats.add(cpu=0, overrun=value)
    path.write_bytes(trace.SerializeToString())
    return path


@pytest.mark.parametrize("overrun", [0, 3])
def test_trace_queries_on_a_synthetic_trace(tmp_path, overrun):
    trace = Trace(synthetic_trace(tmp_path / "t.pftrace", overrun))
    try:
        cpu = [(1000 * MS, 0), (1250 * MS, 250_000), (1500 * MS, 500_000)]
        assert trace.rails() == {"S4M_VDD_CPU": cpu, "S9_EMPTY": []}  # a declared rail stays
        states = trace.thread_states({7}, 1150 * MS, 1300 * MS)
        assert [s for _, s in states[7]] == ["S", "R", "Running"]
        assert trace.sched_span == (1100 * MS, 1400 * MS)
        assert trace.sched_loss == ({"ftrace_cpu_overrun_delta": 3} if overrun else {})
    finally:
        trace.close()
