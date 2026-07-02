"""Task 6 of the speed bundle: thread-parallel hill-climb candidate evaluation.

n_workers=1 must be today's exact serial path; >1 must produce identical
selection and trial ordering (submission-order preserved via pool.map).
"""
import threading

from temporal_exploit.hillclimb import greedy_forward_select


def _fake_world():
    # deterministic evaluate/delta: group value = its length; 'ccc' wins round 1
    def evaluate(groups):
        return {"score": sum(len(g) for g in groups)}

    def paired_delta(challenger, incumbent):
        d = challenger["score"] - incumbent["score"]
        return {"mean_delta": float(d), "ci95": [d - 0.5, d + 0.5], "win_frac": 1.0}

    return evaluate, paired_delta


def test_parallel_matches_serial_selection():
    evaluate, paired_delta = _fake_world()
    serial = greedy_forward_select(["a", "bb", "ccc"], [], evaluate, paired_delta)
    parallel = greedy_forward_select(["a", "bb", "ccc"], [], evaluate, paired_delta, n_workers=3)
    assert parallel["accepted"] == serial["accepted"] == ["ccc", "bb", "a"]
    assert parallel["n_rounds"] == serial["n_rounds"]
    assert [t["added"] for t in parallel["trials"]] == [t["added"] for t in serial["trials"]]


def test_parallel_actually_runs_concurrently():
    evaluate, paired_delta = _fake_world()
    seen = set()

    def spying_evaluate(groups):
        seen.add(threading.current_thread().name)
        return evaluate(groups)

    greedy_forward_select(["a", "bb", "ccc"], [], spying_evaluate, paired_delta, n_workers=3)
    assert len(seen) > 1   # more than one worker thread touched evaluate
