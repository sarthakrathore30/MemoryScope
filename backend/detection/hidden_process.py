"""
Hidden/unlinked process detection (FR-7, TC-DT-01).

Technique: cross-view comparison between pslist (walks the OS's linked list
of active processes) and psscan (pool-tag scan that finds process objects
in memory regardless of whether they're linked into that list). A process
present in psscan but absent from pslist is a strong indicator that it has
been unlinked (a classic DKOM/rootkit hiding technique).
"""
from dataclasses import replace
from typing import List

from analysis.volatility_wrapper import ProcessInfo


def find_hidden_processes(pslist_procs: List[ProcessInfo], psscan_procs: List[ProcessInfo]) -> List[ProcessInfo]:
    """
    Compare pslist vs psscan results and return the set of processes that
    appear only in psscan (i.e. hidden/unlinked), with is_hidden semantics
    conveyed via a returned, merged process list.

    Returns the full merged list of unique processes (keyed by PID) with a
    `is_hidden`-equivalent flag encoded by seen_in_pslist/seen_in_psscan,
    which the caller (detection service) turns into the DB's is_hidden column.
    """
    pslist_pids = {p.pid for p in pslist_procs}
    psscan_by_pid = {p.pid: p for p in psscan_procs}

    merged = {}
    for proc in pslist_procs:
        merged[proc.pid] = replace(proc, seen_in_pslist=True, seen_in_psscan=proc.pid in psscan_by_pid)

    for pid, proc in psscan_by_pid.items():
        if pid not in pslist_pids:
            # Present only via pool scan -> hidden/unlinked.
            merged[pid] = replace(proc, seen_in_pslist=False, seen_in_psscan=True)

    return list(merged.values())


def is_hidden(proc: ProcessInfo) -> bool:
    """A process is considered hidden if psscan found it but pslist did not."""
    return proc.seen_in_psscan and not proc.seen_in_pslist
