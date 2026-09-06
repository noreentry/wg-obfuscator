#!/usr/bin/env python3
"""Correlate wg-obfuscator binary stats dumps between two hosts.

Pairs SENT on one side with RECV on the other by seq. Each process has its own
seq counter, so for tunnel endpoints A and B:

  A SENT seq N  <->  B RECV seq N   (A -> B)
  B SENT seq M  <->  A RECV seq M   (B -> A)

File format: pktstats.h (WGOBST1 header + 16-byte records).

Example::

  python3 scripts/correlate-pktstats.py /path/to/host-a/stats /path/to/host-b/stats \\
    --sender-name host-a --receiver-name host-b --csv pairs.csv
"""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

STATS_MAGIC = 0x315453424F4757  # "WGOBST1\0" LE
HDR_FMT = "<QHHHHIQQIIII12s"  # 64 bytes, pktstats.h stats_file_hdr_t
REC_FMT = "<QIHBB"
HDR_SIZE = 64
REC_SIZE = 16

FLAG_SENT = 0x01
FLAG_ERROR = 0x02

WG_TYPES = {1: "handshake", 2: "handshake_resp", 3: "cookie", 4: "data"}


@dataclass(frozen=True)
class FileMeta:
    path: Path
    run_id_us: int
    file_index: int
    interval_start_us: int
    record_count: int
    dropped_count: int
    section: str


@dataclass(frozen=True)
class Record:
    host: str
    path: Path
    t_us: int
    seq: int
    length: int
    stream: int
    sent: bool
    error: bool
    wg_type: int
    run_id_us: int

    @property
    def wg_type_name(self) -> str:
        return WG_TYPES.get(self.wg_type, f"type{self.wg_type}")


@dataclass
class MatchedPair:
    direction: str
    seq: int
    sent_host: str
    recv_host: str
    sent_t_us: int
    recv_t_us: int
    sent_len: int
    recv_len: int
    sent_stream: int
    recv_stream: int
    wg_type: int
    owd_us: int  # recv - sent (raw clock; apply --clock-offset-us)


def us_to_iso(t_us: int) -> str:
    return datetime.fromtimestamp(t_us / 1_000_000, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )[:-3] + "Z"


def parse_dump_file(path: Path, host: str) -> tuple[FileMeta | None, list[Record]]:
    data = path.read_bytes()
    if len(data) < HDR_SIZE:
        return None, []

    hdr = struct.unpack_from(HDR_FMT, data, 0)
    magic = hdr[0]
    if magic != STATS_MAGIC:
        return None, []

    header_len, record_size = hdr[1], hdr[2]
    if header_len != HDR_SIZE or record_size != REC_SIZE:
        raise ValueError(f"{path}: unexpected header/record size {header_len}/{record_size}")

    section = hdr[12].split(b"\0", 1)[0].decode("ascii", errors="replace")
    meta = FileMeta(
        path=path,
        run_id_us=hdr[6],
        file_index=hdr[5],
        interval_start_us=hdr[7],
        record_count=hdr[9],
        dropped_count=hdr[10],
        section=section,
    )

    records: list[Record] = []
    off = HDR_SIZE
    while off + REC_SIZE <= len(data):
        t_us, seq, length, stream, flags = struct.unpack_from(REC_FMT, data, off)
        records.append(
            Record(
                host=host,
                path=path,
                t_us=t_us,
                seq=seq,
                length=length,
                stream=stream,
                sent=bool(flags & FLAG_SENT),
                error=bool(flags & FLAG_ERROR),
                wg_type=(flags >> 2) & 0x03,
                run_id_us=meta.run_id_us,
            )
        )
        off += REC_SIZE

    return meta, records


def load_host_dir(directory: Path, host: str, run_id: int | None) -> list[Record]:
    records: list[Record] = []
    metas: list[FileMeta] = []
    for path in sorted(directory.glob("main*")):
        if not path.is_file():
            continue
        meta, recs = parse_dump_file(path, host)
        if meta is None:
            continue
        metas.append(meta)
        records.extend(recs)

    if not records:
        return []

    if run_id is None:
        run_counts: dict[int, int] = {}
        for m in metas:
            if m.record_count:
                run_counts[m.run_id_us] = run_counts.get(m.run_id_us, 0) + m.record_count
        if run_counts:
            run_id = max(run_counts, key=run_counts.get)
        else:
            run_id = max(m.run_id_us for m in metas)

    return [r for r in records if r.run_id_us == run_id]


def index_by_seq(records: Iterable[Record], sent: bool, stream: int | None) -> dict[int, list[Record]]:
    out: dict[int, list[Record]] = {}
    for r in records:
        if r.sent != sent:
            continue
        if stream is not None and r.stream != stream:
            continue
        out.setdefault(r.seq, []).append(r)
    return out


def correlate_direction(
    name: str,
    sent_records: dict[int, list[Record]],
    recv_records: dict[int, list[Record]],
) -> tuple[list[MatchedPair], list[Record], list[Record]]:
    pairs: list[MatchedPair] = []
    unmatched_sent: list[Record] = []
    unmatched_recv: list[Record] = []

    all_seqs = set(sent_records) | set(recv_records)
    for seq in sorted(all_seqs):
        sends = sent_records.get(seq, [])
        recvs = recv_records.get(seq, [])

        if sends and recvs:
            for s, rv in zip(sends, recvs):
                pairs.append(
                    MatchedPair(
                        direction=name,
                        seq=seq,
                        sent_host=s.host,
                        recv_host=rv.host,
                        sent_t_us=s.t_us,
                        recv_t_us=rv.t_us,
                        sent_len=s.length,
                        recv_len=rv.length,
                        sent_stream=s.stream,
                        recv_stream=rv.stream,
                        wg_type=s.wg_type,
                        owd_us=rv.t_us - s.t_us,
                    )
                )
            unmatched_sent.extend(sends[len(recvs) :])
            unmatched_recv.extend(recvs[len(sends) :])
        elif sends:
            unmatched_sent.extend(sends)
        else:
            unmatched_recv.extend(recvs)

    return pairs, unmatched_sent, unmatched_recv


def percentile(values: list[int], p: float) -> float | None:
    if not values:
        return None
    xs = sorted(values)
    k = (len(xs) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    if f == c:
        return float(xs[f])
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def summarize_owd(pairs: list[MatchedPair], clock_offset_us: int) -> None:
    if not pairs:
        print("  (no matched pairs)")
        return
    delays = [p.recv_t_us - p.sent_t_us - clock_offset_us for p in pairs]
    neg = sum(1 for d in delays if d < 0)
    print(f"  matched: {len(pairs)}")
    print(f"  owd_us min/median/p95/max: {min(delays)} / {percentile(delays, 50):.0f} / "
          f"{percentile(delays, 95):.0f} / {max(delays)}")
    if clock_offset_us:
        print(f"  (clock offset applied: {clock_offset_us} us)")
    if neg:
        print(f"  negative owd after offset: {neg} ({100*neg/len(delays):.1f}%)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sender_dir", type=Path, help="stats dump dir for first host (A -> B sender)")
    ap.add_argument("receiver_dir", type=Path, help="stats dump dir for second host (A -> B receiver)")
    ap.add_argument("--sender-name", default="sender", help="label for first host")
    ap.add_argument("--receiver-name", default="receiver", help="label for second host")
    ap.add_argument("--sender-stream", type=int, default=None, help="filter sender RECV/SENT by stream id")
    ap.add_argument("--receiver-stream", type=int, default=None, help="filter receiver RECV/SENT by stream id")
    ap.add_argument("--run-id", type=int, default=None, help="only this run_id_us (default: busiest run)")
    ap.add_argument("--clock-offset-us", type=int, default=None, help="recv_time - sent_time bias to subtract")
    ap.add_argument("--csv", type=Path, default=None, help="write matched pairs to CSV")
    ap.add_argument("--show", type=int, default=20, help="print first N matched pairs per direction (0=none)")
    args = ap.parse_args()

    sender_name = args.sender_name
    receiver_name = args.receiver_name

    sender_recs = load_host_dir(args.sender_dir, sender_name, args.run_id)
    receiver_recs = load_host_dir(args.receiver_dir, receiver_name, args.run_id)

    if not sender_recs:
        raise SystemExit(f"No records in {args.sender_dir}")
    if not receiver_recs:
        raise SystemExit(f"No records in {args.receiver_dir}")

    run_id = sender_recs[0].run_id_us
    print(f"run_id_us: {run_id} ({us_to_iso(run_id)})")
    print(f"{sender_name}: {len(sender_recs)} records "
          f"({sum(1 for r in sender_recs if r.sent)} sent, {sum(1 for r in sender_recs if not r.sent)} recv)")
    print(f"{receiver_name}: {len(receiver_recs)} records "
          f"({sum(1 for r in receiver_recs if r.sent)} sent, {sum(1 for r in receiver_recs if not r.sent)} recv)")

    fwd_pairs, fwd_lost, fwd_orphan = correlate_direction(
        f"{sender_name}->{receiver_name}",
        index_by_seq(sender_recs, sent=True, stream=args.sender_stream),
        index_by_seq(receiver_recs, sent=False, stream=args.receiver_stream),
    )

    rev_pairs, rev_lost, rev_orphan = correlate_direction(
        f"{receiver_name}->{sender_name}",
        index_by_seq(receiver_recs, sent=True, stream=args.receiver_stream),
        index_by_seq(sender_recs, sent=False, stream=args.sender_stream),
    )

    clock_offset = args.clock_offset_us
    if clock_offset is None and fwd_pairs:
        raw = [p.recv_t_us - p.sent_t_us for p in fwd_pairs]
        clock_offset = min(raw)
        print(f"\nEstimated clock offset (min raw OWD {sender_name}->{receiver_name}): {clock_offset} us")

    print(f"\n=== {sender_name} -> {receiver_name} ===")
    summarize_owd(fwd_pairs, clock_offset or 0)
    print(f"  sent without recv (loss): {len(fwd_lost)}")
    print(f"  recv without sent (orphan): {len(fwd_orphan)}")

    print(f"\n=== {receiver_name} -> {sender_name} ===")
    summarize_owd(rev_pairs, clock_offset or 0)
    print(f"  sent without recv (loss): {len(rev_lost)}")
    print(f"  recv without sent (orphan): {len(rev_orphan)}")

    all_pairs = fwd_pairs + rev_pairs
    if args.csv:
        import csv

        args.csv.parent.mkdir(parents=True, exist_ok=True)
        with args.csv.open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                [
                    "direction",
                    "seq",
                    "sent_host",
                    "recv_host",
                    "sent_t_us",
                    "recv_t_us",
                    "sent_time_utc",
                    "recv_time_utc",
                    "owd_us",
                    "owd_us_corrected",
                    "sent_len",
                    "recv_len",
                    "sent_stream",
                    "recv_stream",
                    "wg_type",
                ]
            )
            for p in all_pairs:
                owd_corr = p.owd_us - (clock_offset or 0)
                w.writerow(
                    [
                        p.direction,
                        p.seq,
                        p.sent_host,
                        p.recv_host,
                        p.sent_t_us,
                        p.recv_t_us,
                        us_to_iso(p.sent_t_us),
                        us_to_iso(p.recv_t_us),
                        p.owd_us,
                        owd_corr,
                        p.sent_len,
                        p.recv_len,
                        p.sent_stream,
                        p.recv_stream,
                        WG_TYPES.get(p.wg_type, str(p.wg_type)),
                    ]
                )
        print(f"\nWrote {len(all_pairs)} pairs to {args.csv}")

    if args.show:
        for label, pairs in [
            (f"{sender_name}->{receiver_name}", fwd_pairs),
            (f"{receiver_name}->{sender_name}", rev_pairs),
        ]:
            print(f"\n--- sample {label} (first {args.show}) ---")
            for p in pairs[: args.show]:
                owd = p.owd_us - (clock_offset or 0)
                print(
                    f"  seq={p.seq} owd={owd}us wg={WG_TYPES.get(p.wg_type, p.wg_type)} "
                    f"sent={us_to_iso(p.sent_t_us)} recv={us_to_iso(p.recv_t_us)} "
                    f"len {p.sent_len}->{p.recv_len} stream {p.sent_stream}->{p.recv_stream}"
                )


if __name__ == "__main__":
    main()
