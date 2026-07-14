"""Measure PrivateGateway's Excel path with a synthetic workbook only."""
from __future__ import annotations

import argparse
import json
import shutil
import time
from datetime import date, timedelta
from pathlib import Path
from tempfile import mkdtemp

from openpyxl import Workbook

from privategateway import agent_plugin


def build_workbook(path: Path, rows_per_sheet: int, sheets: int) -> int:
    workbook = Workbook(write_only=True)
    base_date = date(2026, 1, 1)
    for sheet_index in range(sheets):
        worksheet = workbook.create_sheet(f"Benchmark_{sheet_index + 1}")
        worksheet.append(["customer_id", "amount", "status", "transaction_date", "note"])
        for row_index in range(rows_per_sheet):
            worksheet.append([
                f"C{sheet_index + 1:02d}{row_index:08d}",
                float(100 + ((row_index * 97) % 100_000)),
                ("ACTIVE", "PAID", "PENDING", "CLOSED")[row_index % 4],
                base_date + timedelta(days=row_index % 365),
                f"synthetic operational note {row_index % 97}",
            ])
    workbook.save(path)
    return rows_per_sheet * sheets * 5


def write_policy(path: Path) -> None:
    path.write_text(
        """security:
  require_presidio: false
columns:
  customer_id: tokenize
  amount: synthesize
  status: keep
  transaction_date: date_shift
  note: tokenize
default:
  unknown_column: review_required
date_shift:
  subject_column: customer_id
  min_days: 1
  max_days: 30
  direction: both
  stability: project
""",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows-per-sheet", type=int, default=2_000)
    parser.add_argument("--sheets", type=int, default=2)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()
    if args.rows_per_sheet < 1 or args.sheets < 1:
        raise SystemExit("rows-per-sheet and sheets must be positive")

    root = Path(mkdtemp(prefix="privategateway_benchmark_"))
    source = root / "synthetic_input.xlsx"
    target = root / "synthetic_safe.xlsx"
    policy = root / "policy.yaml"
    stages: list[tuple[str, float]] = []
    original_root, original_key_root = agent_plugin.GATEWAY_ROOT, agent_plugin.KEY_ROOT
    try:
        build_started = time.perf_counter()
        cells = build_workbook(source, args.rows_per_sheet, args.sheets)
        build_seconds = time.perf_counter() - build_started
        write_policy(policy)
        agent_plugin.GATEWAY_ROOT = root / "gateway"
        agent_plugin.KEY_ROOT = agent_plugin.GATEWAY_ROOT / ".privacy_gateway" / "keys"
        agent_plugin._ensure_project("benchmark")
        preview_started = time.perf_counter()
        generated_policy, review_columns = agent_plugin._prepare_workbook_policy(source)
        auto_policy_preview_seconds = time.perf_counter() - preview_started
        generated_policy.unlink(missing_ok=True)
        if review_columns:
            raise RuntimeError(f"synthetic benchmark unexpectedly requires review: {review_columns}")

        def progress(stage: str, rows_processed: int | None = None, sheets_processed: int | None = None) -> None:
            if not stages or stages[-1][0] != stage:
                stages.append((stage, time.perf_counter()))

        total_started = time.perf_counter()
        result = agent_plugin._stream_sanitize_excel(
            source, target, "benchmark", policy, "sealed_analytics", progress
        )
        total_seconds = time.perf_counter() - total_started
        stage_seconds: dict[str, float] = {}
        for index, (stage, started) in enumerate(stages):
            ended = stages[index + 1][1] if index + 1 < len(stages) else total_started + total_seconds
            stage_seconds[stage] = round(ended - started, 4)
        payload = {
            "workbook": {
                "sheets": args.sheets,
                "rows_per_sheet": args.rows_per_sheet,
                "cells": cells,
                "source_bytes": source.stat().st_size,
                "safe_bytes": target.stat().st_size,
            },
            "seconds": {
                "synthetic_workbook_build": round(build_seconds, 4),
                "auto_policy_preview": round(auto_policy_preview_seconds, 4),
                "gateway_total": round(total_seconds, 4),
                **stage_seconds,
            },
            "throughput": {
                "cells_per_second": round(cells / total_seconds, 2),
                "rows_per_second": round((args.rows_per_sheet * args.sheets) / total_seconds, 2),
            },
            "result": {
                "sheet_count": result["metadata"]["sheet_count"],
                "action_counts": result["redaction_report"]["action_counts"],
            },
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    finally:
        agent_plugin.GATEWAY_ROOT, agent_plugin.KEY_ROOT = original_root, original_key_root
        if args.keep_workdir:
            print(f"benchmark_workdir={root}")
        else:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
