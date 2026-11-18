
import json
import unittest
from pathlib import Path

from triage import MAX_BYTES, InputError, Settings, detect, export_incident, parse_csv, summarize

HEADER = "timestamp,user,source_ip,outcome\n"
DEMO = Path(__file__).resolve().parents[1] / "samples" / "synthetic_logins.csv"


def parse(*records):
    return parse_csv((HEADER + "\n".join(records)).encode())


class TriageTests(unittest.TestCase):
    def test_unsorted_demo_same_timeline_preserves_source_rows(self):
        events, rejected = parse_csv(DEMO.read_bytes())
        self.assertEqual(rejected, [])
        alerts = detect(events, Settings())
        self.assertEqual(alerts, detect(reversed(events), Settings()))
        self.assertEqual([[event.row for event in alert.events] for alert in alerts],
                         [[3, 8, 6], [7, 4, 9, 2]])

    def test_groups_do_not_cross_users_or_ip(self):
        events, _ = parse(
            "2026-01-01T00:00:00Z,a,192.0.2.1,failure",
            "2026-01-01T00:00:01Z,b,192.0.2.1,failure",
            "2026-01-01T00:00:02Z,a,192.0.2.2,failure",
            "2026-01-01T00:00:03Z,a,192.0.2.1,failure",
            "2026-01-01T00:00:04Z,b,192.0.2.1,success",
            "2026-01-01T00:00:05Z,a,192.0.2.2,success",
        )
        self.assertEqual(detect(events, Settings()), [])
        [alert] = detect(events, Settings(2, 10, 15))
        self.assertEqual([event.row for event in alert.events], [2, 5])

    def test_exact_boundaries_and_same_time_success(self):
        events, _ = parse(
            "2026-01-01T00:00:00Z,a,192.0.2.1,failure",
            "2026-01-01T00:10:00Z,a,192.0.2.1,failure",
            "2026-01-01T00:10:00Z,a,192.0.2.1,success",
            "2026-01-01T00:25:00Z,a,192.0.2.1,success",
        )
        [alert] = detect(events, Settings(2, 10, 15))
        self.assertEqual([event.row for event in alert.events], [2, 3, 5])

    def test_late_success_and_stale_failure(self):
        events, _ = parse(
            "2026-01-01T00:00:00Z,a,192.0.2.1,failure",
            "2026-01-01T00:10:00.000001Z,a,192.0.2.1,failure",
            "2026-01-01T00:11:00Z,a,192.0.2.1,failure",
            "2026-01-01T00:26:00.000001Z,a,192.0.2.1,success",
        )
        [alert] = detect(events, Settings(2, 10, 15))
        self.assertEqual([event.row for event in alert.events], [3, 4])

    def test_malformed_rows_and_utc_normalization(self):
        events, rejected = parse(
            "invalid,,bad,maybe",
            "2026-01-01T05:30:00+05:30,a,2001:0db8::1,SUCCESS",
            "bad,short",
            "2026-01-01T00:01:00,a,192.0.2.1,failure",
        )
        self.assertEqual([row.row for row in rejected], [2, 4])
        for field in ("timestamp", "user", "source_ip", "outcome"):
            self.assertIn(field, rejected[0].reason)
        self.assertEqual(events[0].export()["timestamp"], "2026-01-01T00:00:00Z")
        self.assertEqual(events[0].source_ip, "2001:db8::1")
        self.assertEqual(events[1].export()["timestamp"], "2026-01-01T00:01:00Z")

    def test_multiline_extra_column_and_fatal_quoting(self):
        events, rejected = parse_csv(
            (HEADER.strip() + ',note\n2026-01-01T00:00:00Z,a,192.0.2.1,success,"one\ntwo"\n'
             '2026-01-01T00:01:00Z,a,192.0.2.1,success,"broken').encode()
        )
        self.assertEqual([event.row for event in events], [2])
        self.assertEqual([row.row for row in rejected], [4])
        self.assertIn("Reading stopped", rejected[0].reason)

    def test_invalid_utc_offset_is_rejected(self):
        events, rejected = parse("2026-01-01T00:00:00+00:99,a,192.0.2.1,success")
        self.assertEqual(events, [])
        self.assertIn("timestamp", rejected[0].reason)


    def test_schema_and_size(self):
        with self.assertRaisesRegex(InputError, "headers"):
            parse_csv(b"wrong,headers\nx,y")
        with self.assertRaisesRegex(InputError, "2 MiB"):
            parse_csv(b"x" * (MAX_BYTES + 1))

    def test_summary_and_export_only_selected_evidence(self):
        events, _ = parse_csv(DEMO.read_bytes())
        settings = Settings()
        _, selected = detect(events, settings)
        summary = summarize(selected)
        exported = json.loads(export_incident(selected, settings, "Investigating"))
        self.assertEqual(exported["summary"], summary)
        self.assertEqual(exported["matching_row_ids"], [7, 4, 9, 2])
        self.assertEqual([item["row"] for item in exported["evidence"]], [7, 4, 9, 2])
        self.assertEqual(exported["status"], "Investigating")
        self.assertEqual(exported["detection_settings"]["threshold"], 3)
        self.assertIn("source rows 7, 4, 9", summary["Observed behavior"][0])
        self.assertIn("source row 2", summary["Observed behavior"][1])
        self.assertNotIn("devon", json.dumps(exported))
        self.assertNotIn("203.0.113.9", json.dumps(exported))
