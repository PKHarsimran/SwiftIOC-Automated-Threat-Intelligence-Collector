import gzip
import json
from datetime import datetime, timezone
from typing import cast

import requests

from swiftioc.cve_signals import build, concise_cve, parse_epss, target_ids


def test_epss_filters_targets_and_rejects_out_of_range():
    csv = b"# model_version: test\ncve,epss,percentile\nCVE-2026-1000,0.22,0.97\nCVE-2026-2000,1.5,0.99\n"
    header, scores = parse_epss(gzip.compress(csv), {"CVE-2026-1000", "CVE-2026-2000"})
    assert header is not None and "model_version" in header
    assert scores == {"CVE-2026-1000": {"probability": .22, "percentile": .97}}


def test_official_cve_keeps_cisa_ssvc_separate():
    record = {"cveMetadata": {"cveId": "CVE-2026-1000", "state": "PUBLISHED"}, "containers": {
        "cna": {"descriptions": [{"lang": "en", "value": "Example issue"}], "affected": [{"vendor": "A", "product": "B"}]},
        "adp": [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [
            {"other": {"type": "ssvc", "content": {"version": "2.0.3", "options": [{"Exploitation": "active"}, {"Automatable": "yes"}]}}}]}]}}
    detail = concise_cve(record, "CVE-2026-1000")
    assert detail is not None
    assert detail["cisa_ssvc"]["options"] == {"Exploitation": "active", "Automatable": "yes"}
    assert detail["description"] == "Example issue"
    assert concise_cve(record, "CVE-2026-9999") is None


def test_sidecar_uses_daily_file_and_one_official_record_then_cache(tmp_path):
    feed = tmp_path / "latest.jsonl"
    feed.write_text(json.dumps({"type": "cve", "indicator": "CVE-2026-1000"}) + "\n", encoding="utf-8")
    groups = tmp_path / "group.json"
    groups.write_text(json.dumps({"generated_at": "2026-10-05T00:00:00Z", "cves": [
        {"cve_id": "CVE-2026-2000"}]}), encoding="utf-8")
    assert target_ids(feed, json.loads(groups.read_text())) == ({"CVE-2026-1000", "CVE-2026-2000"}, ["CVE-2026-2000"])

    class Response:
        def __init__(self, content):
            self.content = content

        def raise_for_status(self):
            pass

        def json(self):
            return json.loads(self.content)

    class Session:
        calls = 0

        def get(self, url, **_):
            self.calls += 1
            if "epss" in url:
                return Response(gzip.compress(b"cve,epss,percentile\nCVE-2026-1000,0.1,0.9\nCVE-2026-2000,0.2,0.95\n"))
            return Response(json.dumps({"cveMetadata": {"cveId": "CVE-2026-2000", "state": "PUBLISHED"}, "containers": {"cna": {}}}).encode())

    session = Session()
    output = tmp_path / "signals.json"
    now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    result = build(feed, groups, output, session=cast(requests.Session, session), now=now)
    assert session.calls == 2
    assert result["items"]["CVE-2026-2000"]["official_cve"]["status"] == "PUBLISHED"
    assert build(feed, groups, output, session=cast(requests.Session, session), now=now) == result
    assert session.calls == 2
