from swiftioc.attack_guidance import compact


def test_compact_links_group_technique_to_strategy_and_exact_logs():
    objects = [
        {"id": "attack-pattern--1", "type": "attack-pattern", "external_references": [{"external_id": "T1486", "url": "https://attack.mitre.org/techniques/T1486/"}]},
        {"id": "x-mitre-detection-strategy--1", "type": "x-mitre-detection-strategy", "name": "Detect encryption", "external_references": [{"external_id": "DET0678", "url": "https://attack.mitre.org/detectionstrategies/DET0678/"}], "x_mitre_analytic_refs": ["x-mitre-analytic--1"]},
        {"id": "x-mitre-analytic--1", "type": "x-mitre-analytic", "external_references": [{"external_id": "AN1781", "url": "https://attack.mitre.org/detectionstrategies/DET0678/#AN1781"}], "x_mitre_platforms": ["Windows"], "x_mitre_log_source_references": [{"name": "Windows Event Log"}]},
        {"id": "relationship--1", "type": "relationship", "relationship_type": "detects", "source_ref": "x-mitre-detection-strategy--1", "target_ref": "attack-pattern--1"},
    ] + [{"id": f"dummy--{i}", "type": "identity"} for i in range(1000)]
    result = compact({"objects": objects}, {"T1486"}, "2026-10-05T00:00:00Z")
    strategy = result["techniques"]["T1486"]["strategies"][0]
    assert strategy["id"] == "DET0678"
    assert strategy["analytics"][0]["log_sources"] == ["Windows Event Log"]
    assert result["requested_techniques"] == ["T1486"]
