import json

with open('scratch/extracted_84_findings.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

for i in range(0, 30):
    d = data[i]
    print(f"--- FINDING {i+1:02d} ---")
    print(f"ID: {d['finding_id']}")
    print(f"Hive: {d['source_hive']} | EvID: {d['evidence_references']}")
    print(f"Key: {d['registry_key']}")
    print(f"ValName: {d['value_name']} | ValData: {d['value_data']}")
    print(f"Fact: {d['fact']}")
    print(f"Sev: {d['severity']} | Conf: {d['confidence']} | MITRE: {d['mitre_mapping']}")
    print(f"UAI: {d['primary_uai_id']} | FCR: {d['primary_fcr_id']} | ArtID: {d['source_artifact_id']}")
    print()
