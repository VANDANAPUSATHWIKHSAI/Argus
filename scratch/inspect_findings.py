import json

with open('scratch/extracted_84_findings.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

print(f"Total findings loaded: {len(data)}")

for i, d in enumerate(data):
    key = d.get('registry_key') or 'N/A'
    fact = d.get('fact') or ''
    sev = d.get('severity')
    conf = d.get('confidence')
    mitre = d.get('mitre_mapping')
    hive = d.get('source_hive')
    art_id = d.get('source_artifact_id')
    uai_id = d.get('primary_uai_id')
    fcr_id = d.get('primary_fcr_id')
    print(f"{i+1:02d} | ID:{d['finding_id'][:8]} | Hive:{hive} | Sev:{sev} | Conf:{conf} | MITRE:{mitre} | Key:{key[:40]} | UAI:{uai_id} | FCR:{fcr_id}")
