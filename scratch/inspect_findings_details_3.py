import json

with open('scratch/extracted_84_findings.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

for i in range(0, len(data)):
    d = data[i]
    val_data = str(d['value_data']).encode('ascii', 'replace').decode('ascii')
    val_name = str(d['value_name']).encode('ascii', 'replace').decode('ascii')
    key = str(d['registry_key']).encode('ascii', 'replace').decode('ascii')
    fact = str(d['fact']).encode('ascii', 'replace').decode('ascii')
    print(f"{i+1:02d} | ID:{d['finding_id'][:8]} | Hive:{d['source_hive']} | Sev:{d['severity']} | Conf:{d['confidence']} | MITRE:{d['mitre_mapping']} | Key:{key[:35]} | Val:{val_name}={val_data[:20]}")
