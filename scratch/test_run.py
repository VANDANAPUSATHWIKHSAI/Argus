import sys
import json
sys.path.insert(0, '.')
from agents.agent4_malware_behaviour import MalwareBehaviourAgent
from sanitization.gateway import SanitizationGateway

class FastMockLLM:
    def generate(self, prompt, system_prompt=None):
        return 'Grounded Qwen3-8B Reasoning'

with open('agent2_25_samples.json', 'r', encoding='utf-8') as f:
    samples = json.load(f)

gateway = SanitizationGateway()
gateway.classifier = None
gateway.sanitize = lambda text, field_name="fact": text

agent = MalwareBehaviourAgent(
    model=FastMockLLM(),
    fir_repo=None,
    sanitization_gateway=gateway,
    tenant_id='default'
)

sample = samples[0]
out = agent.execute_analysis(sample['case_id'], sample)

with open('agent4_enhanced_output.json', 'w', encoding='utf-8') as f:
    json.dump(out.model_dump(), f, indent=2)

print("SUCCESSFULLY_SAVED_ENHANCED_OUTPUT")
