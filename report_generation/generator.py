# Report Generation Service (structural, formatting only)
# Outputs: PDF, HTML, JSON
# Each stamped with: model name + version, prompt template version,
# RAG corpus snapshot ID, timestamp.
# Enables legal defensibility AND regression testing.
from jinja2 import Environment, FileSystemLoader

class ReportGenerator:
    def generate(self, report_data: dict, format: str = 'html') -> bytes:
        # format: 'html' | 'pdf' | 'json'
        raise NotImplementedError
