import sys
with open('app.py', 'r', encoding='utf-8') as f:
    for i, line in enumerate(f.readlines()[:50]):
        print(f"Line {i}: {line.strip()}")
