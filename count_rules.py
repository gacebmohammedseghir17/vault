#!/usr/bin/env python3
import glob
import os

files = glob.glob('./yara_rules/*.yar') + glob.glob('./yara_rules/*.yara')
print(f'Files found: {files}')

total_rules = 0
for f in files:
    if os.path.exists(f):
        with open(f, 'r', encoding='utf-8') as file:
            content = file.read()
        rules = [line.strip() for line in content.split('\n') if line.strip().startswith('rule ') and not line.strip().startswith('//')]
        print(f'{f}: {len(rules)} rules - {[r.split()[1] for r in rules]}')
        total_rules += len(rules)
    else:
        print(f'File not found: {f}')
        
print(f'Total rules expected: {total_rules}')