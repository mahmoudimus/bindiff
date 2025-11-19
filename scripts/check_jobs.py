#!/usr/bin/env python3
import json
import sys

data = json.load(sys.stdin)
jobs = data.get('jobs', [])

# Check for any completed or failed jobs
completed = [j for j in jobs if j['status'] == 'completed']
in_progress = [j for j in jobs if j['status'] == 'in_progress']

print(f'Completed: {len(completed)}, In Progress: {len(in_progress)}')
print()

# Show completed jobs first
for job in completed:
    name = job['name']
    conclusion = job.get('conclusion', 'N/A')

    if conclusion == 'success':
        color = '\033[92m'
        symbol = '✓'
    else:
        color = '\033[91m'
        symbol = '✗'

    reset = '\033[0m'
    print(f'{color}{symbol} {name}{reset} - {conclusion}')

    if conclusion != 'success':
        print(f'  Log: {job["html_url"]}')

if completed:
    print()

# Show in-progress jobs
for job in in_progress[:3]:
    name = job['name']
    steps = job.get('steps', [])
    current_step = None
    for step in steps:
        if step['status'] == 'in_progress':
            current_step = step['name']
            break
    print(f'⟳ {name}')
    if current_step:
        print(f'  Current: {current_step}')

if len(in_progress) > 3:
    print(f'... and {len(in_progress) - 3} more in progress')
