#!/bin/bash
# Monitor GitHub Actions workflows for the current branch

REPO="mahmoudimus/bindiff"
BRANCH=$(git rev-parse --abbrev-ref HEAD)

echo "Monitoring workflows for branch: $BRANCH"
echo "=========================================="
echo

# Get recent workflow runs
curl -s "https://api.github.com/repos/$REPO/actions/runs?branch=$BRANCH&per_page=3" | \
  python3 -c "
import json, sys
from datetime import datetime

data = json.load(sys.stdin)
runs = data.get('workflow_runs', [])

for run in runs:
    status = run['status']
    conclusion = run.get('conclusion', 'N/A')
    name = run['name']
    created = run['created_at']
    url = run['html_url']
    run_id = run['id']

    # Color codes
    if status == 'completed':
        if conclusion == 'success':
            color = '\033[92m'  # Green
            symbol = '✓'
        elif conclusion == 'failure':
            color = '\033[91m'  # Red
            symbol = '✗'
        else:
            color = '\033[93m'  # Yellow
            symbol = '⚠'
    else:
        color = '\033[94m'  # Blue
        symbol = '⟳'

    reset = '\033[0m'

    print(f'{color}{symbol} {name}{reset}')
    print(f'  Status: {status} - {conclusion}')
    print(f'  Created: {created}')
    print(f'  URL: {url}')

    # Get job details if completed
    if status == 'completed':
        import subprocess
        jobs_json = subprocess.check_output(
            f'curl -s https://api.github.com/repos/{run[\"repository\"][\"full_name\"]}/actions/runs/{run_id}/jobs',
            shell=True
        )
        jobs_data = json.loads(jobs_json)
        jobs = jobs_data.get('jobs', [])

        failed_jobs = [j for j in jobs if j.get('conclusion') == 'failure']
        if failed_jobs:
            print(f'  {color}Failed jobs:{reset}')
            for job in failed_jobs:
                print(f'    - {job[\"name\"]}')
                print(f'      Log: {job[\"html_url\"]}')

    print()
"
