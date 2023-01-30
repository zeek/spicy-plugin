#!/bin/bash

set -e

BRANCH=${1:-main}

ID=$(curl "https://api.github.com/repos/zeek/spicy/commits/${BRANCH}/check-runs" | jq -r '.check_runs[] | select(.app.name == "Cirrus CI") | select(.name=="docker_debian11") | .external_id')
URL="https://api.cirrus-ci.com/v1/artifact/task/${ID}"
curl -o spicy-dev.deb "${URL}/packages/spicy-dev.deb"
