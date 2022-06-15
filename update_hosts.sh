#!/bin/bash
aws ec2 describe-instances --profile neto --query "Reservations[*].Instances[*].{name: Tags[?Key=='Name'] | [0].Value, subsystem: Tags[?Key=='Subsystem'] | [0].Value}" --output json | jq -r '[ .[][] | select( .subsystem != "portal")| select(.name | contains("local-") | not)|select(.name | contains("dev-") | not)]' | tr '[:upper:]' '[:lower:]' > hosts.json
