#!/usr/bin/env bash
# ==============================================================================
# Lynis Test Harness: test_cron_vulnerabilities.sh
# Purpose: Simulates insecure cron targets and wildcard injections to verify
#          SCHD-7705 and SCHD-7706 test detections in Lynis.
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[*] Lynis Scheduling Enhancement Verification Harness${NC}"

TEST_CRON_FILE="/etc/cron.d/test_lynis_scheduling_audit"
TEST_SCRIPT_DIR="/opt/test_lynis_scripts"
TEST_SCRIPT_TARGET="${TEST_SCRIPT_DIR}/vulnerable_backup.sh"

setup_test_cases() {
    echo -e "${YELLOW}[+] Setting up simulated vulnerable test fixtures...${NC}"
    
    # 1. Create a script directory and world-writable target script (for SCHD-7705)
    sudo mkdir -p "${TEST_SCRIPT_DIR}"
    sudo bash -c "cat << 'EOF' > '${TEST_SCRIPT_TARGET}'
#!/bin/bash
# Simulated maintenance job
echo \"Running backup routine\"
EOF"
    # Make target world-writable to trigger SCHD-7705 detection
    sudo chmod 777 "${TEST_SCRIPT_TARGET}"
    echo -e "    - Created world-writable script at: ${TEST_SCRIPT_TARGET} (mode: 777)"

    # 2. Create a test cron job in /etc/cron.d/ containing:
    #    a) Reference to the world-writable script (SCHD-7705)
    #    b) Dangerous wildcard command expansion with tar (SCHD-7706)
    sudo bash -c "cat << 'EOF' > '${TEST_CRON_FILE}'
# Test cron entries for Lynis auditing validation
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin

# Case 1: Insecure target executable (SCHD-7705)
0 2 * * * root ${TEST_SCRIPT_TARGET}

# Case 2: Wildcard argument injection flaw (SCHD-7706)
30 3 * * * root tar -czf /tmp/backup.tar.gz /var/log/*
EOF"
    sudo chmod 644 "${TEST_CRON_FILE}"
    echo -e "    - Created test crontab at: ${TEST_CRON_FILE}"
    echo -e "${GREEN}[+] Fixtures deployed successfully.${NC}\n"
}

cleanup_test_cases() {
    echo -e "\n${YELLOW}[+] Cleaning up simulated test fixtures...${NC}"
    sudo rm -f "${TEST_CRON_FILE}"
    sudo rm -rf "${TEST_SCRIPT_DIR}"
    echo -e "${GREEN}[+] Cleanup complete.${NC}"
}

trap cleanup_test_cases EXIT

setup_test_cases

echo -e "${BLUE}[*] Running Lynis Audit on Scheduled Tasks...${NC}"
echo -e "${BLUE}[*] Executing: lynis audit system --tests SCHD-7704,SCHD-7705,SCHD-7706 --quick${NC}\n"

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin lynis audit system --tests SCHD-7704,SCHD-7705,SCHD-7706 --quick || true

echo -e "\n${GREEN}[*] Test audit execution completed.${NC}"
