#
#################################################################################
#
    # Test        : SCHD-7706
    # Description : Detect wildcard command injection patterns in cron job definitions
    Register --test-no SCHD-7706 --weight M --network NO --category security --description "Detecting dangerous wildcard injection anti-patterns in cron commands"
    if [ ${SKIPTEST} -eq 0 ]; then
        WILDCARD_VULNS_FOUND=0
        DANGEROUS_COMMANDS="tar rsync chown chmod rm cp zip"
        CRON_FILES="/etc/crontab /etc/anacrontab /etc/cron.d/* /var/spool/cron/crontabs/*"
        TEMPDIR="${TEMPDIR:-/tmp}"
        REPORT_LOG="${TEMPDIR}/lynis_wildcard_vulns.txt"
        : > "${REPORT_LOG}"

        for FILE in ${CRON_FILES}; do
            if [ -f "${FILE}" ]; then
                # Search for any line containing a dangerous command alongside an unquoted wildcard
                for CMD in ${DANGEROUS_COMMANDS}; do
                    MATCHING_LINES=$(grep -E "\b${CMD}\b" "${FILE}" 2>/dev/null | grep -E '\s+(\*|/\S+\*)' | grep -v '^\s*#')
                    if [ -n "${MATCHING_LINES}" ]; then
                        printf '%s\n' "${MATCHING_LINES}" | while IFS= read -r BAD_LINE; do
                            if [ -n "${BAD_LINE}" ]; then
                                LogText "VULN: Wildcard expansion with binary '${CMD}' in ${FILE}: ${BAD_LINE}"
                                echo "${FILE}|${CMD}|${BAD_LINE}" >> "${REPORT_LOG}"
                            fi
                        done
                    fi
                done
            fi
        done

        if [ -s "${REPORT_LOG}" ]; then
            Display --indent 2 --text "- Checking scheduled tasks for wildcard injection..." --result "${STATUS_WARNING}" --color RED
            while IFS='|' read -r C_FILE C_CMD C_LINE; do
                ReportWarning ${TEST_NO} "Wildcard expansion detected in a scheduled command" "${C_CMD} in ${C_FILE}" "https://cisofy.com/lynis/controls/SCHD-7706/"
                ReportSuggestion ${TEST_NO} "Replace shell wildcards in privileged scheduled tasks" "${C_FILE}" "https://cisofy.com/lynis/controls/SCHD-7706/"
            done < "${REPORT_LOG}"
            AddHP 0 3
        else
            Display --indent 2 --text "- Checking scheduled tasks for wildcard injection..." --result "${STATUS_OK}" --color GREEN
            AddHP 3 3
        fi

        rm -f "${REPORT_LOG}" 2>/dev/null
    fi
