#
#################################################################################
#
    # Test        : SCHD-7705
    # Description : Audit target script and executable permissions invoked by Cron
    Register --test-no SCHD-7705 --weight M --network NO --category security --description "Auditing permissions of executables and scripts invoked by cron jobs"
    if [ ${SKIPTEST} -eq 0 ]; then
        TEMPDIR="${TEMPDIR:-/tmp}"
        TEMP_PARSE_LIST="${TEMPDIR}/lynis_cron_targets.txt"
        : > "${TEMP_PARSE_LIST}"

        # Collect crontab lines from system-wide and user spools
        SEARCH_SOURCES="/etc/crontab /etc/anacrontab /etc/cron.d/* /var/spool/cron/crontabs/*"
        
        for SRC in ${SEARCH_SOURCES}; do
            if [ -f "${SRC}" ]; then
                # Strip comments and blank lines, then extract executable candidates
                grep -vE '^(\s*#|\s*$|[a-zA-Z_]+[a-zA-Z0-9_]*=)' "${SRC}" 2>/dev/null | while read -r LINE; do
                    # Extract absolute paths matching /bin, /sbin, /usr, /opt, /var, /home, /etc
                    echo "${LINE}" | grep -oE '(/[a-zA-Z0-9_\.\-]+)+' >> "${TEMP_PARSE_LIST}"
                done
            fi
        done

        VULN_TARGETS_FILE="${TEMPDIR}/lynis_vuln_cron_targets.txt"
        : > "${VULN_TARGETS_FILE}"

        if [ -s "${TEMP_PARSE_LIST}" ]; then
            sort -u "${TEMP_PARSE_LIST}" | while read -r TARGET; do
                if [ -f "${TARGET}" ]; then
                    PERM_OCTAL=$(stat -c "%a" "${TARGET}" 2>/dev/null || stat -f "%Op" "${TARGET}" 2>/dev/null | tail -c 4)
                    FILE_OWNER=$(stat -c "%U" "${TARGET}" 2>/dev/null || stat -f "%Su" "${TARGET}" 2>/dev/null)

                    if [ -n "${PERM_OCTAL}" ]; then
                        GROUP_DIGIT=$(( (PERM_OCTAL / 10) % 10 ))
                        OTHER_DIGIT=$(( PERM_OCTAL % 10 ))
                        
                        IS_GROUP_WRITE=0
                        IS_OTHER_WRITE=0
                        if [ ${GROUP_DIGIT} -eq 2 ] || [ ${GROUP_DIGIT} -eq 3 ] || [ ${GROUP_DIGIT} -eq 6 ] || [ ${GROUP_DIGIT} -eq 7 ]; then
                            IS_GROUP_WRITE=1
                        fi
                        if [ ${OTHER_DIGIT} -eq 2 ] || [ ${OTHER_DIGIT} -eq 3 ] || [ ${OTHER_DIGIT} -eq 6 ] || [ ${OTHER_DIGIT} -eq 7 ]; then
                            IS_OTHER_WRITE=1
                        fi

                        if [ "${FILE_OWNER}" != "root" ] || [ ${IS_GROUP_WRITE} -eq 1 ] || [ ${IS_OTHER_WRITE} -eq 1 ]; then
                            LogText "VULN: Target script ${TARGET} in cron has insecure permissions (Owner: ${FILE_OWNER}, Octal: ${PERM_OCTAL})"
                            echo "${TARGET}" >> "${VULN_TARGETS_FILE}"
                        fi
                    fi
                fi
            done
        fi

        if [ -s "${VULN_TARGETS_FILE}" ]; then
            Display --indent 2 --text "- Auditing permissions of cron job targets..." --result "${STATUS_WARNING}" --color RED
            while read -r INSECURE_FILE; do
                ReportWarning ${TEST_NO} "Cron executes a target with weak file permissions" "${INSECURE_FILE}" "https://cisofy.com/lynis/controls/SCHD-7705/"
            done < "${VULN_TARGETS_FILE}"
            AddHP 0 4
        else
            Display --indent 2 --text "- Auditing permissions of cron job targets..." --result "${STATUS_OK}" --color GREEN
            AddHP 4 4
        fi

        # Cleanup temporary parsing artifacts
        rm -f "${TEMP_PARSE_LIST}" "${VULN_TARGETS_FILE}" 2>/dev/null
    fi
