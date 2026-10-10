# Lynis Scheduled Task Auditing Enhancements

Custom security auditing modules for **Lynis** on Linux/Ubuntu, implementing deep transitive target permission analysis and wildcard argument injection detection in scheduled jobs.

Blog post: [low-level-log.blogspot.com](https://low-level-log.blogspot.com/2026/10/improving-lynis-cron-job-audits.html)

## Files in this Directory

- **`tests_scheduling`**: Complete enhanced Lynis include file. Drop-in replacement for `/usr/share/lynis/include/tests_scheduling`.
- **`SCHD-7705_cron_targets.sh`**: Standalone code module for Test `SCHD-7705` (Deep Target Permission Analysis).
- **`SCHD-7706_cron_wildcards.sh`**: Standalone code module for Test `SCHD-7706` (Wildcard Command Injection Detection).
- **`test_cron_vulnerabilities.sh`**: Automated verification test harness script. Sets up simulated vulnerable cron entries and executes a targeted Lynis audit to confirm detection and reporting.
- **`tests_scheduling.orig`**: Backup copy of the stock Lynis 3.0.9 `tests_scheduling` include file.

<br>

---

<details>
<summary><font size="+1.5"><strong>Enhanced Test Descriptions</strong></font></summary>

### 1. Baseline Test: `SCHD-7704`
- **Description:** Verifies that `/etc/crontab`, `/etc/anacrontab`, and spool directories (`/etc/cron.*`, `/var/spool/cron`) are owned exclusively by `root` and stripped of world-writable bits (`o+w`).
- **Limitation:** Only inspects the configuration pointer file; does not inspect what scripts the cron jobs actually execute.

### 2. Enhancement Option 1: `SCHD-7705` (Transitive Target Permission Auditing)
- **Problem:** If a crontab has strict `0600 root:root` permissions but invokes `/opt/scripts/backup.sh` that is world-writable (`0777`) or owned by a non-root user, any local user can modify the script to gain root privilege when cron executes.
- **Detection Logic:**
  1. Parses unmasked directives in `/etc/crontab`, `/etc/anacrontab`, and `/etc/cron.d/*`.
  2. Extracts referenced absolute file paths.
  3. Checks ownership and permissions (`stat -c "%a"` / `stat -c "%U"`).
  4. Flags target scripts that are group-writable, world-writable, or owned by non-root accounts.

### 3. Enhancement Option 2: `SCHD-7706` (Wildcard Command Injection Detection)
- **Problem:** Commands such as `tar -czf /backup/data.tar.gz /var/www/uploads/*` expand wildcards before command execution. An unprivileged user with write access can plant flag files (such as `--checkpoint=1` and `--checkpoint-action=exec=shell.sh`) to execute arbitrary commands as root (GTFOBins pattern).
- **Detection Logic:**
  1. Scans cron entries across system and user spools for high-risk binaries (`tar`, `rsync`, `chown`, `chmod`, `rm`, `cp`, `zip`).
  2. Detects occurrences of unquoted wildcards (`*`) alongside these utilities.
  3. Logs vulnerable lines and generates actionable Lynis security warnings and suggestions.

</details>

---

<br>

## Installation & Deployment in WSL Ubuntu

1. Back up the original Lynis include file:
   ```bash
   sudo cp /usr/share/lynis/include/tests_scheduling /usr/share/lynis/include/tests_scheduling.bak
   ```

2. Copy the enhanced file into Lynis:
   ```bash
   sudo cp tests_scheduling /usr/share/lynis/include/tests_scheduling
   sudo chmod 644 /usr/share/lynis/include/tests_scheduling
   ```

3. Verify that the new tests are registered:
   ```bash
   lynis show tests | grep 'SCHD-77'
   ```


## Running Audits

Run a targeted audit for scheduled tasks:
```bash
sudo lynis audit system --tests SCHD-7704,SCHD-7705,SCHD-7706 --quick
```
<details>
<summary>Or run the automated test harness: (click to expand)</summary>

```bash
chmod +x test_cron_vulnerabilities.sh
sudo ./test_cron_vulnerabilities.sh
```
</details>
