# Lynis Custom Security Auditing Modules: Snap Classic Confinement & Stale SSH Keys

Custom security auditing modules for **Lynis** on Linux/Ubuntu, implementing automated auditing for snap packages running in unconfined classic mode and detection of stale/abandoned SSH public keys across user accounts.

Blog post: [low-level-log.blogspot.com](https://low-level-log.blogspot.com/2026/10/improving-lynis-cron-job-audits.html)

---

## Repository Structure

- **`tests_custom`**: Master custom test loader. Placed into `/usr/share/lynis/include/tests_custom` to automatically load and execute custom checks during Lynis scans.
- **`tests_custom_snaps_confinement`**: Test module for **`CUST-0050`** (Snap Classic Confinement Auditor).
- **`tests_custom_stale_ssh_keys`**: Test module for **`CUST-0100`** (Stale and Abandoned SSH Key Auditor).
- **`tests_custom.template`**: Baseline custom test template provided by upstream Lynis.
- **`other/`**: Contains auxiliary scheduled task auditing modules (`SCHD-7705`, `SCHD-7706`, verification test harness, and `tests_scheduling` include files).

<br>

---

## Custom Test Modules (Click to expand)

<details>
<summary><font size="+1.5"><strong>1. Snap Package Classic Confinement Auditor (`CUST-0050`)</strong></font></summary>

### Rationale & Threat Model
On Ubuntu and modern Linux distributions, Snaps are containerized packages designed to execute in **strict confinement** using AppArmor profiles, seccomp filters, and cgroups to isolate applications from the host filesystem and kernel. However, packages installed with the `--classic` flag operate with classic confinement, completely disabling the sandbox security boundary and granting the application full, unconfined access to the host system just like a traditional package.

If a vulnerable or untrusted package is installed under classic confinement, attackers can compromise host filesystem integrity and escalate privileges.

### Detection Mechanism
1. Verifies the availability of the `snap` binary.
2. Registers test `CUST-0050` (weight: `High`, category: `security`).
3. Queries installed snap packages using `snap list 2>/dev/null | awk '/classic/ {print $1}'`.
4. If classic packages are detected, flags a `[ WARNING ]` in the console, emits a `ReportWarning` identifying the offending package, and issues a remediation `ReportSuggestion` (`sudo snap remove <pkg>`).

</details>

<br>

<details>
<summary><font size="+1.5"><strong>2. Stale and Abandoned SSH Public Key Auditor (`CUST-0100`)</strong></font></summary>

### Rationale & Threat Model
Public key authentication via `~/.ssh/authorized_keys` is the standard for UNIX system access. Over time, systems accumulate high-risk authorization persistence vulnerabilities:
1. **Orphaned User Directories**: When users are removed from `/etc/passwd`, administrators frequently neglect to purge `/home/<username>`. If an attacker gains file write privileges or UID recycling occurs, these pre-authorized keys remain active attack surfaces.
2. **Disabled Accounts with Configured Keys**: System accounts or terminated users often have their login shells set to disabled shells (e.g. `/usr/sbin/nologin`, `/bin/false`). However, if SSH daemon options, port forwarding, or custom subsystems allow authentication, having authorized keys configured for inactive accounts represents an unnecessary security vulnerability and compliance violation.

### Detection Mechanism
1. Registers test `CUST-0100` (weight: `Medium`, category: `security`).
2. Iterates over `/home/*` directories and checks if the corresponding user account still exists in `/etc/passwd`. If missing and `~/.ssh/authorized_keys` is present, raises an abandoned key warning.
3. Parses `/etc/passwd` to identify disabled accounts (`nologin`, `false`, `sync`, `halt`, `shutdown`) that retain `.ssh/authorized_keys` files.
4. Generates granular security warnings and remediation suggestions recommending cleanup.

</details>

<br>

---

## Installation & Deployment in Linux / Ubuntu

Follow these steps to deploy the custom modules into your Lynis installation:

### 1. Copy Test Modules into Lynis Include Directory
```bash
# Copy the custom test modules to Lynis's include directory
sudo cp tests_custom /usr/share/lynis/include/tests_custom
sudo cp tests_custom_snaps_confinement /usr/share/lynis/include/tests_custom_snaps_confinement
sudo cp tests_custom_stale_ssh_keys /usr/share/lynis/include/tests_custom_stale_ssh_keys

# Set standard permissions
sudo chmod 644 /usr/share/lynis/include/tests_custom*
```

### 2. Verify Inclusion
Ensure Lynis detects the custom include file:
```bash
lynis show includedir
```

---

## Running Audits

### Targeted Custom Test Execution
Run a quick audit of the custom security checks:
```bash
sudo lynis audit system --tests CUST-0050,CUST-0100 --quick
```

### Full System Audit
To run a full audit including all built-in benchmarks and our custom tests:
```bash
sudo lynis audit system --quick
```

Review results in the Lynis log files:
- **Audit Log**: `/var/log/lynis.log`
- **Report Data**: `/var/log/lynis-report.dat`
