# ROCS, the Read-Only Compromise Sweep

ROCS checks a Mac, Windows PC, Linux box, or Android phone (over USB) for **known**
spyware and stalkerware indicators published by Amnesty Tech's Security Lab, the
Mobile Verification Toolkit (MVT) project, and Echap. It writes one report that says
what it found, how serious each finding is, and, just as important, **what it could
not check**. It never tells you a device is "clean".

## Why I built it (case study)

I've spent my career on the audit side of security: IT general controls, SOX, SOC 1
and SOC 2 evidence, PCI. Audit teaches you to ask what a control actually covers and
how you know it worked. Consumer "spyware scanners" usually fail that test. They ask
you to run unreviewed code with admin rights, phone home, sometimes ask you to send
"samples" somewhere, and then show a big green checkmark that means very little.

So I set myself a brief: build the scanner I'd be comfortable handing to a
non-technical person, or to an AI assistant acting for them. The design rules were:

1. **Do no harm.** It's read-only by construction, needs no admin, never deletes,
   kills, or quarantines anything, and has no upload path at all.
2. **Separate the networked step from the scan.** Downloading indicators is its own
   explicit command. The scan itself can't open a socket.
3. **Trust only vetted, attributable data.** Every indicator file comes from a short
   allowlist of public research sources, with its URL and SHA-256 recorded and
   re-verified before each scan.
4. **Report coverage, not comfort.** Any area the scan couldn't reach is a
   first-class part of the result. A scan with nothing found says "no known
   indicators in the areas checked", never "clean".
5. **Make it machine-readable without making it dangerous.** The `--json` output
   includes a `must_tell_human` list, and [`CONTRACT.md`](CONTRACT.md) spells out
   what an AI agent must relay and must never do on its own.

Some decisions I'd point a reviewer at:

- **The read-only guarantee is enforced, not promised.** Every external command
  goes through an exact-prefix allowlist (`rocs/common.py`). `adb shell` arguments
  that contain shell metacharacters are rejected. Browser history databases open
  with SQLite `mode=ro&immutable=1`, so not even a lock file or journal gets
  written. The tests snapshot the fixture tree before and after each scan and fail
  on any change.
- **The network is off during scans.** `rocs scan` runs inside a guard that makes
  socket connects and DNS lookups raise. A test also checks that no scan module
  imports an HTTP client. All networked code lives in `rocs/update.py`.
- **Severity is graded honestly.** Many published process-name indicators are iOS
  daemon names built to look like Apple's (`diagnosticd`, for example). A name match
  on a binary in an OS folder is rated LOW as a probable collision. A name match
  outside OS folders is HIGH. Domain, hash, and package-id matches are HIGH.
  Heuristics (autostart from `/tmp` or `%TEMP%`, non-system device-admin or
  accessibility apps on Android) are MEDIUM leads, not verdicts.
- **Stalkerware safety comes first.** For Android stalkerware, the report warns that
  removing it can alert the person who installed it, and points to advocates
  before any technical step.
- **There are no dependencies.** It runs on the Python 3.9+ standard library only,
  so there's no supply chain to audit beyond the interpreter.

## Getting started

```bash
git clone https://github.com/yellowlotuscg/rocs.git && cd rocs
python3 -m rocs update                 # networked: refresh indicators into ~/.rocs/iocs
python3 -m rocs verify-iocs            # offline checksum check
python3 -m rocs scan --out ~/Desktop/rocs.txt               # plain-language report
python3 -m rocs scan --json --out ~/Desktop/rocs.json       # for AI agents (see CONTRACT.md)
python3 -m rocs scan --platform android --out phone.txt     # Android phone over adb
```

- `--ioc-dir DIR` (or the `ROCS_IOC_DIR` environment variable) chooses where indicators live.
- Existing reports are never overwritten unless you pass `--force`.
- Exit codes: `0` no known indicators (**not proof the device is clean**), `10` review needed, `20` indicators found, `3` error or incomplete.
- Requirements: Python 3.9 or newer (tested on 3.9 to 3.13), standard library only. Android needs `adb` (Android platform-tools).

## Safety guarantees (and how they're enforced)

| Guarantee | Enforcement |
|---|---|
| **Read-only** | Only allowlisted read commands can run (`common.READ_ONLY_COMMANDS`). Anything else raises `CommandRefused`. Browser history databases open with SQLite `mode=ro&immutable=1`, so nothing gets locked and no journal is written. Tests take a snapshot of the fixture tree before and after each scan and require them to match byte for byte. |
| **No admin needed** | It never calls sudo, UAC or root. Anything that needs elevation is listed under "What I could not check". |
| **No network during a scan** | The scan runs inside `no_network()`, which makes socket connect and DNS lookups raise. Tests also confirm that no scan module imports an HTTP client. The only networked code is `rocs/update.py`. |
| **Writes only the report** | It writes to the `--out` path you choose. It refuses to overwrite an existing file without `--force` (files open in `x` mode). |
| **Never sends samples** | No upload code exists anywhere. The JSON always reports `mode.samples_uploaded: false`. |
| **Vetted indicators only** | `update` downloads only from `raw.githubusercontent.com`, only from owners on the allowlist (`mvt-project`, `AmnestyTech`, `AssoEchap`), and records the URL, SHA-256, size and fetch time of each file. Each scan re-checks those checksums and skips any file that has changed. |

## Indicator sources

Edit these only on purpose, in `sources.json`:

- **MVT indicators index** (`mvt-project/mvt-indicators/indicators.yaml`). It pulls in Amnesty Tech, Citizen Lab, Meta, Google and Lookout work: Pegasus, Predator, RCS Lab, QuaDream, Operation Triangulation, Candiru, NoviSpy, BTMOB and more.
- **Echap stalkerware-indicators** (`AssoEchap/stalkerware-indicators/generated/stalkerware.stix2`): about 180 stalkerware families, with package ids, signing certificates, hashes and C2 domains.
- **Amnesty Tech investigations** (`AmnestyTech/investigations`): the Pegasus and Cytrox STIX2 files.

The Oct 28, 2026 update pulled 20 bundles with **11,338 indicators**: 6,548 domains, 3,461 SHA-256 hashes, 680 Android packages, 486 signing certs, 83 process names, 15 file names and 65 email addresses.

## What each platform checks

| Platform | Checked | Not checked (always listed in the report) |
|---|---|---|
| **macOS** | running processes (`ps`); `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` (program, args and binary hash); legacy login items; configuration profiles (`profiles list`); Safari, Chrome, Brave, Edge, Arc and Firefox history domains | login and background items on macOS 13+ (root-only database: run `sudo sfltool dumpbtm` yourself); `/System` launchd (protected by SIP); kernel and system extensions; TCC grants; unified logs. Safari history needs Full Disk Access for the terminal, otherwise it's listed as not checked. |
| **Windows** | processes (`tasklist`); services and their binary paths (`Get-CimInstance Win32_Service`); scheduled tasks (`schtasks /query`); HKCU/HKLM Run and RunOnce keys (`winreg`, read-only); Chrome, Edge, Brave and Firefox history | process paths and hashes for other users; SYSTEM-hidden tasks; drivers; WMI subscriptions; event logs. History of an open browser may be locked; close the browser and retry. |
| **Linux** | `/proc` processes (names, exe paths, hashes, deleted-on-disk binaries); systemd system and user units (`ExecStart*`); `/etc/crontab`, `/etc/cron.d`, `cron.*` scripts and the user crontab; XDG autostart; `/etc/ld.so.preload`; Chrome, Chromium, Brave, Edge and Firefox history | other users' process paths; root-only crontabs; kernel modules and rootkits; live network connections |
| **Android** (adb, no root) | installed packages vs stalkerware and spyware package ids; non-system **device-admin** apps; non-system **accessibility** services; notification listeners; sideloaded apps; optional SHA-256 of user APKs | APK signing certificates; anything hidden by a root-level implant; SMS and call logs; the system partition |
| **iOS** | not scanned by rocs (see below) | |

Severity levels:

- **HIGH**: matched a published indicator (domain, hash, package, or a process name outside OS folders).
- **MEDIUM**: a suspicious pattern for a human to review, such as autostart from `/tmp`, `%TEMP%`, `Users\Public` or hidden folders; `ld.so.preload`; a deleted running binary; a non-system device admin or accessibility app.
- **LOW**: worth a look, such as config profiles, notification listeners, or an indicator name colliding with an OS binary in a system folder.
- **INFO**: context, such as the sideloaded app list.

## iPhone / iPad: use MVT, don't reimplement it

Phone spyware like Pegasus leaves its traces in places only a full backup analysis
can reach. Amnesty's **Mobile Verification Toolkit** is the reference tool.

```bash
python3 -m venv ~/mvt && source ~/mvt/bin/activate
pip install mvt==2026.10.26
mvt-ios download-iocs                       # fetch current indicators
# 1. Finder (or iTunes) > the iPhone > "Encrypt local backup" > Back Up Now.
# 2. Decrypt a COPY of the backup; MVT will prompt for the password:
mvt-ios decrypt-backup -d ~/mvt-decrypted ~/Library/Application\ Support/MobileSync/Backup/<UDID>
# 3. Check it:
mvt-ios check-backup --output ~/mvt-results ~/mvt-decrypted
```

Matches are written as `*_detected.json` in the output folder. Treat any match as
serious and contact the Amnesty Security Lab or Access Now (below).

For deeper Android work, MVT has removed direct adb analysis. Use **AndroidQF** to
acquire the device, then run `mvt-android check-androidqf <folder>`. Leave MVT's
optional `--virustotal` off unless you choose to send hashes to VirusTotal.

## Threat model

**In scope:** commodity stalkerware someone installed with physical access (the
Echap families), and known mercenary-spyware infrastructure or artefacts that show
up on desktops (browser visits to known exploit or C2 domains, persistence that
matches published names or hashes). It also flags suspicious persistence for a
human to triage.

**Out of scope, and you should assume it may be missed:**

- New, custom or unpublished spyware. Only known indicators can match.
- Zero-click phone exploits (Pegasus, Predator, Triangulation) that leave nothing on
  a computer. Use MVT on the phone itself.
- Anything running with more privilege than the scan (root, kernel, firmware). It
  can hide from any on-host, non-admin tool.
- Account-level compromise: email forwarding rules, cloud backups, shared Apple
  IDs or Google accounts, location sharing. Review these in the account settings.
- Network-level interception.

**False positives happen.** Some indicator names are iOS daemon names that resemble
real Apple ones (for example `diagnosticd`). rocs rates a name match as low when
the binary sits in an OS folder. Medium and low findings are leads, not verdicts.

## When to use MVT or a professional instead

- You're a journalist, activist, lawyer, politician or dissident, or you've had an
  Apple or Google "state-sponsored attack" notice. Go straight to MVT and the
  **Amnesty Security Lab** (https://securitylab.amnesty.org/get-help/) or the
  **Access Now Helpline** (https://www.accessnow.org/help/).
- You suspect a partner, ex or family member is monitoring you. Talk to the
  **Coalition Against Stalkerware** (https://stopstalkerware.org/) or the
  **US National DV Hotline (1-800-799-7233)** first, from a device they can't
  reach. Removing stalkerware can alert them and make things more dangerous.
- Any HIGH finding on a work or client machine: preserve evidence and bring in
  incident response. Don't wipe first.
- You need legal evidence. Use a forensic professional who keeps chain of custody.

## For AI agents

Read `CONTRACT.md`. In short: relay `must_tell_human`, never say "clean", never
delete or upload anything, and never run `update` or a scan without the human's OK.

## Development

```bash
python3 -m unittest discover -s tests -t . -v
```

The tests use only fake indicators (`tests/fixtures/fake_iocs.stix2`) and fixture
filesystem trees in temp folders. Commands are faked, so the tests never touch the
host or the network.

## License

MIT. See [LICENSE](LICENSE). Indicator data isn't redistributed here. `rocs update`
downloads it from the original publishers, under their own terms.

## Layout

```
rocs/cli.py            commands, no_network() guard, exit codes
rocs/update.py         the only networked code: allowlisted download + manifest
rocs/iocs.py           STIX2 parsing, checksum-verified loading, domain matching
rocs/common.py         read-only command allowlist, findings, history reader, heuristics
rocs/report.py         verdict logic, plain-text and JSON reports
rocs/collectors/       linux.py, macos.py, windows.py, android.py, procs.py
sources.json               vetted indicator sources + host/owner allowlists
tests/                     unittest suite with fake IOCs and fixtures
```
