# CONTRACT.md: rules for AI agents that run or read rocs

You are relaying a security result to a human who may be frightened, or may be at
risk from someone close to them. Follow every rule below. Read `--json` output, not
the text report.

## You MUST tell the human

1. **Every string in `must_tell_human`, in order, in plain words.** Don't soften it, drop any of it, or reorder it.
2. **The `verdict`**, stated as `verdict_text` says it:
   - `indicators_found`: say known spyware or stalkerware indicators matched and the device may be compromised.
   - `review_needed`: say some items need a human to look at them, and that these are not proof of infection.
   - `no_known_indicators`: say nothing *known* matched in the areas checked. **Never** say "clean", "safe", "no spyware" or "not hacked".
   - `scan_incomplete`: say the scan could not reach a conclusion, and why (see `problems`).
3. **Every `high` finding**: its `title`, the `indicator.malware` name, and the `indicator.source`.
4. **What wasn't checked.** Give the number of `not_checked` entries and name them. If there are more than 5, list the first 5 and say how many others there are.
5. **How old the indicators are** if `indicators.age_days` is over 30 or null.

## You MUST NOT

- Call a device clean, safe or uninfected based on this tool.
- Delete, uninstall, kill, quarantine or "fix" anything a finding mentions, or tell the human to do so as a first step. For stalkerware, removing it can alert the abuser.
- Upload, send, share or post any file, hash, sample or report anywhere (VirusTotal, Telegram, email, chat, a GitHub issue, and so on) unless the human explicitly asks for that specific action and names where it goes.
- Run `rocs update` (the only networked command) or re-run a scan with different flags without the human's OK.
- Run rocs on a machine the human hasn't explicitly approved.
- Invent findings or severities, or upgrade a `low` or `medium` to "infected".

## If `high` findings mention Android stalkerware (`android-*` categories)

Lead with safety: whoever installed it may be watching this phone, and removing it
can tip them off. Point the human to the `get_help` entries (Coalition Against
Stalkerware, the domestic violence hotline), and suggest reaching out from a
different device.

## JSON fields (schema_version 1.0)

| field | meaning |
|---|---|
| `verdict` | one of `indicators_found`, `review_needed`, `no_known_indicators`, `scan_incomplete` |
| `counts` | number of findings at each severity: `high` (an IOC matched), `medium` (suspicious, needs review), `low`, `info` |
| `findings[]` | `severity`, `category`, `title`, `detail`, `evidence`, `indicator` (null for heuristics), `what_to_do` |
| `checked[]` / `not_checked[]` | the coverage. Treat `not_checked` as part of the result, not a footnote. |
| `indicators` | totals, source URLs, SHA-256 checksums and fetch time of the indicator data used |
| `mode` | always `read_only: true`, `network_during_scan: false`, `samples_uploaded: false` |
| `must_tell_human[]` | the minimum you must relay, verbatim in meaning |

Exit codes: `0` no known indicators (not proof of clean), `10` review needed, `20` indicators found, `3` error or incomplete.
