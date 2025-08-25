# Detections (SPL) — Brute Force, Lateral Movement, Privilege Escalation, Risk Scoring

## Notes
- Assumes your data is in `index=main` (or `security`). Adjust if needed.
- Linux: `sourcetype=linux_secure`
- Windows: `sourcetype=WinEventLog:Security`
- Lookup: `asset_users.csv` with `user,dept,role,mfa_enabled,sensitivity`

---

## 1) Brute Force → Success (within 5 minutes)
Detect >=5 failed logins from the same src/dest/user in 5 minutes followed by a success.

```spl
(index=main OR index=security)
(sourcetype=linux_secure OR sourcetype="WinEventLog:Security")
("Failed password" OR EventCode=4625 OR signature="An account failed to log on")
| eval platform=if(sourcetype="linux_secure","linux","windows")
| eval user=if(isnull(user), mvindex(split(_raw," for "),1), user)
| eval src=coalesce(src, mvindex(split(_raw," from "),1))
| eval dest=coalesce(dest, host)
| bin _time span=1m
| stats count AS failed by src dest user span=5m _time
| where failed>=5
| join type=left src dest user [
    search (index=main OR index=security)
    (sourcetype=linux_secure OR sourcetype="WinEventLog:Security")
    ("Accepted password" OR EventCode=4624 OR signature="An account was successfully logged on")
    | eval user=if(isnull(user), mvindex(split(_raw," for "),1), user)
    | eval src=coalesce(src, mvindex(split(_raw," from "),1))
    | eval dest=coalesce(dest, host)
    | bin _time span=5m
    | stats earliest(_time) AS success_time by src dest user
]
| where isnotnull(success_time)
| eval desc="Possible brute force followed by success"
| table _time src dest user failed success_time desc
