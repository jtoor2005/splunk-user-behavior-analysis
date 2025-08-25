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

## 2) Lateral Movement (rapid host hopping or explicit credentials / remote tools)

Flags users who:

  - Successfully log on to ≥3 distinct hosts in 15 minutes, or

  - Trigger explicit credentials or a remote admin tool indicator.

(index=main OR index=security)
(sourcetype=linux_secure OR sourcetype="WinEventLog:Security")
(("Accepted password" OR EventCode=4624) OR signature="Logon by explicit credentials" OR signature="New process created (psexec.exe)")
| eval dest=coalesce(dest, host)
| eval event_class=case(signature="Logon by explicit credentials","explicit-creds",
                        like(_raw,"%Accepted password%"),"ssh-success",
                        signature="New process created (psexec.exe)","remote-tool",
                        true(),"other")
| bin _time span=5m
| stats dc(dest) AS distinct_hosts values(event_class) AS indicators min(_time) AS first_seen max(_time) AS last_seen by user src span=15m
| where distinct_hosts>=3 OR mvfind(indicators,"explicit-creds")>=0 OR mvfind(indicators,"remote-tool")>=0
| eval reason=if(distinct_hosts>=3,"rapid host hopping", mvjoin(indicators,","))
| table first_seen last_seen user src distinct_hosts reason

## 3) Privilege Escalation (Linux sudo/su; Windows 4672/4688 elevated)
Detects sudo/su activity on Linux and privileged/elevated process events on Windows.

(index=main OR index=security)
( sourcetype=linux_secure AND ("sudo:" OR "su: (to" OR "COMMAND=/bin/vi /etc/shadow")
  OR (sourcetype="WinEventLog:Security" AND (EventCode=4672 OR (EventCode=4688 AND like(signature,"%Elevated%"))) ) )
| eval action=case(sourcetype="linux_secure" AND like(_raw,"%sudo%"),"sudo",
                   sourcetype="linux_secure" AND like(_raw,"%su: (to%"),"su",
                   EventCode=4672,"SeDebug/privs assigned",
                   EventCode=4688,"Elevated process",
                   true(),"other")
| eval dest=coalesce(dest, host)
| table _time user src dest action signature

## 4) Risk Scoring (user-level, explainable)
Signals:

   - Brute force = 5 pts
   - Lateral movement = 7 pts
   - Privilege escalation = 9 pts
     Adjustments (from asset_users.csv):
   - MFA enabled → −2 pts
   - Sensitivity: >=3 → +2, =2 → +1

| union [
  search (index=main OR index=security) (sourcetype=linux_secure OR sourcetype="WinEventLog:Security")
  ("Failed password" OR EventCode=4625)
  | eval src=coalesce(src, mvindex(split(_raw," from "),1))
  | stats count AS failed by user src dest span=15m
  | where failed>=5
  | eval signal="bruteforce", points=5
], [
  search (index=main OR index=security) (sourcetype=linux_secure OR sourcetype="WinEventLog:Security")
  (("Accepted password" OR EventCode=4624) OR signature="Logon by explicit credentials" OR signature="New process created (psexec.exe)")
  | eval dest=coalesce(dest, host)
  | bin _time span=15m
  | stats dc(dest) AS distinct_hosts values(signature) AS sigs by user src
  | where distinct_hosts>=3 OR mvfind(sigs,"Logon by explicit credentials")>=0 OR mvfind(sigs,"New process created (psexec.exe)")>=0
  | eval signal="lateral", points=7
], [
  search (index=main OR index=security)
  ( sourcetype=linux_secure AND ("sudo:" OR "su: (to") ) OR (sourcetype="WinEventLog:Security" AND (EventCode=4672 OR EventCode=4688))
  | eval signal="priv-esc", points=9
]
| stats sum(points) AS base_points values(signal) AS signals by user
| lookup asset_users.csv user OUTPUT dept role mfa_enabled sensitivity
| eval mfa_penalty=if(mfa_enabled="true",-2,0)
| eval sens_bonus=case(sensitivity>=3,2, sensitivity=2,1, true(),0)
| eval risk_score=base_points + mfa_penalty + sens_bonus
| eval risk_bucket=case(risk_score>=12,"High", risk_score>=6,"Medium", true(),"Low")
| sort -risk_score
| table user dept role signals base_points mfa_enabled sensitivity risk_score risk_bucket

## 5) Dashboard Panels (queries to wire into panels)

A) Failed login trend (24h)

(index=main OR index=security) (sourcetype=linux_secure OR sourcetype="WinEventLog:Security")
("Failed password" OR EventCode=4625)
| timechart span=15m count AS failed_logins

B) Top offending IPs

(index=main OR index=security) (sourcetype=linux_secure OR sourcetype="WinEventLog:Security")
("Failed password" OR EventCode=4625)
| eval src=coalesce(src, mvindex(split(_raw," from "),1))
| stats count AS attempts by src
| sort -attempts | head 10

C) Brute force → success
Use the full query from section 1.

D) Lateral movement
Use the full query from section 2.

E) Privilege escalation
Use the full query from section 3.

F) Risk score by user (bar)

<risk scoring search from section 4>
| where risk_bucket="High" OR risk_bucket="Medium"
| chart max(risk_score) BY user

G) High‑risk users (single value)

<risk scoring search from section 4>
| where risk_bucket="High"
| stats count AS high_risk_users
