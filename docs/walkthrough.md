# Walkthrough

1. In Splunk Cloud: Add Data → Upload linux_auth.log, windows_security.csv, asset_users.csv.
2. Set sourcetypes: linux_secure, WinEventLog:Security, and add asset_users as a lookup.
3. Run queries from spl/detections.md and build dashboard panels.
4. Export dashboard JSON into dashboards/auth_security_dashboard.json and add screenshots/.
