# 🔐 Detect Brute-force Login Attempts (Linux)
index=* sourcetype=linux_secure "Failed password"
| stats count by src, user
| where count > 5

# 🚨 Detect Repeated Privilege Escalations
index=* sourcetype=linux_secure ("sudo" OR "su")
| stats count by user
| where count > 3

# 🛑 Detect Failed Windows Logins
index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, IpAddress
| where count > 5

# 🌐 Detect Web Resource Errors (Access Logs)
index=* sourcetype=apache_access status>=400
| stats count by status, uri_path
