# 🛡️ Brute Force & Privilege Escalation Detection with Splunk

## 📌 Overview
This project simulates a **Security Information and Event Management (SIEM)** workflow using **Splunk** to detect and visualize common attacker behaviors:
- **Brute force login attempts**
- **Lateral movement across hosts**
- **Privilege escalation events**

The goal is to demonstrate how Splunk Processing Language (SPL) queries and dashboards can be used to monitor authentication logs, highlight suspicious activity, and assign **risk scores** to users.

---

## ✅ What Has Been Done
- **Repository Structure:** Organized into `data/`, `spl/`, `dashboards/`, `screenshots/`, and `docs/`.
- **Sample Data:** Added `linux_auth.log`, `windows_security.csv`, and `asset_users.csv` (lookup for departments, roles, and MFA).
- **Detection Logic:** Completed [`spl/detections.md`](./spl/detections.md) with queries for:
  - Brute Force → Success
  - Lateral Movement
  - Privilege Escalation
  - Risk Scoring by user
  - Dashboard panel queries
- **Supporting Files:** Added `macros.conf`, placeholder dashboard JSON, and walkthrough doc.
- **Version Control:** All progress tracked with meaningful commits on GitHub.

---

## 🚧 Work Still To Be Done
- **Data Ingestion:** Upload sample logs and lookup into Splunk Cloud trial.
- **Run Queries:** Verify detections work in Splunk Search & Reporting.
- **Build Dashboard:** Create panels for failed logins, brute force, lateral movement, privilege escalation, and risk scoring.
- **Export Dashboard:** Replace `dashboards/auth_security_dashboard.json` with actual export.
- **Screenshots:** Add visualizations of detections and dashboard panels to `/screenshots/`.
- **Documentation Polish:** Expand `docs/walkthrough.md` and update this README with screenshots and final results.

---

## ⚙️ Tools & Stack
- **Splunk Cloud (Free Trial)**
- **SPL (Splunk Processing Language)**
- **Simulated Logs:** Linux auth logs & Windows Security Event logs
- **Lookup Files:** User → Department → Role → MFA mapping

---

## 🔮 Next Steps
Stay tuned — once the data is ingested and the dashboard is built, this repo will include:
- Screenshots of detections
- Exported Splunk dashboard JSON
- A reproducible walkthrough for anyone to try

---
