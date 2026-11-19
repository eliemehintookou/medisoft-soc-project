# EBIOS RM Risk Analysis — MediSoft (Healthcare SaaS)

> A full cyber risk analysis built with **EBIOS Risk Manager**, the risk management method published by **ANSSI** (French national cybersecurity agency).

This project applies the complete EBIOS RM methodology to a realistic fictional case study: **MediSoft**, a ~40-person company that publishes a SaaS appointment-booking software for medical practices and therefore hosts **patient health data**.

It is a **GRC-focused** project (Governance, Risk & Compliance), deliberately built to complement a hands-on, offensive-security portfolio with a structured, methodology-driven piece aligned with **ISO/IEC 27001** and **GDPR**.

---

## 📄 Deliverable

The complete risk analysis report is available here: **[`Analyse_EBIOS_RM_MediSoft.pdf`](./Analyse_EBIOS_RM_MediSoft.pdf)**

---

## 🎯 Why this project

A security portfolio that is only technical/offensive tells half the story. Real-world security work also means **assessing risk, prioritizing, and deciding what to treat** — the governance side. This project demonstrates the ability to run a recognized risk-analysis method end to end, and to **bridge technical findings with compliance frameworks** (a rare mix for a junior profile).

The case study intentionally reuses a cloud architecture (AWS VPC/EC2/RDS/S3) similar to my [CSPM audit project](https://github.com/eliemehintookou/aws-cloud-security-cspm), so the technical weaknesses detected there become the vulnerabilities analyzed here.

---

## 🧩 The 5 EBIOS RM workshops

| Workshop | Focus | Key output |
|---|---|---|
| **1 — Scope & security baseline** | Business values, supporting assets, gap analysis | 11-point baseline gap table |
| **2 — Risk origins** | Who would attack, and why (risk source / target objective pairs) | Prioritized shortlist of 4 threat couples |
| **3 — Strategic scenarios** | High-level attack paths linking risk sources to business values | Scenario map + severity rating (G1–G4) |
| **4 — Operational scenarios** | Technical kill chain, mapped to **MITRE ATT&CK** | Step-by-step ransomware scenario |
| **5 — Risk treatment** | Treatment strategy, security measures, residual risk | Action plan (PACS) |

---

## 🔑 Key results

**Business values identified**
- Availability of the SaaS booking service
- Confidentiality of patient health data
- Software development & update process
- Billing & subscription management

**Top risks (after analysis)**

| Risk | Initial level | Strategy | Residual |
|---|---|---|---|
| Ransomware (availability) | 🔴 Very high | Reduce | 🟡 Medium |
| Health-data theft (confidentiality) | 🔴 Very high | Reduce + Transfer | 🟡 Medium |
| Source-code theft via supplier | 🟠 High | Reduce | 🟢 Low |
| Malicious insider | 🟠 High | Reduce | 🟡 Medium |
| Website defacement (hacktivist) | 🟢 Low | **Accept** | 🟢 Low |

**Operational scenario — ransomware kill chain (MITRE ATT&CK)**

`Reconnaissance (T1589/T1595)` → `Initial Access (T1566)` → `Execution & Persistence (T1204/T1547)` → `Discovery & Privilege Escalation (T1087/T1003/T1068)` → `Lateral Movement (T1021/T1570)` → `Impact (T1486/T1567)`

A central finding: lateral movement succeeds **because** of a baseline gap (flat, unsegmented network) identified in Workshop 1 — the analysis holds together from gap → vulnerability → treatment measure.

---

## 🛠️ Frameworks & concepts used

- **EBIOS Risk Manager** (ANSSI) — full 5-workshop methodology
- **MITRE ATT&CK** — operational scenario technique mapping
- **ISO/IEC 27001** (Annex A controls) & **GDPR** (art. 32) — security baseline references
- Risk rating by **severity × likelihood**, residual risk, treatment strategies (reduce / transfer / accept / refuse)

---

## 👤 Author

**Elie MEHINTO** — M2 Cybersecurity & Networks student, **currently looking for an apprenticeship (alternance) in cybersecurity** (1 week school / 3 weeks company, starting 2026).

- 📧 emploielie@gmail.com
- 💼 LinkedIn: [bit.ly/4nk6Yz2](http://bit.ly/4nk6Yz2)
- 💻 GitHub: [bit.ly/4u5TGJ4](https://bit.ly/4u5TGJ4)

---

*Personal upskilling project. Fictional case study — any resemblance to a real company is coincidental. Methodology © ANSSI (EBIOS Risk Manager).*
