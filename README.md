# VulScan Pro

**Tagline:** *Scan Smart.Stay Secure.*

VulScan Pro is a beginner-friendly yet insightful web application security scanner designed to detect high-impact vulnerabilities in modern web apps. This isn't just a script—it’s an educational step toward understanding how attacks behave and how applications unintentionally expose weaknesses.

The project focuses on three commonly exploited vulnerability categories:

- ✸ **Cross-Site Scripting (XSS)**
- 💉 **SQL Injection (SQLi)**
- 🎣 **CSRF (Cross-Site Request Forgery) risk patterns**

Built with Python and equipped with a minimal web interface, VulScan Pro helps you manage scans, review findings with evidence, and export results for reporting and learning.

---

## ⚡ Key Capabilities

| Capability | Purpose |
|---|---|
| Intelligent crawling | Finds URLs and form input fields automatically |
| Payload injection | Tests input reflection & database error behaviour |
| Lightweight UI dashboard | Start scans, track status, view results |
| Evidence-backed logs | Each finding includes severity + proof |
| Export reports | Save findings as CSV for review and PDF for documentation |
| Ethical guardrails | Designed for owned or permitted test targets only |

---

## 🧠 Inspiration Behind the Build

Most students start cybersecurity by learning definitions. But real security isn’t theoretical—it’s behavioural. VulScan Pro was built to answer questions like:

- “How does a reflected XSS payload actually look in a response?”
- “What kind of errors scream SQL injection vulnerability?”
- “Do forms submit data without tokens that could prevent CSRF?”

The aim isn’t perfection—it’s awareness, experimentation, and responsibility.

---

## 🧰 Tech Stack

- **Programming Language:** `Python 3.x`
- **Libraries:**
  - `requests` → HTTP interactions
  - `BeautifulSoup` → HTML parsing
  - `urllib.parse` → URL analysis
  - `Flask` → scan dashboard UI
  - `SQLite` → storing scan records & flaw evidence
  - `pandas` → building exportable reports
- **Security Baseline:** `OWASP Top 10 checklist approach`

---

## 🧭 Project Flow

```text
Input URL → Crawl pages & forms → Inject attack payloads 
      → Detect unsafe behaviour → Store results 
            → Display evidence via Flask UI → Export report
