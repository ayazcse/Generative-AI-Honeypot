# 🍯 AI-Powered High-Interaction Honeypot

An advanced, high-fidelity deception environment built with **Python** and **Google Gemini 2.5 Pro**. This honeypot simulates a real Debian Linux server to lure attackers, using Generative AI to provide dynamic, context-aware command responses.



## 🚀 Features

* **Dynamic AI Responses:** Integrated with **Gemini 2.5 Pro** to simulate realistic terminal output for complex system commands.
* **Filter Bypass Logic:** Implements custom prompt engineering and **Multi-step Retry Logic** to ensure 100% response consistency for sensitive commands like `whoami` and `cat /etc/passwd`.
* **Stateful Simulation:** Local directory tracking (`cd`, `pwd`) ensures the AI maintains context of where the attacker is in the file system.
* **Forensic Logging:** All attacker sessions, IPs, and command histories are serialized into a local **SQLite** database for post-incident analysis.
* **Multi-threaded:** Capable of handling multiple concurrent attacker connections.

## 🛠️ Technical Stack

* **Language:** Python 3.x
* **AI Engine:** Google Generative AI (Gemini SDK)
* **Network:** Socket Programming (TCP/IP)
* **Database:** SQLite3
* **Concurrency:** Threading

## 🔧 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/ai-honeypot.git](https://github.com/your-username/ai-honeypot.git)
   cd ai-honeypot
