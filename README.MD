# 🛡️ AI-Driven Hacker Mindset Generator
## Mini Project Plan (with Cloud LLM)

---

## 1. Project Summary

| Item | Detail |
|------|--------|
| **Title** | AI-Driven Hacker Mindset Generator |
| **Goal** | Generate attack strategies for cybersecurity education |
| **Duration** | 4 Weeks |
| **Team Size** | 4 Members |
| **Cloud LLM** | Google Gemini API (Free Tier) |

---

## 2. Tech Stack

```
┌─────────────────────────────────────────┐
│           TECH STACK                     │
├──────────────┬──────────────────────────┤
│ Language     │ Python 3.10+             │
│ Framework    │ Flask                    │
│ Cloud LLM   │ Google Gemini 1.5 Flash  │
│ Database     │ SQLite                   │
│ Frontend     │ HTML / CSS / JS          │
│ CLI Engine   │ Python Click Library     │
│ API Format   │ REST (JSON)             │
│ Deployment   │ Render / Railway (Free)  │
│ Version Ctrl │ GitHub                   │
└──────────────┴──────────────────────────┘
```

---

## 3. System Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌─────────────────┐
│              │     │                  │     │                 │
│   USER       │────▶│   FLASK SERVER   │────▶│  GEMINI API     │
│  (CLI/Web)   │     │   (Backend)      │     │  (Cloud LLM)    │
│              │◀────│                  │◀────│                 │
└──────────────┘     └───────┬──────────┘     └─────────────────┘
                             │
                     ┌───────▼──────────┐
                     │                  │
                     │   SQLite DB      │
                     │  (Store Reports) │
                     │                  │
                     └──────────────────┘
```

---

## 4. CLI Usage (Implemented)

The backend is built as a Python CLI tool. You can run it using `python -m secux.cli` or the `secux` command (if PATH is configured).

### Core Commands

| Command | Description |
|---------|-------------|
| `secux logscan` | Run a security scan on system logs (last 24h) |
| `secux logscan --monitor` | Enable real-time continuous monitoring |
| `secux logscan --list-logs` | List all available log files on the system |
| `secux help` | Show all available options and commands |

### Advanced Usage

```powershell
# Analyze specific timeframe (in hours)
python -m secux.cli logscan --timeframe 48

# Filter by minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
python -m secux.cli logscan --severity HIGH

# Export results to a JSON file
python -m secux.cli logscan --output report.json

# Custom monitoring interval (in seconds)
python -m secux.cli logscan --monitor --interval 30
```

---

## 5. Running the Backend

### Prerequisites
- Python 3.10+
- Installed dependencies (`pip install -r Backend/requirements.txt`)

### Installation (Editable Mode)
```powershell
cd Backend
pip install -e .
```

### Execution Note
If the `secux` command is not recognized (due to PATH issues), always use the `python -m` syntax:
```powershell
python -m secux.cli <command>
```


---

## 6. Week-by-Week Plan

### **📅 Week 1: Setup + Cloud LLM Integration**

| Task | Owner | Status |
|------|-------|--------|
| Setup Python + Flask project | Member 1 | ⬜ |
| Get Gemini API key (free) | Member 2 | ⬜ |
| Test Gemini API calls | Member 2 | ⬜ |
| Build CLI parser using Click | Member 3 | ⬜ |
| Setup SQLite database | Member 4 | ⬜ |
| Implement `/help` command | Member 3 | ⬜ |
| Create GitHub repo | Member 1 | ⬜ |

**Key Files:**
```
project/
├── app.py              # Flask server
├── cli.py              # CLI command handler
├── llm_engine.py       # Gemini API wrapper
├── database.py         # SQLite operations
├── requirements.txt
└── .env                # API keys
```

---

### **📅 Week 2: Core Attack Generation**

| Task | Owner | Status |
|------|-------|--------|
| Build `/analyze` command | Member 1 | ⬜ |
| Design LLM prompt templates | Member 2 | ⬜ |
| Build `/generate` command | Member 2 | ⬜ |
| Build `/attacks` command | Member 3 | ⬜ |
| Build `/details` command | Member 3 | ⬜ |
| Store results in SQLite | Member 4 | ⬜ |
| Error handling + validation | Member 1 | ⬜ |

**LLM Prompt Template:**
```python
PROMPT = """
You are a cybersecurity expert simulating 
a hacker's mindset for EDUCATIONAL purposes.

Target System: {system_description}

Analyze this system and provide:
1. Identified vulnerabilities
2. Possible attack strategies
3. Step-by-step attack execution
4. Tools a hacker would use
5. Severity rating (Low/Medium/High/Critical)
6. Defense recommendations

Format as structured JSON.
"""
```

---

### **📅 Week 3: Advanced Features + Web UI**

| Task | Owner | Status |
|------|-------|--------|
| Build `/defend` command | Member 1 | ⬜ |
| Build `/severity` command | Member 2 | ⬜ |
| Build `/simulate` command | Member 2 | ⬜ |
| Build `/report` command | Member 3 | ⬜ |
| Build `/export` command | Member 3 | ⬜ |
| Create web dashboard (HTML/CSS) | Member 4 | ⬜ |
| Connect web UI to Flask API | Member 4 | ⬜ |

**Web UI Pages:**
```
templates/
├── index.html          # Input form
├── results.html        # Attack strategies display
├── report.html         # Full report view
static/
├── style.css           # Styling
└── script.js           # Frontend logic
```

---

### **📅 Week 4: Testing + Documentation + Demo**

| Task | Owner | Status |
|------|-------|--------|
| Unit test all commands | Member 1 | ⬜ |
| Test with 5+ system types | Member 2 | ⬜ |
| Write project documentation | Member 3 | ⬜ |
| Create demo presentation | Member 4 | ⬜ |
| Deploy to Render/Railway | Member 1 | ⬜ |
| Record demo video | Member 4 | ⬜ |
| Final bug fixes | All | ⬜ |

---

## 7. Gemini API Setup

```python
# llm_engine.py

import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

model = genai.GenerativeModel("gemini-1.5-flash")

def analyze_system(description):
    prompt = f"""
    [EDUCATIONAL PURPOSE ONLY]
    Analyze this system as a cybersecurity expert:
    System: {description}
    
    Provide:
    1. Vulnerabilities found
    2. Attack strategies
    3. Execution steps
    4. Severity ratings
    5. Defense measures
    
    Return as JSON format.
    """
    response = model.generate_content(prompt)
    return response.text
```

**.env file:**
```
GEMINI_API_KEY=your_api_key_here
```

---

## 8. Sample Output

```
User: /analyze "PHP website with MySQL, login form, 
       no input sanitization, no HTTPS"

System: ✅ Analysis Complete | ID: SYS_001

┌─────────────────────────────────────────┐
│  VULNERABILITY REPORT - SYS_001        │
├─────────┬───────────┬──────────────────┤
│ # │ Attack      │ Severity          │
├───┼─────────────┼───────────────────┤
│ 1 │ SQL Inject  │ 🔴 CRITICAL       │
│ 2 │ XSS         │ 🔴 HIGH           │
│ 3 │ MITM Attack │ 🟠 HIGH           │
│ 4 │ Brute Force │ 🟡 MEDIUM         │
│ 5 │ CSRF        │ 🟡 MEDIUM         │
└───┴─────────────┴───────────────────┘

Type /details SYS_001 1 for full strategy
Type /defend SYS_001 for recommendations
```

---

## 9. Budget

```
┌────────────────────┬──────────┐
│ Item               │ Cost     │
├────────────────────┼──────────┤
│ Gemini API         │ FREE     │
│ Render Hosting     │ FREE     │
│ GitHub             │ FREE     │
│ VS Code            │ FREE     │
│ Domain (optional)  │ ~$10     │
├────────────────────┼──────────┤
│ TOTAL              │ $0 - $10 │
└────────────────────┴──────────┘
```

---

## 9. Risk Mitigation

| Risk | Solution |
|------|----------|
| API rate limits | Cache responses in SQLite |
| Misuse of tool | Add ethical disclaimers |
| API key exposure | Use `.env` + `.gitignore` |
| LLM hallucination | Validate against OWASP DB |
| Server downtime | Local fallback mode |

---

## 10. Deliverables Checklist

- [ ] Working CLI with 12 commands
- [ ] Web dashboard UI
- [ ] Gemini API integration
- [ ] SQLite report storage
- [ ] Export functionality (JSON/PDF/TXT)
- [ ] Project documentation
- [ ] GitHub repository
- [ ] Live demo
- [ ] Deployment link

---

> **⚠️ DISCLAIMER:** This project is strictly for **educational and defensive cybersecurity** purposes. All attack simulations are theoretical and do not interact with real systems.

---

**Ready to start? Begin with Week 1! 🚀**