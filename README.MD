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
