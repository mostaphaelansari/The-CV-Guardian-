# 🛡️ The CV Guardian

**An intelligent security platform that detects malicious, weaponized, and AI-generated CVs/resumes before they reach your hiring pipeline.**

CV Guardian analyzes uploaded PDF, DOCX, and TXT files through **11 security checks** and a **7-dimension AI-generation scoring framework**, returning a structured threat report with risk scores, findings, and actionable recommendations.

---

## 🎯 Why This Exists

Recruitment pipelines are a high-value attack surface. Malicious actors embed:
- **Code injection** (SQL, XSS, command, prompt) in resume text fields
- **JavaScript & embedded objects** inside PDF structures
- **Obfuscated payloads** using Base64 encoding or Unicode tricks
- **Social engineering** language designed to manipulate automated systems

Meanwhile, the rise of AI-generated resumes creates a separate problem: **candidates submitting fully machine-written CVs** that bypass traditional screening.

CV Guardian addresses both threats in a single analysis pipeline.

---

## 🏗️ Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Client /   │     │   Sandbox    │     │  NLP Service  │
│   Browser    │────▶│   Service    │     │  (Python)     │
│              │     │  :3001       │     │  :5000        │
└──────┬───────┘     └──────────────┘     └──────────────┘
       │                    ▲                     ▲
       ▼                    │                     │
┌──────────────┐            │                     │
│  Main API    │────────────┴─────────────────────┘
│  (Express)   │
│  :3000       │──────────▶ MongoDB :27017
└──────────────┘
```

| Service | Tech | Port | Role |
|---------|------|------|------|
| **Main API** | Node.js / Express | 3000 | Orchestrates analysis, serves UI & API |
| **Sandbox** | Node.js | 3001 | Isolates file parsing (PDF, DOCX) in a separate process |
| **NLP Service** | Python / Flask | 5000 | Sentiment analysis via Hugging Face Transformers |
| **Database** | MongoDB | 27017 | Persists analysis reports |

---

## 🔍 Security Checks (11 Layers)

| # | Check | Severity | What It Detects |
|---|-------|----------|-----------------|
| 1 | **Page Count Policy** | medium | Documents exceeding page limits |
| 2 | **Suspicious URLs** | high/critical | Malware domains, URL shorteners, executable links |
| 3 | **Content Heuristics** | medium | Social engineering phrases ("enable macros", "click here") |
| 4 | **Injection Detection** | critical | SQL injection, XSS, command injection, prompt injection |
| 5 | **Obfuscation Patterns** | high | Hex-encoded streams, suspicious PDF operators |
| 6 | **Metadata Anomalies** | medium/critical | Missing creator, malware tool signatures, future dates |
| 7 | **JavaScript Detection** | critical | `/JS`, `/JavaScript`, `/OpenAction` in PDF structure |
| 8 | **Embedded Objects** | critical | `/EmbeddedFile`, `/RichMedia`, `/XFA` in PDF |
| 9 | **Encoded Payloads** | critical | Base64-encoded attack strings with dangerous decoded content |
| 10 | **Unicode Obfuscation** | critical | Fullwidth Unicode characters hiding injection patterns |
| 11 | **AI-Generation Scoring** | medium/high | 7-dimension framework detecting machine-written CVs |

---

## 🤖 AI-Generation Risk Scoring Framework

A structured **0–35 scoring grid** analyzing 7 dimensions (each scored 0–5):

| Dimension | What It Measures |
|-----------|-----------------|
| **1.1 Buzzword Density** | Corporate filler phrases per 100 words ("proven track record", "synergy") |
| **1.2 Sentence Uniformity** | Sentence length variance + structural repetition |
| **1.3 Friction Absence** | Lack of real-world language (debugging, trade-offs, challenges) |
| **2.1 Tool Specificity** | Missing version numbers, concrete libraries, architecture details |
| **2.2 Scale Realism** | Absence of quantified metrics (users, latency, data volume) |
| **2.3 Timeline Plausibility** | Unrealistic role/project density vs. time ranges |
| **4.0 Stylometric Indicators** | Type-token ratio, burstiness, sentence length variance |
| **3.0 Cross-Consistency** | *(Manual)* — Compare with GitHub, LinkedIn, portfolio |

### Risk Interpretation

| Total Score | Risk Level | Action |
|-------------|------------|--------|
| 0–15 | ✅ Likely Human | No penalty |
| 16–25 | ⚠️ Mixed / Assisted | Medium finding, +5 score |
| 26–35 | 🔶 Likely AI-Assisted | High finding, +15 score |
| 36+ | 🔴 Highly AI-Generated | High finding, +25 score |

> **Note:** This is probabilistic, not definitive. The strongest discriminator remains a live technical drill where you ask: *"What failed? How did you debug it? What would you change?"*

---

## 📁 Project Structure

```
The-CV-Guardian-/
├── server.js                   # Entry point
├── package.json
├── Dockerfile
├── docker-compose.yml
│
├── src/
│   ├── app.js                  # Express app setup (middleware, routes, error handling)
│   ├── config/
│   │   ├── index.js            # App config (PORT, MAX_FILE_SIZE, MONGO_URI)
│   │   └── db.js               # MongoDB connection via Mongoose
│   ├── controllers/
│   │   └── reportController.js # Analysis & report endpoints
│   ├── models/
│   │   └── Report.js           # Mongoose schema (findings, metadata, aiScore)
│   ├── routes/
│   │   └── api.js              # API routes with Swagger docs & Multer upload
│   ├── services/
│   │   ├── fileAnalyzer.js     # Core: 11 security checks + AI scoring (1100+ lines)
│   │   ├── nlpService.js       # NLP service client
│   │   └── sandboxService.js   # Sandbox service client
│   └── utils/
│       └── helpers.js
│
├── sandbox/                    # Isolated file parsing microservice
│   ├── server.js               # Express server on :3001
│   └── package.json
│
├── nlp_service/                # Python NLP microservice
│   ├── app.py                  # Flask server on :5000 (Hugging Face sentiment)
│   └── requirements.txt
│
├── public/                     # Frontend UI
│   ├── index.html
│   ├── style.css
│   └── app.js
│
└── test/                       # Test suite
    ├── testAnalyzer.js          # Core security checks (injection, encoding, obfuscation)
    ├── testBotDetection.js      # AI-generation scoring framework
    ├── testPromptInjection.js   # Prompt injection detection
    ├── reproduce_user_score.js  # Integration: full analysis via API
    └── verification_script.js   # Environment check
```

---

## 🚀 Getting Started

### Prerequisites

- **Node.js** ≥ 18
- **Python** ≥ 3.9
- **MongoDB** ≥ 6.0

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/mostaphaelansari/The-CV-Guardian-.git
cd The-CV-Guardian-

# 2. Install Main API dependencies
npm install

# 3. Install Sandbox dependencies
cd sandbox && npm install && cd ..

# 4. Install NLP Service dependencies
pip install -r nlp_service/requirements.txt
```

### Running the Application

Start each service in a separate terminal:

```bash
# Terminal 1 – MongoDB
mongod --dbpath ./data/db --bind_ip 127.0.0.1

# Terminal 2 – NLP Service (downloads model on first run)
python nlp_service/app.py

# Terminal 3 – Sandbox Service
cd sandbox && npm start

# Terminal 4 – Main API
npm start
```

Once running:
- **Web UI**: http://localhost:3000
- **API Docs (Swagger)**: http://localhost:3000/api-docs

### Docker

```bash
docker-compose up --build
```

---

## 📡 API Endpoints

### `POST /api/analyze`
Upload a file for analysis.

| Parameter | Type | Description |
|-----------|------|-------------|
| `file` | multipart/form-data | PDF, DOCX, or TXT file (max 15MB) |

**Response:**
```json
{
  "id": "uuid",
  "fileName": "resume.pdf",
  "score": 45,
  "riskLevel": "high",
  "findings": [
    {
      "check": "Injection Detection",
      "severity": "critical",
      "message": "SQL tautology injection detected..."
    }
  ],
  "aiScore": {
    "dimensions": {
      "1.1_buzzword_density": 4,
      "1.2_sentence_uniformity": 2,
      "1.3_friction_absence": 5,
      "2.1_tool_specificity": 5,
      "2.2_scale_realism": 4,
      "2.3_timeline_plausibility": 0,
      "4.0_stylometric": 2,
      "3.0_cross_consistency": null
    },
    "total": 22,
    "riskLabel": "Mixed / Assisted"
  },
  "recommendations": ["🤖 This CV appears to be bot-generated..."],
  "metadata": { ... }
}
```

### `GET /api/reports`
List all stored analysis reports.

### `GET /api/reports/:id`
Retrieve a specific report by ID.

---

## 🧪 Testing

```bash
# Security checks (injection, encoding, obfuscation)
node test/testAnalyzer.js

# AI-generation scoring framework
node test/testBotDetection.js

# Prompt injection detection
node test/testPromptInjection.js

# Full API integration (requires running server)
node test/reproduce_user_score.js
```

---

## ⚙️ Configuration

Environment variables (or defaults in `src/config/index.js`):

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 3000 | Main API port |
| `MONGO_URI` | `mongodb://localhost:27017/cv-guardian` | MongoDB connection string |
| `NLP_SERVICE_URL` | `http://localhost:5000` | NLP service endpoint |
| `SANDBOX_URL` | `http://localhost:3001` | Sandbox service endpoint |
| `MAX_FILE_SIZE` | 15 MB | Maximum upload size |

---

## 🔒 Security Design

- **Sandboxed parsing** — Untrusted files are parsed in an isolated service, not in the main process
- **Rate limiting** — API routes are rate-limited to prevent abuse
- **File type restriction** — Only PDF, DOCX, and TXT files are accepted
- **Size limits** — Uploads capped at 15 MB
- **Read-only Docker** — Production container runs with `read_only: true`
- **Fail-secure** — If sandbox is unreachable, files are denied (not silently passed)

---

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE).