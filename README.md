# Cyber Analyst — MVP

AI + ML cybersecurity system that analyzes SIEM alerts, detects attack patterns, correlates events into timelines, and generates plain-language explanations.

## Quick Start

### 1. Start PostgreSQL

```bash
docker-compose up -d
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your LLM API key
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Initialize the database

```bash
python -m backend.db.init_db
```

### 5. Run the backend

```bash
uvicorn backend.main:app --reload
```

### 6. Run the frontend (separate terminal)

```bash
streamlit run frontend/app.py
```

### 7. Demo

Open the Streamlit UI, upload `data/sample_logs.json`, and explore detected incidents.

## Architecture

```
Data Layer:  Ingestion → Parser → Rule Engine + Isolation Forest → Correlator → Timeline → PostgreSQL
LLM Layer:   Incident data → Prompt → LLM (OpenAI/Anthropic) → Explanation
Agent Layer: Streamlit Dashboard + Chat Interface
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /upload-logs | Upload JSON/CSV log file |
| GET | /incidents | List all detected incidents |
| GET | /incidents/{id} | Get incident detail with explanation |
| GET | /timeline/{id} | Get attack timeline for an incident |
| POST | /chat | Ask a question about incidents |
