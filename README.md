# SecureRAG Auditor 🛡️

SecureRAG Auditor is a cutting-edge multi-agent scanning system designed to penetrate and audit LLM RAG (Retrieval-Augmented Generation) pipelines. Built with **LangGraph**, **CrewAI**, and **FastAPI**, it deploys specialized agents to test for Prompt Injection, Hallucinations, and Data Leakage vulnerabilities.

## How it Works

1. **Target RAG Pipeline**: A mock vulnerable RAG application is included (`src/target`). It is seeded with confidential data, fake API keys, and has no prompt safeguards.
2. **Auditor Agents (CrewAI)**:
   - **Injection Detector**: Tries to break the system prompt or override instructions.
   - **Hallucination Auditor**: Tests for ungrounded or fabricated responses.
   - **Leakage Scanner**: Attempts to extract sensitive documents and API keys from the vector store.
3. **LangGraph Orchestrator**: Manages the audit state machine and aggregates the findings into a Pydantic `AuditReport`.
4. **Streamlit UI**: A clean dashboard to run the audit and visualize security metrics.

## Setup Instructions

1. **Clone & Environment**
Ensure you are using Python 3.10+.
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. **API Keys**
Copy `.env.example` to `.env` and add your Groq API key:
```bash
cp .env.example .env
# Edit .env and insert your GROQ_API_KEY
```

3. **Initialize the Target System**
This will build the local FAISS vector store with mock vulnerable documents.
```bash
python -m src.target.data
```

## Running the Application

You will need two terminal tabs.

**Terminal 1 (FastAPI Backend)**:
```bash
uvicorn src.api:app --reload
```
This starts the orchestration server on `http://127.0.0.1:8000`.

**Terminal 2 (Streamlit Frontend)**:
```bash
streamlit run src/ui.py
```
This will open the dashboard in your browser. Click **Start Full Audit** to watch the agents attack the target pipeline in the background and generate your report!

## Tech Stack
- Orchestration: `LangGraph`
- Multi-Agent Framework: `CrewAI`
- RAG/Embeddings: `LangChain`, `HuggingFace`
- LLM API: `Groq`
- Backend: `FastAPI`
- UI: `Streamlit`
