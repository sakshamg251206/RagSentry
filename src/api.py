import os
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from src.target.rag import query_rag
from src.auditor.graph import run_audit

app = FastAPI(
    title="SecureRAG Auditor API",
    description="API for the vulnerable RAG target and the Multi-Agent Auditor",
    version="1.0.0",
)

class QueryRequest(BaseModel):
    prompt: str

class QueryResponse(BaseModel):
    response: str

@app.post("/target/query", response_model=QueryResponse)
async def api_query_target(req: QueryRequest):
    """Hits the vulnerable Target RAG system."""
    res = query_rag(req.prompt)
    return QueryResponse(response=res)

@app.post("/audit/start")
async def api_start_audit():
    """Triggers the LangGraph multi-agent audit process."""
    if not os.getenv("GROQ_API_KEY"):
        raise HTTPException(status_code=500, detail="GROQ_API_KEY is missing in environment.")
    
    try:
        report = run_audit()
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit failed: {str(e)}")

# Run via: uvicorn src.api:app --reload
