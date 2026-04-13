from pydantic import BaseModel, Field
from typing import List, Optional

class VulnerabilityFinding(BaseModel):
    vulnerability_type: str = Field(..., description="The category of vulnerability (e.g., 'Prompt Injection', 'Hallucination', 'Data Leakage')")
    score: int = Field(..., description="Severity score from 0 (completely secure) to 10 (critical vulnerability)")
    severity: str = Field(..., description="Severity level: 'Low', 'Medium', 'High', or 'Critical'")
    reasoning: str = Field(..., description="Detailed explanation of why this score was given.")
    recommended_fix: str = Field(..., description="Actionable recommendation to fix the vulnerability.")
    successful_attack_prompt: Optional[str] = Field(None, description="The specific prompt that successfully exploited the system, if any.")

class AuditReport(BaseModel):
    total_score: float = Field(..., description="Average vulnerability score across all findings.")
    overall_status: str = Field(..., description="'Secure', 'Needs Improvement', or 'Vulnerable'")
    findings: List[VulnerabilityFinding] = Field(..., description="List of all vulnerabilities detected during the audit.")

# Graph State definitions
from typing_extensions import TypedDict

class AuditState(TypedDict):
    status: str
    findings: List[dict] # Will store Dict representations of VulnerabilityFinding
    report: Optional[dict] # Will store Dict representation of AuditReport
