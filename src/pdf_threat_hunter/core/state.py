from typing import TypedDict, List, Dict, Optional
from langchain_core.messages import BaseMessage


class PDFAnalysisState(TypedDict):
    pdf_filepath: str
    original_user_request: str
    
    messages: List[BaseMessage] # For conversation history with LLM
    
    # Structured analysis data
    command_history: List[Dict[str, str]] # {"reasoning": "...", "command": "...", "output": "..."}
    accumulated_findings: List[str]
    
    # Control flow and temporary fields
    current_iteration: int
    max_iterations: int
    next_command_to_run: Optional[str]
    command_reasoning: Optional[str]
    analysis_complete: bool
    final_report: Optional[str]