import shlex
import subprocess
import os # For path normalization if needed

from langchain_core.tools import BaseTool

from typing import TypedDict, List, Dict, Optional, Annotated
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver # For persistence if needed
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, BaseMessage
import json

import shlex
import subprocess
import os # For path normalization if needed
import uuid

from langchain_core.tools import BaseTool

load_dotenv()

from prompts import SYSTEM_PROMPT_CONTENT, PLANNER_PROMPT_TEMPLATE, INTERPRETER_PROMPT_TEMPLATE

# ---------- TOKEN-BUDGET CONSTANTS ----------
MAX_RAW_CHARS      = 2000   # keep at most this many characters of the last tool output
MAX_FINDINGS       = 30     # keep only the newest N findings per prompt
MAX_DIALOG_TURNS   = 6      # last N AI/Human messages + the (mini) system prompt
# -------------------------------------------



import json, re, textwrap

def safe_json_loads(text: str) -> dict:
    """
    Accept raw JSON **or** JSON inside ``` fences.
    Raises json.JSONDecodeError if no valid JSON found.
    """
    text = text.strip()
    try:
        return json.loads(text)                     # raw?
    except json.JSONDecodeError:
        # try to pull JSON out of ```…``` block
        m = re.search(r"```(?:json)?\s*({.*?})\s*```", text, re.S)
        if m:
            inner = textwrap.dedent(m.group(1))
            return json.loads(inner)
        raise            # bubble up original error





class SafeShellTool(BaseTool):
    name: str = "SafeShell"
    description: str = (
        "Executes whitelisted shell commands for static PDF analysis. "
        "Input must be the exact command string to execute (e.g., 'python3 pdfid.py -f /path/to/file.pdf')."
    )

    # Allowlist of executable names (e.g., 'grep', 'file').
    # Assumes these are in the system PATH.
    # For scripts, list them under ALLOWED_PYTHON_SCRIPTS if run via 'python3'.
    ALLOWED_EXECUTABLES: list[str] = [
        "file", "grep", "cat", "strings",
        "xxd",          # hex ⇄ raw
        "head", "tail",
    ]

    # Allowlist of Python scripts. Assumes they are found relative to CWD or have paths.
    # The agent will call them like "python3 script_name.py arguments"
    ALLOWED_PYTHON_SCRIPTS: list[str] = [
        "pdf-parser.py",
        "pdfid.py",
        "rtfobj.py",
        "b64decode.py",
    ]
    
    # You might want to define specific, absolute paths to your scripts for security
    # SCRIPT_DIRECTORY = "/path/to/your/analysis_scripts/" 

    def _is_command_allowed(self, command_parts: list[str]) -> bool:
        if not command_parts:
            return False
        
        executable = command_parts[0]

        # 1. Check direct executables
        if executable in self.ALLOWED_EXECUTABLES:
            return True
        
        # 2. Check for 'python3' followed by an allowed script
        if executable == "python3" and len(command_parts) > 1:
            # script_name_with_potential_path = command_parts[1]
            # For simplicity, assuming script name is directly after python3
            # In a production system, you'd want to normalize paths and check against SCRIPT_DIRECTORY
            script_name = os.path.basename(command_parts[1]) # Get just the script name
            if script_name in self.ALLOWED_PYTHON_SCRIPTS:
                return True
        
        return False

    def _run(self, command_string: str) -> str:
        command_string = command_string.strip()
        if not command_string:
            return "ERROR: No command provided."

        try:
            # Safely split the command string into parts
            command_parts = shlex.split(command_string)
        except ValueError as e:
            return f"ERROR: Invalid command format (e.g., unmatched quotes): {e}"

        if not self._is_command_allowed(command_parts):
            allowed_exec_str = ", ".join(self.ALLOWED_EXECUTABLES)
            allowed_scripts_str = ", ".join([f"python3 {s}" for s in self.ALLOWED_PYTHON_SCRIPTS])
            return (
                f"ERROR: Command not allowed. Allowed are: {allowed_exec_str}, {allowed_scripts_str}"
            )

        try:
            # Note: Consider running in a specific working directory if needed
            # process = subprocess.run(command_parts, capture_output=True, text=True, timeout=30, check=False, cwd=self.working_directory)
            process = subprocess.run(command_parts, capture_output=True, text=True, timeout=60, check=False, env=os.environ.copy())
            
            stdout = process.stdout.strip()
            stderr = process.stderr.strip()
            
            output = ""
            if stdout:
                output += f"STDOUT:\n{stdout}\n"
            if stderr:
                output += f"STDERR:\n{stderr}\n"
            if not stdout and not stderr:
                output = "Command executed with no output."
            if process.returncode != 0:
                output += f"Return Code: {process.returncode}\n"
                
            return output

        except subprocess.TimeoutExpired:
            return "ERROR: Command timed out."
        except FileNotFoundError:
            return f"ERROR: Executable '{command_parts[0]}' not found. Ensure it's in PATH or specified correctly."
        except Exception as e:
            return f"ERROR: Failed to execute command: {e}"


# if __name__ == '__main__':
#     tool = SafeShellTool()
#     print(tool.run("file README.md"))
#     print(tool.run("python3 my_script.py --arg value")) # Assuming my_script.py is not in ALLOWED_PYTHON_SCRIPTS
#     print(tool.run("ls -l")) # Not allowed
#     print(tool.run("grep 'def' safe_shell_tool_langgraph.py")) # Allowed if grep is



# --- State Definition ---
class PDFAnalysisState(TypedDict):
    pdf_filepath: str
    original_user_request: str

    pdfid_output: str
    pdfstats_output: str
    
    messages: List[BaseMessage] # For conversation history with LLM
    
    # Structured analysis data
    command_history: List[Dict[str, str]] # {"reasoning": "...", "command": "...", "output": "..."}
    accumulated_findings: List[str]

    code_blocks: Dict[str, str]
    
    # Control flow and temporary fields
    current_iteration: int
    max_iterations: int
    next_command_to_run: Optional[str]
    command_reasoning: Optional[str]
    analysis_complete: bool
    final_report: Optional[str]


# --- Initialize Tools and Model ---
# The primary tool is our SafeShellTool
safe_shell_tool = SafeShellTool()

# We'll use a powerful model for reasoning and command generation
# Adjust model name and API key as needed (uses .env by default for OPENAI_API_KEY)
llm = ChatOpenAI(model="gpt-4o", temperature=0) 


# --- Graph Nodes ---

def initialize_analysis(state: PDFAnalysisState) -> PDFAnalysisState:
    """Initializes the analysis state and runs a predefined first scan."""
    
    # --- Automatically run initial pdfid scan ---
    # Ensure the filepath is properly quoted if it might contain spaces
    pdfid_cmd = f'python3 pdfid.py -f "{state["pdf_filepath"]}"' 
    print(f"INITIALIZE: Automatically running: {pdfid_cmd}")
    pdfid_out = safe_shell_tool.invoke(pdfid_cmd)

    stats_cmd = f'python3 pdf-parser.py -a "{state["pdf_filepath"]}"'
    print(f"INITIALIZE: Automatically running: {stats_cmd}")
    stats_out = safe_shell_tool.invoke(stats_cmd)
    
    history = [
        {"reasoning": "Automated keyword scan", "command": pdfid_cmd,  "output": pdfid_out},
        {"reasoning": "Automated stats dump",  "command": stats_cmd,  "output": stats_out},
    ]
    # --- End of automatic scan ---

    initial_system_message = SystemMessage(
        content=SYSTEM_PROMPT_CONTENT.format(
            ALLOWED_EXECUTABLES_STR=", ".join(safe_shell_tool.ALLOWED_EXECUTABLES),
            ALLOWED_PYTHON_SCRIPTS_STR=", ".join([f"python3 {s}" for s in safe_shell_tool.ALLOWED_PYTHON_SCRIPTS])
        )
    )
        
    initial_human_message_content = (
        f"{state['original_user_request']}\n\n"
        f"The initial `pdfid.py -f` scan output is:\n"
        f"```\n{pdfid_out[:2000]}\n```\n\n"
        f"The initial `pdf-parser.py -a` scan output is:\n"
        f"```\n{stats_out[:2000]}\n```\n\n"
        "Please begin your detailed analysis by planning the next command based on this initial information."
    )
    initial_human_message = HumanMessage(content=initial_human_message_content)
    
    return {
        **state,
        "messages": [initial_system_message, initial_human_message],
        "command_history": history,
        "accumulated_findings": [], 
        "current_iteration": 0, # This first auto-step doesn't count as an LLM iteration yet
        "analysis_complete": False,
        "final_report": None,
        "pdfid_output": pdfid_out,
        "pdfstats_output": stats_out,
        "code_blocks": {},
    }

def plan_next_command(state: PDFAnalysisState) -> PDFAnalysisState:
    """LLM decides the next shell command."""
    history_tail   = state["command_history"][-MAX_DIALOG_TURNS:] if state["command_history"] else []
    last_cmd_info  = history_tail[-1] if history_tail else {}
    history_txt = "\n".join(f"- {c['command']}" for c in history_tail)

    last_output = last_cmd_info.get("output", "")[:MAX_RAW_CHARS]
    recent_findings = state["accumulated_findings"][-MAX_FINDINGS:]


    planner_prompt = PLANNER_PROMPT_TEMPLATE.format(
        pdfid_output        = state["pdfid_output"][:2000],
        pdfstats_output     = state["pdfstats_output"][:2000],
        pdf_filepath        = state["pdf_filepath"],
        current_iteration   = state["current_iteration"],
        max_iterations      = state["max_iterations"],
        executed_commands   = history_txt,
        accumulated_findings= recent_findings,
        last_command        = last_cmd_info.get("command", "N/A"),
        last_command_output = last_output,
    )

    if len(state["messages"]) > (MAX_DIALOG_TURNS + 1):      # +1 for big system at idx 0
        state["messages"] = [state["messages"][0]] + state["messages"][-MAX_DIALOG_TURNS:]
    messages_for_llm = state["messages"] + [HumanMessage(content=planner_prompt)]
    response = llm.invoke(messages_for_llm)

    try:
        parsed = safe_json_loads(response.content)
        reasoning = parsed.get("reasoning", "")
        cmd      = parsed.get("command_to_run")

        if re.search(r"[<{].*[>}]?", cmd):
            retry_msg = SystemMessage(
                content="Your previous command still had a placeholder. "
                        "Replace EVERY placeholder with a real object number, filename or string."
            )
            response = llm.invoke(state["messages"] + [retry_msg, HumanMessage(content=planner_prompt)])
            cmd_json = safe_json_loads(response.content)
            cmd = cmd_json.get("command_to_run", "")

        if cmd == "ANALYSIS_COMPLETE":
            return {**state, "messages": state["messages"] + [response],
                    "analysis_complete": True, "command_reasoning": reasoning}

        if cmd:
            return {**state, "messages": state["messages"] + [response],
                    "next_command_to_run": cmd, "command_reasoning": reasoning}

        # fall-back – no command
        return {**state, "messages": state["messages"] + [response],
                "analysis_complete": True, "command_reasoning": "No command produced."}

    except json.JSONDecodeError:
        return {**state, "messages": state["messages"] + [response],
                "analysis_complete": True, "command_reasoning": "JSON parse error."}



def execute_command(state: PDFAnalysisState) -> PDFAnalysisState:
    """Executes the planned command using SafeShellTool."""
    if not state["next_command_to_run"]:
        return {**state, "command_history": state["command_history"] + [{"reasoning": state.get("command_reasoning", "N/A"), "command": "N/A", "output": "No command was planned."}]}

    command_output = safe_shell_tool.invoke(state["next_command_to_run"])
    
    new_command_history_entry = {
        "reasoning": state.get("command_reasoning", "N/A"),
        "command": state["next_command_to_run"],
        "output": command_output,
    }
    
    updated_messages = state["messages"] + [
        AIMessage( # This could be structured as a tool call/result if using bind_tools more formally
            content=f"Executed command: {state['next_command_to_run']}\nOutput:\n{command_output}"
        )
    ]
    return {
        **state,
        "messages": updated_messages,
        "command_history": state["command_history"] + [new_command_history_entry],
        "next_command_to_run": None, # Clear after execution
        "command_reasoning": None,
        "current_iteration": state["current_iteration"] + 1,
    }

def interpret_results_and_update_findings(state: PDFAnalysisState) -> PDFAnalysisState:
    """LLM interprets last command output and updates findings."""
    last = state["command_history"][-1] if state["command_history"] else {}
    interp_prompt = INTERPRETER_PROMPT_TEMPLATE.format(
        executed_command    = last.get("command", "N/A"),
        command_output      = last.get("output", "")[:MAX_RAW_CHARS],
        accumulated_findings= state["accumulated_findings"][-MAX_FINDINGS:]
    )

    if len(state["messages"]) > (MAX_DIALOG_TURNS + 1):      # +1 for big system at idx 0
        state["messages"] = [state["messages"][0]] + state["messages"][-MAX_DIALOG_TURNS:]
    messages_for_llm = state["messages"] + [HumanMessage(content=interp_prompt)]
    response = llm.invoke(messages_for_llm)

    try:
        new_findings = safe_json_loads(response.content).get("new_findings", [])
        code_blocks: dict[str, str] = safe_json_loads(response.content).get("code_blocks", {})
        if not isinstance(new_findings, list):
            new_findings = ["Interpreter JSON format error."]
    except json.JSONDecodeError:
        new_findings = ["Interpreter JSON parse error."]
        code_blocks = {}

    state["command_history"][-1]["output"] = "omitted"

    merged_blocks = {**state.get("code_blocks", {}), **code_blocks}

    return {
        **state,
        "messages": state["messages"] + [response],
        "accumulated_findings": state["accumulated_findings"] + new_findings,
        "code_blocks": merged_blocks,
    }


def compile_final_report(state: PDFAnalysisState) -> PDFAnalysisState:
    """LLM compiles the final report based on all findings and history."""
    messages_for_llm = state["messages"] + [
        HumanMessage(
            content=(
                "The analysis is now complete. Please provide a comprehensive final report. "
                "Summarize the original request, all commands executed with their key outputs (briefly), "
                "and all accumulated findings. Conclude with an overall threat assessment of the PDF. "
                "If any decoded code or scripts were extracted, include an explanation of how they fit "
                "into the attack chain."
            )
        )
    ]
    
    response = llm.invoke(messages_for_llm)
    final_text = response.content

    if state.get("code_blocks"):       
        artefacts = []
        artefacts.append("\n### Decoded / Extracted Code Artefacts")
        for label, text in state["code_blocks"].items():
            snippet = text if len(text) < 10000 else text[:10000] + " …(truncated)…"
            artefacts.append(f"\n---- {label} ----\n{snippet}\n")
        final_text += "\n".join(artefacts)
    return {**state, "messages": state["messages"] + [response], "final_report": final_text}


# --- Conditional Edges ---
def should_continue_analysis(state: PDFAnalysisState) -> str:
    """Determines if the analysis should continue or end."""
    if state["analysis_complete"]:
        return "compile_report"
    if state["current_iteration"] >= state["max_iterations"]:
        print(f"Max iterations ({state['max_iterations']}) reached.")
        return "compile_report"
    return "plan_command"


# --- Build the Graph ---
workflow = StateGraph(PDFAnalysisState)

workflow.add_node("initialize", initialize_analysis)
workflow.add_node("plan_command", plan_next_command)
workflow.add_node("execute_command", execute_command)
workflow.add_node("interpret_results", interpret_results_and_update_findings)
workflow.add_node("compile_report", compile_final_report)

workflow.add_edge(START, "initialize")
workflow.add_edge("initialize", "plan_command")

workflow.add_conditional_edges(
    "plan_command",
    lambda x: "execute_command" if not x["analysis_complete"] else "compile_report",
    {
        "execute_command": "execute_command",
        "compile_report": "compile_report",
    }
)

workflow.add_edge("execute_command", "interpret_results")

workflow.add_conditional_edges(
    "interpret_results",
    should_continue_analysis, # Uses the function defined above
    {
        "plan_command": "plan_command",
        "compile_report": "compile_report",
    }
)
workflow.add_edge("compile_report", END)

# For persistence (optional, good for long-running tasks or debugging)
memory = MemorySaver() 
app = workflow.compile(checkpointer=memory)

# app = workflow.compile()


# --- Running the Graph ---
if __name__ == "__main__":
    pdf_to_analyze = "./hello_world_js.pdf" # <--- Or your desired PDF path
    pdf_to_analyze = "87c740d2b7c22f9ccabbdef412443d166733d4d925da0e8d6e5b310ccfc89e13.pdf"
    
    # Check if the PDF path needs updating or if the file exists
    if pdf_to_analyze == "/path/to/your/suspicious.pdf" or not os.path.exists(pdf_to_analyze):
        print(f"ERROR: PDF file not found at '{pdf_to_analyze}'.")
        print("Please update the 'pdf_to_analyze' variable with a valid PDF path.")
    else:
        initial_input = {
            "pdf_filepath": pdf_to_analyze,
            "original_user_request": f"Analyze the PDF file at {pdf_to_analyze} for any signs of malicious or suspicious activity.",
            "max_iterations": 10, # Adjust as needed
            "messages": [] 
        }

        thread_id = str(uuid.uuid4())
        config = {"configurable": {"thread_id": thread_id}} 
        
        print(f"Starting analysis for PDF: {pdf_to_analyze} with Thread ID: {thread_id}")

        final_event_state = None # Variable to store the last state from the stream

        for event_idx, event_data in enumerate(app.stream(initial_input, config=config, stream_mode="values")):
            print(f"\n--- Event {event_idx} ---")
            
            # In stream_mode="values", event_data is the full state dictionary after a node executes
            current_state_values = event_data 
            final_event_state = current_state_values # Keep track of the latest state

            print(f"Current Iteration in State: {current_state_values.get('current_iteration', 'N/A')}")
            
            if current_state_values.get("next_command_to_run"):
                 print(f"Planned Command: {current_state_values['next_command_to_run']}")
            
            current_messages = current_state_values.get("messages")
            if current_messages:
                if isinstance(current_messages, list) and current_messages:
                    last_message = current_messages[-1]
                    print(f"Last Message Type: {type(last_message).__name__}")
                    if hasattr(last_message, 'content'):
                        print(f"Last Message Content Snippet: {str(last_message.content)[:200]}...")
                elif isinstance(current_messages, list) and not current_messages:
                    print("Messages list is empty.")
                else:
                    print(f"Messages key contains unexpected type: {type(current_messages)}")
            else:
                print("Messages key is missing in this event/state.")

            if current_state_values.get("accumulated_findings"):
                print(f"Accumulated Findings: {current_state_values['accumulated_findings']}")
            
            if current_state_values.get("analysis_complete"):
                print("Analysis marked as complete in this event.")
            
            if current_state_values.get("final_report"):
                print("Final report generated in this event. Analysis likely concluding.")
        
        # --- Analysis via stream is complete ---

        if final_event_state:
            print("\n\n--- FINAL REPORT (from end of stream) ---")
            print(final_event_state.get("final_report", "No final report generated by end of stream."))

            print("\n--- FULL FINAL STATE (from end of stream) ---")
            # Define a custom serializer for BaseMessage objects if needed for more detail
            # For now, str(o) will convert message objects to their string representation.
            try:
                final_state_json_str = json.dumps(final_event_state, indent=2, default=lambda o: str(o))
                print(final_state_json_str)

                # Save the full final state to a local JSON file
                output_filename = f"pdf_analysis_report_{thread_id}.json"
                with open(output_filename, 'w') as f:
                    json.dump(final_event_state, f, indent=2, default=lambda o: str(o))
                print(f"\nFull final state saved to: {output_filename}")

            except TypeError as e:
                print(f"Error serializing final state to JSON: {e}")
                print("Final state might contain non-serializable objects not handled by default=str(o).")
                print("Printing the raw final_event_state for inspection:")
                print(final_event_state)

        else:
            print("\nStream did not yield any events, so no final state was captured.")
