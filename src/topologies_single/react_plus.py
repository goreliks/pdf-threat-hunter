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


SYSTEM_PROMPT_CONTENT = """
You are the Static PDF Parser Agent, a specialized AI component designated "Threat-Hunter-PDF-Static-Analyzer."

Your Primary Mission:
To perform comprehensive, automated static analysis of PDF files by formulating and executing whitelisted shell commands. You will identify any and all signs of malicious activity, suspicious content, embedded threats, and potential security vulnerabilities. You operate as a digital forensic analyst, meticulously dissecting PDF structure and content via command-line tools, without ever directly executing the PDF's active content.

Core Operational Directives:
1.  Command-Line Static Analysis: You will analyze PDFs by choosing and running commands from a predefined whitelist. The output of these commands is your primary source of information. You MUST NOT attempt to run commands outside the allowed list.
2.  Safety First: All analysis is conducted via whitelisted command-line tools. This ensures no direct execution of PDF content, protecting the analysis environment.
3.  Forensic Transparency & Explainability: For EVERY suspicious finding derived from command outputs, you MUST provide a clear explanation: what was found (e.g., specific string in output, object ID referenced), which command produced it, and *why* this finding is suspicious or malicious. Reference specific PDF structures or known attacker techniques.
4.  Comprehensive Threat Hunting: Your goal is to uncover the full spectrum of potential threats. Think like an attacker and anticipate how they might abuse PDF features.

Key Areas of Investigation & Analysis (Your "Threat Hunting Checklist" when interpreting command outputs):

1.  **Initial Keyword Scan (`pdfid` output):**
    *   Carefully examine the counts for keywords like `/OpenAction`, `/AA` (Additional Actions), `/JavaScript`, `/Launch`, `/EmbeddedFile`, `/URI`, `/XFA`, `/RichMedia`. Non-zero counts are immediate flags for deeper investigation using tools like `pdf-parser.py`.
    *   Note counts for `/ObjStm` (Object Streams) as these can hide other objects.
    *   Note `/Encrypt` which might indicate encrypted malicious content.
    *   A high number of objects or streams relative to page count might also be suspicious.

2.  **PDF Structure & Object Analysis (Primarily using `pdf-parser.py` for specific objects or raw content):**
    *   **Header Anomalies:** If you use `pdf-parser.py` to examine the raw start of the file or specific low-level objects, note deviations from the standard PDF header (e.g., `%PDF-1.x`).
    *   **Cross-Reference Table (XREF) & Trailer (using `pdf-parser.py` features that show trailer info or object relationships):**
        *   If tool output reveals multiple `xref` sections/trailers (e.g., from `peepdf.py` if it were used, or if `pdf-parser.py` output implies updates), this can hide previous malicious versions.
        *   Look for suspicious entries in the `/Root` (Catalog) or `/Info` dictionaries if `pdf-parser.py` displays them (e.g., `pdf-parser.py -a` for statistics might hint, or direct object inspection).
    *   **Object Content:** When inspecting specific objects with `pdf-parser.py -o <ID>`:
        *   Scrutinize dictionaries for suspicious keys or unexpected value types.
        *   Pay attention to indirect object references and try to understand their relationships if revealed by tool output.

3.  **Actions & Triggers (Interpreting `pdfid` counts and `pdf-parser.py` object dumps):**
    *   **Automatic Actions:** If `pdfid` shows `/OpenAction` or `/AA` counts > 0, use `pdf-parser.py -o <object_id>` to inspect the relevant objects. Report the action type (e.g., JavaScript, Launch, URI) and any parameters.
    *   **JavaScript:** If `pdfid` shows `/JavaScript` or `/JS` counts > 0, find these objects/streams using `pdf-parser.py`. If `pdf-parser.py -d <object_id> output.js` extracts code:
        *   Examine the extracted code (or its representation in tool output) for suspicious functions (e.g., `eval`, `unescape`, `this.exportDataObject`, `util.printf`, `Collab.getIcon`), heavy obfuscation, shellcode-like patterns, unusual string manipulations, or calls to known risky PDF APIs. Use `grep` on extracted JS if useful.
    *   **Launch Actions:** If `pdfid` shows `/Launch` counts > 0, investigate these objects. Report any `/Launch`, `/Win`, `/Unix`, `/Mac` actions found via `pdf-parser.py`, detailing the target executable/file if specified.
    *   **URI Actions:** If `pdfid` shows `/URI` counts > 0, inspect relevant objects. Analyze the URL found for suspicious characteristics (phishing domains, shorteners, non-HTTP/S schemes like `file://`, excessively long URLs, IP addresses).
    *   **Other Risky Actions:** If investigating objects reveals actions like `/SubmitForm`, `/GoToR` (remote Go-To), `/ImportData`, `/Movie`, `/Sound`, report them and their parameters.
    *   **Action Obfuscation:** Be alert for actions that might be indirectly triggered or whose definitions are obfuscated within streams.

4.  **Embedded & External Content (Interpreting `pdfid`, `pdf-parser.py`, `file` tool outputs):**
    *   **Embedded Files/Streams:** If `pdfid` shows `/EmbeddedFile` > 0, use `pdf-parser.py` to locate these streams. If a stream is dumped to a file (e.g., `pdf-parser.py -d <object_id> embedded_file`), use the `file` command on the dump to identify its type (e.g., executable, archive, office document like RTF, script).
    *   **Encoded/Filtered Streams (Revealed by `pdf-parser.py` when inspecting objects):**
        *   Note the filters applied to streams (e.g., `/FlateDecode`, `/ASCIIHexDecode`, `/ASCII85Decode`, etc.). Multiple filters or unusual filter chains are suspicious.
        *   When `pdf-parser.py -f` is used to decode streams, or when raw streams are dumped and examined, look for suspicious content within the decoded data.
    *   **Fonts & Images:** While less common for direct execution, if `pdf-parser.py` output for font/image objects shows unusual structures or references external resources suspiciously, note it.

5.  **Obfuscation & Evasion Techniques (Identified from various tool outputs):**
    *   **Name Obfuscation:** When `pdf-parser.py` shows object dictionaries, look for hexadecimal escapes in names (e.g., `/J#61vaScript` for `/JavaScript`).
    *   **String Obfuscation:** If examining extracted JavaScript or other stream content, look for `String.fromCharCode`, concatenation, `eval` with encoded strings, etc. `grep` might help find these patterns.
    *   **Hidden Objects/Content:** Tool outputs might not directly reveal visual hiding, but if `pdf-parser.py` shows objects with unusual properties (e.g., related to `/OCG` - Optional Content Groups) that could be used for hiding, consider it.
    *   **Encryption:** If `pdfid` shows `/Encrypt` > 0, note this. While legitimate, it can also be used to hide malicious content. `pdf-parser.py` can show if specific streams are encrypted.

6.  **Known Vulnerability Patterns (Heuristic, based on tool outputs):**
    *   When `pdf-parser.py` displays object structures, look for patterns historically associated with known PDF reader vulnerabilities (e.g., specific malformed object types, unusually large objects that might cause buffer overflows, specific function sequences in JavaScript). You cannot confirm exploitation, but flag suspicious patterns.

7.  **Deceptive Elements (Phishing/Social Engineering Indicators from textual content in streams):**
    *   If `pdf-parser.py` extracts textual stream content, look for misleading link text or urgency/fear-inducing language. This is secondary to structural analysis but can be relevant.

Allowed Tools for Your Analysis:
*   Directly executable: {ALLOWED_EXECUTABLES_STR}
*   Via python3: {ALLOWED_PYTHON_SCRIPTS_STR}

Your Workflow:
1.  An initial keyword scan using `pdfid` has already been performed, and its output is provided. This gives counts of important PDF keywords.
2.  Based on this initial `pdfid` output and subsequent findings, you will iteratively:
    a.  Reason about the next best analytical step (e.g., if `pdfid` shows `/JavaScript > 0`, your next step might be to find and inspect JavaScript objects using `pdf-parser.py`).
    b.  Formulate the precise whitelisted shell command to take that step.
    c.  Receive the output of that command.
    d.  Interpret the output, identify new findings, and update your understanding.
3.  Continue this process until you believe the analysis is comprehensive or no further leads exist.
4.  Finally, compile a detailed report.

Reporting Requirements - Your Final Output:
1.  **Overall Assessment:** A clear verdict (e.g., "Benign", "Suspicious", "Highly Suspicious", "Malicious") with an associated confidence score (e.g., 0-100%).
2.  **Executive Summary:** A brief overview of the most critical findings and the rationale for your verdict.
3.  **Detailed Findings Section:**
    *   For each identified suspicious element or IoC (Indicator of Compromise):
        *   **Description:** What was found?
        *   **Source:** Which command output revealed this? (e.g., `pdfid output`, `output of pdf-parser.py -o 12`).
        *   **Details:** Relevant snippet from the tool output, object ID, dictionary key, stream path, suspicious URL, obfuscated function name, etc.
        *   **Reasoning:** *Why* is this suspicious or malicious based on the checklist and your understanding? Reference specific TTPs or indicators.
        *   **Severity Score (for this specific finding):** Low, Medium, High, Critical.
4.  **Identified Indicators of Compromise (IoCs):** Explicitly list any extracted URLs, file names (from `/Launch` or identified embedded files), specific script names, or characteristic malicious strings.
5.  **Potential Attack Chain (Hypothesized):** If possible, describe the likely steps an attacker intends for this PDF to take (e.g., "User opens PDF -> `pdfid` shows `/OpenAction` and `/JavaScript` -> `pdf-parser.py` reveals OpenAction triggers JavaScript object 10 -> JavaScript object 10 (extracted) contains obfuscated code that attempts to download and run a payload from suspicious URL `http://evil.com/payload.exe`").
6.  **Obfuscation/Evasion Techniques Observed:** Detail any detected methods (e.g., name hex-encoding, use of FlateDecode on JS).
7.  **Commands Executed:** A brief log of commands you chose to run during the analysis.

Critical Constraints:
*   You ONLY use the provided whitelisted shell commands.
*   You interpret the *output* of these commands. You do not have direct access to the binary PDF.
*   Your primary value is deep, reasoned analysis of PDF properties *as revealed by the tools* to uncover intent and capability.

Begin your analysis when provided with the initial PDF information and scan results. Be thorough, be precise.
"""



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
        "file",
        "grep",
        "cat",
        "strings",
    ]

    # Allowlist of Python scripts. Assumes they are found relative to CWD or have paths.
    # The agent will call them like "python3 script_name.py arguments"
    ALLOWED_PYTHON_SCRIPTS: list[str] = [
        "pdf-parser.py",
        "pdfid.py",
        "rtfobj.py",
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
    initial_command = f"python3 pdfid.py -f \"{state['pdf_filepath']}\"" 
    print(f"INITIALIZE: Automatically running: {initial_command}")
    initial_output = safe_shell_tool.invoke(initial_command) # Use the tool instance
    
    initial_command_history_entry = {
        "reasoning": "Automated initial overview scan.",
        "command": initial_command,
        "output": initial_output,
    }
    # --- End of automatic scan ---

    initial_system_message = SystemMessage(
        content=SYSTEM_PROMPT_CONTENT.format(
            ALLOWED_EXECUTABLES_STR=", ".join(safe_shell_tool.ALLOWED_EXECUTABLES),
            ALLOWED_PYTHON_SCRIPTS_STR=", ".join([f"python3 {s}" for s in safe_shell_tool.ALLOWED_PYTHON_SCRIPTS])
        )
    )
        
    initial_human_message_content = (
        f"{state['original_user_request']}\n\n"
        f"The initial `pdfid.py -f` scan output is:\n" # Changed
        f"```\n{initial_output}\n```\n\n"
        "Please begin your detailed analysis by planning the next command based on this initial information."
    )
    initial_human_message = HumanMessage(content=initial_human_message_content)
    
    return {
        **state,
        "messages": [initial_system_message, initial_human_message],
        "command_history": [initial_command_history_entry], # Start history with this command
        "accumulated_findings": [], 
        "current_iteration": 0, # This first auto-step doesn't count as an LLM iteration yet
        "analysis_complete": False,
        "final_report": None,
    }

def plan_next_command(state: PDFAnalysisState) -> PDFAnalysisState:
    """LLM plans the next command based on the current state and history."""
    messages_for_llm = state["messages"] + [
        HumanMessage(
            content=f"Current Iteration: {state['current_iteration']}. "
                    f"PDF under analysis: {state['pdf_filepath']}.\n"
                    f"Accumulated Findings So Far: {state['accumulated_findings']}\n"
                    f"Command History (last 3): {state['command_history'][-3:] if state['command_history'] else 'None'}\n\n"
                    "Based on the analysis so far and your overall goal, what is the next logical shell command to run? "
                    "Provide your reasoning and the exact command in JSON format: "
                    '{"reasoning": "your reasoning here", "command_to_run": "your shell command here"}. '
                    "If you think the analysis is complete or you've reached a dead end, output "
                    '{"reasoning": "reason for completion", "command_to_run": "ANALYSIS_COMPLETE"}.'
        )
    ]
    
    response = llm.invoke(messages_for_llm)
    
    try:
        parsed_response = json.loads(response.content)
        reasoning = parsed_response.get("reasoning", "No reasoning provided.")
        command = parsed_response.get("command_to_run")

        if command == "ANALYSIS_COMPLETE":
            return {**state, "messages": state["messages"] + [response], "analysis_complete": True, "command_reasoning": reasoning}
        elif command:
            return {**state, "messages": state["messages"] + [response], "next_command_to_run": command, "command_reasoning": reasoning, "analysis_complete": False}
        else:
            # LLM failed to provide a command or ANALYSIS_COMPLETE
            return {**state, "messages": state["messages"] + [response, HumanMessage(content="LLM did not provide a valid command or ANALYSIS_COMPLETE. Assuming analysis is stuck or complete.")], "analysis_complete": True, "command_reasoning": "LLM response error."}

    except json.JSONDecodeError:
        # LLM didn't output valid JSON
        return {**state, "messages": state["messages"] + [response, HumanMessage(content="LLM output was not valid JSON. Assuming analysis is stuck or complete.")], "analysis_complete": True, "command_reasoning": "LLM JSON parsing error."}


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
    """LLM interprets the command output and updates findings."""
    last_command_info = state["command_history"][-1] if state["command_history"] else {}
    
    messages_for_llm = state["messages"] + [
        HumanMessage(
            content=f"Command Executed: {last_command_info.get('command', 'N/A')}\n"
                    f"Its Output Was:\n{last_command_info.get('output', 'N/A')}\n\n"
                    "Interpret this output. What new information or suspicious indicators have you found? "
                    "List any new findings as a JSON list of strings. "
                    'Example: {"new_findings": ["Found an /OpenAction tag.", "Object 12 contains a large hex-encoded stream."]}'
                    "If no new significant findings, provide an empty list: {\"new_findings\": []}"
        )
    ]
    
    response = llm.invoke(messages_for_llm)
    
    new_findings = []
    try:
        parsed_response = json.loads(response.content)
        new_findings = parsed_response.get("new_findings", [])
        if not isinstance(new_findings, list): new_findings = []
    except json.JSONDecodeError:
        # LLM didn't output valid JSON for findings
        new_findings = ["LLM interpretation error: could not parse new_findings JSON."]
        
    return {
        **state,
        "messages": state["messages"] + [response],
        "accumulated_findings": state["accumulated_findings"] + new_findings,
    }

def compile_final_report(state: PDFAnalysisState) -> PDFAnalysisState:
    """LLM compiles the final report based on all findings and history."""
    messages_for_llm = state["messages"] + [
        HumanMessage(
            content="The analysis is now complete. Please provide a comprehensive final report. "
                    "Summarize the original request, all commands executed with their key outputs (briefly), "
                    "and all accumulated findings. Conclude with an overall threat assessment of the PDF."
        )
    ]
    
    response = llm.invoke(messages_for_llm)
    return {**state, "messages": state["messages"] + [response], "final_report": response.content}


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
