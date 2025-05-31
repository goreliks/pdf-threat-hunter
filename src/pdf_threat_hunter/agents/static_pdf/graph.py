import os
import json
import uuid
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from pdf_threat_hunter.core.state import PDFAnalysisState
from pdf_threat_hunter.tools.safe_shell import SafeShellTool
from dotenv import load_dotenv

load_dotenv()


with open("src/pdf_threat_hunter/agents/static_pdf/prompt.md", "r") as f:
    SYSTEM_PROMPT_CONTENT = f.read()


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
# memory = MemorySaver() 
# app = workflow.compile(checkpointer=memory)

app = workflow.compile()



# --- Running the Graph ---
if __name__ == "__main__":
    pdf_to_analyze = "./hello_world_js.pdf" # <--- Or your desired PDF path
    
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