from langchain_core.tools import BaseTool
import os
import shlex
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent.parent.parent / "analysis_tools"


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
        

        if (
            len(command_parts) > 1
            and command_parts[0] == "python3"
            and (script_name := os.path.basename(command_parts[1])) in self.ALLOWED_PYTHON_SCRIPTS
        ):
            abs_path = SCRIPT_DIR / script_name      # analysis_tools/pdfid.py …
            command_parts[1] = str(abs_path)

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