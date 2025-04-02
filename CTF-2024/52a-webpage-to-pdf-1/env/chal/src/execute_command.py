# Thanks LLM, I am a full-stack python programmer with security in mind now!
# https://poe.com/s/wuK3sK1GFql2Ay3A8EfO

import subprocess
import shlex

def execute_command(command):
    """
    Execute an external OS program securely with the provided command.

    Args:
        command (str): The command to execute.

    Returns:
        tuple: (stdout, stderr, return_code)
    """
    # Split the command into arguments safely
    args = shlex.split(command)

    try:
        # Execute the command and capture the output
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True  # Raises CalledProcessError for non-zero exit codes
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.CalledProcessError as e:
        # Return the error output and return code if command fails
        return e.stdout, e.stderr, e.returncode

# Example usage
if __name__ == "__main__":
    command = "ls -l"  # Replace with your command
    stdout, stderr, return_code = execute_command(command)
    print("STDOUT:", stdout)
    print("STDERR:", stderr)
    print("Return Code:", return_code)