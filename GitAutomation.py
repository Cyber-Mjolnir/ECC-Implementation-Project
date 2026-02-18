import subprocess
import sys

def run_command(command):
    try:
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            shell=True, 
            encoding='utf-8', 
            errors='replace'
        )
        # We return both the output and the error code
        return result.stdout.strip(), result.returncode, result.stderr
    except Exception as e:
        return "", 1, str(e)

def automate_git():
    print("Checking for changes...")
    subprocess.run("git add .", shell=True)
    
    diff_changes, code, err = run_command("git diff --cached")
    
    if not diff_changes:
        print("No changes detected. Nothing to commit.")
        return

    print("Generating commit message via Gemini...")
    prompt = f"Summarize these changes in one short sentence: {diff_changes[:1500]}"
    
    # Try to get message from Gemini
    gemini_output, code, err = run_command(f'gemini --prompt "{prompt}"')

    # If Gemini fails (Error 429 or any other error)
    if code != 0 or "error" in gemini_output.lower() or not gemini_output:
        print("\n[!] Gemini is currently unavailable (Rate limited or Server busy).")
        commit_message = input("Please enter a manual commit message: ").strip()
    else:
        # Clean the output in case Gemini CLI includes headers/logs
        # Usually, we want the last line of the output if it's chatty
        commit_message = gemini_output.split('\n')[-1].replace('"', '').strip()
        print(f"Gemini suggested: {commit_message}")
        confirm = input("Use this message? (y/n): ").lower()
        if confirm != 'y':
            commit_message = input("Enter manual message: ").strip()

    if not commit_message:
        print("Commit cancelled.")
        return

    # Commit and Push
    print(f"Committing: {commit_message}")
    subprocess.run(f'git commit -m "{commit_message}"', shell=True)
    
    print("Pushing to GitHub...")
    subprocess.run("git push origin main", shell=True) 

if __name__ == "__main__":
    automate_git()