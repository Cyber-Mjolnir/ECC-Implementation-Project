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
        return result.stdout.strip(), result.returncode
    except Exception:
        return "", 1

def automate_git():
    print("Checking changes...")
    subprocess.run("git add .", shell=True)
    
    # We use --stat to get just the file names and number of lines changed.
    # This is MUCH smaller than a full diff, making the prompt faster.
    diff_stat, code = run_command("git diff --cached --stat")
    
    if not diff_stat:
        print("No changes found.")
        return

    print("Requesting 1-sentence summary...")
    
    # Keeping the prompt extremely short to reduce processing time
    prompt = f"Write a 5-word commit message for these files: {diff_stat}"
    
    # Using the -p flag for non-interactive mode as you requested
    output, code = run_command(f'gemini -p "{prompt}"')

    # Logic to handle if Gemini is slow or failing
    if code != 0 or not output:
        commit_msg = input("Gemini failed. Enter message manually: ")
    else:
        # Get only the last line (ignores the 'Loaded credentials' logs)
        commit_msg = output.split('\n')[-1].strip()
        print(f"Suggested: {commit_msg}")
        
    if commit_msg:
        subprocess.run(f'git commit -m "{commit_msg}"', shell=True)
        print("Pushing...")
        subprocess.run("git push origin main", shell=True)

if __name__ == "__main__":
    automate_git()