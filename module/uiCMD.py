import shutil
import os

def get_center_padding(text):
    """Calculates spaces needed to center text based on terminal width."""
    columns = shutil.get_terminal_size().columns
    padding = (columns - len(text)) // 2
    return " " * max(0, padding)

def center_print(text):
    """Prints text centered in the terminal."""
    print(get_center_padding(text) + text)
    
    
def clear_console():
    """Clears terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')