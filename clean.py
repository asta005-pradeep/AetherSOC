import os
import shutil
import glob

def clean_project(directory):
    print(f"Cleaning project directory: {directory}")
    
    # Remove __pycache__ directories
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in dirs:
            if name == '__pycache__':
                dir_path = os.path.join(root, name)
                print(f"Removing directory: {dir_path}")
                shutil.rmtree(dir_path, ignore_errors=True)
                
    # Remove .pyc files
    for root, dirs, files in os.walk(directory):
        for name in files:
            if name.endswith('.pyc') or name.endswith('.pyo'):
                file_path = os.path.join(root, name)
                print(f"Removing file: {file_path}")
                try:
                    os.remove(file_path)
                except Exception as e:
                    print(f"Failed to remove {file_path}: {e}")

    # Remove venv or env if they exist (though they shouldn't usually be deleted by a script, 
    # we will do it here if explicitly requested, but let's check if they exist first)
    for venv_dir in ['venv', 'env']:
        venv_path = os.path.join(directory, venv_dir)
        if os.path.exists(venv_path) and os.path.isdir(venv_path):
            print(f"Removing virtual environment: {venv_path}")
            shutil.rmtree(venv_path, ignore_errors=True)
            
    print("\nCleanup complete! Your folder is ready for GitHub.")

if __name__ == '__main__':
    current_dir = os.path.dirname(os.path.abspath(__file__))
    clean_project(current_dir)
