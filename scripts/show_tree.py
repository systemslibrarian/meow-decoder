import os
from pathlib import Path

def show_tree(directory, prefix="", ignore_patterns=None):
    """Show directory tree structure."""
    if ignore_patterns is None:
        ignore_patterns = ['__pycache__', '.pyc', '.pytest_cache', 'htmlcov', '.egg-info', '.git']
    
    items = sorted(Path(directory).iterdir(), key=lambda x: (not x.is_dir(), x.name))
    items = [x for x in items if not any(pattern in str(x) for pattern in ignore_patterns)]
    
    for i, item in enumerate(items):
        is_last = i == len(items) - 1
        current_prefix = "└── " if is_last else "├── "
        
        if item.is_dir():
            print(f"{prefix}{current_prefix}{item.name}/")
            extension = "    " if is_last else "│   "
            show_tree(item, prefix + extension, ignore_patterns)
        else:
            print(f"{prefix}{current_prefix}{item.name}")

print("meow-decoder/")
show_tree(".", ignore_patterns=['__pycache__', '.pyc', '.pytest_cache', 'htmlcov', '.egg-info'])
