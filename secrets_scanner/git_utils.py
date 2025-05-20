#!/usr/bin/env python3
"""
Git utilities for the enhanced Python secrets scanner.
"""

import os
import subprocess
from typing import List, Tuple


class GitUtils:
    """
    Utility class for Git operations.
    
    Provides methods to interact with Git repositories, check if files are
    gitignored, and analyze Git history.
    """
    
    @staticmethod
    def is_git_repository(directory: str = ".") -> bool:
        """
        Check if the directory is a Git repository.
        
        Args:
            directory: Directory to check
            
        Returns:
            True if the directory is a Git repository, False otherwise
        """
        try:
            result = subprocess.run(
                ["git", "-C", directory, "rev-parse", "--is-inside-work-tree"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            return result.returncode == 0 and result.stdout.strip() == "true"
        except Exception:
            return False
    
    @staticmethod
    def get_gitignore_patterns(directory: str = ".") -> List[str]:
        """
        Get the patterns from .gitignore file.
        
        Args:
            directory: Directory containing the .gitignore file
            
        Returns:
            List of patterns from the .gitignore file
        """
        gitignore_path = os.path.join(directory, ".gitignore")
        patterns = []
        
        if os.path.isfile(gitignore_path):
            try:
                with open(gitignore_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        patterns.append(line)
            except Exception as e:
                print(f"⚠️ Warning: Could not read .gitignore file: {e}")
        
        return patterns
    
    @staticmethod
    def is_file_gitignored(file_path: str, directory: str = ".") -> bool:
        """
        Check if a file is ignored by Git.
        
        Args:
            file_path: Path to the file to check
            directory: Directory containing the Git repository
            
        Returns:
            True if the file is gitignored, False otherwise
        """
        try:
            result = subprocess.run(
                ["git", "-C", directory, "check-ignore", "-q", file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            return result.returncode == 0
        except Exception:
            return False
    
    @staticmethod
    def is_file_still_tracked(file_path: str, directory: str = ".") -> bool:
        """
        Check if a file is still tracked by Git.
        
        Args:
            file_path: Path to the file to check
            directory: Directory containing the Git repository
            
        Returns:
            True if the file is still tracked, False otherwise
        """
        try:
            result = subprocess.run(
                ["git", "-C", directory, "ls-files", "--error-unmatch", file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            return result.returncode == 0
        except Exception:
            return False
    
    @staticmethod
    def is_file_in_git_history(file_path: str, directory: str = ".") -> bool:
        """
        Check if a file has been previously committed to Git.
        
        Args:
            file_path: Path to the file to check
            directory: Directory containing the Git repository
            
        Returns:
            True if the file is in Git history, False otherwise
        """
        try:
            rel_path = os.path.relpath(file_path, directory)
            result = subprocess.run(
                ["git", "-C", directory, "log", "--all", "--name-only", "--format=format:", "--", rel_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            return bool(result.stdout.strip())
        except Exception as e:
            print(f"⚠️ Warning: Could not check git history for {file_path}: {e}")
            return False
    
    @staticmethod
    def get_historical_files(directory: str = ".") -> List[Tuple[str, bool]]:
        """
        Get files from Git history that are now gitignored.
        
        Args:
            directory: Directory containing the Git repository
            
        Returns:
            List of tuples containing (file_path, is_still_tracked)
        """
        if not GitUtils.is_git_repository(directory):
            return []
        
        historical_files = []
        
        try:
            # Get all files that have ever been in Git history
            result = subprocess.run(
                ["git", "-C", directory, "log", "--all", "--name-only", "--format=format:"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            
            # Create a set of unique file paths from history
            all_historical_paths = set()
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    full_path = os.path.abspath(os.path.join(directory, line.strip()))
                    all_historical_paths.add(full_path)
            
            # Check which files are now gitignored but still exist
            for file_path in all_historical_paths:
                if not os.path.exists(file_path):
                    continue
                
                # Check if file is gitignored
                is_ignored = GitUtils.is_file_gitignored(file_path, directory)
                if is_ignored:
                    # Check if file is still tracked despite being gitignored
                    is_tracked = GitUtils.is_file_still_tracked(file_path, directory)
                    historical_files.append((file_path, is_tracked))
            
            return historical_files
            
        except Exception as e:
            print(f"⚠️ Error analyzing Git history: {e}")
            return []
