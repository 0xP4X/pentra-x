#!/usr/bin/env python3
"""
PENTRA-X Progress Indicators
Spinner and progress bar classes for visual feedback during long operations.
"""

import sys
import time
import threading
from typing import Optional, List

from .colors import Colors


class Spinner:
    """Enhanced spinner with multiple animation styles and progress tracking."""
    
    SPINNER_STYLES = {
        'dots': ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
        'line': ['|', '/', '-', '\\'],
        'arrow': ['←', '↖', '↑', '↗', '→', '↘', '↓', '↙'],
        'box': ['▖', '▘', '▝', '▗'],
        'bounce': ['⠁', '⠂', '⠄', '⡀', '⢀', '⠠', '⠐', '⠈'],
        'pulse': ['█', '▓', '▒', '░', '▒', '▓'],
        'circle': ['◐', '◓', '◑', '◒'],
        'star': ['✶', '✷', '✸', '✹', '✺', '✹', '✸', '✷'],
    }
    
    def __init__(
        self,
        message: str = "Working...",
        style: str = 'dots',
        show_progress: bool = False,
        total: int = 100
    ):
        """
        Initialize spinner.
        
        Args:
            message: Message to display alongside spinner
            style: Animation style from SPINNER_STYLES
            show_progress: Whether to show progress percentage
            total: Total count for progress calculation
        """
        self.message = message
        self.style = style
        self.frames = self.SPINNER_STYLES.get(style, self.SPINNER_STYLES['dots'])
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.show_progress = show_progress
        self.current = 0
        self.total = total
        self.start_time: Optional[float] = None
        
    def start(self) -> 'Spinner':
        """Start the spinner animation. Returns self for chaining."""
        self.running = True
        self.start_time = time.time()
        
        def spin():
            idx = 0
            while self.running:
                frame = self.frames[idx % len(self.frames)]
                
                if self.show_progress:
                    percentage = (self.current / self.total) * 100 if self.total > 0 else 0
                    elapsed = time.time() - self.start_time
                    eta = self._calculate_eta(elapsed)
                    status = f"\r{Colors.OKCYAN}{frame}{Colors.ENDC} {self.message} [{percentage:.1f}%] ETA: {eta}  "
                else:
                    status = f"\r{Colors.OKCYAN}{frame}{Colors.ENDC} {self.message}  "
                
                sys.stdout.write(status)
                sys.stdout.flush()
                time.sleep(0.1)
                idx += 1
        
        self.thread = threading.Thread(target=spin, daemon=True)
        self.thread.start()
        return self
    
    def update_progress(self, current: int, total: Optional[int] = None) -> None:
        """Update progress for progress bar mode."""
        self.current = current
        if total is not None:
            self.total = total
    
    def _calculate_eta(self, elapsed: float) -> str:
        """Calculate estimated time remaining."""
        if self.current <= 0 or elapsed <= 0:
            return "calculating..."
        
        rate = self.current / elapsed
        remaining = self.total - self.current
        eta_seconds = remaining / rate if rate > 0 else 0
        
        if eta_seconds < 60:
            return f"{eta_seconds:.0f}s"
        elif eta_seconds < 3600:
            return f"{eta_seconds / 60:.1f}m"
        else:
            return f"{eta_seconds / 3600:.1f}h"
    
    def stop(self, success: bool = True) -> None:
        """Stop the spinner with optional success indicator."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
        
        # Clear the line
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()
        
        # Print final status
        if success:
            print(f"{Colors.OKGREEN}✓{Colors.ENDC} {self.message} - Done!")
        else:
            print(f"{Colors.FAIL}✗{Colors.ENDC} {self.message} - Failed!")
    
    def __enter__(self) -> 'Spinner':
        """Context manager entry."""
        return self.start()
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.stop(success=exc_type is None)


class ProgressBar:
    """Simple progress bar for operations with known total."""
    
    def __init__(self, total: int, description: str = "Progress", width: int = 40):
        """
        Initialize progress bar.
        
        Args:
            total: Total number of items
            description: Description text
            width: Width of the progress bar in characters
        """
        self.total = total
        self.current = 0
        self.description = description
        self.width = width
        self.start_time = time.time()
    
    def update(self, increment: int = 1) -> None:
        """Update progress by increment."""
        self.current = min(self.current + increment, self.total)
        self._display()
    
    def set_progress(self, current: int) -> None:
        """Set current progress to a specific value."""
        self.current = min(current, self.total)
        self._display()
    
    def _display(self) -> None:
        """Display the progress bar."""
        percentage = (self.current / self.total) * 100 if self.total > 0 else 0
        filled = int(self.width * self.current / self.total) if self.total > 0 else 0
        
        bar = '█' * filled + '░' * (self.width - filled)
        
        # Calculate elapsed and ETA
        elapsed = time.time() - self.start_time
        if self.current > 0:
            eta_seconds = (elapsed / self.current) * (self.total - self.current)
            eta = f"{eta_seconds:.0f}s" if eta_seconds < 60 else f"{eta_seconds / 60:.1f}m"
        else:
            eta = "..."
        
        status = f"\r{Colors.OKCYAN}{self.description}{Colors.ENDC} |{bar}| {percentage:.1f}% ETA: {eta}  "
        sys.stdout.write(status)
        sys.stdout.flush()
    
    def finish(self, success: bool = True) -> None:
        """Finish the progress bar."""
        self.current = self.total
        self._display()
        print()  # New line
        
        if success:
            print(f"{Colors.OKGREEN}[+] {self.description} completed!{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[-] {self.description} failed!{Colors.ENDC}")
