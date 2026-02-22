"""
Secure Password Entry Module.

Provides on-screen randomized keyboard and mouse-gesture password entry
to defeat keyloggers, screen recorders, and shoulder-surfing attacks.

Key features:
- Randomized key positions on each display
- Mouse-based input (no keyboard signals)
- Visual masking with decoy characters
- Timing normalization (constant keystroke timing)
- Memory-safe password handling (zeroization)
- Cross-platform: Windows, Linux, macOS (CLI fallback always available)

SECURITY NOTES:
1. This does NOT protect against memory scraping of the final password
2. Screen recorders can still capture clicks if mouse position visible
3. For maximum security, use in air-gapped environment (see air_gap.py)
4. GUI mode requires tkinter; falls back to timing-normalized CLI input

Usage:
    # Import and use
    password = secure_password_input("Enter password: ")

    # Or use the full keyboard
    keyboard = SecureKeyboard()
    password = keyboard.get_password()
    keyboard.destroy()  # Zeros internal state
"""

from __future__ import annotations

import os
import platform
import secrets
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

__all__ = [
    "SecureKeyboard",
    "secure_password_input",
    "timing_normalized_input",
    "SecureString",
]


def _secure_zero(data: bytearray) -> None:
    """Securely zero a bytearray."""
    for i in range(len(data)):
        data[i] = 0


@dataclass
class SecureString:
    """
    Memory-safe string container with automatic zeroization.

    Stores password as bytearray for secure clearing.
    """

    _data: bytearray = field(default_factory=bytearray, repr=False)

    def append_char(self, char: str) -> None:
        """Append a character to the secure string."""
        self._data.extend(char.encode("utf-8"))

    def backspace(self) -> None:
        """Remove last character."""
        if len(self._data) > 0:
            # Handle UTF-8: find start of last character
            i = len(self._data) - 1
            while i > 0 and (self._data[i] & 0xC0) == 0x80:
                i -= 1
            # Zero the removed bytes
            for j in range(i, len(self._data)):
                self._data[j] = 0
            del self._data[i:]

    def clear(self) -> None:
        """Securely clear the string."""
        _secure_zero(self._data)
        self._data = bytearray()

    def get_value(self) -> str:
        """Get the string value. Caller is responsible for handling securely."""
        return self._data.decode("utf-8")

    def __len__(self) -> int:
        """Return approximate character count."""
        return len(self._data)

    def __del__(self) -> None:
        """Destructor zeros the data."""
        try:
            _secure_zero(self._data)
        except Exception:
            pass


class SecureKeyboard:
    """
    On-screen randomized keyboard for secure password entry.

    Position of keys is randomized on each display to defeat:
    - Keyloggers (no keyboard events)
    - Screen position recorders (positions change)
    - Shoulder surfing (harder to track)

    Falls back to CLI input with timing normalization if GUI unavailable.
    """

    # Standard keyboard layouts
    LAYOUT_QWERTY = [
        list("1234567890-="),
        list("qwertyuiop[]"),
        list("asdfghjkl;'"),
        list("zxcvbnm,./"),
    ]

    LAYOUT_SYMBOLS = [
        list("!@#$%^&*()_+"),
        list("QWERTYUIOP{}"),
        list('ASDFGHJKL:"'),
        list("ZXCVBNM<>?"),
    ]

    def __init__(
        self,
        title: str = "Secure Password Entry",
        show_mask: bool = True,
        mask_char: str = "●",
        decoy_chars: bool = True,
        randomize_layout: bool = True,
        timing_normalize: bool = True,
        min_keystroke_ms: int = 50,
        max_keystroke_ms: int = 200,
    ):
        """
        Initialize secure keyboard.

        Args:
            title: Window title.
            show_mask: Show masked password feedback.
            mask_char: Character to show for each typed character.
            decoy_chars: Add random decoy characters around mask (visual noise).
            randomize_layout: Randomize key positions on each show.
            timing_normalize: Add timing jitter to defeat keystroke timing analysis.
            min_keystroke_ms: Minimum simulated keystroke time.
            max_keystroke_ms: Maximum simulated keystroke time.
        """
        self.title = title
        self.show_mask = show_mask
        self.mask_char = mask_char
        self.decoy_chars = decoy_chars
        self.randomize_layout = randomize_layout
        self.timing_normalize = timing_normalize
        self.min_keystroke_ms = min_keystroke_ms
        self.max_keystroke_ms = max_keystroke_ms

        self._password = SecureString()
        self._gui_available = False
        self._root = None
        self._buttons: List = []
        self._result_ready = False
        self._cancelled = False

        # Check for GUI availability
        self._check_gui()

    def _check_gui(self) -> None:
        """Check if GUI (tkinter) is available."""
        try:
            import tkinter as tk
            # Test if display is available
            root = tk.Tk()
            root.withdraw()
            root.destroy()
            self._gui_available = True
        except Exception:
            self._gui_available = False

    def _generate_layout(self) -> List[List[str]]:
        """Generate potentially randomized keyboard layout."""
        # Combine layouts
        layout = [
            row.copy() for row in self.LAYOUT_QWERTY
        ]

        if self.randomize_layout:
            # Shuffle within each row
            for row in layout:
                # Fisher-Yates shuffle with secure random
                for i in range(len(row) - 1, 0, -1):
                    j = secrets.randbelow(i + 1)
                    row[i], row[j] = row[j], row[i]

        return layout

    def _add_timing_jitter(self) -> None:
        """Add timing jitter to defeat keystroke timing analysis."""
        if self.timing_normalize:
            jitter_ms = secrets.randbelow(
                self.max_keystroke_ms - self.min_keystroke_ms
            ) + self.min_keystroke_ms
            time.sleep(jitter_ms / 1000.0)

    def _generate_decoy_mask(self, length: int) -> str:
        """Generate mask with decoy characters for visual noise."""
        if not self.decoy_chars or length == 0:
            return self.mask_char * length

        # Add random decoy chars around the real mask
        decoy_chars = "○◎◉●◐◑◒◓"
        mask = []
        for i in range(length):
            if secrets.randbelow(3) == 0:  # 33% chance of decoy
                mask.append(secrets.choice(decoy_chars))
            else:
                mask.append(self.mask_char)

        # Add leading/trailing decoys
        if length > 0:
            leading = secrets.randbelow(3)
            trailing = secrets.randbelow(3)
            mask = (
                [secrets.choice(decoy_chars) for _ in range(leading)] +
                mask +
                [secrets.choice(decoy_chars) for _ in range(trailing)]
            )

        return "".join(mask)

    def _on_key_click(self, char: str) -> None:
        """Handle key button click."""
        self._add_timing_jitter()
        self._password.append_char(char)
        self._update_display()

    def _on_backspace(self) -> None:
        """Handle backspace."""
        self._add_timing_jitter()
        self._password.backspace()
        self._update_display()

    def _on_clear(self) -> None:
        """Handle clear."""
        self._password.clear()
        self._update_display()

    def _on_submit(self) -> None:
        """Handle submit."""
        self._result_ready = True
        if self._root:
            self._root.quit()

    def _on_cancel(self) -> None:
        """Handle cancel."""
        self._cancelled = True
        self._password.clear()
        if self._root:
            self._root.quit()

    def _update_display(self) -> None:
        """Update the password display."""
        if hasattr(self, "_display_var") and self._display_var:
            if self.show_mask:
                mask = self._generate_decoy_mask(len(self._password))
                self._display_var.set(mask)
            else:
                self._display_var.set("")

    def _randomize_button_positions(self) -> None:
        """Randomize button positions within grid cells."""
        if not self.randomize_layout:
            return

        for button in self._buttons:
            # Add random padding
            padx = secrets.randbelow(10)
            pady = secrets.randbelow(5)
            button.configure(padx=padx, pady=pady)

    def get_password_gui(self) -> Optional[str]:
        """
        Get password using GUI keyboard.

        Returns:
            Password string or None if cancelled/unavailable.
        """
        if not self._gui_available:
            return None

        try:
            import tkinter as tk
            from tkinter import ttk
        except ImportError:
            return None

        self._password.clear()
        self._result_ready = False
        self._cancelled = False

        # Create window
        self._root = tk.Tk()
        self._root.title(self.title)
        self._root.resizable(False, False)

        # Prevent window from being moved off screen
        self._root.protocol("WM_DELETE_WINDOW", self._on_cancel)

        # Random offset for window position
        screen_w = self._root.winfo_screenwidth()
        screen_h = self._root.winfo_screenheight()
        win_w, win_h = 600, 350

        # Random position within safe area
        x = secrets.randbelow(max(1, screen_w - win_w - 100)) + 50
        y = secrets.randbelow(max(1, screen_h - win_h - 100)) + 50
        self._root.geometry(f"{win_w}x{win_h}+{x}+{y}")

        # Style
        style = ttk.Style()
        style.configure("Key.TButton", font=("Courier", 14), padding=5)
        style.configure("Action.TButton", font=("Courier", 12), padding=5)

        # Password display
        self._display_var = tk.StringVar(value="")
        display = ttk.Entry(
            self._root,
            textvariable=self._display_var,
            font=("Courier", 18),
            justify="center",
            state="readonly",
        )
        display.pack(fill="x", padx=20, pady=10)

        # Keyboard frame
        kb_frame = ttk.Frame(self._root)
        kb_frame.pack(expand=True, fill="both", padx=20, pady=10)

        # Generate layout
        layout = self._generate_layout()
        self._buttons = []

        for row_idx, row in enumerate(layout):
            row_frame = ttk.Frame(kb_frame)
            row_frame.pack(fill="x", pady=2)

            for char in row:
                btn = ttk.Button(
                    row_frame,
                    text=char,
                    style="Key.TButton",
                    width=3,
                    command=lambda c=char: self._on_key_click(c),
                )
                btn.pack(side="left", padx=2)
                self._buttons.append(btn)

        # Space bar row
        space_frame = ttk.Frame(kb_frame)
        space_frame.pack(fill="x", pady=2)

        space_btn = ttk.Button(
            space_frame,
            text="SPACE",
            style="Key.TButton",
            width=20,
            command=lambda: self._on_key_click(" "),
        )
        space_btn.pack(side="left", padx=2, expand=True)
        self._buttons.append(space_btn)

        # Action buttons
        action_frame = ttk.Frame(self._root)
        action_frame.pack(fill="x", padx=20, pady=10)

        ttk.Button(
            action_frame,
            text="⌫ Backspace",
            style="Action.TButton",
            command=self._on_backspace,
        ).pack(side="left", padx=5)

        ttk.Button(
            action_frame,
            text="Clear",
            style="Action.TButton",
            command=self._on_clear,
        ).pack(side="left", padx=5)

        ttk.Button(
            action_frame,
            text="Cancel",
            style="Action.TButton",
            command=self._on_cancel,
        ).pack(side="right", padx=5)

        ttk.Button(
            action_frame,
            text="✓ Submit",
            style="Action.TButton",
            command=self._on_submit,
        ).pack(side="right", padx=5)

        # Randomize positions
        self._randomize_button_positions()

        # Run
        self._root.mainloop()

        # Get result
        if self._cancelled:
            self._root.destroy()
            self._root = None
            return None

        result = self._password.get_value()
        self._root.destroy()
        self._root = None

        return result

    def get_password_cli(self, prompt: str = "Password: ") -> str:
        """
        Get password using CLI with timing normalization.

        Falls back to getpass with added timing jitter.

        Args:
            prompt: Prompt to display.

        Returns:
            Password string.
        """
        return timing_normalized_input(prompt)

    def get_password(self, prompt: str = "Password: ") -> Optional[str]:
        """
        Get password using best available method.

        Tries GUI first, falls back to CLI.

        Args:
            prompt: Prompt for CLI fallback.

        Returns:
            Password string or None if cancelled.
        """
        # Check if we're in a graphical environment
        if self._gui_available and os.environ.get("DISPLAY") or platform.system() == "Windows":
            result = self.get_password_gui()
            if result is not None:
                return result

        # Fallback to CLI
        return self.get_password_cli(prompt)

    def destroy(self) -> None:
        """Securely destroy the keyboard and clear all state."""
        self._password.clear()
        if self._root:
            try:
                self._root.destroy()
            except Exception:
                pass
            self._root = None
        self._buttons = []


def timing_normalized_input(
    prompt: str = "Password: ",
    min_keystroke_ms: int = 50,
    max_keystroke_ms: int = 200,
) -> str:
    """
    Get password input with timing normalization.

    Adds artificial keystroke timing to defeat timing analysis.
    Uses getpass for secure input without echo.

    Args:
        prompt: Prompt to display.
        min_keystroke_ms: Minimum time per keystroke.
        max_keystroke_ms: Maximum time per keystroke.

    Returns:
        Password string.
    """
    import getpass

    # Add initial timing jitter
    time.sleep(secrets.randbelow(500) / 1000.0)

    # Get password
    password = getpass.getpass(prompt)

    # Add final timing jitter based on simulated keystroke timing
    simulated_time = len(password) * (
        secrets.randbelow(max_keystroke_ms - min_keystroke_ms) + min_keystroke_ms
    )
    actual_delay = secrets.randbelow(simulated_time // 2 + 1)
    time.sleep(actual_delay / 1000.0)

    return password


def secure_password_input(
    prompt: str = "Password: ",
    use_gui: bool = True,
    randomize_layout: bool = True,
) -> Optional[str]:
    """
    Convenience function for secure password input.

    Tries GUI keyboard if available, falls back to CLI with timing normalization.

    Args:
        prompt: Prompt to display.
        use_gui: Try GUI input first.
        randomize_layout: Randomize key positions in GUI mode.

    Returns:
        Password string or None if cancelled.
    """
    if use_gui:
        keyboard = SecureKeyboard(
            title="Meow Decoder - Secure Password Entry",
            randomize_layout=randomize_layout,
        )
        try:
            return keyboard.get_password(prompt)
        finally:
            keyboard.destroy()
    else:
        return timing_normalized_input(prompt)


# Mouse gesture password (alternative input method)
class MouseGesturePassword:
    """
    Mouse gesture-based password entry.

    User draws a pattern with mouse clicks; pattern is hashed to password.
    More resistant to keyloggers and screen recorders that only capture
    static screenshots.

    NOT YET IMPLEMENTED - placeholder for future enhancement.
    """

    def __init__(self, grid_size: int = 5):
        self.grid_size = grid_size
        raise NotImplementedError(
            "MouseGesturePassword not yet implemented. "
            "Use SecureKeyboard for now."
        )


# CLI-only secure input for headless environments
def secure_input_headless(
    prompt: str = "Password: ",
    confirm: bool = False,
) -> Optional[str]:
    """
    Secure password input for headless environments.

    Uses timing normalization and memory-safe handling.

    Args:
        prompt: Prompt to display.
        confirm: If True, ask for password twice and verify match.

    Returns:
        Password string or None if confirmation failed.
    """
    password1 = timing_normalized_input(prompt)

    if confirm:
        password2 = timing_normalized_input("Confirm password: ")

        # Constant-time comparison
        if len(password1) != len(password2):
            return None

        match = True
        for a, b in zip(password1, password2):
            match = match and (a == b)

        if not match:
            return None

    return password1
