"""
🐱 ASCII Terminal QR Code Generator
Renders QR codes directly in terminal using Unicode block characters

Inspired by TXQR's qrterminal approach.
Useful for headless servers and SSH sessions.

Features:
- Pure ASCII/Unicode rendering (no GUI required)
- Multiple output modes (ASCII, Unicode blocks, colored)
- Compact and large display options
- Works over SSH
"""

import sys
import shutil
from typing import Optional, List
import qrcode
from qrcode.constants import ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q, ERROR_CORRECT_H


# Unicode block characters for QR rendering
BLOCKS = {
    'full': '█',
    'upper_half': '▀',
    'lower_half': '▄',
    'empty': ' ',
    # ASCII fallbacks
    'ascii_full': '##',
    'ascii_empty': '  ',
}


class ASCIIQRCode:
    """
    ASCII/Unicode QR code renderer for terminal display.
    
    Renders QR codes using Unicode block characters or ASCII art.
    Each terminal "pixel" can represent 2 QR modules vertically
    using half-block characters for compact display.
    """
    
    # ANSI color codes
    WHITE_BG = "\033[47m"
    BLACK_BG = "\033[40m"
    WHITE_FG = "\033[97m"
    BLACK_FG = "\033[30m"
    RESET = "\033[0m"
    INVERT = "\033[7m"
    
    def __init__(self, data: str, error_correction: str = 'M',
                 box_size: int = 1, border: int = 2):
        """
        Initialize ASCII QR code.
        
        Args:
            data: Data to encode in QR code
            error_correction: Error correction level (L/M/Q/H)
            box_size: Not used for ASCII (kept for API compatibility)
            border: Border size in modules
        """
        self.data = data
        self.border = border
        
        # Map error correction
        ec_map = {
            'L': ERROR_CORRECT_L,
            'M': ERROR_CORRECT_M,
            'Q': ERROR_CORRECT_Q,
            'H': ERROR_CORRECT_H,
        }
        self.error_correction = ec_map.get(error_correction.upper(), ERROR_CORRECT_M)
        
        # Generate QR code
        self.qr = qrcode.QRCode(
            version=None,  # Auto-detect
            error_correction=self.error_correction,
            box_size=1,
            border=border,
        )
        self.qr.add_data(data)
        self.qr.make(fit=True)
        
        # Get matrix
        self.matrix = self.qr.get_matrix()
        self.size = len(self.matrix) if self.matrix else 0
    
    def render_unicode(self, invert: bool = False) -> str:
        """
        Render QR code using Unicode half-block characters.
        
        This is the most compact representation - each terminal row
        displays 2 QR rows using ▀ (upper half) and ▄ (lower half).
        
        Args:
            invert: Invert colors (white on black vs black on white)
            
        Returns:
            String representation of QR code
        """
        if not self.matrix:
            return ""
        
        lines = []
        height = len(self.matrix)
        width = len(self.matrix[0]) if height > 0 else 0
        
        # Process two rows at a time
        for row in range(0, height, 2):
            line = ""
            for col in range(width):
                top = self.matrix[row][col]
                bottom = self.matrix[row + 1][col] if row + 1 < height else False
                
                if invert:
                    top, bottom = not top, not bottom
                
                # Select character based on pattern
                if top and bottom:
                    line += BLOCKS['full']
                elif top and not bottom:
                    line += BLOCKS['upper_half']
                elif not top and bottom:
                    line += BLOCKS['lower_half']
                else:
                    line += BLOCKS['empty']
            
            lines.append(line)
        
        return '\n'.join(lines)
    
    def render_ascii(self, invert: bool = False) -> str:
        """
        Render QR code using pure ASCII characters.
        
        Less compact but works on systems without Unicode support.
        Uses ## for black modules and spaces for white.
        
        Args:
            invert: Invert colors
            
        Returns:
            ASCII string representation
        """
        if not self.matrix:
            return ""
        
        lines = []
        for row in self.matrix:
            line = ""
            for cell in row:
                if invert:
                    cell = not cell
                line += BLOCKS['ascii_full'] if cell else BLOCKS['ascii_empty']
            lines.append(line)
        
        return '\n'.join(lines)
    
    def render_large(self, invert: bool = False) -> str:
        """
        Render QR code at double size for better visibility.
        
        Each QR module becomes 2x2 characters.
        Good for high-resolution terminals or accessibility.
        
        Args:
            invert: Invert colors
            
        Returns:
            Large string representation
        """
        if not self.matrix:
            return ""
        
        lines = []
        for row in self.matrix:
            line1 = ""
            line2 = ""
            for cell in row:
                if invert:
                    cell = not cell
                char = BLOCKS['full'] * 2 if cell else BLOCKS['empty'] * 2
                line1 += char
                line2 += char
            lines.append(line1)
            lines.append(line2)
        
        return '\n'.join(lines)
    
    def render_colored(self, invert: bool = True) -> str:
        """
        Render QR code with ANSI color codes.
        
        Uses background colors for cleaner appearance.
        Best for modern terminals with color support.
        
        Args:
            invert: Invert colors (default True for white-on-black terminal)
            
        Returns:
            Colored string representation
        """
        if not self.matrix:
            return ""
        
        lines = []
        for row in self.matrix:
            line = ""
            for cell in row:
                if invert:
                    cell = not cell
                
                if cell:
                    line += f"{self.WHITE_BG}  {self.RESET}"
                else:
                    line += f"{self.BLACK_BG}  {self.RESET}"
            
            lines.append(line)
        
        return '\n'.join(lines)
    
    def render(self, mode: str = 'unicode', invert: bool = False) -> str:
        """
        Render QR code in specified mode.
        
        Args:
            mode: Rendering mode ('unicode', 'ascii', 'large', 'colored')
            invert: Invert colors
            
        Returns:
            String representation
        """
        modes = {
            'unicode': self.render_unicode,
            'ascii': self.render_ascii,
            'large': self.render_large,
            'colored': self.render_colored,
        }
        
        renderer = modes.get(mode, self.render_unicode)
        return renderer(invert=invert)
    
    def print(self, mode: str = 'unicode', invert: bool = False) -> None:
        """Print QR code to stdout."""
        print(self.render(mode=mode, invert=invert))
    
    @property
    def version(self) -> int:
        """Return QR version (1-40)."""
        return self.qr.version
    
    @property
    def module_count(self) -> int:
        """Return number of modules per side."""
        return self.size


def generate_terminal_qr(data: str, mode: str = 'unicode',
                        error_correction: str = 'M',
                        invert: bool = False,
                        border: int = 2) -> str:
    """
    Generate QR code string for terminal display.
    
    Args:
        data: Data to encode
        mode: Rendering mode ('unicode', 'ascii', 'large', 'colored')
        error_correction: Error correction level (L/M/Q/H)
        invert: Invert colors
        border: Border size
        
    Returns:
        String representation of QR code
    """
    qr = ASCIIQRCode(data, error_correction=error_correction, border=border)
    return qr.render(mode=mode, invert=invert)


def print_terminal_qr(data: str, mode: str = 'unicode',
                     error_correction: str = 'M',
                     invert: bool = False,
                     border: int = 2,
                     title: Optional[str] = None) -> None:
    """
    Print QR code to terminal.
    
    Args:
        data: Data to encode
        mode: Rendering mode ('unicode', 'ascii', 'large', 'colored')
        error_correction: Error correction level (L/M/Q/H)
        invert: Invert colors
        border: Border size
        title: Optional title to display above QR
    """
    if title:
        print(f"\n🐱 {title}")
        print("─" * (len(title) + 4))
    
    qr = ASCIIQRCode(data, error_correction=error_correction, border=border)
    
    # Check terminal size
    term_width, term_lines = shutil.get_terminal_size()
    
    # Calculate required size
    # Unicode mode: 1 char width per module, 0.5 char height per module
    # ASCII/Large/Colored: 2 char width per module, 1 char height per module
    # We ignore border in calculation as qrcode adds it internally to matrix, but we added manual border param
    # actually qr.size is the module count including border if qrcode lib added it. 
    # But ASCIIQRCode init sets border=border in qrcode.QRCode. So self.size INCLUDES border.
    
    req_width = qr.size
    req_lines = qr.size
    
    if mode == 'unicode':
        req_lines = (qr.size + 1) // 2
    elif mode in ['ascii', 'colored']:
        req_width = qr.size * 2
        req_lines = qr.size
    elif mode == 'large':
        req_width = qr.size * 2
        req_lines = qr.size * 2
        
    # Safety Check
    if req_width > term_width or req_lines > term_lines:
        error_msg = (
            f"❌ Terminal too small for QR code!\n"
            f"   Required: {req_width}x{req_lines}\n"
            f"   Has:      {term_width}x{term_lines}\n"
            f"   Try maximizing window or using 'unicode' mode."
        )
        raise ValueError(error_msg)

    print(qr.render(mode=mode, invert=invert))
    
    # Print info
    print(f"\n📊 QR Version: {qr.version} ({qr.module_count}x{qr.module_count} modules)")
    print(f"📦 Data size: {len(data)} bytes")


class AnimatedTerminalQR:
    """
    Animated QR display for terminal (like TXQR's txqr-ascii).
    
    Displays QR codes in sequence with timing, useful for
    air-gap transfer when receiver can capture the terminal.
    """
    
    def __init__(self, data_list: List[bytes], fps: int = 5,
                 mode: str = 'unicode', error_correction: str = 'H'):
        """
        Initialize animated QR display.
        
        Args:
            data_list: List of data chunks to encode
            fps: Frames per second
            mode: Rendering mode
            error_correction: Error correction level
        """
        self.data_list = data_list
        self.fps = fps
        self.mode = mode
        self.error_correction = error_correction
        self.frame_delay = 1.0 / fps
    
    def _clear_screen(self) -> None:
        """Clear terminal screen."""
        print("\033[2J\033[H", end="")
    
    def _move_cursor_home(self) -> None:
        """Move cursor to top-left."""
        print("\033[H", end="")
    
    def play(self, loop: bool = True, clear: bool = True) -> None:
        """
        Play animated QR sequence.
        
        Args:
            loop: Loop animation
            clear: Clear screen between frames
        """
        import time
        
        frame = 0
        total = len(self.data_list)
        
        if clear:
            self._clear_screen()
        
        try:
            while True:
                data = self.data_list[frame]
                
                if clear:
                    self._move_cursor_home()
                
                # Render frame
                if isinstance(data, bytes):
                    data_str = data.hex()[:100]  # Truncate for display
                else:
                    data_str = str(data)
                
                qr = ASCIIQRCode(data_str, error_correction=self.error_correction)
                print(qr.render(mode=self.mode, invert=True))
                
                # Frame info
                print(f"\n🎬 Frame {frame + 1}/{total} | {self.fps} FPS")
                print(f"💾 Data: {len(data)} bytes")
                print("\nPress Ctrl+C to stop")
                
                frame = (frame + 1) % total
                
                if not loop and frame == 0:
                    break
                
                time.sleep(self.frame_delay)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Animation stopped")


# Testing
if __name__ == "__main__":
    print("🐱 ASCII Terminal QR Code Demo\n")
    
    test_data = "https://github.com/meow-decoder"
    
    # Demo all modes
    modes = ['unicode', 'ascii', 'colored']
    
    for mode in modes:
        print(f"\n{'='*60}")
        print(f"Mode: {mode.upper()}")
        print('='*60)
        print_terminal_qr(test_data, mode=mode, invert=True)
    
    # Large mode
    print(f"\n{'='*60}")
    print("Mode: LARGE (2x size)")
    print('='*60)
    qr = ASCIIQRCode("MEOW", border=1)
    print(qr.render_large(invert=True))
    
    print("\n✅ ASCII QR Demo complete!")
    print("💡 Tip: Use 'unicode' mode for compact display")
    print("        Use 'colored' mode for best visibility")
    print("        Use 'ascii' mode for legacy terminals")
