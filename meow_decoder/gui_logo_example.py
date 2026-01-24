"""
🐱 GUI Logo Splash Screen Integration
Example code for adding logo to meow_dashboard.py

This shows how to:
1. Load SVG logo
2. Convert to DearPyGui texture
3. Display as splash screen
4. Auto-close after delay
"""

import dearpygui.dearpygui as dpg
from pathlib import Path
import threading
import time


def load_svg_as_texture(svg_path: Path, tag: str = "logo_texture"):
    """
    Load SVG file and convert to DearPyGui texture.
    
    Requires: cairosvg, Pillow
    
    Args:
        svg_path: Path to SVG file
        tag: Texture tag for DPG
        
    Returns:
        (width, height) of texture
    """
    try:
        from cairosvg import svg2png
        from PIL import Image
        import io
        
        # Read SVG
        svg_data = svg_path.read_text()
        
        # Convert SVG to PNG with high quality
        png_data = svg2png(
            bytestring=svg_data.encode(),
            scale=2,  # 2x for retina displays
        )
        
        # Load as PIL Image
        img = Image.open(io.BytesIO(png_data))
        width, height = img.size
        
        # Convert to RGBA
        img_rgba = img.convert("RGBA")
        
        # Get pixel data as flat list (normalized to 0-1)
        pixels = list(img_rgba.getdata())
        texture_data = []
        for r, g, b, a in pixels:
            texture_data.extend([r/255.0, g/255.0, b/255.0, a/255.0])
        
        # Create DPG texture
        with dpg.texture_registry():
            dpg.add_raw_texture(
                width=width,
                height=height,
                default_value=texture_data,
                format=dpg.mvFormat_Float_rgba,
                tag=tag
            )
        
        return width, height
        
    except ImportError:
        print("⚠️  cairosvg or Pillow not installed. Cannot load SVG.")
        print("   Install with: pip install cairosvg Pillow")
        return None, None
    except Exception as e:
        print(f"❌ Error loading SVG: {e}")
        return None, None


def show_splash_screen(duration: float = 2.0):
    """
    Show logo splash screen on GUI startup.
    
    Args:
        duration: How long to show splash (seconds)
    """
    # Load logo
    logo_path = Path("assets/meow-decoder-logo.svg")
    
    if not logo_path.exists():
        print(f"⚠️  Logo not found at: {logo_path}")
        return
    
    # Convert to texture
    width, height = load_svg_as_texture(logo_path, "splash_logo")
    
    if width is None:
        return  # Failed to load
    
    # Calculate center position
    viewport_width = dpg.get_viewport_width()
    viewport_height = dpg.get_viewport_height()
    
    window_width = width + 40
    window_height = height + 80
    
    pos_x = (viewport_width - window_width) // 2
    pos_y = (viewport_height - window_height) // 2
    
    # Create splash window
    with dpg.window(
        label="Meow Decoder",
        modal=True,
        no_close=True,
        no_resize=True,
        no_move=True,
        no_title_bar=True,
        tag="splash_window",
        pos=(pos_x, pos_y),
        width=window_width,
        height=window_height,
    ):
        # Logo image
        dpg.add_image("splash_logo")
        
        # Loading indicator
        dpg.add_spacing(count=2)
        dpg.add_loading_indicator(
            style=1,  # Dots style
            circle_count=8,
            speed=1.5,
            radius=2.0,
        )
        dpg.add_text("Loading... Initializing cat utilities 😸")
    
    # Auto-close after duration
    def close_splash():
        time.sleep(duration)
        if dpg.does_item_exist("splash_window"):
            dpg.delete_item("splash_window")
    
    threading.Thread(target=close_splash, daemon=True).start()


def show_about_dialog():
    """
    Show about dialog with logo.
    
    Can be called from menu: Help > About
    """
    logo_path = Path("assets/meow-minimal.svg")
    
    if logo_path.exists():
        load_svg_as_texture(logo_path, "about_logo")
    
    with dpg.window(
        label="About Meow Decoder",
        modal=True,
        tag="about_window",
        width=400,
        height=300,
        pos=(100, 100),
    ):
        if dpg.does_alias_exist("about_logo"):
            dpg.add_image("about_logo", width=80, height=80)
        
        dpg.add_spacing(count=2)
        dpg.add_text("Meow Decoder v4.0", color=(255, 140, 66))
        dpg.add_text("Smuggle bytes through the air")
        
        dpg.add_separator()
        
        dpg.add_text("🐱 Quantum Nine Lives Edition")
        dpg.add_text("🔐 AES-256-GCM + Argon2id + Kyber")
        dpg.add_text("🌊 Fountain Codes + QR Encoding")
        dpg.add_text("📡 Optical Air-Gap Transfer")
        
        dpg.add_separator()
        
        dpg.add_text("Licensed under MIT License")
        dpg.add_text("© 2026 Your Name")
        
        dpg.add_spacing(count=2)
        
        dpg.add_button(
            label="Close",
            width=-1,
            callback=lambda: dpg.delete_item("about_window")
        )


# === INTEGRATION EXAMPLE ===

def main():
    """
    Example of integrating logo into meow_dashboard.py
    """
    # Create DPG context
    dpg.create_context()
    
    # Create viewport
    dpg.create_viewport(
        title="Meow Decoder - GUI Dashboard",
        width=1000,
        height=700,
    )
    
    # Setup DPG
    dpg.setup_dearpygui()
    
    # Show splash BEFORE showing viewport
    show_splash_screen(duration=2.5)
    
    # Create main window
    with dpg.window(label="Main", tag="main_window"):
        dpg.add_text("Meow Decoder Dashboard")
        dpg.add_button(label="About", callback=show_about_dialog)
    
    # Set primary window
    dpg.set_primary_window("main_window", True)
    
    # Show viewport
    dpg.show_viewport()
    
    # Start DPG
    dpg.start_dearpygui()
    
    # Cleanup
    dpg.destroy_context()


if __name__ == "__main__":
    print("🎨 Testing Logo Integration...")
    print()
    print("This example shows:")
    print("  ✅ Loading SVG logo")
    print("  ✅ Converting to DPG texture")
    print("  ✅ Showing splash screen")
    print("  ✅ Auto-closing after delay")
    print("  ✅ About dialog with logo")
    print()
    
    # Check dependencies
    try:
        import cairosvg
        import PIL
        print("✅ cairosvg and Pillow installed")
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("   Install with: pip install cairosvg Pillow")
        exit(1)
    
    # Check if logo exists
    if not Path("assets/meow-decoder-logo.svg").exists():
        print("⚠️  Logo not found. Make sure assets/ directory is present.")
        exit(1)
    
    print()
    print("🚀 Launching GUI with logo splash...")
    main()
