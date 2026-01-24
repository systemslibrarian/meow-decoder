# 🎨 Meow Decoder - Branding & Logo Guide
## Complete Visual Identity System

**Version:** 1.0  
**Date:** 2026-01-22  
**Status:** Ready for Use

---

## 📁 **Assets Included**

All logo files are in the `assets/` directory:

| File | Size | Usage | Format |
|------|------|-------|--------|
| **meow-decoder-logo.svg** | 400×120 | Main logo (dark theme) | SVG |
| **meow-decoder-logo-light.svg** | 400×120 | Main logo (light theme) | SVG |
| **meow-decoder-logo-mono.svg** | 400×120 | Monochrome (print) | SVG |
| **meow-icon-128.svg** | 128×128 | Square icon | SVG |
| **meow-minimal.svg** | 80×80 | Minimal badge | SVG |
| **favicon.svg** | 32×32 | Favicon | SVG |

---

## 🎨 **Brand Colors**

### **Primary Colors**

```css
/* Cat Orange */
--cat-orange: #ff8c42;
--cat-orange-dark: #ff6b35;

/* Cyan Lock */
--cyan-lock: #4ecdc4;
--cyan-dark: #44a3a0;

/* Dark Background */
--bg-dark: #1a1a2e;
--bg-dark-alt: #16213e;
```

### **Secondary Colors**

```css
/* Text */
--text-dark: #2d3436;
--text-gray: #636e72;
--text-light: #b2bec3;

/* Light Theme */
--bg-light: #f8f9fa;
--bg-light-alt: #e9ecef;
--border-light: #dee2e6;
```

### **Accent Colors**

```css
/* QR Scan Effect */
--qr-scan: #4ecdc4;

/* Signal Waves */
--signal: #4ecdc4;

/* Badges */
--badge-version: #4ecdc4;
--badge-quantum: #ff6b35;
```

---

## 📐 **Logo Specifications**

### **Main Logo (Dark Theme)**

**File:** `meow-decoder-logo.svg`

**Dimensions:** 400×120 pixels  
**Aspect Ratio:** 10:3  
**Min Display Size:** 200px wide  
**Background:** Dark gradient (#1a1a2e → #16213e)

**Elements:**
- Cat face with QR-scanning eyes (left)
- Lock icon (security badge)
- Signal waves (air-gap transmission)
- "MEOW DECODER" text
- Subtitle: "Smuggle bytes through the air"
- Version badge (v4.0)
- Quantum badge
- Paw print (decorative)

**Use for:**
- README.md header
- Dark-themed websites
- Dark-mode documentation
- GitHub/GitLab dark mode
- Presentations (dark backgrounds)

---

### **Light Theme Logo**

**File:** `meow-decoder-logo-light.svg`

**Dimensions:** 400×120 pixels  
**Background:** Light gradient (#f8f9fa → #e9ecef)

**Use for:**
- Light-themed websites
- Documentation on white backgrounds
- Printed materials (color)
- Light-mode GitHub/GitLab
- Presentations (light backgrounds)

---

### **Monochrome Logo**

**File:** `meow-decoder-logo-mono.svg`

**Dimensions:** 400×120 pixels  
**Colors:** Black & white only

**Use for:**
- Academic papers
- Black & white printing
- Fax documents (if anyone still uses those!)
- Simple printer-friendly docs
- High-contrast accessibility mode

---

### **Square Icon**

**File:** `meow-icon-128.svg`

**Dimensions:** 128×128 pixels  
**Format:** Square, centered cat face  
**Background:** Dark gradient with rounded corners

**Use for:**
- App icons (desktop/mobile)
- Social media avatars
- Repository avatar
- Package registry icons
- MacOS/Windows/Linux app icons

---

### **Favicon**

**File:** `favicon.svg`

**Dimensions:** 32×32 pixels  
**Ultra-simplified design**

**Use for:**
- Website favicon
- Browser tabs
- Bookmarks
- PWA icons (small sizes)

---

### **Minimal Badge**

**File:** `meow-minimal.svg`

**Dimensions:** 80×80 pixels  
**Transparent background**

**Use for:**
- Stickers
- Badges
- Small icons in UI
- Status indicators
- Compact displays

---

## 📍 **Where to Use Each Logo**

### **1. README.md (Top of File)**

```markdown
<p align="center">
  <img src="assets/meow-decoder-logo.svg" alt="Meow Decoder" width="400">
</p>

# Meow Decoder
**Smuggle bytes through the air**
```

**Result:** Logo appears at top of README, perfectly branded!

---

### **2. Documentation Headers**

For all major docs (THREAT_MODEL.md, ARCHITECTURE.md, SECURITY.md):

```markdown
<p align="center">
  <img src="assets/meow-decoder-logo.svg" alt="Meow Decoder" width="300">
</p>

---

# Document Title
[Content...]
```

**Why smaller (300px)?** Docs are longer, don't want logo to dominate.

---

### **3. GUI Splash Screen (meow_dashboard.py)**

```python
import dearpygui.dearpygui as dpg
from pathlib import Path

def show_splash_screen():
    """Show logo splash on startup."""
    
    # Load logo
    logo_path = Path("assets/meow-decoder-logo.svg")
    
    # Convert SVG to texture (requires cairosvg + PIL)
    from cairosvg import svg2png
    from PIL import Image
    import io
    
    svg_data = logo_path.read_text()
    png_data = svg2png(bytestring=svg_data.encode(), scale=2)
    img = Image.open(io.BytesIO(png_data))
    
    # Convert to DPG texture
    width, height = img.size
    img_rgba = img.convert("RGBA")
    texture_data = list(img_rgba.getdata())
    
    with dpg.texture_registry():
        dpg.add_raw_texture(
            width=width,
            height=height,
            default_value=texture_data,
            format=dpg.mvFormat_Float_rgba,
            tag="logo_texture"
        )
    
    # Show splash window
    with dpg.window(label="Meow Decoder", modal=True, no_close=True, 
                    tag="splash", pos=(100, 100)):
        dpg.add_image("logo_texture")
        dpg.add_text("Loading... Please wait")
        dpg.add_loading_indicator()
    
    # Auto-close after 2 seconds
    def close_splash():
        dpg.delete_item("splash")
    
    import threading
    threading.Timer(2.0, close_splash).start()
```

**Result:** Beautiful splash screen on GUI startup!

---

### **4. setup.py (Package Metadata)**

```python
from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
long_description = Path("README.md").read_text()

setup(
    name="meow-decoder",
    version="4.0.0",
    description="Smuggle bytes through the air - Optical air-gap file transfer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    
    author="Your Name",
    author_email="you@example.com",
    
    url="https://github.com/yourusername/meow-decoder",
    project_urls={
        "Documentation": "https://github.com/yourusername/meow-decoder/docs",
        "Source": "https://github.com/yourusername/meow-decoder",
        "Logo": "https://raw.githubusercontent.com/yourusername/meow-decoder/main/assets/meow-decoder-logo.svg",
        "Icon": "https://raw.githubusercontent.com/yourusername/meow-decoder/main/assets/meow-icon-128.svg",
    },
    
    packages=find_packages(),
    package_data={
        "meow_decoder": ["assets/*.svg"],
    },
    
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "Pillow>=10.0.0",
        "opencv-python>=4.8.0",
        "pyzbar>=0.1.9",
        "qrcode>=7.4.2",
        "argon2-cffi>=23.1.0",
    ],
    
    extras_require={
        "quantum": ["liboqs-python>=0.9.0"],
        "gui": ["dearpygui>=1.10.0"],
        "dev": ["pytest>=7.4.0", "black>=23.7.0"],
    },
    
    entry_points={
        "console_scripts": [
            "meow-encode=meow_decoder.encode:main",
            "meow-decode=meow_decoder.decode_gif:main",
            "meow-dashboard=meow_decoder.meow_dashboard:main",
        ],
    },
    
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
        "Topic :: Multimedia :: Graphics",
    ],
    
    keywords="encryption air-gap qr-code fountain-codes security cryptography",
)
```

**Result:** Professional PyPI package with logo references!

---

### **5. GitHub/GitLab Repository Settings**

**Repository Avatar:**
- Upload `meow-icon-128.svg` as repository avatar
- Square format, perfect for GitHub/GitLab

**Social Preview:**
- Use `meow-decoder-logo.svg` (dark theme)
- Dimensions: Will be cropped to 1280×640 for Open Graph
- Center the logo for best appearance

**Release Assets:**
- Include `assets/` directory in releases
- Reference logos in release notes

---

### **6. Website/Documentation Site**

**Favicon:**
```html
<link rel="icon" type="image/svg+xml" href="/assets/favicon.svg">
<link rel="apple-touch-icon" sizes="180x180" href="/assets/meow-icon-128.svg">
```

**Header:**
```html
<header>
  <img src="/assets/meow-decoder-logo.svg" alt="Meow Decoder" class="logo">
</header>
```

**Dark/Light Mode:**
```html
<!-- Auto-switch based on theme -->
<picture>
  <source srcset="/assets/meow-decoder-logo.svg" media="(prefers-color-scheme: dark)">
  <source srcset="/assets/meow-decoder-logo-light.svg" media="(prefers-color-scheme: light)">
  <img src="/assets/meow-decoder-logo.svg" alt="Meow Decoder">
</picture>
```

---

## 🎭 **Logo Variations Summary**

| Variation | When to Use |
|-----------|-------------|
| **Dark Theme** | Default, dark backgrounds, README |
| **Light Theme** | Light backgrounds, printed color docs |
| **Monochrome** | B&W printing, academic papers |
| **Square Icon** | App icons, avatars, social media |
| **Favicon** | Browser tabs, bookmarks |
| **Minimal Badge** | Stickers, compact displays, badges |

---

## 🚫 **Logo Usage Don'ts**

### **Don't:**

❌ Stretch or distort the logo  
❌ Change the cat's color to non-orange  
❌ Remove the lock icon  
❌ Use Comic Sans for the text (please!)  
❌ Add drop shadows or effects  
❌ Place on busy backgrounds  
❌ Use below 200px wide (minimum size)  
❌ Rotate or skew  
❌ Use old/outdated versions  

### **Do:**

✅ Maintain aspect ratio  
✅ Use adequate white space around logo  
✅ Use correct version for theme (dark/light)  
✅ Use SVG when possible (scalable!)  
✅ Use monochrome for B&W printing  
✅ Credit the project when using logo  

---

## 📏 **Minimum Sizes**

| Logo Type | Minimum Width | Minimum Height |
|-----------|---------------|----------------|
| Main Logo | 200px | 60px |
| Square Icon | 64px | 64px |
| Favicon | 32px | 32px |
| Minimal | 40px | 40px |

**Below these sizes:** Logo becomes illegible!

---

## 🎨 **Color Palette Guide**

### **Primary Palette:**

```
Cat Orange:     #ff8c42  [███████████████] 
Cat Dark:       #ff6b35  [███████████████]
Cyan Lock:      #4ecdc4  [███████████████]
Cyan Dark:      #44a3a0  [███████████████]
Dark BG:        #1a1a2e  [███████████████]
```

### **When to Use Each Color:**

**Cat Orange (#ff8c42):**
- Primary brand color
- Cat illustrations
- Accent elements
- Call-to-action buttons

**Cyan Lock (#4ecdc4):**
- Security features
- Interactive elements
- Links and highlights
- Success states

**Dark BG (#1a1a2e):**
- Dark theme backgrounds
- Code blocks
- Terminal screenshots

---

## 📦 **Export Formats**

All logos provided as **SVG** (Scalable Vector Graphics):

**Advantages:**
- ✅ Infinite scalability (no pixelation!)
- ✅ Small file size
- ✅ Editable with text editors
- ✅ CSS styling possible
- ✅ Perfect for web

**Need PNG?** Convert with:
```bash
# Using cairosvg
cairosvg meow-decoder-logo.svg -o meow-decoder-logo.png -W 800

# Using Inkscape
inkscape meow-decoder-logo.svg --export-png=meow-decoder-logo.png --export-width=800

# Using ImageMagick
convert -density 300 meow-decoder-logo.svg meow-decoder-logo.png
```

---

## 🎯 **Quick Reference**

**Need a logo fast?** Here's what to use:

| Scenario | Use This File |
|----------|---------------|
| GitHub README | `meow-decoder-logo.svg` |
| Documentation | `meow-decoder-logo.svg` (300px) |
| Favicon | `favicon.svg` |
| App Icon | `meow-icon-128.svg` |
| Social Media | `meow-icon-128.svg` |
| Stickers | `meow-minimal.svg` |
| Print (color) | `meow-decoder-logo-light.svg` |
| Print (B&W) | `meow-decoder-logo-mono.svg` |
| Badge/Status | `meow-minimal.svg` |

---

## 📄 **License**

Meow Decoder logos are part of the Meow Decoder project and follow the same license (MIT).

**You may:**
- ✅ Use in documentation
- ✅ Use in presentations about the project
- ✅ Use in articles/blogs about the project
- ✅ Modify for non-commercial use

**Attribution appreciated but not required.**

---

## 🎉 **Examples in the Wild**

Once you use these logos, they'll appear:

✅ At the top of your README (first thing visitors see!)  
✅ As your repository avatar (instant recognition!)  
✅ In documentation headers (professional look!)  
✅ In your GUI splash screen (polished UX!)  
✅ On PyPI package page (stands out!)  
✅ In conference presentations (memorable!)  
✅ On stickers at hacker conferences! 😸  

---

## 🐾 **Final Notes**

**The Meow Decoder logo represents:**
- 🐱 **Cat:** Stealth, independence, curiosity
- 🔐 **Lock:** Security, encryption, protection
- 📡 **Waves:** Air-gap transmission, optical transfer
- 🎨 **Colors:** Modern, tech-forward, approachable

**It's designed to be:**
- Memorable (cat + security)
- Professional (clean design)
- Playful (maintains the fun theme!)
- Versatile (works in many contexts)

---

**🐾 Use the logo proudly! Make Meow Decoder instantly recognizable! 😺🎨**

---

**Last Updated:** 2026-01-22  
**Logo Version:** 1.0  
**Status:** Ready for Production
