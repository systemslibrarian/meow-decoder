"""
🐱 Meow Decoder - Setup Configuration
Professional Python package setup for PyPI distribution
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
README = Path(__file__).parent / "README.md"
long_description = README.read_text(encoding="utf-8") if README.exists() else ""

# Read requirements
REQUIREMENTS = Path(__file__).parent / "requirements.txt"
if REQUIREMENTS.exists():
    install_requires = [
        line.strip() 
        for line in REQUIREMENTS.read_text().splitlines() 
        if line.strip() and not line.startswith("#")
    ]
else:
    install_requires = [
        "cryptography>=41.0.0",
        "Pillow>=10.0.0",
        "opencv-python>=4.8.0",
        "pyzbar>=0.1.9",
        "qrcode[pil]>=7.4.2",
        "argon2-cffi>=23.1.0",
        "numpy>=1.24.0",
    ]

setup(
    # Basic package info
    name="meow-decoder",
    version="5.0.0",
    description="🐱 Schrödinger's Clowder - Optical air-gap file transfer with quantum plausible deniability",
    long_description=long_description,
    long_description_content_type="text/markdown",
    
    # Author info
    author="Paul Morel",
    author_email="paul.morel@example.com",  # Update this
    
    # URLs
    url="https://github.com/pmorel/meow-decoder",  # Update this
    project_urls={
        "Documentation": "https://github.com/pmorel/meow-decoder#readme",
        "Source Code": "https://github.com/pmorel/meow-decoder",
        "Bug Reports": "https://github.com/pmorel/meow-decoder/issues",
        "Changelog": "https://github.com/pmorel/meow-decoder/blob/main/CHANGELOG.md",
        "Logo": "https://raw.githubusercontent.com/yourusername/meow-decoder/main/assets/meow-decoder-logo.svg",
        "Icon": "https://raw.githubusercontent.com/yourusername/meow-decoder/main/assets/meow-icon-128.svg",
    },
    
    # Package discovery
    packages=find_packages(exclude=["tests", "tests.*", "docs", "examples"]),
    
    # Include non-Python files
    include_package_data=True,
    package_data={
        "meow_decoder": [
            "assets/*.svg",
            "assets/*.png",
            "sounds/*.wav",
        ],
    },
    
    # Python version
    python_requires=">=3.8",
    
    # Dependencies
    install_requires=install_requires,
    
    # Optional dependencies
    extras_require={
        # Post-quantum cryptography
        "quantum": [
            "liboqs-python>=0.9.0",
        ],
        
        # GUI dashboard
        "gui": [
            "dearpygui>=1.10.0",
            "cairosvg>=2.7.0",  # For SVG rendering in GUI
        ],
        
        # Low-memory streaming mode
        "streaming": [
            "psutil>=5.9.0",
        ],
        
        # Cat sound effects
        "sounds": [
            "playsound>=1.3.0",
        ],
        
        # Progress bars
        "progress": [
            "tqdm>=4.66.0",
        ],
        
        # Development tools
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "flake8>=6.1.0",
            "mypy>=1.5.0",
            "bandit>=1.7.5",
        ],
        
        # Documentation
        "docs": [
            "sphinx>=7.1.0",
            "sphinx-rtd-theme>=1.3.0",
        ],
        
        # All extras
        "all": [
            "liboqs-python>=0.9.0",
            "dearpygui>=1.10.0",
            "cairosvg>=2.7.0",
            "psutil>=5.9.0",
            "playsound>=1.3.0",
            "tqdm>=4.66.0",
        ],
    },
    
    # Console scripts (CLI commands)
    entry_points={
        "console_scripts": [
            "meow-encode=meow_decoder.encode:main",
            "meow-decode=meow_decoder.decode_gif:main",
            "meow-webcam=meow_decoder.decode_webcam_with_resume:main",
            "meow-dashboard=meow_decoder.meow_gui_enhanced:main",
        ],
    },
    
    # PyPI classifiers
    classifiers=[
        # Development status
        "Development Status :: 4 - Beta",
        
        # Intended audience
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Information Technology",
        
        # License
        "License :: OSI Approved :: MIT License",
        
        # Programming language
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        
        # Topics
        "Topic :: Security :: Cryptography",
        "Topic :: Multimedia :: Graphics",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Archiving",
        "Topic :: Communications :: File Sharing",
        
        # Operating systems
        "Operating System :: OS Independent",
        
        # Natural language
        "Natural Language :: English",
        
        # Environment
        "Environment :: Console",
        "Environment :: X11 Applications",
    ],
    
    # Keywords for PyPI search
    keywords=[
        "encryption",
        "air-gap",
        "qr-code",
        "fountain-codes",
        "security",
        "cryptography",
        "post-quantum",
        "optical-transfer",
        "data-exfiltration",
        "steganography",
        "aes-gcm",
        "argon2",
        "kyber",
        "forward-secrecy",
    ],
    
    # Licensing
    license="MIT",
    
    # Zip safe
    zip_safe=False,
)
