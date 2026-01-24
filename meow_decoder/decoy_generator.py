#!/usr/bin/env python3
"""
Decoy Generator for Schrödinger's Yarn Ball
Generates convincing innocent files for plausible deniability

"You cannot prove a secret exists unless you already know how to look for it."
"""

import io
import zipfile
import secrets
from datetime import datetime, timedelta
from typing import List, Tuple
from pathlib import Path


class DecoyGenerator:
    """
    Generate convincing innocent decoy files.
    
    Creates realistic-looking innocent content that serves as
    plausible deniability for the real encrypted payload.
    """
    
    # Cat-themed lorem ipsum
    CAT_LOREM = """
    The Feline Manifesto: A Study in Elegance
    
    Cats are perhaps the most mysterious of all domesticated animals. Their 
    independent nature and graceful movements have captivated humans for 
    millennia. Unlike their canine counterparts, cats maintain an air of 
    aristocratic dignity that commands respect.
    
    Historical records show that cats were revered in ancient Egypt, where 
    they were associated with the goddess Bastet. This reverence was well-
    deserved, as cats provided invaluable pest control services, protecting 
    grain stores from rodents.
    
    Modern cats continue this proud tradition, though they have adapted to 
    contemporary life with remarkable ease. Whether lounging in sunbeams or 
    engaging in midnight zoomies, cats remind us that life should be lived 
    with both grace and spontaneity.
    
    The average cat sleeps 12-16 hours per day, a schedule that many humans 
    secretly envy. This sleep cycle is not laziness but rather an evolutionary 
    adaptation from their wild ancestors who needed to conserve energy between 
    hunts.
    
    In conclusion, cats represent the perfect balance of independence and 
    companionship. They are neither demanding nor distant, but rather exist 
    in a state of quantum superposition—simultaneously aloof and affectionate, 
    depending on their observation by humans.
    """
    
    # Shopping list items
    SHOPPING_ITEMS = [
        "Cat food (salmon flavor)",
        "Litter box liners",
        "Scratching post",
        "Catnip toys",
        "Milk",
        "Bread",
        "Eggs",
        "Coffee beans",
        "Fresh salmon",
        "Cheese",
        "Apples",
        "Bananas",
        "Yogurt",
        "Pasta",
        "Tomato sauce"
    ]
    
    # Fake file names for vacation photos
    PHOTO_NAMES = [
        "IMG_2023_beach.jpg",
        "IMG_2024_sunset.jpg",
        "IMG_2025_mountains.jpg",
        "vacation_001.jpg",
        "vacation_002.jpg",
        "family_photo.jpg"
    ]
    
    @staticmethod
    def generate_lorem_pdf_content() -> bytes:
        """
        Generate fake PDF content (as text).
        
        Real PDFs are complex, but we just need something that looks
        plausible in a hex dump and has reasonable size.
        """
        # Minimal PDF structure
        pdf = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /Contents 4 0 R /MediaBox [0 0 612 792] >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT
/F1 12 Tf
72 720 Td
(The Feline Manifesto) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000214 00000 n
trailer
<< /Size 5 /Root 1 0 R >>
startxref
293
%%EOF
"""
        return pdf
    
    @staticmethod
    def generate_shopping_list() -> str:
        """Generate random shopping list."""
        items = secrets.SystemRandom().sample(
            DecoyGenerator.SHOPPING_ITEMS,
            k=secrets.randbelow(len(DecoyGenerator.SHOPPING_ITEMS) - 5) + 5
        )
        
        date = datetime.now() - timedelta(days=secrets.randbelow(30))
        
        content = f"Shopping List - {date.strftime('%B %d, %Y')}\n"
        content += "=" * 50 + "\n\n"
        
        for i, item in enumerate(items, 1):
            content += f"{i}. {item}\n"
        
        content += "\n" + "=" * 50 + "\n"
        content += "Remember: Don't forget the cat treats!\n"
        
        return content
    
    @staticmethod
    def generate_fake_image(size: int = 1024) -> bytes:
        """
        Generate fake image data (random but plausible-looking).
        
        Args:
            size: Target size in bytes
        """
        # JPEG header
        header = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
        
        # Random data that looks like compressed image
        body = secrets.token_bytes(size - len(header) - 2)
        
        # JPEG end marker
        footer = b'\xff\xd9'
        
        return header + body + footer
    
    @classmethod
    def generate_vacation_photos(cls, count: int = 3) -> List[Tuple[str, bytes]]:
        """
        Generate fake vacation photo files.
        
        Args:
            count: Number of photos to generate
            
        Returns:
            List of (filename, content) tuples
        """
        photos = []
        photo_names = secrets.SystemRandom().sample(cls.PHOTO_NAMES, k=min(count, len(cls.PHOTO_NAMES)))
        
        for name in photo_names:
            # Vary size for realism (50-200 KB)
            size = 50000 + secrets.randbelow(150000)
            content = cls.generate_fake_image(size)
            photos.append((name, content))
        
        return photos
    
    @classmethod
    def generate_notes_file(cls) -> str:
        """Generate personal notes file."""
        content = "Personal Notes\n"
        content += "=" * 50 + "\n\n"
        content += f"Date: {datetime.now().strftime('%B %d, %Y')}\n\n"
        content += "Things to remember:\n"
        content += "- Feed cats twice daily\n"
        content += "- Water the plants on Wednesdays\n"
        content += "- Call mom this weekend\n"
        content += "- Vet appointment next Tuesday 3pm\n"
        content += "- Grocery shopping on Saturday\n\n"
        content += "Random thoughts:\n"
        content += cls.CAT_LOREM[:200] + "...\n"
        
        return content
    
    @classmethod
    def generate_decoy_archive(cls, target_size: int = 50000) -> bytes:
        """
        Generate complete decoy archive (ZIP).
        
        Args:
            target_size: Approximate target size in bytes
            
        Returns:
            ZIP file content as bytes
        """
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add cat manifesto PDF
            zf.writestr('The_Feline_Manifesto.pdf', cls.generate_lorem_pdf_content())
            
            # Add shopping list
            zf.writestr('shopping_list.txt', cls.generate_shopping_list())
            
            # Add notes
            zf.writestr('notes.txt', cls.generate_notes_file())
            
            # Add vacation photos to reach target size
            current_size = zip_buffer.tell()
            remaining = target_size - current_size
            
            if remaining > 10000:
                # Add photos to fill space
                num_photos = max(1, remaining // 80000)
                photos = cls.generate_vacation_photos(num_photos)
                
                # Create vacation_photos subfolder
                for photo_name, photo_data in photos:
                    zf.writestr(f'vacation_photos/{photo_name}', photo_data)
        
        return zip_buffer.getvalue()


def generate_convincing_decoy(target_size: int = None) -> bytes:
    """
    Generate convincing decoy data.
    
    Args:
        target_size: Target size in bytes (optional)
        
    Returns:
        Decoy data as bytes
    """
    if target_size is None:
        # Default to 50-100 KB
        target_size = 50000 + secrets.randbelow(50000)
    
    return DecoyGenerator.generate_decoy_archive(target_size)


if __name__ == "__main__":
    # Test decoy generation
    print("🐱 Generating decoy data...")
    decoy = generate_convincing_decoy(100000)
    print(f"✅ Generated {len(decoy):,} bytes of convincing decoy")
    
    # Verify it's a valid ZIP
    import zipfile
    try:
        with zipfile.ZipFile(io.BytesIO(decoy), 'r') as zf:
            print(f"✅ Valid ZIP with {len(zf.namelist())} files:")
            for name in zf.namelist():
                info = zf.getinfo(name)
                print(f"   - {name} ({info.file_size:,} bytes)")
    except Exception as e:
        print(f"❌ ZIP validation failed: {e}")
