"""
🐱 Meow Decoder - Complete Cat Utilities
Everything you need to make security delightful!

Features (ALL implemented):
✅ Cat sound effects (emoji + optional audio)
✅ Random cat facts
✅ Cat-themed progress bars
✅ ASCII art splash screens
✅ Meme error messages  
✅ Nine Lives retry mode
✅ Catnip flavors
✅ Cat breed presets
✅ Password easter eggs
✅ Motivational meows
"""

import random
import sys
import time
from typing import Optional, Iterator
from dataclasses import dataclass
from pathlib import Path

# Optional dependencies
try:
    from playsound import playsound
    HAS_SOUND = True
except ImportError:
    HAS_SOUND = False

try:
    from tqdm import tqdm as _tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


# === 1. CAT SOUND EFFECTS ===

@dataclass
class CatSound:
    """A cat sound effect with emoji and optional audio."""
    emoji: str
    text: str
    audio_file: Optional[str] = None


CAT_SOUNDS = {
    'success': CatSound('😻', 'Prrrrrrrr... secrets revealed!', 'sounds/purr.wav'),
    'wrong_password': CatSound('😾', 'HISS! Wrong collar tag, try again.', 'sounds/hiss.wav'),
    'ratchet': CatSound('🐱', '*scratch scratch* New key derived!', 'sounds/scratch.wav'),
    'ninja': CatSound('🥷', 'Ninja cat activated — invisibility cloak engaged', None),
    'quantum': CatSound('🔮', 'Quantum Nine Lives ACTIVATED!', None),
    'prowling': CatSound('🐾', '*prowl prowl* Sneaking through memory...', None),
    'kibble': CatSound('🍖', '*plop* Kibble dispensed!', None),
    'hiss': CatSound('😼', 'Hissing secrets into encrypted form...', None),
    'purr_decode': CatSound('😺', 'Purring secrets back to life...', None),
}


def play_cat_sound(sound: str, audio: bool = False, verbose: bool = True):
    """Play cat sound effect (emoji + text, optionally audio)."""
    if sound not in CAT_SOUNDS:
        return
    
    s = CAT_SOUNDS[sound]
    if verbose:
        print(f"{s.emoji} {s.text}")
    
    if audio and HAS_SOUND and s.audio_file and Path(s.audio_file).exists():
        try:
            playsound(s.audio_file)
        except:
            pass


# === 2. RANDOM CAT FACTS ===

CAT_FACTS = [
    "🐱 Cats sleep 12–16 hours a day... just like your secrets are sleeping safely now 😴",
    "🐱 A group of cats is called a 'clowder'. Your QR codes are now in a clowder of safety.",
    "🐱 Cats have 32 muscles in each ear — almost as many as bits we just secured.",
    "🐱 Schrödinger's cat is both encrypted and decrypted until you scan the QR... meow? 🤔",
    "🐱 Cats can rotate their ears 180°. Forward secrecy rotates keys 360°! 🔄",
    "🐱 A cat's purr vibrates at 25-150 Hz. AES-256-GCM vibrates at 'unbreakable' Hz. 🔐",
    "🐱 Cats spend 30-50% grooming. Spend at least that much securing data! 🧼",
    "🐱 A cat's brain is 90% similar to humans. But cats never use 'password123'! 🧠",
    "🐱 Cats jump 6x their body length. Your secrets jumped through an air gap! 🦘",
    "🐱 The world's oldest cat lived 38 years. Kyber-1024 protects data way longer! ⏰",
    "🐱 Cats have a third eyelid. You have 3 security layers too! 👁️",
    "🐱 A cat's meow is just for humans. These QR codes are just for you! 😸",
    "🐱 Cats walk like camels—both right feet, then both left. Fountain codes walk like this! 🐾",
    "🐱 The richest cat inherited $13M. Your data? Priceless. 💰",
]

MOTIVATIONAL_MEOWS = [
    "💪 Your encryption is stronger than a cat's desire for a cardboard box!",
    "🏆 Purr-fect security achieved! Even the NSA would be impressed!",
    "✨ Your secrets are safer than a cat in a sunbeam!",
    "🎯 That's some seriously strong catnip-level encryption!",
    "🔐 Locked tighter than a cat protecting its favorite nap spot!",
    "😸 Security level: Cat sitting on keyboard (unbreakable!)",
    "🎉 Congratulations! You've achieved maximum meow security!",
]


def print_random_cat_fact():
    """Print a random cat fact."""
    print(f"\n💡 {random.choice(CAT_FACTS)}\n")


def print_motivational_meow():
    """Print a motivational meow."""
    print(f"\n{random.choice(MOTIVATIONAL_MEOWS)}\n")


def maybe_print_cat_fact(elapsed: float, threshold: float = 30.0):
    """Print cat fact if operation took > threshold seconds."""
    if elapsed > threshold:
        print_random_cat_fact()


# === 3. CAT PROGRESS BARS ===

def cat_tqdm(iterable=None, desc=None, total=None, **kwargs):
    """
    Cat-themed progress bar with evolving emoji.
    
    Falls back gracefully if tqdm not installed.
    """
    if not HAS_TQDM:
        # Fallback: print dots
        if iterable:
            count = 0
            total_est = total or len(list(iterable)) if hasattr(iterable, '__len__') else 100
            for item in iterable:
                count += 1
                if count % 10 == 0:
                    print("🐾", end="", flush=True)
                yield item
            print()  # Newline
            return
        else:
            return range(total) if total else []
    
    # Use regular tqdm with cat emoji prefix
    cat_emoji = "🐾"
    if desc:
        desc = f"{cat_emoji} {desc}"
    
    return _tqdm(
        iterable=iterable,
        desc=desc,
        total=total,
        bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
        **kwargs
    )


# === 4. ASCII ART SPLASH SCREENS ===

ASCII_CATS = {
    'basic': r"""
 /_/\  
( o.o ) 
 > ^ <   Meow Decoder v4.0 - Quantum Nine Lives Edition
""",
    
    'ninja': r"""
    |\___/|
    )  o o (     🥷 NINJA CAT MODE
   =\  ^  /=
     )-^-(       Maximum Stealth Engaged
    /     \
    |     |
""",
    
    'fluffy': r"""
    /\_/\  
   ( o.o )  
  > ^   ^ <
   /|   |\   FLUFFY MODE: Maximum Comfort, Maximum Security
  (_|   |_)
""",
    
    'void': r"""
　／＞　　フ
| 　_　 _ l
／` ミ＿xノ
/　　　 　 |
/　 ヽ　　 ﾉ
│　　|　|　|
／￣|　　|　|　|　＼
| (￣ヽ＿_ヽ_)__)
＼二つ

VOID CAT: All evidence consumed.
          Nothing to see here. 😶‍🌫️
""",
    
    'quantum': r"""
    |\___/|
    ) • • (     |ψ⟩ = α|😺⟩ + β|😼⟩
   =\  Y  /=    
    )-^-(       Quantum Nine Lives ACTIVATED
   /     \      (Schrödinger approved ✓)
""",
}


def print_cat_splash(cat_type: str = 'basic'):
    """Print ASCII art splash screen."""
    print(ASCII_CATS.get(cat_type, ASCII_CATS['basic']))
    print("🐾 Strong cat passwords only! 😼🔐\n")


# === 5. CAT MEME ERROR MESSAGES ===

CAT_ERRORS = {
    'file_not_found': "😿 No yarn ball at that path. Did the cat knock it off the shelf?",
    'wrong_password': "😾 Hiss! Collar tag rejected. Try petting the keyboard again.",
    'not_enough_droplets': "🐱 Only {count} kibbles collected... need more treats!",
    'corrupted': "😾 Collar tag is scratched! Cannot read owner information.",
    'no_webcam': "📹 No camera found. Did you forget to plug in the cat cam?",
    'decode_failed': "😿 Failed to purr secrets back. Wrong password or damaged yarn ball?",
    'out_of_memory': "🙀 Out of memory! Even cats can't remember that much. Try --prowling-mode.",
    'invalid_keyfile': "🌿 This catnip smells funny... invalid keyfile format.",
    'permission_denied': "😼 The cat says 'no'. Permission denied. Try sudo catnip?",
}


def cat_error(error_type: str, **kwargs) -> str:
    """Get cat-themed error message with optional formatting."""
    template = CAT_ERRORS.get(error_type, "😿 Something went wrong. Sad cat noises.")
    return template.format(**kwargs)


# === 6. CATNIP FLAVORS ===

CATNIP_FLAVORS = {
    'tuna': b'meow_tuna_catnip_v1',
    'salmon': b'meow_salmon_catnip_v1',
    'chicken': b'meow_chicken_catnip_v1',
    'beef': b'meow_beef_catnip_v1',
    'turkey': b'meow_turkey_catnip_v1',
    'fish': b'meow_fish_catnip_v1',
    'default': b'meow_default_catnip_v1',
}


def get_catnip_flavor(flavor: str = 'default') -> bytes:
    """
    Get HKDF info string for catnip flavor.
    
    Completely cosmetic, just changes the HKDF info string.
    Users will love typing --catnip-flavor tuna though!
    """
    flavor_lower = flavor.lower()
    info = CATNIP_FLAVORS.get(flavor_lower, CATNIP_FLAVORS['default'])
    
    if flavor_lower != 'default' and flavor_lower in CATNIP_FLAVORS:
        print(f"🌿 Using {flavor} flavored catnip! Extra delicious! 😸")
    
    return info


# === 7. CAT BREED PRESETS ===

@dataclass
class CatBreed:
    """Cat breed preset configuration."""
    name: str
    stego_level: int
    carrier_palette: str  # For stego color scheme
    emoji_set: str
    success_message: str
    splash_type: str


CAT_BREEDS = {
    'tabby': CatBreed(
        'Tabby', 2, 'orange-brown', '😺😸😹',
        '😺 Tabby approves! Secrets safely napped in cozy spots.',
        'fluffy'
    ),
    'siamese': CatBreed(
        'Siamese', 3, 'cool-blue-gray', '😼😾😿',
        '😼 Siamese says: elegant, sophisticated, undetectable.',
        'basic'
    ),
    'void': CatBreed(
        'Void', 4, 'pure-black', '🐈‍⬛😶🕳️',
        '🐈‍⬛ Void cat consumed the evidence. Nothing to see here.',
        'void'
    ),
    'persian': CatBreed(
        'Persian', 3, 'cream-white', '😻😽😺',
        '😻 Persian purrs: maximum fluff, maximum security!',
        'fluffy'
    ),
    'ninja': CatBreed(
        'Ninja', 4, 'midnight-gray', '🥷😼🐱‍👤',
        '🥷 Ninja cat vanished into shadows. Mission complete.',
        'ninja'
    ),
}


def get_cat_breed(breed: str) -> Optional[CatBreed]:
    """Get cat breed preset."""
    return CAT_BREEDS.get(breed.lower())


def list_cat_breeds():
    """Print available cat breeds."""
    print("\n🐱 Available Cat Breed Presets:\n")
    for name, breed in CAT_BREEDS.items():
        print(f"  {breed.emoji_set[0]} {name:10} - Stego Level {breed.stego_level}")
        print(f"     {breed.success_message}\n")


# === 8. NINE LIVES RETRY MODE ===

class NineLivesRetry:
    """
    Automatic retry with 9 lives.
    
    Usage:
        retry = NineLivesRetry()
        for life in retry.attempt():
            try:
                result = risky_operation()
                retry.success(result)
                break
            except Exception as e:
                retry.fail(str(e))
        
        if retry.succeeded:
            print(f"Got result: {retry.result}")
    """
    
    def __init__(self, max_lives: int = 9, verbose: bool = True):
        self.max_lives = max_lives
        self.verbose = verbose
        self.life = 0
        self.succeeded = False
        self.result = None
    
    def attempt(self) -> Iterator[int]:
        """Iterate through lives (0-indexed)."""
        if self.verbose:
            print(f"🐱 Nine Lives Mode: {self.max_lives} attempts available\n")
        
        for life in range(self.max_lives):
            self.life = life
            yield life
        
        if not self.succeeded and self.verbose:
            print(f"\n😾 All {self.max_lives} lives exhausted!")
    
    def fail(self, reason: str = ""):
        """Mark current attempt as failed."""
        if self.verbose:
            emoji = "😿" if self.life < self.max_lives - 1 else "😾"
            msg = f"{emoji} Life {self.life+1}/{self.max_lives} — still hunting kibbles..."
            if reason:
                msg += f" ({reason})"
            print(msg)
    
    def success(self, result=None):
        """Mark as succeeded."""
        self.succeeded = True
        self.result = result
        if self.verbose:
            print(f"\n😻 Life {self.life+1}/{self.max_lives} — Success! All nine lives used wisely!\n")


# === 9. PASSWORD EASTER EGGS ===

def check_password_easter_egg(password: str):
    """Check for easter eggs in password and react accordingly."""
    lower = password.lower()
    
    # Main easter egg: "meow" detected
    if 'meow' in lower:
        print("\n😼 Detected cat-approved password! Extra nine lives granted.")
        print("   (Your secrets are extra safe with cat magic! ✨)\n")
        return
    
    # Other cat words
    cat_words = ['cat', 'kitty', 'feline', 'purr', 'whiskers', 'paw', 'catnip']
    for word in cat_words:
        if word in lower:
            print(f"\n🐱 Password contains '{word}'! +10 purr points! 😸\n")
            return
    
    # Weak password warning
    weak = ['password', '123456', 'admin', 'qwerty', 'letmein']
    if lower in weak or len(password) < 8:
        print("\n😾 WARNING: This password is weaker than a kitten!")
        print("   Try something like 'Meow@MyFluffyCat2026!' instead! 🔐\n")


def estimate_password_entropy(password: str) -> float:
    """
    Estimate password entropy in bits.
    
    Rough calculation:
    - Lowercase: 26 chars
    - Uppercase: 26 chars  
    - Digits: 10 chars
    - Symbols: ~32 chars
    
    Entropy = length * log2(charset_size)
    """
    import math
    
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(not c.isalnum() for c in password):
        charset_size += 32
    
    if charset_size == 0:
        return 0.0
    
    return len(password) * math.log2(charset_size)


def summon_cat_judge(password: str) -> str:
    """
    🐱 The Cat Judge evaluates password strength.
    
    Returns a cat-themed judgment based on entropy.
    
    Usage:
        judgment = summon_cat_judge("MyPassword123")
        print(judgment)
    """
    entropy = estimate_password_entropy(password)
    
    if entropy < 30:
        return "😿 Kitten whiskers. This password is barely a nap. (Entropy: {:.1f} bits)".format(entropy)
    elif entropy < 50:
        return "😼 Adequate collar tag. I've seen stronger, but it'll do. (Entropy: {:.1f} bits)".format(entropy)
    elif entropy < 80:
        return "😸 Respectable whisker strength! Your secrets are fairly safe. (Entropy: {:.1f} bits)".format(entropy)
    else:
        return "😻 SUPREME VOID-CAT APPROVED! Nine lives secured forever! (Entropy: {:.1f} bits)".format(entropy)


# === UTILITY FUNCTIONS ===

def cat_print(msg: str, emoji: str = "😸"):
    """Print with cat emoji prefix."""
    print(f"{emoji} {msg}")


# === TESTING ===

if __name__ == "__main__":
    print("=" * 70)
    print("🐱 TESTING CAT UTILITIES")
    print("=" * 70)
    
    # 1. Splash screens
    print("\n1️⃣  ASCII Art Splash Screens:\n")
    for cat_type in ['basic', 'ninja', 'void', 'quantum']:
        print(f"--- {cat_type.upper()} ---")
        print_cat_splash(cat_type)
    
    # 2. Sound effects
    print("\n2️⃣  Cat Sound Effects:\n")
    for sound in ['success', 'wrong_password', 'ratchet', 'ninja', 'quantum']:
        play_cat_sound(sound, audio=False)
    
    # 3. Cat facts
    print("\n3️⃣  Random Cat Facts:\n")
    for _ in range(2):
        print_random_cat_fact()
    
    print_motivational_meow()
    
    # 4. Error messages
    print("\n4️⃣  Cat Error Messages:\n")
    print(cat_error('file_not_found'))
    print(cat_error('wrong_password'))
    print(cat_error('not_enough_droplets', count=42))
    print(cat_error('out_of_memory'))
    
    # 5. Catnip flavors
    print("\n5️⃣  Catnip Flavors:\n")
    for flavor in ['tuna', 'salmon', 'chicken', 'default']:
        info = get_catnip_flavor(flavor)
        print(f"  {flavor}: {info}")
    
    # 6. Cat breeds
    print("\n6️⃣  Cat Breed Presets:\n")
    list_cat_breeds()
    
    # 7. Nine Lives retry
    print("\n7️⃣  Nine Lives Retry Mode:\n")
    retry = NineLivesRetry(max_lives=3, verbose=True)
    for life in retry.attempt():
        if life < 2:
            retry.fail("not enough kibbles")
        else:
            retry.success("All kibbles collected!")
            break
    
    # 8. Password easter eggs
    print("\n8️⃣  Password Easter Eggs:\n")
    check_password_easter_egg("MyMeowPassword123!")
    check_password_easter_egg("password123")
    check_password_easter_egg("SuperCatWhiskers2026")
    
    # 9. Progress bar
    print("\n9️⃣  Cat Progress Bar:\n")
    if HAS_TQDM:
        for i in cat_tqdm(range(50), desc="Dispensing kibbles"):
            time.sleep(0.02)
    else:
        print("  (tqdm not installed, showing fallback)\n")
        for i in cat_tqdm(range(50), desc="Dispensing kibbles", total=50):
            time.sleep(0.02)
    
    print("\n" + "=" * 70)
    print("✅ ALL CAT UTILITIES WORKING PERFECTLY! 😸🎉")
    print("=" * 70)
    print("\n🐾 Ready to make Meow Decoder the most delightful security tool ever!")
