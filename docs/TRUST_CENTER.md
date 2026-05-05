# Meow Decoder Trust Center

This document explains, in plain language, what Meow Decoder is designed to do, what it does not promise, and which features are recommended versus advanced or experimental.

The short version:

Meow Decoder is designed to help move files between systems without using a network connection, by converting encrypted data into scanable on-screen transfers.

## What Meow Decoder Is Good At

Meow Decoder is strongest when you need to:

- move files across an air gap
- avoid Wi-Fi, Bluetooth, cloud, or network transfer
- use a phone as an optical bridge instead of a trusted compute endpoint
- recover from imperfect capture conditions such as dropped frames or shaky recording

## What Meow Decoder Tries to Protect

At a high level, Meow Decoder is built to provide:

- encryption before transfer
- integrity checks during recovery
- offline-friendly transport using screen-to-camera capture
- local-first handling where possible

In the intended workflow, the phone is used as a camera and temporary carrier, not as the place where sensitive decryption happens.

## What Meow Decoder Does Not Promise

Meow Decoder should not be described as magic, invisible, or risk-free.

It does not promise:

- protection against every forensic technique
- safety against every nation-state or lab-grade adversary
- zero risk if your endpoints are already compromised
- perfect concealment for experimental deniability or camouflage features
- consumer-grade simplicity in every advanced workflow

If your threat model is extremely high risk, you should read the full security and threat-model documentation and treat advanced features conservatively.

## What Stays Local

The intended product model is local-first:

- the sender machine encrypts before transfer
- the receiver reconstructs and decrypts after capture
- the phone can be treated as a capture bridge rather than a trusted decryption endpoint

Some workflows export intermediate artifacts such as captured transfer files. Those artifacts are part of the transport path and should be handled carefully.

## What the Phone Is Trusted For

In the standard workflow, the phone is trusted to:

- see the sender screen
- capture frames accurately enough for recovery
- hold the captured transfer long enough for export

The phone is not intended to be the place where the core desktop decryption trust lives.

That distinction is one of the main reasons the product is useful.

## Recommended, Advanced, and Experimental Features

This taxonomy exists to make the default path clearer.

### Recommended

These are the features most users should start with.

| Feature | Status | Why it exists |
|---------|--------|---------------|
| Standard encrypted offline transfer | Recommended | Core sender-to-receiver workflow |
| Guided mobile capture | Recommended | Helps users complete transfer reliably |
| Standard export and desktop recovery | Recommended | Clean completion path for normal use |
| Default resilient transfer settings | Recommended | Best balance of reliability and simplicity |

Recommended means:

- this is the path the product should optimize for
- this is what documentation should lead with
- this is what first-time users should see first

### Advanced

These are useful power-user features, but they should not dominate the main flow.

| Feature | Status | Why it exists |
|---------|--------|---------------|
| Redundancy tuning | Advanced | Fine-tuning transfer resilience |
| Manual import and recovery utilities | Advanced | Fallback and specialist workflows |
| Diagnostics and capture metrics | Advanced | Troubleshooting and validation |
| Alternate transport or receiver workflows | Advanced | Operational flexibility |

Advanced means:

- useful when you know why you need it
- available, but not part of the default story
- should be visually secondary in product surfaces

### Experimental

These features may be valuable, but they require more careful framing and should not be sold as the default promise of the product.

| Feature | Status | Why it exists |
|---------|--------|---------------|
| Cat camouflage and presentation-layer stego features | Experimental | Aesthetic camouflage and research exploration |
| Duress and deniability workflows | Experimental | Specialized threat-model scenarios |
| Schrodinger mode | Experimental | Research-grade dual-secret behavior |
| Highly caveated concealment claims | Experimental | Not appropriate as default user promise |

Experimental means:

- feature behavior may require more explanation
- tradeoffs are more nuanced
- threat-model claims should be read carefully
- the product should not force first-time users through these decisions

## How to Think About Trust

The right mental model is:

- Meow Decoder is a serious offline transfer tool
- it encrypts before transfer
- it uses optical transport to move data across isolation boundaries
- some advanced features go beyond the default product promise and need more scrutiny

The wrong mental model is:

- every feature is equally mature
- every mode is equally appropriate for first-time users
- camouflage or deniability features eliminate operational risk

## Best Current Default Recommendation

If you are new to Meow Decoder, the safest starting point is:

1. use the standard encrypted transfer flow
2. use the default transfer settings
3. use the mobile app as a guided receiver
4. export the captured transfer and recover on desktop

Start there before exploring specialized modes.

## Questions a Careful User Should Ask

Before using any advanced feature, ask:

- what problem am I solving that the default flow does not solve?
- what extra assumptions does this mode introduce?
- is this feature improving transport, improving usability, or changing the threat model?
- is this recommended, advanced, or experimental?

If the answers are unclear, the default workflow is usually the better choice.

## Related Docs

- `README.md` for the main product overview
- `QUICKSTART.md` for the fastest path to a working transfer
- `docs/USAGE.md` for operational guidance
- `docs/THREAT_MODEL.md` for security assumptions and limitations
- `docs/ROADMAP.md` for maturity and audit milestones