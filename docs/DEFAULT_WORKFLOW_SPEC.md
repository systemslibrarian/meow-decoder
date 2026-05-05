# Default Workflow Specification

This document defines the product's recommended default workflow in plain language.

It is intentionally narrower than the full feature set. The purpose is to make the best path obvious for first-time and mainstream users while leaving advanced capabilities available elsewhere.

## Product Rule

The default workflow should answer one question clearly:

How do I move a file offline, safely, with the least amount of setup?

If any screen or doc introduces decisions that are not required to answer that question, those decisions should move behind an advanced surface.

## Default Workflow Summary

The recommended path is:

1. Choose file on sender
2. Enter password
3. Start transfer
4. Scan sender screen with mobile receiver
5. Export captured transfer
6. Recover original file on receiver desktop

This is the story the product should tell in every public surface.

## Default Workflow States

### State 1: Prepare Transfer

User goal:

- choose what to send

Required user inputs:

- file
- password

Optional inputs hidden under Advanced:

- alternate modes
- redundancy tuning
- camouflage or deniability features
- specialist transfer settings

Recommended primary copy:

- Title: Start an Offline Transfer
- Support line: Choose a file, set a password, and show the transfer on screen.

Primary action:

- Start Transfer

### State 2: Show Transfer

User goal:

- present the transfer for capture

Required user understanding:

- keep this screen visible
- receiver phone should scan it
- stop only when told it is safe

Recommended primary copy:

- Title: Scan This Transfer
- Support line: Keep this screen visible while the receiver app captures the transfer.

Recommended helper copy:

- Increase screen brightness
- Keep the animation fully visible
- Do not close the page during capture

Primary status language:

- Receiver not connected yet
- Receiver is scanning
- Transfer in progress
- Safe to stop

### State 3: Pair Receiver

User goal:

- get the phone into capture mode quickly

Recommended primary copy:

- Title: Scan Sender Screen
- Support line: Point your phone at the sender screen to begin capture.

Secondary actions:

- Import Previous Transfer
- Manual Tools
- Diagnostics

The home screen should not lead with manual session entry.

### State 4: Capture

User goal:

- hold the phone correctly until capture is complete

Recommended copy style:

- short
- situational
- action-oriented

Recommended guidance phrases:

- Hold steady
- Move a little closer
- Reduce glare
- Keep the full code visible
- Almost done
- You can stop now

Do not lead with:

- frame math
- raw capture ratios
- duplicate percentages
- internal transport terminology

That information may still exist in diagnostics.

### State 5: Finish and Export

User goal:

- complete the transfer and hand off safely

Recommended primary copy:

- Title: Transfer Captured
- Support line: Your capture is ready to export for recovery on the receiving computer.

Primary action:

- Export Transfer

Secondary actions:

- Show Verification Details
- Use Backup Export

Recommended completion states:

- Ready to export
- Export complete
- Verification details available

Avoid leading with artifact-centric language like raw JSON or chunk mechanics unless the user opens details.

### State 6: Recover on Desktop

User goal:

- reconstruct original file successfully

Recommended primary copy:

- Title: Recover File
- Support line: Import the captured transfer and enter your password to recover the original file.

Primary action:

- Recover File

## Web Screen Intent

### `web_demo/templates/encode.html`

Job:

- sender setup

Should emphasize:

- file selection
- password
- default mode
- start transfer

Should de-emphasize:

- mode comparison
- experimental framing
- technical implementation detail

### `web_demo/templates/result.html`

Job:

- sender transfer state

Should emphasize:

- what the receiver should do next
- how long to keep the screen visible
- when it is safe to stop

### `web_demo/templates/decode.html`

Job:

- receiver desktop recovery

Should emphasize:

- import capture
- enter password
- recover original file

### `web_demo/templates/modes.html`

Job:

- advanced feature education

This should not be the default entry point to the product story.

### `web_demo/templates/cat_mode.html`

Job:

- optional advanced or experimental demonstration

This should remain available, but it should not define the default product message.

## Mobile Screen Intent

### `mobile/src/screens/OnboardingScreen.tsx`

Job:

- teach how to succeed on first transfer

Should emphasize:

- what the app does
- how to point the phone
- how to know when capture is finished

Should avoid:

- dense feature explanation
- early advanced-mode education

### `mobile/src/screens/HomeScreen.tsx`

Job:

- launch capture quickly

Should emphasize:

- scan sender screen

Should de-emphasize:

- manual entry
- JSON-first imports
- specialist fallback tools

### `mobile/src/screens/CaptureScreen.tsx`

Job:

- guide successful capture

Should emphasize:

- camera stability
- readable action hints
- clear completion state

### `mobile/src/screens/ExportScreen.tsx`

Job:

- close the loop and hand off safely

Should emphasize:

- completion
- export
- verification confidence
- next step on desktop

## Default Copy Pack

These lines are not final UI copy. They are intended to set tone and direction.

### Hero Copy

- Move Files Offline, Safely.
- Turn encrypted files into scanable on-screen transfers.
- Use a phone camera as the bridge, not the trust anchor.

### Sender Copy

- Start an Offline Transfer
- Scan This Transfer
- Keep this screen visible while the receiver captures it.
- Safe to stop

### Receiver Copy

- Scan Sender Screen
- Hold steady
- Almost done
- Transfer Captured
- Ready to export

### Recovery Copy

- Recover File
- Import the captured transfer and enter your password.
- Integrity verified

## Language Rules

Use language that is:

- direct
- calm
- outcome-focused
- understandable without protocol knowledge

Avoid leading with language that is:

- probabilistic
- jargon-heavy
- mode-heavy
- self-disqualifying

Examples:

- Prefer: Ready to export
- Avoid: Capture completeness ratio likely sufficient

- Prefer: Safe to stop
- Avoid: Threshold reached for probable decode

- Prefer: Scan sender screen
- Avoid: Load capture request metadata

## UX Decision Filter

Before exposing a control in the default path, ask:

- is this required for a successful first transfer?
- does this reduce user confusion?
- would most users know why they need this?

If the answer is no, move it behind Advanced or Diagnostics.

## Success Criteria

This spec is successful when:

- the same default story appears in docs, web, and mobile
- the default path requires minimal explanation
- advanced features remain available without hijacking the product identity
- users can finish a transfer without learning internal implementation vocabulary