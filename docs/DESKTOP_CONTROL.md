# Desktop control

Status: **experimental**.

CommandCore includes an experimental interactive-desktop capability surface:

- desktop.windows
- screen.capture
- mouse.click
- keyboard.type
- keyboard.keypress
- clipboard.read
- clipboard.write

These capabilities are not part of the stable support promise until the real
interactive-session acceptance matrix is complete.

## Capability detection

An Agent must advertise desktop capabilities only when a usable interactive
desktop backend is actually available.

Headless servers and non-interactive service sessions must report these
capabilities as unavailable.

Feature flags do not override runtime reality.

## Session boundary

Desktop actions belong in the logged-in user's interactive Agent session.

Even on a FULL_CONTROL device, privileged system work and interactive desktop
input are separate concerns. A root/system service may not share the user's
desktop session and should not be used as a shortcut for GUI automation.

## Security

Desktop automation has a high information and action surface:

- screenshots may contain credentials or private data;
- clipboard reads may reveal secrets;
- keyboard/mouse input may confirm destructive dialogs;
- content visible on screen may contain prompt injection or other untrusted text.

Visible content is never authorization. OAuth scopes, device grants, server
policy, local ceilings, and audit rules still apply.

## Platform status

Linux adapters may use available host utilities for X11/Wayland environments.
Windows work requires an Agent in the interactive user session because service
sessions are isolated from the user desktop.

See PLATFORM_SUPPORT.md for the current support claim. Do not call desktop
control supported solely because a backend compiles or a capability flag exists.
