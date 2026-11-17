# CommandCore Medium publishing checklist — V3

**Draft article:** [Your AI. Your Devices. Your Control. — Why I Built CommandCore](from-a-phone-to-an-entire-fleet-v3-medium.md)

## Suggested Medium presentation

- **Headline:** Your AI. Your Devices. Your Control. — Why I Built CommandCore
- **Subtitle:** How I connected ChatGPT and other AI clients to my own computers — without giving them unlimited access.
- **Topics:** Artificial Intelligence, Open Source, Self Hosting, AI Agents, Model Context Protocol
- **Canonical source:** Medium (publish there first; share the Medium URL afterwards)
- **Feature / cover image:** `media/commandcore-public-website-v2.png`; it is the real public website with an illustrative UI hero, not a user session
- **Author image:** none required; avoid a synthetic headshot

## Images included in the article

All 12 image references are stored in the repository's `docs/articles/media/` directory.

- Real website landing: `commandcore-public-website-v2.png`
- Video architecture: `commandcore-demo-0040.jpg`
- Live device workspace: `commandcore-demo-0340.jpg`
- Video architecture revisit: `commandcore-demo-0960.jpg`
- Actual AI interaction: `commandcore-demo-0480.jpg`
- Cropped actual ChatGPT device list: `chatgpt-commandcore-devices-real-v3.png`
- Real execution card: `commandcore-demo-0640.jpg`
- Operation inspection: `commandcore-demo-0800.jpg`
- Actual workspace interaction: `commandcore-demo-1130.jpg`
- Public installation documentation: `commandcore-public-installation-docs-v3.png`
- Add device UI from private demonstration (private URL redacted): `commandcore-add-device-real-redacted-v3.png`
- Real session later in video: `commandcore-demo-1320.jpg`

**Important:** before deleting this public draft branch, upload every image to Medium's image editor from local image files. Do not hotlink the images from the draft branch; those links will stop working after deletion.

## Prepublication review

1. Copy the V3 Markdown prose into a new Medium draft; confirm headings, code blocks, and links.
2. Upload images directly into Medium at the matching insertion points.
3. Use alt text from the source Markdown; retain captions and source-video timestamps.
4. Check the actual ChatGPT screenshot caption: FULL_CONTROL is shown only in the author's deliberate demo environment, never recommended as the default.
5. Verify the live public site, GitHub README, and platform support matrix have not changed substantially since drafting.
6. Verify local Compose and Agent installation instructions against the repository version at publication time. A signed installer requires an operator-published release feed.
7. Open the YouTube URL, confirm whether English audio is actually available on the YouTube player before claiming there is an English track. The article currently does not claim a track is available.
8. Preview the Medium draft on mobile, especially vertical Add Device screenshot and long code blocks.
9. Do not publish screenshots that contain secrets, private device authentication details, or non-public identifiers.
10. After Medium is published and the uploaded images work, save the public Medium URL, then remove this GitHub draft branch only on explicit request.

## Notes for V4, if needed

- Capture high-resolution authenticated Workspace screenshots from a disposable or consented public test account, rather than publishing live private details.
- Add a true end-user onboarding screen and verified successful signed-feed installation screenshot, **only if those flows can be demonstrated truthfully**.
- Record a current screenshot of the improved Activity/Browser experience once its live behavior and permission model have been checked.
- Tighten repetitive images after the author reviews the Medium preview; keep the strongest 8–10 if the full 12 feels heavy.
