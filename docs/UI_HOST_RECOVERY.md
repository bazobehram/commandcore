# Mounted widget connection recovery

The Activity and Browser viewers bound host initialization and tool requests to
15 seconds. A host that leaves a request unresolved now produces an unavailable
state with recovery controls instead of an indefinite connecting indicator or a
permanently disabled Refresh button. Late responses cannot overwrite that state.
The deadline does not cancel a server action or prove that an action failed.
The shared bridge never automatically repeats mutations.

This changes no tool schemas, authorization, conversation attribution, or
private-control boundaries. A host-level failure before the widget mounts still
requires the host's own retry control. Private Resume remains in the private
control window; pausing and resuming the live preview does not change AI control.

The isolated regression covers stalled host promises, recovery, late responses,
and read-only retry behavior. It does not replace acceptance in a signed-in
ChatGPT client or constitute physical mobile-device acceptance.


## Stop Browser (candidate b19)

The embedded Browser toolbar includes **Stop Browser**. It closes this
conversation's verified Browser; it does not stop the ChatGPT response or finish
the task. Its request uses the existing `browser.close` tool with optional
`session_ref` and `expected_session_id` fields. Existing callers remain compatible.
The existing OAuth scope and owner/conversation gate are preserved. The gateway
compares the expected ID inside its release lock, preventing an old card from
closing a replacement session. Private control still blocks closure; the button
explains that the operator must resume AI control privately first.

The UI clears its preview while stopping and reports Stopped only after the
server confirms release. A timeout reports an unconfirmed stop and offers a
read-only refresh; it never repeats the close automatically. Stop does not undo
website actions. Candidate b19 uses a new task resource identity while retaining
b18 aliases for saved conversations. It requires deployment and actual host
acceptance before a production success claim.


Activity and Browser own separate header states. Background Activity refreshes
cannot label an absent, private, stopping, stopped or unverified Browser as Live.
Changing tabs restores the selected view's current status. Changing viewer
identity clears the previous Activity status while attribution is rechecked.


## MCP Apps initialization (candidate b20)

The widget always performs `ui/initialize`, awaits its response, and sends
`ui/notifications/initialized` before issuing `tools/call`. The presence of
`window.openai.callTool` is not proof that this handshake has occurred. Standard
bridge calls are primary. Only an explicit unsupported-method response allows
fallback to the existing native alias; a timeout never selects another transport
or repeats an action. Request correlation and parent-window checks still apply.
This follows the [official MCP UI quickstart](https://developers.openai.com/plugins/build/app-quickstart).
The first-load failure must still be rechecked in ChatGPT before claiming it fixed.
