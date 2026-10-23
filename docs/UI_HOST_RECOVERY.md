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
