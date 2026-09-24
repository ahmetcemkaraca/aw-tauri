# PeakActivity desktop

An experimental Tauri desktop shell derived from ActivityWatch. This source keeps
upstream copyright and MPL 2.0 notices. PeakActivity is independent and is not
endorsed by ActivityWatch.

The desktop executable is `peakactivity`; the application identifier is
`app.peakactivity.desktop`. The product version is 0.1.0. These are development
identifiers, not evidence of signed installers or store registration.

## Local development

Install the target platform's Tauri prerequisites, Node and Rust. Use the pinned
lockfiles. The web interface input must contain the corresponding PeakActivity
component changes and editable icon; the inherited upstream gitlink alone does
not contain those changes yet. Public component URL/pin integration remains a
release gate.

With a reviewed web interface checkout alongside this component:

```sh
npm ci
make WEBUI_DIR=../aw-webui dev
```

Use `make WEBUI_DIR=../aw-webui build` for a local artifact. The override also sets
the exact web asset directory supplied to the embedded server. This is not a
publication command and does not sign, upload or certify an installer.

The embedded Rust server comes from the sibling public `aw-server-rust` checkout,
so that desktop and server use the same reviewed source. The desktop requests
SQLCipher and uses separate PeakActivity data/configuration directories. Native
keychain access is required; plaintext migration, recovery UI and capture controls are still in development. Local API access
uses expiring scoped sessions; the main WebView acquires its credential by native
IPC, and capture helpers receive process-bound renewal grants. External browser
views in mini mode do not yet have a pairing flow and cannot authorize themselves. Use synthetic activity.

## Verification scope

`make check` checks Rust compilation and linting after prebuild. Windows, macOS
and Linux installation, native permissions, tray behavior, suspend/resume,
accessibility and vault recovery require their own device acceptance.

## Recording consent

Recording begins disabled in a fresh vault. Review the permitted data sources and
fields, then enable recording in Privacy controls. Pause revokes collector access
before saving the stopped state; stale pending edits cannot undo that pause.
Known browsers without a reliable private-window signal are excluded. Unknown
applications still need user-defined exclusions; this is not a universal browser
classification claim.

Capture helpers must come from the packaged resource tree. Debug builds may use
an explicitly selected reviewed helper stage:

```sh
PEAKACTIVITY_HELPERS_DIR="$(pwd)/../reviewed-helpers/modules" make WEBUI_DIR=../aw-webui dev
```

Release builds ignore this override and do not launch ambient PATH helpers.
Changes to source/field consent restart the relevant collectors. A missing or
failed helper appears as degraded recording. Native permission, timing, resume and
recovery behavior still require the platform acceptance pass.
