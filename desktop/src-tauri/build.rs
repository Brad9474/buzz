// Shared schema, included from the same source the runtime command parses with,
// so the build-time validation below and the runtime parse cannot drift.
include!("src/commands/reconnect_hook_config.rs");

use base64::Engine as _;

/// Refuse to produce a release binary with no frontend inside it.
///
/// Tauri decides between "embed `frontendDist`" and "load `build.devUrl` at
/// runtime" from a Cargo feature, not from the profile:
///
///   tauri/build.rs   `let dev = !has_feature("custom-protocol");`
///                    `println!("cargo:dev={dev}");`
///   tauri-macros     `dev: cfg!(not(feature = "custom-protocol"))`
///   tauri-codegen    `else if dev && config.build.dev_url.is_some() {
///                        EmbeddedAssets::default()  // empty
///                    }`
///
/// `tauri build` turns the feature on (it passes `--features
/// tauri/custom-protocol`). A bare `cargo build --release` does not, and the
/// result is an optimised binary carrying zero web assets that silently points
/// WebView2 at `build.devUrl` (`http://localhost:1420`). It compiles clean, it
/// is byte-identical to itself across copies, and it passes any hash or string
/// check you throw at it -- then renders an empty ERR_CONNECTION_REFUSED
/// window on a machine with no dev server running.
///
/// That shipped to the fleet on 2026-08-10. The only cheap signal was the
/// missing ~8.5 MB of assets. Fail at build time instead.
///
/// The signal used here is `DEP_TAURI_DEV`. `tauri` declares `links = "Tauri"`,
/// so its `cargo:dev=<bool>` instruction reaches direct dependents as that
/// variable -- it is the same value tauri-codegen branches on, read from the
/// same source, rather than an inference about how the build was invoked.
/// Checking this crate's own `CARGO_FEATURE_CUSTOM_PROTOCOL` does NOT work:
/// the CLI enables the feature on the `tauri` dependency, not on us.
///
/// Note this deliberately does NOT assert on `devUrl` being set: `devUrl` is
/// always set and must stay set for `tauri dev`. The feature is the real
/// switch.
///
/// Escape hatch: set BUZZ_ALLOW_RELEASE_WITHOUT_FRONTEND=1 for a
/// release-profile build that genuinely does not need a UI (profiling a
/// sidecar path, `cargo test --release`, bisecting a codegen bug).
fn assert_frontend_will_be_embedded() {
    println!("cargo:rerun-if-env-changed=BUZZ_ALLOW_RELEASE_WITHOUT_FRONTEND");

    if std::env::var("PROFILE").as_deref() != Ok("release")
        || std::env::var_os("BUZZ_ALLOW_RELEASE_WITHOUT_FRONTEND").is_some()
    {
        return;
    }

    match std::env::var("DEP_TAURI_DEV").as_deref() {
        // Frontend will be embedded. This is what a correct release build looks like.
        Ok("false") => {}
        Ok("true") => panic!(
            "\n\
             ------------------------------------------------------------------\n\
             REFUSING TO BUILD: release profile in Tauri dev-loading mode.\n\
             \n\
             DEP_TAURI_DEV=true means the `custom-protocol` feature is off, so\n\
             tauri-codegen will embed NO frontend assets and the app will load\n\
             build.devUrl (http://localhost:1420) at runtime -- a blank\n\
             ERR_CONNECTION_REFUSED window on any machine without a dev\n\
             server. It builds and hashes clean, so nothing downstream\n\
             catches it. This shipped on 2026-08-10.\n\
             \n\
             Build the desktop app through the Tauri CLI, which enables the\n\
             feature and builds the frontend first:\n\
             \n\
                 cd desktop && pnpm tauri build\n\
                 just desktop-release-build <target>\n\
             \n\
             Or, to drive cargo directly:\n\
             \n\
                 cargo build --release --features custom-protocol\n\
             \n\
             If you really want a UI-less release binary, set\n\
             BUZZ_ALLOW_RELEASE_WITHOUT_FRONTEND=1.\n\
             ------------------------------------------------------------------\n"
        ),
        other => panic!(
            "\n\
             ------------------------------------------------------------------\n\
             REFUSING TO BUILD: could not determine whether the frontend will\n\
             be embedded. Expected DEP_TAURI_DEV to be \"true\" or \"false\",\n\
             got {other:?}.\n\
             \n\
             That variable comes from tauri's `cargo:dev` instruction via\n\
             `links = \"Tauri\"`. If a tauri upgrade changed or dropped it,\n\
             this guard needs updating -- do not just delete it, or the\n\
             2026-08-10 blank-window failure can ship again unnoticed.\n\
             \n\
             To build anyway: BUZZ_ALLOW_RELEASE_WITHOUT_FRONTEND=1.\n\
             ------------------------------------------------------------------\n"
        ),
    }
}

fn main() {
    assert_frontend_will_be_embedded();

    println!("cargo:rerun-if-env-changed=BUZZ_RELAY_URL");
    println!("cargo:rerun-if-env-changed=BUZZ_RELAY_HTTP");
    println!("cargo:rerun-if-env-changed=BUZZ_UPDATER_PUBLIC_KEY");
    println!("cargo:rerun-if-env-changed=BUZZ_UPDATER_ENDPOINT");
    println!("cargo:rerun-if-env-changed=BUZZ_BUILD_BUZZ_AGENT_PROVIDER");
    println!("cargo:rerun-if-env-changed=BUZZ_BUILD_BUZZ_AGENT_MODEL");
    println!("cargo:rerun-if-env-changed=BUZZ_BUILD_AGENT_ENV");
    println!("cargo:rerun-if-env-changed=BUZZ_BUILD_RELAY_RECONNECT_CMD");
    println!("cargo:rerun-if-env-changed=BUZZ_BUILD_OBSERVER_ARCHIVE_DEFAULT");
    println!("cargo:rerun-if-env-changed=BUZZ_BUILD_AGENT_METRIC_ARCHIVE_DEFAULT");
    println!("cargo:rerun-if-env-changed=BUZZ_BUILD_AUTO_CONNECT_DEFAULT_RELAY");
    println!("cargo:rustc-check-cfg=cfg(buzz_updater_enabled)");

    if let Ok(relay_url) = std::env::var("BUZZ_RELAY_URL") {
        println!("cargo:rustc-env=BUZZ_DESKTOP_BUILD_RELAY_URL={relay_url}");
    }

    if let Ok(relay_http) = std::env::var("BUZZ_RELAY_HTTP") {
        println!("cargo:rustc-env=BUZZ_DESKTOP_BUILD_RELAY_HTTP={relay_http}");
    }

    if let Ok(provider) = std::env::var("BUZZ_BUILD_BUZZ_AGENT_PROVIDER") {
        println!("cargo:rustc-env=BUZZ_DESKTOP_BUILD_BUZZ_AGENT_PROVIDER={provider}");
    }

    if let Ok(model) = std::env::var("BUZZ_BUILD_BUZZ_AGENT_MODEL") {
        println!("cargo:rustc-env=BUZZ_DESKTOP_BUILD_BUZZ_AGENT_MODEL={model}");
    }

    // Generic KEY=VALUE pairs to inject into every spawned agent process.
    // Newline-delimited; each line must be non-empty and contain exactly one
    // `=` separator with a non-empty key.  OSS builds leave this unset.
    // The validated value is base64-encoded before emitting so the single-line
    // Cargo build-script output carries all pairs (Cargo output is line-oriented;
    // a raw multiline value would be silently truncated to the first line).
    if let Ok(raw) = std::env::var("BUZZ_BUILD_AGENT_ENV") {
        for (line_no, line) in raw.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let eq = line.find('=').unwrap_or_else(|| {
                panic!(
                    "BUZZ_BUILD_AGENT_ENV line {}: missing '=' separator in {:?}",
                    line_no + 1,
                    line
                )
            });
            let key = &line[..eq];
            if key.is_empty() {
                panic!(
                    "BUZZ_BUILD_AGENT_ENV line {}: key must not be empty in {:?}",
                    line_no + 1,
                    line
                );
            }
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        println!("cargo:rustc-env=BUZZ_DESKTOP_BUILD_AGENT_ENV={encoded}");
    }

    if let Ok(val) = std::env::var("BUZZ_BUILD_RELAY_RECONNECT_CMD") {
        let parsed: serde_json::Value = serde_json::from_str(&val)
            .unwrap_or_else(|e| panic!("BUZZ_BUILD_RELAY_RECONNECT_CMD is not valid JSON: {e}"));
        serde_json::from_value::<ReconnectHookConfig>(parsed).unwrap_or_else(|e| {
            panic!("BUZZ_BUILD_RELAY_RECONNECT_CMD doesn't match ReconnectHookConfig: {e}")
        });
        println!("cargo:rustc-env=BUZZ_DESKTOP_BUILD_RELAY_RECONNECT_CMD={val}");
    }

    // Presence-only flag: when set (any non-empty value), observer-feed archive
    // defaults to ON for the current identity on first run.  OSS builds leave
    // this unset → default OFF.  No JSON validation needed — the command only
    // checks `.is_some()`.
    if std::env::var("BUZZ_BUILD_OBSERVER_ARCHIVE_DEFAULT").is_ok() {
        println!("cargo:rustc-env=BUZZ_DESKTOP_BUILD_OBSERVER_ARCHIVE_DEFAULT=1");
    }

    // Presence-only flag: when set (any non-empty value), agent-turn-metric
    // archive defaults to ON for the current identity on first run.  OSS builds
    // leave this unset → default OFF.
    if std::env::var("BUZZ_BUILD_AGENT_METRIC_ARCHIVE_DEFAULT").is_ok() {
        println!("cargo:rustc-env=BUZZ_DESKTOP_BUILD_AGENT_METRIC_ARCHIVE_DEFAULT=1");
    }

    // Presence-only release capability: internal desktop builds opt into
    // auto-connecting their configured default relay on first run. OSS builds
    // leave this unset and retain explicit community selection.
    if std::env::var("BUZZ_BUILD_AUTO_CONNECT_DEFAULT_RELAY").is_ok() {
        println!("cargo:rustc-env=BUZZ_DESKTOP_BUILD_AUTO_CONNECT_DEFAULT_RELAY=1");
    }

    let updater_public_key = std::env::var("BUZZ_UPDATER_PUBLIC_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let updater_endpoint = std::env::var("BUZZ_UPDATER_ENDPOINT")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if updater_public_key.is_some() && updater_endpoint.is_some() {
        println!("cargo:rustc-cfg=buzz_updater_enabled");
    }

    // Cargo test executables get no embedded Windows manifest (tauri_build
    // attaches one to bin targets only), so the loader binds comctl32 v5, which
    // lacks TaskDialogIndirect (statically imported via tauri-plugin-dialog/rfd)
    // and debug test exes die at load with STATUS_ENTRYPOINT_NOT_FOUND. Declaring
    // the Common Controls v6 dependency makes link.exe emit a side-by-side
    // <exe>.manifest that the loader honors for manifest-less executables;
    // binaries with an embedded manifest (the real app) ignore it.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        println!(
            "cargo:rustc-link-arg=/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
        );
    }

    tauri_build::try_build(
        tauri_build::Attributes::new().plugin(
            "websocket",
            tauri_build::InlinedPlugin::new()
                .commands(&["connect", "send", "disconnect", "disconnect_all"])
                .default_permission(tauri_build::DefaultPermissionRule::AllowAllCommands),
        ),
    )
    .expect("failed to build Tauri application");
}
