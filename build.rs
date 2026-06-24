// Embed an "requireAdministrator" manifest so users get a UAC prompt.
fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        // Use embed-manifest only on Windows host build.
        if let Err(err) = embed_manifest::embed_manifest(
            embed_manifest::new_manifest("Fdiff")
                .ui_access(false)
                .requested_execution_level(embed_manifest::manifest::ExecutionLevel::RequireAdministrator),
        ) {
            // Don't fail the build if manifest embedding fails (e.g. on cross-build).
            println!("cargo:warning=embed_manifest failed: {err}");
        }
    }
    println!("cargo:rerun-if-changed=build.rs");
}
