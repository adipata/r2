// build.rs discovery seed test (R0, handed to R7, spec §4.1.1).
#[test]
fn build_rs_lists_every_command_module() {
    let stems: Vec<&str> = crate::commands::module_commands()
        .into_iter()
        .map(|(stem, _)| stem)
        .collect();
    assert_eq!(
        stems,
        [
            "copy",
            "crypto",
            "help",
            "kek",
            "key_template",
            "keys",
            "misc",
            "providers"
        ]
    );
}

// build.rs itself, compiled as a module so its file-name filter is unit-testable.
#[allow(dead_code, clippy::panic)]
#[path = "../../build.rs"]
mod build_script;

#[test]
fn build_rs_skips_file_stems_that_are_not_module_names() {
    for ok in ["keys", "key_template", "_private", "a1", "copy"] {
        assert!(build_script::is_module_stem(ok), "{ok}");
    }
    for bad in [
        "",
        "_",
        "mod",
        "fn",
        "type",
        ".#keys",
        ".keys",
        "key-template",
        "2fa",
        "keys.bak",
        "kéys",
    ] {
        assert!(!build_script::is_module_stem(bad), "{bad}");
    }
}
