// R0 skeleton — owner R0 (generated from spec §4)
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
