// r2-config (spec §4.8; owner R2): embedded defaults, discovery + merge, the typed model
// and the PyYAML-faithful YAML loader/emitter used by every crate that reads or writes YAML.
#![forbid(unsafe_code)]
pub mod decode;
pub mod dirs;
pub mod loader;
pub mod model;
pub mod yaml;
