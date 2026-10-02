//! clap arguments (spec §4.9.11; owner R7) — c2 `app._build_parser`. Usage and error texts
//! are clap's (§11 D19); the options and their semantics are c2's.
use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgAction, Parser};

/// Interactive cryptographic operator console.
#[derive(Debug, Parser)]
#[command(
    name = "r2",
    version,
    about = "Interactive cryptographic operator console.",
    disable_version_flag = true
)]
pub(crate) struct Args {
    /// show program's version number and exit
    #[arg(long, action = ArgAction::Version)]
    #[allow(dead_code)] // clap acts on it (prints "r2 <version>" and exits)
    version: Option<bool>,
    /// path to an external configuration file (overrides discovery)
    #[arg(long, value_name = "PATH")]
    config: Option<OsString>,
    /// force DEBUG logging, mirror warnings to stderr, print full tracebacks
    #[arg(long)]
    pub(crate) debug: bool,
}

impl Args {
    /// `--config` as `load_config` takes it: an EMPTY value counts as absent (c2
    /// `Path(args.config) if args.config else None`, §4.8.1).
    pub(crate) fn config_path(&self) -> Option<PathBuf> {
        self.config
            .as_ref()
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(argv: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("r2").chain(argv.iter().copied()))
    }

    #[test]
    fn flags_parse() {
        let args = parse(&["--config", "/x/r2.yaml", "--debug"]).unwrap();
        assert!(args.debug);
        assert_eq!(args.config_path(), Some(PathBuf::from("/x/r2.yaml")));
        let args = parse(&[]).unwrap();
        assert!(!args.debug);
        assert_eq!(args.config_path(), None);
        // an empty --config counts as absent
        assert_eq!(parse(&["--config", ""]).unwrap().config_path(), None);
        assert_eq!(parse(&["--config="]).unwrap().config_path(), None);
    }

    #[test]
    fn usage_errors_exit_2_and_version_has_no_short_flag() {
        for argv in [&["--bogus"][..], &["extra"], &["--config"], &["-V"]] {
            let err = parse(argv).unwrap_err();
            assert_eq!(err.exit_code(), 2, "{argv:?}");
        }
        let err = parse(&["--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert_eq!(err.exit_code(), 0);
        assert_eq!(
            err.to_string(),
            format!("r2 {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}
