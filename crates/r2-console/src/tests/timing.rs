// Operation timing tests (spec §11 D31 — r2 only; no c2 counterpart to port).
//
// With the timing display on (`r2_core::runtime::set_timing_shown(true)`, which the r2
// binary does for real sessions) the result of a timed operation carries the provider time:
// the hex result's footer "<n> bytes in <t>", " in <t>" at the very end of the text result
// lines (after ", <fmt>-encoded" on `export --kek`), a "loaded/unwrapped in <t>" line after
// the load / load --kek table, and an extra plain span after verify's verdict. With it off (the in-process default) every output is c2's, unchanged.
// FakeProvider + ScriptedIo throughout (§4.10). The flag is thread-local: each test turns it
// on through a guard that turns it off again, even when the test fails.
use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use r2_core::error::{ConsoleError, Result};
use r2_core::io::{Renderable, Span, TableData, Tone};
use r2_core::keys::KeyInfo;
use r2_core::params::Params;
use r2_core::runtime::{format_elapsed, set_timing_shown, timed};
use r2_provider::{GenerateRequest, MechanismInvocation, Provider, ProviderRegistry, WrapOptions};
use r2_testkit::{FakeHooks, FakeProvider, ScriptedIo};

use super::keys_cmd_support::{
    Pair, aes_material, ctx_with, make_pair, private_material, rsa_spki_der,
};
use crate::testing::run_line;

const DATA_16: &str = "00112233445566778899aabbccddeeff";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Timing display on for this thread while alive (off again on drop, even on panic).
struct TimingOn;

impl TimingOn {
    fn new() -> Self {
        set_timing_shown(true);
        Self
    }
}

impl Drop for TimingOn {
    fn drop(&mut self) {
        set_timing_shown(false);
    }
}

/// Asserts `text` is one `format_elapsed` value: whole µs, whole ms, or seconds with two
/// decimals.
fn assert_elapsed(text: &str) {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let ok = if let Some(n) = text.strip_suffix("µs") {
        digits(n)
    } else if let Some(n) = text.strip_suffix("ms") {
        digits(n)
    } else if let Some(n) = text.strip_suffix('s') {
        matches!(n.split_once('.'), Some((whole, frac)) if digits(whole) && frac.len() == 2 && digits(frac))
    } else {
        false
    };
    assert!(ok, "not an elapsed time: {text:?}");
}

/// `line` is `head` + " in <t>" (+ `tail`); returns <t>.
fn timed_line<'a>(line: &'a str, head: &str, tail: &str) -> &'a str {
    let rest = line
        .strip_prefix(head)
        .and_then(|rest| rest.strip_prefix(" in "))
        .and_then(|rest| rest.strip_suffix(tail))
        .unwrap_or_else(|| panic!("{line:?} is not {head:?} + \" in <t>\" + {tail:?}"));
    assert_elapsed(rest);
    rest
}

/// The `format_elapsed` text back as a Duration (for "less than" checks).
fn parse_elapsed(text: &str) -> Duration {
    if let Some(n) = text.strip_suffix("µs") {
        Duration::from_micros(n.parse().unwrap())
    } else if let Some(n) = text.strip_suffix("ms") {
        Duration::from_millis(n.parse().unwrap())
    } else {
        Duration::from_secs_f64(text.strip_suffix('s').unwrap().parse().unwrap())
    }
}

fn hex_results(io: &ScriptedIo) -> Vec<(Vec<u8>, Option<String>, Option<Duration>)> {
    io.renderables()
        .into_iter()
        .filter_map(|r| match r {
            Renderable::Hex {
                data,
                title,
                elapsed,
            } => Some((data.to_vec(), title, elapsed)),
            _ => None,
        })
        .collect()
}

fn table_titles(io: &ScriptedIo) -> Vec<String> {
    io.renderables()
        .into_iter()
        .filter_map(|r| match r {
            Renderable::Table(TableData { title, .. }) => title,
            _ => None,
        })
        .collect()
}

fn last_line(io: &ScriptedIo) -> String {
    io.output().last().cloned().unwrap_or_default()
}

/// A make_pair session with AES "aeskey" (bytes 0..32) in mem.
fn crypto_pair() -> Pair {
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "aeskey", None, None)
        .unwrap();
    p
}

/// `crate::testing::run_line` under the process-global state lock (the verbs honor the
/// process-global Ctrl-C flag, §11 D13).
fn run_locked(ctx: &crate::context::AppContext, line: &str) -> Result<crate::repl::Flow> {
    let _lock = r2_testkit::global_state_lock();
    r2_core::runtime::reset_interrupt();
    run_line(ctx, line)
}

// ---------------------------------------------------------------------------
// timing on: crypto verbs
// ---------------------------------------------------------------------------

#[test]
fn encrypt_hex_result_shows_the_provider_time() {
    let _on = TimingOn::new();
    let p = crypto_pair();
    run_locked(&p.ctx, &format!("encrypt mem:aeskey ecb 0x{DATA_16}")).unwrap();
    let results = hex_results(&p.io);
    assert_eq!(results.len(), 1);
    let (data, title, elapsed) = &results[0];
    assert_eq!(data.len(), 16);
    assert_eq!(title.as_deref(), Some("ciphertext — AES-ECB"));
    let elapsed = elapsed.expect("the hex result carries the provider time");
    // the footer: "<n> bytes in <t>"
    let shown = format_elapsed(elapsed);
    assert_elapsed(&shown);
    let text = p.io.text();
    assert!(
        text.lines()
            .last()
            .unwrap()
            .contains(&format!(" 16 bytes in {shown} ")),
        "{text}"
    );
}

#[test]
fn encrypt_out_line_ends_with_the_time() {
    let _on = TimingOn::new();
    let p = crypto_pair();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("ct.bin");
    run_locked(
        &p.ctx,
        &format!("encrypt mem:aeskey ecb 0x{DATA_16} --out {}", out.display()),
    )
    .unwrap();
    assert_eq!(p.io.output().len(), 1);
    timed_line(
        &last_line(&p.io),
        &format!("wrote 16 bytes to {}", out.display()),
        "",
    );
    assert!(hex_results(&p.io).is_empty());
}

#[test]
fn sign_and_verify_show_the_time() {
    let _on = TimingOn::new();
    let p = crypto_pair();
    run_locked(&p.ctx, "sign mem:aeskey cmac 0xdeadbeef").unwrap();
    let (mac, _, elapsed) = hex_results(&p.io).remove(0);
    assert!(elapsed.is_some());
    let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
    run_locked(
        &p.ctx,
        &format!("verify mem:aeskey cmac 0xdeadbeef --sig 0x{hex}"),
    )
    .unwrap();
    let Some(Renderable::Styled(lines)) = p.io.renderables().pop() else {
        panic!("{:?}", p.io.renderables());
    };
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert_eq!(line.len(), 2, "{line:?}");
    assert_eq!(
        line[0],
        Span {
            text: "signature VALID".to_owned(),
            tone: Tone::Success,
        }
    );
    assert_eq!(line[1].tone, Tone::Plain);
    assert_elapsed(line[1].text.strip_prefix(" in ").unwrap());
    timed_line(&last_line(&p.io), "signature VALID", "");
}

#[test]
fn random_hex_result_shows_the_time() {
    let _on = TimingOn::new();
    let p = make_pair(&[]);
    run_locked(&p.ctx, "random mem 8").unwrap();
    let (data, title, elapsed) = hex_results(&p.io).remove(0);
    assert_eq!(data.len(), 8);
    assert_eq!(title.as_deref(), Some("random — mem"));
    assert_elapsed(&format_elapsed(elapsed.unwrap()));
}

// ---------------------------------------------------------------------------
// timing on: key management
// ---------------------------------------------------------------------------

#[test]
fn generate_lines_end_with_the_time() {
    let _on = TimingOn::new();
    let p = make_pair(&[]);
    run_line(&p.ctx, "generate mem aes size=256 --label k").unwrap();
    timed_line(&last_line(&p.io), "generated mem:k (256-bit aes)", "");
    run_line(&p.ctx, "generate mem rsa size=2048 --label pair").unwrap();
    timed_line(
        &last_line(&p.io),
        "generated 2048-bit rsa keypair mem:pair (public key shares the label/id)",
        "",
    );
}

#[test]
fn load_shows_the_time_after_the_table() {
    let _on = TimingOn::new();
    let p = make_pair(&[]);
    run_line(&p.ctx, &format!("load mem aes {DATA_16} --label lk")).unwrap();
    // the title stays c2's (a table title wraps at the table's width); the time follows
    assert_eq!(table_titles(&p.io), ["loaded into mem"]);
    timed_line(&last_line(&p.io), "loaded", "");
}

#[test]
fn export_lines_end_with_the_time() {
    let _on = TimingOn::new();
    let dir = tempfile::tempdir().unwrap();
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "aes1", None, None)
        .unwrap();
    p.mem
        .import_key(&private_material(), "rsa1", None, None)
        .unwrap();
    // plain
    let raw = dir.path().join("key.bin");
    run_line(&p.ctx, &format!("export mem:aes1 {}", raw.display())).unwrap();
    timed_line(
        &last_line(&p.io),
        &format!("wrote 32 bytes to {} (raw)", raw.display()),
        "",
    );
    // --public
    let public = dir.path().join("pub.der");
    run_line(
        &p.ctx,
        &format!("export mem:rsa1 {} --public --format der", public.display()),
    )
    .unwrap();
    timed_line(
        &last_line(&p.io),
        &format!(
            "wrote {} bytes to {} (der)",
            rsa_spki_der().len(),
            public.display()
        ),
        "",
    );
    // p12 with --password (the PKCS#12 build itself is not provider time, but the
    // export_key calls are)
    let p12 = dir.path().join("bundle.p12");
    run_line(
        &p.ctx,
        &format!(
            "export mem:rsa1 {} --format p12 --password pw",
            p12.display()
        ),
    )
    .unwrap();
    let written = std::fs::read(&p12).unwrap().len();
    timed_line(
        &last_line(&p.io),
        &format!("wrote {written} bytes to {} (p12)", p12.display()),
        "",
    );
}

#[test]
fn csr_line_ends_with_the_time() {
    let _on = TimingOn::new();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("req.csr");
    let p = make_pair(&[]);
    p.mem
        .import_key(&private_material(), "webkey", None, None)
        .unwrap();
    run_line(&p.ctx, &format!("csr mem:webkey {}", out.display())).unwrap();
    timed_line(
        &last_line(&p.io),
        &format!(
            "wrote CSR for mem:webkey to {} (subject: CN=webkey)",
            out.display()
        ),
        "",
    );
}

#[test]
fn export_kek_line_ends_with_the_time() {
    let _on = TimingOn::new();
    let dir = tempfile::tempdir().unwrap();
    let p = make_pair(&[]);
    p.mem
        .import_key(&aes_material(), "kek", None, None)
        .unwrap();
    p.mem
        .import_key(&aes_material(), "target", None, None)
        .unwrap();
    let out = dir.path().join("wrapped.hex");
    run_line(
        &p.ctx,
        &format!(
            "export mem:target {} --kek kek --mech kwp --outformat hex",
            out.display()
        ),
    )
    .unwrap();
    timed_line(
        &last_line(&p.io),
        &format!(
            "wrote {}: 32-byte blob wrapped under mem:kek with AES-KEY-WRAP-PAD, hex-encoded",
            out.display()
        ),
        "",
    );
    // raw: no encoding note
    let raw = dir.path().join("wrapped.bin");
    run_line(
        &p.ctx,
        &format!("export mem:target {} --kek kek --mech kwp", raw.display()),
    )
    .unwrap();
    timed_line(
        &last_line(&p.io),
        &format!(
            "wrote {}: 32-byte blob wrapped under mem:kek with AES-KEY-WRAP-PAD",
            raw.display()
        ),
        "",
    );
}

#[test]
fn load_kek_shows_the_time_after_the_table() {
    let _on = TimingOn::new();
    let p = make_pair(&[]);
    let kek = p
        .mem
        .import_key(&aes_material(), "kek", None, None)
        .unwrap();
    let target = p
        .mem
        .import_key(&aes_material(), "src", None, None)
        .unwrap();
    let blob = p
        .mem
        .wrap_key(
            &kek,
            &MechanismInvocation::new("AES-KEY-WRAP-PAD", Params::new()),
            &target,
            &WrapOptions::default(),
        )
        .unwrap();
    let hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();
    run_line(
        &p.ctx,
        &format!("load mem aes {hex} --kek kek --mech kwp --label back"),
    )
    .unwrap();
    assert_eq!(
        table_titles(&p.io),
        ["unwrapped into mem (AES-KEY-WRAP-PAD)"]
    );
    timed_line(&last_line(&p.io), "unwrapped", "");
}

#[test]
fn copy_line_ends_with_the_time() {
    let _on = TimingOn::new();
    let p = make_pair(&[]);
    p.mem.import_key(&aes_material(), "k", None, None).unwrap();
    run_line(&p.ctx, "copy mem:k mem --label k3").unwrap();
    timed_line(&last_line(&p.io), "copied mem:k -> mem:k3 (secret aes)", "");
}

// ---------------------------------------------------------------------------
// timing off (the in-process default): c2's output unchanged
// ---------------------------------------------------------------------------

#[test]
fn timing_off_by_default_leaves_the_output_unchanged() {
    assert!(!r2_core::runtime::timing_shown());
    let p = crypto_pair();
    run_locked(&p.ctx, &format!("encrypt mem:aeskey ecb 0x{DATA_16}")).unwrap();
    let (_, _, elapsed) = hex_results(&p.io).remove(0);
    assert_eq!(elapsed, None);
    let footer = p.io.text().lines().last().unwrap().to_owned();
    assert!(footer.contains(" 16 bytes "), "{footer}");
    assert!(!footer.contains(" in "), "{footer}");

    run_line(&p.ctx, "generate mem aes size=256 --label k").unwrap();
    assert_eq!(last_line(&p.io), "generated mem:k (256-bit aes)");
    run_line(&p.ctx, &format!("load mem aes {DATA_16} --label lk")).unwrap();
    assert_eq!(table_titles(&p.io), ["loaded into mem"]);
    run_line(&p.ctx, "copy mem:k mem --label k3").unwrap();
    assert_eq!(last_line(&p.io), "copied mem:k -> mem:k3 (secret aes)");
    run_locked(&p.ctx, "sign mem:aeskey cmac 0xdeadbeef").unwrap();
    let (mac, _, elapsed) = hex_results(&p.io).pop().unwrap();
    assert_eq!(elapsed, None);
    let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
    run_locked(
        &p.ctx,
        &format!("verify mem:aeskey cmac 0xdeadbeef --sig 0x{hex}"),
    )
    .unwrap();
    assert_eq!(
        p.io.renderables().pop().unwrap(),
        Renderable::Styled(vec![vec![Span {
            text: "signature VALID".to_owned(),
            tone: Tone::Success,
        }]])
    );
}

/// Turning it off again restores the plain output on the same thread.
#[test]
fn timing_can_be_switched_off_again() {
    let p = make_pair(&[]);
    {
        let _on = TimingOn::new();
        run_line(&p.ctx, "generate mem aes size=256 --label a").unwrap();
        timed_line(&last_line(&p.io), "generated mem:a (256-bit aes)", "");
    }
    run_line(&p.ctx, "generate mem aes size=256 --label b").unwrap();
    assert_eq!(last_line(&p.io), "generated mem:b (256-bit aes)");
}

// ---------------------------------------------------------------------------
// the time is per command
// ---------------------------------------------------------------------------

const SLOW: Duration = Duration::from_millis(40);

/// Provider time accumulated outside a command never reaches its result.
#[test]
fn run_line_resets_the_time_before_each_command() {
    let _on = TimingOn::new();
    let p = crypto_pair();
    timed(|| std::thread::sleep(SLOW));
    run_locked(&p.ctx, &format!("encrypt mem:aeskey ecb 0x{DATA_16}")).unwrap();
    let (_, _, elapsed) = hex_results(&p.io).remove(0);
    assert!(elapsed.unwrap() < SLOW, "{elapsed:?}");
}

/// A failed command's provider time does not leak into the next command's result.
#[test]
fn a_failed_commands_time_does_not_leak() {
    struct SlowThenFail {
        failed: Cell<bool>,
    }
    impl FakeHooks for SlowThenFail {
        fn generate_key(
            &self,
            _next: &dyn Provider,
            _request: &GenerateRequest,
        ) -> Option<Result<KeyInfo>> {
            if self.failed.replace(true) {
                return None;
            }
            std::thread::sleep(SLOW);
            Some(Err(ConsoleError::provider("token busy")))
        }
    }
    let _on = TimingOn::new();
    let mem = Rc::new(FakeProvider::new("mem").with_hooks(Rc::new(SlowThenFail {
        failed: Cell::new(false),
    })));
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::clone(&mem) as Rc<dyn Provider>)
        .unwrap();
    let io = Rc::new(ScriptedIo::empty());
    let ctx = ctx_with(&io, registry, None);
    let err = run_line(&ctx, "generate mem aes size=256 --label k").unwrap_err();
    assert_eq!(err.message, "token busy");
    run_line(&ctx, "generate mem aes size=256 --label k").unwrap();
    let line = last_line(&io);
    let shown = timed_line(&line, "generated mem:k (256-bit aes)", "");
    assert!(parse_elapsed(shown) < SLOW, "{shown}");
}
