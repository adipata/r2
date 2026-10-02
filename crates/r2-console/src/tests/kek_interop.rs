// Wrapped-key interop with c2 (R15 Accept: "c2-exported blobs load in r2, and vice
// versa"). The vectors in fixtures/kek_interop/ were written by c2@408d6f2's own REPL
// (`gen_kek_interop.py`, memory provider): fixed KEK bytes 00..1f, AES target 20..3f, a
// fixed RSA KEK pair and a fixed P-256 target.
//
// - c2 → r2: every c2 blob (kw/kwp/cbc/gcm/oaep/pkcs1, raw/hex/b64 files, an EC PKCS#8
//   payload) loads through r2's `load --kek --file` and yields the original key.
// - r2 → c2: the deterministic mechanisms (KW, KWP, CBC and GCM with fixed IVs) produce
//   byte-identical blobs in r2, so c2 loads them exactly as its own; the randomized RSA
//   blobs r2 wrote (`r2_oaep.b64`, `r2_pkcs1.bin`, from the ignored `write_r2_blobs`) were
//   loaded by c2 in the generator's part 2, and stay loadable in r2.
use std::path::{Path, PathBuf};
use std::rc::Rc;

use r2_core::codec::decode_data;
use r2_core::io::ConsoleIo;
use r2_core::keyparse::{KeyHint, parse_key_material};
use r2_memory::MemoryProvider;
use r2_provider::{KeySelector, Provider, ProviderRegistry};
use r2_testkit::ScriptedIo;

use crate::context::AppContext;
use crate::testing::{CtxBuilder, run_line};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tests/fixtures/kek_interop")
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn target() -> Vec<u8> {
    (32u8..64).collect()
}

const CBC_IV: &str = "000102030405060708090a0b0c0d0e0f";
const GCM_IV: &str = "000102030405060708090a0b";

/// An r2 session over a real MemoryProvider holding c2's SETUP objects.
fn session() -> (Rc<AppContext>, Rc<MemoryProvider>) {
    let mem = Rc::new(MemoryProvider::new("mem"));
    let registry = ProviderRegistry::new();
    registry
        .register(Rc::clone(&mem) as Rc<dyn Provider>)
        .unwrap();
    let io = Rc::new(ScriptedIo::empty());
    let ctx = CtxBuilder::new(io as Rc<dyn ConsoleIo>)
        .providers(registry)
        .build();
    let dir = fixtures();
    for line in [
        format!(
            "load mem aes {} --label kek",
            hex(&(0u8..32).collect::<Vec<_>>())
        ),
        format!("load mem aes {} --label target", hex(&target())),
        format!(
            "load mem --file {} --label rsakek",
            dir.join("rsa_kek.pem").display()
        ),
        format!(
            "load mem --file {} --label rsakek",
            dir.join("rsa_kek_pub.pem").display()
        ),
        format!(
            "load mem --file {} --label ectarget",
            dir.join("ec_target.pem").display()
        ),
    ] {
        run_line(&ctx, &line).unwrap();
    }
    (ctx, mem)
}

fn exported(mem: &MemoryProvider, label: &str) -> Vec<u8> {
    let key = mem.find_key(&KeySelector::label(label)).unwrap();
    mem.export_key(&key).unwrap().data.to_vec()
}

fn ec_target_pkcs8() -> Vec<u8> {
    let pem = std::fs::read(fixtures().join("ec_target.pem")).unwrap();
    parse_key_material(&pem, KeyHint::Auto, None)
        .unwrap()
        .remove(0)
        .data
        .to_vec()
}

#[test]
fn c2_exported_blobs_load_in_r2() {
    let (ctx, mem) = session();
    let dir = fixtures();
    for (file, kek, mech, params) in [
        ("c2_kw.bin", "kek", "kw", String::new()),
        ("c2_kwp.hex", "kek", "kwp", String::new()),
        ("c2_cbc.b64", "kek", "cbc", format!("iv=0x{CBC_IV}")),
        ("c2_gcm.bin", "kek", "gcm", format!("iv=0x{GCM_IV}")),
        ("c2_oaep.bin", "rsakek", "oaep", String::new()),
        ("c2_pkcs1.b64", "rsakek", "pkcs1", String::new()),
    ] {
        run_line(
            &ctx,
            &format!(
                "load mem aes --file {} --kek {kek} --mech {mech} {params} --label from-{mech}",
                dir.join(file).display()
            ),
        )
        .unwrap();
        assert_eq!(exported(&mem, &format!("from-{mech}")), target(), "{file}");
    }
    // a private-key payload: unencrypted PKCS#8 DER inside the blob (§5.4)
    run_line(
        &ctx,
        &format!(
            "load mem ec --file {} --kek kek --mech kwp --label ecback",
            dir.join("c2_ec_kwp.bin").display()
        ),
    )
    .unwrap();
    assert_eq!(exported(&mem, "ecback"), ec_target_pkcs8());
}

#[test]
fn r2_deterministic_blobs_are_byte_identical_to_c2() {
    let (ctx, _mem) = session();
    let dir = fixtures();
    let out = tempfile::tempdir().unwrap();
    for (file, source, mech, params, outformat) in [
        ("c2_kw.bin", "target", "kw", String::new(), "raw"),
        ("c2_kwp.hex", "target", "kwp", String::new(), "hex"),
        (
            "c2_cbc.b64",
            "target",
            "cbc",
            format!("iv=0x{CBC_IV}"),
            "b64",
        ),
        (
            "c2_gcm.bin",
            "target",
            "gcm",
            format!("iv=0x{GCM_IV}"),
            "raw",
        ),
        ("c2_ec_kwp.bin", "ectarget", "kwp", String::new(), "raw"),
    ] {
        let path = out.path().join(file);
        run_line(
            &ctx,
            &format!(
                "export mem:{source} {} --kek kek --mech {mech} {params} --outformat {outformat}",
                path.display()
            ),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            std::fs::read(dir.join(file)).unwrap(),
            "{file}"
        );
    }
}

#[test]
fn r2_rsa_blobs_checked_by_c2_still_load_in_r2() {
    let (ctx, mem) = session();
    let dir = fixtures();
    for (file, mech) in [("r2_oaep.b64", "oaep"), ("r2_pkcs1.bin", "pkcs1")] {
        run_line(
            &ctx,
            &format!(
                "load mem aes --file {} --kek rsakek --mech {mech} --label r2-{mech}",
                dir.join(file).display()
            ),
        )
        .unwrap();
        assert_eq!(exported(&mem, &format!("r2-{mech}")), target(), "{file}");
    }
    // the b64 file is text, as `--outformat b64` writes it
    let text = std::fs::read_to_string(dir.join("r2_oaep.b64")).unwrap();
    assert!(text.ends_with('\n'));
    assert_eq!(decode_data(text.trim()).unwrap().0.len(), 256);
}

#[test]
#[ignore = "fixture writer: regenerates r2_oaep.b64 / r2_pkcs1.bin for gen_kek_interop.py part 2"]
fn write_r2_blobs() {
    let (ctx, _mem) = session();
    let dir = fixtures();
    run_line(
        &ctx,
        &format!(
            "export mem:target {} --kek rsakek:pub --mech oaep --outformat b64",
            dir.join("r2_oaep.b64").display()
        ),
    )
    .unwrap();
    run_line(
        &ctx,
        &format!(
            "export mem:target {} --kek rsakek:pub --mech pkcs1",
            dir.join("r2_pkcs1.bin").display()
        ),
    )
    .unwrap();
}
