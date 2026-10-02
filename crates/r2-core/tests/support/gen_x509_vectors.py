"""R6 parity vectors for x509build/x509info (run in c2@408d6f2's venv, pyca 49.0):

    cd ../c2 && uv run python ../r2/crates/r2-core/tests/support/gen_x509_vectors.py \
        > ../r2/crates/r2-core/tests/support/x509_vectors.rs && (cd ../r2 && cargo fmt)

* SUBJECTS: `x509.Name.from_rfc4514_string(s)` → DER of `name.public_bytes()`, or the
  ValueError text c2 embeds in "invalid subject {s!r}: {text}"; plus, for parsed subjects,
  whether c2's `build_csr` re-parse (`load_der_x509_csr`) rejects the name (its text).
* NAMES: `x509.Name.from_bytes(der).rfc4514_string()` and the first CN, or the error.
No key material is committed: the CSR check signs with a key generated per run.
"""
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from c2.core.errors import ConsoleError
from c2.core.x509build import SignatureAlg, build_csr

SUBJECTS = [
    "CN=mykey", "CN=mykey,O=ACME", "not a subject at all", "", "CN=", "C=US", "C=USA", "C=é",
    "CN=a+O=b", "CN=b+CN=a", "CN=a+CN=a", "cn=x", "SN=x", "emailAddress=x",
    "1.2.840.113549.1.9.1=a@b", "2.5.4.5=123", "2.5.4.46=x", "1.3.6.1.4.1.311.60.2.1.3=US",
    "1.3.6.1.4.1.311.60.2.1.3=USA", "DC=example,DC=com", "UID=u", "STREET=s", "L=l,ST=s",
    "CN=#0c03616263", "CN=#zz", "CN=#616", "CN=#ff", "CN=a\\,b", "CN=a\\2cb", "CN=\\c3\\a9",
    "CN=\\ff", "CN=\\c3", "CN=a\\", "CN= a", "CN=a ", "CN=\\ a\\ ", "CN=a\"b", "CN=a;b",
    "CN=a,", ",CN=a", "CN=a,,O=b", "CN=a=b", "CN=a#b", "CN=#", "CN=é", "CN=" + "x" * 64,
    "CN=" + "x" * 65, "CN=" + "é" * 32, "CN=" + "é" * 33, "CN=a\x00b", "1.2=a", "3.1=x",
    "1.40=x", "0.39=x", "2.999=x", "1.2.840.99999999999999999999999999999=x",
    "1.2.840.999999999999999999999999999999999999999999=x", "1.2" + ".1234567" * 20 + "=x",
    "2.5.4.3=x", "01.2=x", "1.2.03=x", "1.2.=x", "1=x", "CN =x", "CN= x", "CN=x ,O=y",
    "CN=日本", "O=", "OU=a+OU=b", "CN=a+", "+CN=a", "CN=\\#a", "CN=\\=", "CN=a\\=b", "X-Y=1",
    "CN=\x7f", "CN=\x01", "CN=a\nb", "CN=a\\00b", "CN=\\41\\42", "CN=\\4", "CN=\\zz",
    "CN=\\gg", "CN=a b", "CN=  ", "CN= ", "CN=#41", "CN=#4142,O=x", "CN=#c3a9", "2.5.4.6=US",
    "C=U", "C=Ü", "CN=a\\+b", "CN=x,1.2.3.4=y", "CN=x+1.2.3.4=y", "CN=a\;b\\<c\\>d",
    "CN=a<b", "CN=a>b", "DC=é", "emailAddress", "CN", "=x", "CN=x,", "CN=x;O=y",
    "CN=\U0001F600", "CN=\\f0\\9f\\98\\80", "CN=\\e2\\82", "CN=\\80", "CN=\\e2\\28\\a1",
    "CN=\\c0\\af", "CN=\\ed\\a0\\80", "CN=#e282", "CN=#80", "CN=\\41\\c3",
    "CN=\\f4\\90\\80\\80", "1.2.3=", "1.2.3= ", "OU=", "2.5.4.45=ab", "2.5.4.45=#0302000a",
    "CN=#٣٣", "CN=\\٣٣", "1.2.٣=x", "1.٣=x", "A٣=x", "CN=a\\\\", "CN=\\\\\\41", "CN=a\\ ",
    "CN=\\\"q\\\"", "C=a*,CN=x", "CN=x+C=a*", "CN=x,O=y+C=a*", "C=a*,C=b*", "2.5.4.5=a_b",
    "1.3.6.1.4.1.311.60.2.1.3=é", "CN=x,CN=x", "O=a+OU=a", "CN=a+cn=b", "CN=a\\2", "CN=\\2g",
    "CN=a#", "CN=#\\41", "CN=x\t", "CN=\ty", "CN=é ", "STREET=1 Main St.",
]


def tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 128:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + body


def name(rdns: list[list[tuple[bytes, bytes]]]) -> bytes:
    return tlv(0x30, b"".join(
        tlv(0x31, b"".join(tlv(0x30, oid + val) for oid, val in rdn)) for rdn in rdns))


CN = bytes.fromhex("0603550403")
O = bytes.fromhex("060355040a")
UNK = bytes.fromhex("06032a0304")
UID = bytes.fromhex("0603550445")
EMAIL = bytes.fromhex("06092a864886f70d010901")
NAMES = {
    "bitstring_uid": name([[(UID, tlv(3, b"\x00\xab\xcd"))]]),
    "octet": name([[(CN, tlv(4, b"abc"))]]),
    "seq": name([[(CN, tlv(0x30, b""))]]),
    "utf8bad": name([[(CN, tlv(12, b"\xff"))]]),
    "bmp": name([[(CN, tlv(30, "é€".encode("utf-16-be")))]]),
    "bmpodd": name([[(CN, tlv(30, b"\x00"))]]),
    "univ": name([[(CN, tlv(28, "é😀".encode("utf-32-be")))]]),
    "printable_bad": name([[(CN, tlv(19, b"a_b@"))]]),
    "numeric": name([[(CN, tlv(18, b"12 3"))]]),
    "visible": name([[(CN, tlv(26, b"vis"))]]),
    "utctime": name([[(CN, tlv(23, b"x"))]]),
    "ia5": name([[(EMAIL, tlv(22, b"a@b"))]]),
    "empty_cn": name([[(CN, tlv(12, b""))]]),
    "escapes": name([[(CN, tlv(12, '#a"+,;<>\\\x00 '.encode()))]]),
    "lead_space": name([[(CN, tlv(12, b" x"))]]),
    "only_space": name([[(CN, tlv(12, b" "))]]),
    "two_space": name([[(CN, tlv(12, b"  "))]]),
    "hash_mid": name([[(CN, tlv(12, b"a#"))]]),
    "eq": name([[(CN, tlv(12, b"a=b"))]]),
    "multi_rdn": name([[(CN, tlv(12, b"a")), (O, tlv(12, b"b"))], [(UNK, tlv(12, b"z"))]]),
    "unsorted_set": name([[(O, tlv(12, b"b")), (CN, tlv(12, b"a"))]]),
    "empty_name": name([]),
    "empty_rdn": name([[]]),
    "dup_in_rdn": name([[(CN, tlv(12, b"a")), (CN, tlv(12, b"a"))]]),
    "long_cn": name([[(CN, tlv(12, b"x" * 70))]]),
    "all_short": name([[(bytes.fromhex("06035504" + h), tlv(12, b"v"))]
                       for h in ["03", "07", "08", "0a", "0b", "06", "09"]]
                      + [[(bytes.fromhex("060a0992268993f22c640119"), tlv(22, b"dc"))],
                         [(bytes.fromhex("060a0992268993f22c640101"), tlv(12, b"uid"))]]),
    "bigoid": name([[(bytes.fromhex("06112a8648a8b1f0bedcedb985f9a9ffffff7f"), tlv(12, b"v"))]]),
    "ctrl": name([[(CN, tlv(12, "a\nb\x7f é".encode()))]]),
    "two_cn": name([[(CN, tlv(12, b"first"))], [(CN, tlv(12, b"second"))]]),
    "cn_in_multi": name([[(O, tlv(12, b"o")), ]] + [[(CN, tlv(30, "ü".encode("utf-16-be")))]]),
}


def rs(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif o < 0x20 or o == 0x7F or o > 0x7E:
            out.append("\\u{%x}" % o)
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def main() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    print("// @generated by gen_x509_vectors.py in c2@408d6f2's venv (pyca 49.0). Do not edit.")
    print("#![allow(dead_code)]")
    print()
    print("/// (subject, Ok(name DER hex) | Err(pyca text), c2 build_csr re-parse error or \"\")")
    print("pub const SUBJECTS: &[(&str, Result<&str, &str>, &str)] = &[")
    for s in SUBJECTS:
        try:
            der = x509.Name.from_rfc4514_string(s).public_bytes()
        except ValueError as exc:
            print(f"    ({rs(s)}, Err({rs(str(exc))}), \"\"),")
            continue
        csr_err = ""
        try:
            build_csr(spki, subject=s, sig_alg=SignatureAlg.ECDSA_SHA256,
                      sign=lambda t: key.sign(t, ec.ECDSA(hashes.SHA256())))
        except ConsoleError as exc:
            assert str(exc).startswith("assembled CSR failed to parse: "), exc
            csr_err = str(exc)[len("assembled CSR failed to parse: "):]
        print(f"    ({rs(s)}, Ok(\"{der.hex()}\"), {rs(csr_err)}),")
    print("];")
    print()
    print("/// Ok((rfc4514_string, first CN)) | Err(pyca exception class + text)")
    print("pub type NameOutcome = Result<(&'static str, Option<&'static str>), &'static str>;")
    print()
    print("/// (case, name DER hex, outcome)")
    print("pub const NAMES: &[(&str, &str, NameOutcome)] = &[")
    for k, der in NAMES.items():
        try:
            n = x509.Name.from_bytes(der)
            text = n.rfc4514_string()
            cns = n.get_attributes_for_oid(NameOID.COMMON_NAME)
            cn = f"Some({rs(cns[0].value)})" if cns else "None"
            print(f"    (\"{k}\", \"{der.hex()}\", Ok(({rs(text)}, {cn}))),")
        except Exception as exc:  # noqa: BLE001 — recorded verbatim
            print(f"    (\"{k}\", \"{der.hex()}\", Err({rs(type(exc).__name__ + ': ' + str(exc))})),")
    print("];")


main()
