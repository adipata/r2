"""Self-tests of the harness normalization (R13): prompt texts are compared, only the
echoed input is dropped. Run: ``python3 -B -m unittest discover -s parity/harness``."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from normalize import normalize  # noqa: E402

INPUTS = ["encrypt mem:k", "3", "IVHEX", "load mem --file x.p12", "pw", "exit"]
SECRETS = {"pw"}
PAD = " " * 20


def c2_out(select: str = "Select [1-4]: ", iv: str = "IV (16 bytes): ") -> str:
    lines = [
        "Warning: Input is not a terminal (fd=0).",
        "c2 0.2.0 — type 'help' for commands",
        f"c2> encrypt mem:k{PAD}c2> encrypt mem:k\r",
        "  1  ecb",
        f"{select}3{PAD}{select}3\r",
        f"{iv}IVHEX{PAD}{iv}IVHEX\r",
        "ciphertext: 00",
        f"c2> load mem --file x.p12{PAD}c2> load mem --file x.p12\r",
        f"Password for PKCS#12: **{PAD}Password for PKCS#12: **\r",
        "loaded",
        f"c2> exit{PAD}c2> exit\r",
        "",
    ]
    return "\n".join(lines)


def r2_out(select: str = "Select [1-4]: ", iv: str = "IV (16 bytes): ", extra: str = "") -> str:
    lines = [
        "r2 0.2.0 — type 'help' for commands",
        "r2> encrypt mem:k",
        "  1  ecb",
        f"{select}3",
        f"{iv}IVHEX",
        "ciphertext: 00",
        "r2> load mem --file x.p12",
        "Password for PKCS#12: ",
        *([extra] if extra else []),
        "loaded",
        "r2> exit",
        "",
    ]
    return "\n".join(lines)


def norm(tool: str, text: str) -> list[str]:
    return normalize(text, tool, "/w", "/f", INPUTS, SECRETS)


class PromptsAreCompared(unittest.TestCase):
    def test_same_prompts_are_equal_and_kept(self) -> None:
        c2, r2 = norm("c2", c2_out()), norm("r2", r2_out())
        self.assertEqual(c2, r2)
        self.assertIn("PROMPT: Select [1-4]: 3", r2)
        self.assertIn("PROMPT: IV (16 bytes): IVHEX", r2)
        self.assertIn("PROMPT: Password for PKCS#12: **", r2)
        self.assertFalse(any(line.startswith(("r2>", "c2>")) for line in r2), r2)

    def test_changed_prompt_text_is_a_difference(self) -> None:
        self.assertNotEqual(norm("c2", c2_out()), norm("r2", r2_out(select="Pick one> ")))
        self.assertNotEqual(norm("c2", c2_out()), norm("r2", r2_out(iv="Totally wrong? ")))
        self.assertNotEqual(norm("c2", c2_out(iv="IV: ")), norm("r2", r2_out()))

    def test_output_ending_like_a_prompt_is_not_swallowed(self) -> None:
        # an extra r2 line ending in ': ' while an input is pending stays in the transcript
        self.assertNotEqual(norm("c2", c2_out()), norm("r2", r2_out(extra="note: ")))

    def test_echoed_secret_is_a_difference(self) -> None:
        leaked = r2_out().replace("Password for PKCS#12: \n", "Password for PKCS#12: pw\n")
        self.assertNotEqual(norm("c2", c2_out()), norm("r2", leaked))

    def test_incremental_c2_render_reduces_to_the_final_copy(self) -> None:
        text = c2_out().replace(
            f"{'IV (16 bytes): '}IVHEX{PAD}{'IV (16 bytes): '}IVHEX\r",
            "IV (16 bytes): IV\r\n\r\n   IV (16 bytes): IVHEX\r\n     IV (16 bytes): IVHEX\r",
        )
        self.assertEqual(norm("c2", text), norm("r2", r2_out()))
        once = c2_out().replace(
            f"{'IV (16 bytes): '}IVHEX{PAD}{'IV (16 bytes): '}IVHEX\r",
            "IV (16 bytes): IVH\r\n\r\n" + PAD + "IV (16 bytes): IVHEX\r",
        )
        self.assertEqual(norm("c2", once), norm("r2", r2_out()))

    def test_c2_80_column_wrap_is_rejoined(self) -> None:
        iv = "IV (16 bytes): IVHEX"
        long_prompt = "x" * 75 + " IV (16 bytes): "  # the echo crosses column 80
        wrapped_echo = long_prompt + "IVHEX"
        head, tail = wrapped_echo[:79], wrapped_echo[80:]
        wrap = f"\r{' ' * 79}{wrapped_echo[79]}\r\n"
        text = c2_out().replace(
            f"{iv}{PAD}{iv}\r", f"{head}{wrap}{tail}{PAD}{head}{wrap}{tail}\r"
        )
        self.assertEqual(
            norm("c2", text), norm("r2", r2_out(iv=long_prompt))
        )

    def test_c2_prompt_echo_after_a_command_echo_run_is_kept(self) -> None:
        # an answer piped without its final newline: prompt_toolkit re-renders the command
        # echo and the prompt echo as one carriage-return run, then aborts (R13 PAR4-1)
        run = (
            "c2>\r\n\r\n     c2> generate mem aes\r\n\r\n   c2> generate mem aes\r\n"
            "Key label: lbl\r\n\r\n        Key label: lbl\r\nAborted.\n"
        )
        r2 = "r2> generate mem aes\nKey label: lbl\nAborted.\n"
        inputs = ["generate mem aes", "lbl"]
        c2_lines = normalize(run, "c2", "/w", "/f", inputs, set())
        self.assertEqual(c2_lines, normalize(r2, "r2", "/w", "/f", inputs, set()))
        self.assertIn("PROMPT: Key label: lbl", c2_lines)
        changed = run.replace("Key label", "Key name")
        self.assertNotEqual(
            normalize(changed, "c2", "/w", "/f", inputs, set()),
            normalize(r2, "r2", "/w", "/f", inputs, set()),
        )

    def test_unparsed_c2_echo_is_kept_for_the_diff(self) -> None:
        text = c2_out().replace(
            f"{'IV (16 bytes): '}IVHEX{PAD}{'IV (16 bytes): '}IVHEX\r", "IV (16\r\nbytes): IVHEX\r"
        )
        self.assertNotEqual(norm("c2", text), norm("r2", r2_out()))


class RowOrderIsCompared(unittest.TestCase):
    MEM_AB = "r2> keys mem\n mem:a  secret  aes\n mem:b  secret  aes\n"
    MEM_BA = "r2> keys mem\n mem:b  secret  aes\n mem:a  secret  aes\n"

    def test_memory_row_order_is_a_difference(self) -> None:
        # memory listing order (insertion order) is c2 behavior: never sorted away
        self.assertNotEqual(
            normalize(self.MEM_AB, "r2", "/w", "/f", ["keys mem"]),
            normalize(self.MEM_BA, "r2", "/w", "/f", ["keys mem"]),
        )
        self.assertNotEqual(
            normalize(self.MEM_AB, "r2", "/w", "/f", ["keys mem"], token_provider="hsm"),
            normalize(self.MEM_BA, "r2", "/w", "/f", ["keys mem"], token_provider="hsm"),
        )

    def test_token_rows_and_handles_are_normalized_only_in_token_mode(self) -> None:
        ab = "r2> keys hsm\n hsm:a  secret  aes\n hsm:b  secret  aes\nhandle 7\n"
        ba = "r2> keys hsm\n hsm:b  secret  aes\n hsm:a  secret  aes\nhandle 9\n"
        self.assertEqual(
            normalize(ab, "r2", "/w", "/f", ["keys hsm"], token_provider="hsm"),
            normalize(ba, "r2", "/w", "/f", ["keys hsm"], token_provider="hsm"),
        )
        self.assertNotEqual(
            normalize(ab, "r2", "/w", "/f", ["keys hsm"]),
            normalize(ba, "r2", "/w", "/f", ["keys hsm"]),
        )


if __name__ == "__main__":
    unittest.main()
