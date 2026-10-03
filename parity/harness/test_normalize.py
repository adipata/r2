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


class HexResult(unittest.TestCase):
    """§11 D28: c2's grouped hex panel compares equal to r2's one-line hex result."""

    C2 = [
        "╭─ ciphertext — AES-CBC ──────────────╮",
        "│ c3180a43 959e647b e62f6f8e ae5ba11a │",
        "│ 00112233 c2c2c2c2                   │",
        "╰────────────────────────── 24 bytes ─╯",
    ]
    R2 = [
        "╭─ ciphertext — AES-CBC ───────╮",
        "c3180a43959e647be62f6f8eae5ba11a00112233c2c2c2c2",
        "╰─────────────────── 24 bytes ─╯",
    ]

    def test_grouped_rows_become_one_line(self) -> None:
        c2 = normalize("\n".join(self.C2), "c2", "/w", "/f")
        r2 = normalize("\n".join(self.R2), "r2", "/w", "/f")
        self.assertEqual(c2, r2)
        self.assertIn("c3180a43959e647be62f6f8eae5ba11a00112233c2c2c2c2", r2)

    def test_changed_hex_or_count_is_a_difference(self) -> None:
        c2 = normalize("\n".join(self.C2), "c2", "/w", "/f")
        r2 = [self.R2[0], self.R2[1].replace("c3", "c4"), self.R2[2]]
        self.assertNotEqual(c2, normalize("\n".join(r2), "r2", "/w", "/f"))
        r2 = [self.R2[0], self.R2[1], self.R2[2].replace("24", "25")]
        self.assertNotEqual(c2, normalize("\n".join(r2), "r2", "/w", "/f"))

    def test_other_panels_are_left_alone(self) -> None:
        error = ["╭─ error ─╮", "│ dead    │", "╰─────────╯"]
        self.assertEqual(normalize("\n".join(error), "c2", "/w", "/f"), ["error", "dead"])


class RandomHelpRow(unittest.TestCase):
    """§11 D29: r2's help row of the r2-only ``random`` command is dropped, nothing else."""

    HEAD = [" command     summary", "─" * 78]
    ROWS = [
        " quit        Leave the console (providers are shut down)",
        " sign        Sign data or compute a MAC (mechanism prompted when omitted)",
    ]
    RANDOM = " random      Generate random bytes with a provider's RNG"

    def help_text(self, *rows: str) -> str:
        """The ``help`` table as printed (the command echo is covered by the echo tests)."""
        return "\n".join([*self.HEAD, *rows, "help <command> shows its usage"])

    def test_r2_help_with_the_row_equals_c2_help_without_it(self) -> None:
        c2 = normalize(self.help_text(*self.ROWS), "c2", "/w", "/f")
        r2_help = self.help_text(self.ROWS[0], self.RANDOM, self.ROWS[1])
        r2 = normalize(r2_help, "r2", "/w", "/f")
        self.assertEqual(c2, r2)
        self.assertNotIn("random Generate random bytes with a provider's RNG", r2)

    def test_a_changed_random_summary_is_still_a_difference(self) -> None:
        c2 = normalize(self.help_text(*self.ROWS), "c2", "/w", "/f")
        changed = self.RANDOM.replace("RNG", "random number generator")
        r2 = normalize(self.help_text(self.ROWS[0], changed, self.ROWS[1]), "r2", "/w", "/f")
        self.assertNotEqual(c2, r2)
        self.assertIn(
            "random Generate random bytes with a provider's random number generator", r2
        )

    def test_c2_output_is_untouched(self) -> None:
        # the rule is r2-only: the same row in c2's output is kept (and so reported)
        c2 = normalize(self.RANDOM, "c2", "/w", "/f")
        self.assertEqual(c2, ["random Generate random bytes with a provider's RNG"])


class RandomIvPrompt(unittest.TestCase):
    """§11 D30: r2's "empty = random" note on IV prompts compares as c2's prompt."""

    INPUTS = ["encrypt mem:k cbc c0fe", "0x00112233445566778899aabbccddeeff"]

    def r2(self, prompt: str) -> list[str]:
        out = f"r2> {self.INPUTS[0]}\n{prompt}: {self.INPUTS[1]}\nok\n"
        return normalize(out, "r2", "/w", "/f", self.INPUTS)

    def c2(self, prompt: str) -> list[str]:
        answer = f"{prompt}: {self.INPUTS[1]}"
        out = f"c2> {self.INPUTS[0]}{PAD}c2> {self.INPUTS[0]}\r\n{answer}{PAD}{answer}\r\nok\n"
        return normalize(out, "c2", "/w", "/f", self.INPUTS)

    def test_the_note_is_removed_from_r2_prompts(self) -> None:
        r2 = self.r2("IV (16 bytes, empty = random)")
        self.assertEqual(r2, self.c2("IV (16 bytes)"))
        self.assertIn("PROMPT: IV (16 bytes): 0x00112233445566778899aabbccddeeff", r2)

    def test_a_changed_prompt_is_still_a_difference(self) -> None:
        self.assertNotEqual(self.r2("IV (32 bytes, empty = random)"), self.c2("IV (16 bytes)"))

    def test_c2_output_is_untouched(self) -> None:
        c2 = normalize("IV (16 bytes, empty = random): x", "c2", "/w", "/f")
        self.assertEqual(c2, ["IV (16 bytes, empty = random): x"])


class OperationTiming(unittest.TestCase):
    """§11 D31: r2's provider time is removed wherever it sits, nothing else."""

    def same(self, c2: str, r2: str) -> None:
        self.assertEqual(normalize(c2, "c2", "/w", "/f"), normalize(r2, "r2", "/w", "/f"))

    def test_text_results(self) -> None:
        for unit in ("412µs", "4ms", "1.23s"):
            self.same(
                "generated mem:k (256-bit aes)",
                f"generated mem:k (256-bit aes) in {unit}",
            )

    def test_hex_footer_and_empty_result(self) -> None:
        self.same(
            "╭─ ciphertext — AES-CBC ───────╮\n│ c3180a43 │\n╰─────── 4 bytes ─╯",
            "╭─ ciphertext — AES-CBC ───────╮\nc3180a43\n╰─────── 4 bytes in 4ms ─╯",
        )
        self.same(
            "╭─ plaintext ──────────╮\n│ (empty — 0 bytes) │\n╰────────────────────╯",
            "╭─ plaintext ──────────╮\n│ (empty — 0 bytes) │\n╰──────────── in 3ms ─╯",
        )

    def test_wrapped_suffix_and_centered_title(self) -> None:
        # rich wraps the suffix like any other words, also between "in" and the time
        self.same("wrote 4 bytes to /w/d1.\nbin (raw)", "wrote 4 bytes to /w/d1.\nbin (raw) in\n4ms")
        self.same("wrote 4 bytes to /w/d1.\nbin (raw)", "wrote 4 bytes to /w/d1.\nbin (raw)\nin 4ms")
        self.same(
            "     unwrapped into mem\n (AES-KEY-WRAP-PAD)",
            "     unwrapped into mem\n (AES-KEY-WRAP-PAD) in\n        45µs",
        )

    def test_the_load_timing_line_is_dropped(self) -> None:
        table = "  loaded into mem\n ref     class    algorithm\n mem:k   secret   aes\n"
        self.same(table, table + "loaded in 17µs\n")
        unwrapped = "unwrapped into mem (AES-GCM)\n ref class algorithm\n"
        self.same(unwrapped, unwrapped + "unwrapped in 1.05s\n")

    def test_mid_line_text_is_kept(self) -> None:
        # only a time ending its line (or a hex footer) is a timing suffix
        for text in ("generated mem:k in 5ms x (256-bit aes)", "r2> delete mem:x in 5ms y"):
            self.assertEqual(normalize(text, "r2", "/w", "/f"), [text])
        self.assertEqual(normalize("key k in 5ms", "r2", "/w", "/f"), ["key k"])

    def test_a_changed_count_or_text_is_still_a_difference(self) -> None:
        c2 = normalize("╰─── 16 bytes ─╯", "c2", "/w", "/f")
        self.assertNotEqual(c2, normalize("╰─── 17 bytes in 4ms ─╯", "r2", "/w", "/f"))
        c2 = normalize("signature VALID", "c2", "/w", "/f")
        self.assertNotEqual(c2, normalize("signature INVALID in 4ms", "r2", "/w", "/f"))

    def test_c2_output_is_untouched(self) -> None:
        self.assertEqual(normalize("done in 4ms", "c2", "/w", "/f"), ["done in 4ms"])
        # only a well-formed time is removed
        self.assertEqual(normalize("done in 4 ms", "r2", "/w", "/f"), ["done in 4 ms"])


class RsaSizeChoices(unittest.TestCase):
    """§11 D32: r2's RSA size hint also lists 8192; the rest of the hint is compared."""

    def test_the_8192_choice_is_normalized_away(self) -> None:
        c2 = normalize("size: invalid choice '1000'\nhint: choices: 2048, 3072, 4096", "c2", "/w", "/f")
        r2 = normalize(
            "size: invalid choice '1000'\nhint: choices: 2048, 3072, 4096, 8192", "r2", "/w", "/f"
        )
        self.assertEqual(c2, r2)

    def test_other_lists_still_differ(self) -> None:
        c2 = normalize("hint: choices: 2048, 3072, 4096", "c2", "/w", "/f")
        self.assertNotEqual(c2, normalize("hint: choices: 2048, 4096, 8192", "r2", "/w", "/f"))
        self.assertEqual(
            normalize("hint: choices: 2048, 3072, 4096, 8192", "c2", "/w", "/f"),
            ["hint: choices: 2048, 3072, 4096, 8192"],
        )


if __name__ == "__main__":
    unittest.main()
