import json
import shutil
import subprocess

from smack.diffprod.diff import parse_unified_diff
from smack.diffprod.pipeline import build_from_bpl
from smack.diffprod.provenance import parse_boogie_with_provenance


LEFT_BPL = """
procedure main();
implementation main()
{
  var x: int;

entry:
  assume {:sourceloc "demo.c" 2 1} {:c_line "x = 0;"} {:llvm.func "main"} {:llvm.bb "entry"} {:llvm.inst "main:entry:0"} {:llvm.op "store"} true;
  x := 0;
  goto exit;

stable:
  assume {:sourceloc "demo.c" 10 1} {:llvm.func "main"} {:llvm.bb "stable"} {:llvm.inst "main:stable:0"} {:llvm.op "add"} true;
  assume true;
  return;

exit:
  assert x >= 0;
  return;
}
"""

RIGHT_BPL = LEFT_BPL.replace('x = 0;', 'x = 1;').replace('x := 0;', 'x := 1;')

PATCH = """--- a/demo.c
+++ b/demo.c
@@ -2,1 +2,1 @@
-x = 0;
+x = 1;
"""


def test_parse_unified_diff_hunks():
    hunks = parse_unified_diff(PATCH)
    assert len(hunks) == 1
    assert hunks[0].old_path == "demo.c"
    assert hunks[0].new_start == 2


def test_parse_smack_space_separated_provenance_attrs():
    parsed = parse_boogie_with_provenance(LEFT_BPL)
    stmt_id = "proc:main:block:entry:stmt:0"
    origin = parsed.provenance.origin_set(stmt_id).records[0]
    assert origin.source_span.file == "demo.c"
    assert origin.source_span.start_line == 2
    assert origin.llvm_inst_id == "main:entry:0"
    assert "normalized SMACK attribute syntax before parsing" in parsed.diagnostics


def test_source_diff_closes_over_cfg_and_data_dependencies():
    result = build_from_bpl(
        left_bpl=LEFT_BPL,
        right_bpl=RIGHT_BPL,
        diff_text=PATCH,
        left_entry="main",
        right_entry="main",
    )
    impacted = result.impact.left.impacted_blocks
    assert "proc:main:block:entry" in impacted
    assert "proc:main:block:exit" in impacted
    assert "x" in result.impact.left.variables


def test_unchanged_blocks_are_summarized_and_report_is_jsonable():
    result = build_from_bpl(
        left_bpl=LEFT_BPL,
        right_bpl=RIGHT_BPL,
        diff_text=PATCH,
        left_entry="main",
        right_entry="main",
    )
    assert any(r.block_id == "proc:main:block:stable" for r in result.summaries.left)
    assert "procedure" in result.product.text
    assert result.to_json()["summaries"]["left"]
    json.dumps(result.to_json())


def test_raw_quotes_in_source_line_metadata_are_sanitized():
    bpl = LEFT_BPL.replace(
        '{:c_line "x = 0;"}',
        '{:c_line "__SMACK_code("assume true;");"}',
    )
    parsed = parse_boogie_with_provenance(bpl)
    stmt_id = "proc:main:block:entry:stmt:0"
    assert parsed.provenance.origin_set(stmt_id).records[0].c_line == (
        '__SMACK_code("assume true;");'
    )


def test_smack_generated_bpl_builds_egraph_product(tmp_path):
    smack = shutil.which("smack") or "/usr/local/bin/smack"
    if not shutil.which(smack) and not shutil.which("/usr/local/bin/smack"):
        raise AssertionError("smack executable not found")

    left = tmp_path / "left.c"
    right = tmp_path / "right.c"
    diff = tmp_path / "change.diff"
    left_bpl = tmp_path / "left.bpl"
    right_bpl = tmp_path / "right.bpl"
    left.write_text("int f(int x) {\n  return x + 0;\n}\n")
    right.write_text("int f(int x) {\n  return x - 0;\n}\n")
    diff.write_text(
        "\n".join(
            [
                "--- a/left.c",
                "+++ b/right.c",
                "@@ -2,1 +2,1 @@",
                "-  return x + 0;",
                "+  return x - 0;",
            ]
        )
        + "\n"
    )

    subprocess.run(
        [smack, "-t", "--entry-points", "f", "-bpl", str(left_bpl), str(left)],
        cwd=tmp_path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    subprocess.run(
        [smack, "-t", "--entry-points", "f", "-bpl", str(right_bpl), str(right)],
        cwd=tmp_path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    result = build_from_bpl(
        left_bpl=left_bpl.read_text(),
        right_bpl=right_bpl.read_text(),
        diff_text=diff.read_text(),
        left_entry="f",
        right_entry="f",
        alignment="legacy",
    )

    assert result.product.actual_product_available is True
    assert result.product.actual_source == "smack-boogie"
    assert any(
        outcome["success"] and outcome["resolution"] == "egraph"
        for outcome in result.product.egraph_outcomes
    )
    assert "assert ($r_P == $r_Q);" in result.product.text
