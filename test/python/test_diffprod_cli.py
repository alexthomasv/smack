import json
import os
import shutil
import subprocess

import pytest


def diff_product_cli():
    candidates = [
        "/home/ubuntu/boogie-parser/smack/bin/smack",
        shutil.which("smack"),
        "/usr/local/bin/smack",
    ]
    checked = []
    for smack in candidates:
        if not smack or not os.path.exists(smack):
            continue
        completed = subprocess.run(
            [smack, "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        checked.append((smack, completed.stdout))
        if completed.returncode == 0 and "--diff-product" in completed.stdout:
            return smack
    if checked:
        pytest.fail("available smack executable does not expose --diff-product")
    pytest.skip("smack executable not found")


def assert_boogie_verifies(path):
    boogie = shutil.which("boogie")
    if boogie is None:
        pytest.skip("boogie executable not found")
    completed = subprocess.run(
        [boogie, str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    assert "Error:" not in completed.stdout
    assert "0 errors" in completed.stdout


def run_cli_case(tmp_path, name, extra_args):
    left = tmp_path / f"{name}_left.c"
    right = tmp_path / f"{name}_right.c"
    diff = tmp_path / f"{name}.diff"
    product = tmp_path / f"{name}.bpl"
    report = tmp_path / f"{name}.json"
    left.write_text("int f(int x) {\n  return x + 0;\n}\n")
    right.write_text("int f(int x) {\n  return x - 0;\n}\n")
    diff.write_text(
        "\n".join(
            [
                f"--- a/{left.name}",
                f"+++ b/{right.name}",
                "@@ -2,1 +2,1 @@",
                "-  return x + 0;",
                "+  return x - 0;",
            ]
        )
        + "\n"
    )
    env = dict(os.environ)
    existing = env.get("PYTHONPATH")
    paths = [
        "/home/ubuntu/boogie-parser/smack/share",
        "/home/ubuntu/boogie-parser/diffprod",
    ]
    if existing:
        paths.append(existing)
    env["PYTHONPATH"] = os.pathsep.join(paths)
    tool_paths = [
        "/home/ubuntu/boogie-parser/smack/build-llvm22c",
        "/usr/lib/llvm-22/bin",
    ]
    if env.get("PATH"):
        tool_paths.append(env["PATH"])
    env["PATH"] = os.pathsep.join(tool_paths)
    completed = subprocess.run(
        [
            diff_product_cli(),
            "--quiet",
            "--diff-product",
            str(diff),
            "--diff-left",
            str(left),
            "--diff-right",
            str(right),
            "--diff-left-entry",
            "f",
            "--diff-right-entry",
            "f",
            "--diff-product-out",
            str(product),
            "--diff-product-json",
            str(report),
            *extra_args,
        ],
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        env=env,
    )
    assert completed.returncode == 0, completed.stdout
    assert product.exists()
    assert report.exists()
    return product, json.loads(report.read_text())


def run_easy_cli_case(tmp_path, name, mode):
    left = tmp_path / f"{name}_left.c"
    right = tmp_path / f"{name}_right.c"
    diff = tmp_path / f"{name}.diff"
    product = tmp_path / f"{name}.bpl"
    report = tmp_path / f"{name}.json"
    left.write_text("int f(int x) {\n  return x + 0;\n}\n")
    right.write_text("int f(int x) {\n  return x - 0;\n}\n")
    diff.write_text(
        "\n".join(
            [
                f"--- a/{left.name}",
                f"+++ b/{right.name}",
                "@@ -2,1 +2,1 @@",
                "-  return x + 0;",
                "+  return x - 0;",
            ]
        )
        + "\n"
    )
    env = dict(os.environ)
    existing = env.get("PYTHONPATH")
    paths = [
        "/home/ubuntu/boogie-parser/smack/share",
        "/home/ubuntu/boogie-parser/diffprod",
    ]
    if existing:
        paths.append(existing)
    env["PYTHONPATH"] = os.pathsep.join(paths)
    tool_paths = [
        "/home/ubuntu/boogie-parser/smack/build-llvm22c",
        "/usr/lib/llvm-22/bin",
    ]
    if env.get("PATH"):
        tool_paths.append(env["PATH"])
    env["PATH"] = os.pathsep.join(tool_paths)
    if mode == "functions":
        mode_args = [
            "--product-mode",
            "functions",
            "--left",
            str(left),
            "--right",
            str(right),
        ]
    else:
        mode_args = [
            "--product-mode",
            "patch",
            "--source",
            str(left),
            "--patch",
            str(diff),
        ]
    completed = subprocess.run(
        [
            diff_product_cli(),
            "--quiet",
            *mode_args,
            "--entry",
            "f",
            "--product-out",
            str(product),
            "--product-json",
            str(report),
        ],
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        env=env,
    )
    assert completed.returncode == 0, completed.stdout
    assert product.exists()
    assert report.exists()
    return product, json.loads(report.read_text())


def test_diff_product_cli_writes_product_and_json_for_alignment_modes(tmp_path):
    product, report = run_cli_case(
        tmp_path,
        "auto",
        ["--diff-product-verify"],
    )
    assert report["product"]["actual_product_available"] is True
    assert report["product"]["selection"]
    assert any(candidate["selected"] for candidate in report["product"]["selection"])
    assert report["equivalence"]["checked"] is True
    assert report["equivalence"]["verified"] is True
    assert_boogie_verifies(product)

    product, report = run_cli_case(
        tmp_path,
        "legacy_no_egraph",
        ["--diff-product-alignment", "legacy", "--diff-product-no-egraph"],
    )
    assert report["product"]["actual_product_available"] is True
    assert report["product"]["mode"] == "legacy"
    assert report["product"]["egraph_success"] is False
    assert report["product"]["egraph_outcomes"] == []
    assert report["impact"]["left"]["impacted_blocks"]
    assert report["summaries"]["left"] is not None
    assert report["failure_cut"]
    assert_boogie_verifies(product)

    product, report = run_cli_case(
        tmp_path,
        "baseline",
        ["--diff-product-alignment", "baseline"],
    )
    assert report["product"]["actual_product_available"] is True
    assert report["product"]["mode"] == "baseline"
    assert report["product"]["lockstep_outcomes"] == []
    assert report["product"]["egraph_outcomes"] == []
    assert_boogie_verifies(product)


def test_easy_product_mode_functions_uses_llvm_matcher_alignment(tmp_path):
    product, report = run_easy_cli_case(tmp_path, "functions", "functions")

    assert report["product"]["actual_product_available"] is True
    assert any("interface mode: functions" in d for d in report["diagnostics"])
    assert report["llvm_match"]
    assert report["llvm_match"]["source"] == "smack-cpp"
    assert report["llvm_match"]["stats"]["matcher_ms"] >= 0
    assert report["llvm_match"]["chunks"]
    assert report["product"]["selection"]
    assert_boogie_verifies(product)


def test_easy_product_mode_patch_materializes_right_source(tmp_path):
    product, report = run_easy_cli_case(tmp_path, "patch", "patch")

    assert report["product"]["actual_product_available"] is True
    assert any("interface mode: patch" in d for d in report["diagnostics"])
    assert report["llvm_match"]["source"] == "smack-cpp"
    assert report["impact"]["left"]["impacted_blocks"]
    assert report["impact"]["right"]["impacted_blocks"]
    assert_boogie_verifies(product)


def test_product_mode_requires_smack_cpp_matcher(tmp_path):
    left = tmp_path / "missing_tool_left.c"
    right = tmp_path / "missing_tool_right.c"
    product = tmp_path / "missing_tool.bpl"
    left.write_text("int f(int x) {\n  return x + 0;\n}\n")
    right.write_text("int f(int x) {\n  return x - 0;\n}\n")

    env = dict(os.environ)
    existing = env.get("PYTHONPATH")
    paths = [
        "/home/ubuntu/boogie-parser/smack/share",
        "/home/ubuntu/boogie-parser/diffprod",
    ]
    if existing:
        paths.append(existing)
    env["PYTHONPATH"] = os.pathsep.join(paths)
    tool_dir = tmp_path / "tools"
    tool_dir.mkdir()
    extern_statics = "/home/ubuntu/boogie-parser/smack/build-llvm22c/extern-statics"
    if not os.path.exists(extern_statics):
        pytest.skip("extern-statics is not built")
    os.symlink(extern_statics, tool_dir / "extern-statics")
    env["PATH"] = os.pathsep.join(
        [str(tool_dir), "/usr/lib/llvm-22/bin", "/usr/bin", "/bin"]
    )

    completed = subprocess.run(
        [
            diff_product_cli(),
            "--quiet",
            "--product-mode",
            "functions",
            "--left",
            str(left),
            "--right",
            str(right),
            "--entry",
            "f",
            "--product-out",
            str(product),
        ],
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        env=env,
    )

    assert completed.returncode != 0
    assert "llvm-diffmatch2bpl" in completed.stdout
    assert "on PATH" in completed.stdout
