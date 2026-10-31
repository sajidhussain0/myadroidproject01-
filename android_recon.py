#!/usr/bin/env python3
"""
android_recon.py

Static + dynamic-prep automation for Android app analysis, built on the
Hextree Dynamic Instrumentation workflow (jadx + grep + Frida). It is a
force-multiplier for the manual steps in your notes: instead of running
jadx, grepping by hand, and hand-writing frida-trace commands for every
Activity/Fragment, this does it in one pass and hands you:

  1. A decompiled source tree (via jadx)
  2. A markdown findings report (crypto, pinning, storage, WebView, intents,
     exported components, hard-coded secrets, etc.) with file:line refs
  3. Auto-generated frida-trace commands for every Activity/Fragment found
     in the manifest
  4. A starter Frida hook script (hooks.js) with ready-to-fill templates
     for every class flagged as interesting

Use only on your own apps or apps you are authorized to test.

-----------------------------------------------------------------------
USAGE
-----------------------------------------------------------------------
  python3 android_recon.py /path/to/app.apk [--out OUTDIR] [--process NAME]

Requires: jadx on PATH (same tool your notes already use).
Everything else is Python standard library, so no extra install needed.

-----------------------------------------------------------------------
WHAT IT DOES NOT DO
-----------------------------------------------------------------------
  - It does not run any exploit, bypass, or attack on its own.
  - It does not decrypt, crack, or extract secrets — it only flags
    *locations in source* worth a human look (that's a lead, not proof,
    same caveat as in your original notes).
  - It does not touch a live device; frida-trace commands are printed/
    saved for you to run yourself once you've reviewed the findings.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Patterns worth flagging, with a short human explanation + suggestion.
# Each entry: (label, regex, why it matters, suggested next step)
FINDINGS_PATTERNS = [
    (
        "Certificate pinning",
        re.compile(r"CertificatePinner|X509TrustManager|checkServerTrusted|TrustManagerImpl", re.I),
        "App may validate/pin TLS certificates here.",
        "Hook the setter/validator (see section 11-12 pattern) to observe or test behavior in your lab.",
    ),
    (
        "Network security config",
        re.compile(r"networkSecurityConfig|NetworkSecurityConfig", re.I),
        "Custom trust anchors / cleartext policy may be defined.",
        "Check res/xml/network_security_config.xml for trust-anchors and cleartextTrafficPermitted.",
    ),
    (
        "TLS/SSL context setup",
        re.compile(r"\bSSLContext\b|\bSSLSocketFactory\b", re.I),
        "Custom TLS context construction.",
        "Confirm which TrustManager/KeyManager it uses; enumerate overloads before hooking.",
    ),
    (
        "Crypto primitives",
        re.compile(r"\bCipher\.getInstance|\bMessageDigest\.getInstance|\bSecretKeySpec\b|\bKeyGenerator\b", re.I),
        "App performs encryption/hashing locally.",
        "Hook Cipher.doFinal / init to inspect keys, IVs, and plaintext at runtime (lab only).",
    ),
    (
        "Hard-coded secret-looking string",
        re.compile(r'(api[_-]?key|secret|token|password)\s*=\s*"[^"\s]{6,}"', re.I),
        "Possible embedded credential or key.",
        "Confirm manually — many hits are false positives (placeholders, test values).",
    ),
    (
        "WebView usage",
        re.compile(r"\bWebView\b|addJavascriptInterface|loadUrl\(", re.I),
        "WebView bridges can expose Java methods to JS or load untrusted content.",
        "Check addJavascriptInterface() exposure and loadUrl() sources.",
    ),
    (
        "Shared/local storage",
        re.compile(r"\bSharedPreferences\b|openOrCreateDatabase|getExternalStorageDirectory", re.I),
        "Local data persistence — possible sensitive data at rest.",
        "Check what's written (grep nearby .putString/.edit calls) and file permissions.",
    ),
    (
        "Native/JNI bridge",
        re.compile(r"\bSystem\.loadLibrary\(|native\s+\w+\s+\w+\(", re.I),
        "Native code may implement logic not visible in Java/Kotlin source.",
        "Trace native exports with frida-trace -I '<libname>.so'; symbols may be stripped.",
    ),
    (
        "Root / emulator / debugger detection",
        re.compile(r"isDebuggerConnected|/system/bin/su|RootBeer|Build\.FINGERPRINT|TracerPid", re.I),
        "App may try to detect instrumentation, root, or emulation.",
        "These checks can interfere with Frida; hook the detection method to return a benign value in-lab.",
    ),
    (
        "Intent / deep link handling",
        re.compile(r"getIntent\(\)|\bonNewIntent\(|Intent\.ACTION_VIEW", re.I),
        "Handles incoming Intents — relevant to the Intent Surface Attack topic.",
        "Review extras/data parsing for missing validation; map to exported components in the manifest.",
    ),
]

ACTIVITY_LIFECYCLE_METHODS = ["onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy", "onNewIntent"]
FRAGMENT_LIFECYCLE_METHODS = ["onCreate", "onCreateView", "onViewCreated", "onResume", "onPause", "onDestroyView"]


def run_jadx(apk_path: Path, out_dir: Path) -> Path:
    if shutil.which("jadx") is None:
        sys.exit("[x] 'jadx' not found on PATH. Install it first (same tool used in your notes).")
    decompiled = out_dir / "jadx_out"
    print(f"[*] Decompiling {apk_path} -> {decompiled}")
    subprocess.run(["jadx", "-d", str(decompiled), str(apk_path)], check=True)
    return decompiled


def parse_manifest(decompiled_dir: Path):
    """Return (package_name, activities, exported_components)."""
    manifest_path = decompiled_dir / "resources" / "AndroidManifest.xml"
    if not manifest_path.exists():
        # fallback location in some jadx versions
        candidates = list(decompiled_dir.rglob("AndroidManifest.xml"))
        if not candidates:
            print("[!] AndroidManifest.xml not found; skipping manifest parsing.")
            return None, [], []
        manifest_path = candidates[0]

    tree = ET.parse(manifest_path)
    root = tree.getroot()
    package = root.attrib.get("package", "")

    activities = []
    exported = []

    app_el = root.find("application")
    if app_el is not None:
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for el in app_el.findall(tag):
                name = el.attrib.get(f"{ANDROID_NS}name", "")
                exported_attr = el.attrib.get(f"{ANDROID_NS}exported")
                has_intent_filter = el.find("intent-filter") is not None
                is_exported = exported_attr == "true" or (exported_attr is None and has_intent_filter)
                full_name = name if name.startswith(".") is False and "." in name else f"{package}{name}" if name.startswith(".") else name
                if tag == "activity":
                    activities.append(full_name)
                if is_exported:
                    exported.append((tag, full_name, "has intent-filter" if has_intent_filter else "exported=true"))

    return package, activities, exported


def scan_sources(decompiled_dir: Path):
    """Walk decompiled .java sources and apply FINDINGS_PATTERNS."""
    sources_dir = decompiled_dir / "sources"
    if not sources_dir.exists():
        sources_dir = decompiled_dir  # fallback

    findings = []  # list of dicts
    java_files = list(sources_dir.rglob("*.java"))
    print(f"[*] Scanning {len(java_files)} decompiled source files...")

    for jf in java_files:
        try:
            text = jf.read_text(errors="ignore")
        except Exception:
            continue
        lines = text.splitlines()
        for label, pattern, why, suggestion in FINDINGS_PATTERNS:
            for i, line in enumerate(lines, start=1):
                if pattern.search(line):
                    findings.append({
                        "label": label,
                        "file": str(jf.relative_to(sources_dir)),
                        "line": i,
                        "snippet": line.strip()[:160],
                        "why": why,
                        "suggestion": suggestion,
                    })
    return findings


def guess_class_name(java_rel_path: str) -> str:
    """Turn sources/io/hextree/fridatarget/Foo.java -> io.hextree.fridatarget.Foo"""
    p = Path(java_rel_path)
    parts = list(p.parts)
    if parts and parts[-1].endswith(".java"):
        parts[-1] = parts[-1][:-5]
    return ".".join(parts)


def write_report(out_dir: Path, package: str, activities: list, exported: list, findings: list):
    report_path = out_dir / "findings_report.md"
    with report_path.open("w") as f:
        f.write(f"# Android Recon Report\n\n")
        f.write(f"**Package:** `{package}`\n\n")

        f.write("## Activities (from manifest)\n\n")
        if activities:
            for a in activities:
                f.write(f"- `{a}`\n")
        else:
            f.write("_None found / manifest not parsed._\n")
        f.write("\n")

        f.write("## Exported components (potential Intent Surface Attack entry points)\n\n")
        if exported:
            f.write("| Type | Name | Reason |\n|---|---|---|\n")
            for tag, name, reason in exported:
                f.write(f"| {tag} | `{name}` | {reason} |\n")
        else:
            f.write("_None explicitly exported, or manifest not parsed._\n")
        f.write("\n")

        f.write("## Static findings (leads, not proof — verify manually)\n\n")
        if not findings:
            f.write("_No pattern matches found._\n")
        else:
            by_label = {}
            for fdg in findings:
                by_label.setdefault(fdg["label"], []).append(fdg)
            for label, items in by_label.items():
                f.write(f"### {label} ({len(items)} hit{'s' if len(items) != 1 else ''})\n\n")
                f.write(f"**Why it matters:** {items[0]['why']}\n\n")
                f.write(f"**Suggested next step:** {items[0]['suggestion']}\n\n")
                for it in items[:25]:  # cap listing per label to keep report readable
                    f.write(f"- `{it['file']}:{it['line']}` — `{it['snippet']}`\n")
                if len(items) > 25:
                    f.write(f"- ... and {len(items) - 25} more\n")
                f.write("\n")

    print(f"[*] Wrote report -> {report_path}")
    return report_path


def write_trace_commands(out_dir: Path, process_name: str, activities: list, package: str):
    trace_path = out_dir / "trace_commands.sh"
    with trace_path.open("w") as f:
        f.write("#!/usr/bin/env bash\n")
        f.write("# Auto-generated frida-trace commands. Run individually, not all at once,\n")
        f.write("# unless you want very noisy combined output.\n\n")
        f.write(f"HOST=127.0.0.1:27042\n")
        f.write(f"PROC={process_name}\n\n")

        f.write("# Whole-app Java namespace trace\n")
        if package:
            f.write(f"# frida-trace -H $HOST -j '{package}.!' -n $PROC\n\n")

        f.write("# Per-activity lifecycle traces\n")
        for act in activities:
            for m in ACTIVITY_LIFECYCLE_METHODS:
                f.write(f"# frida-trace -H $HOST -j '{act}!{m}' -n $PROC\n")
            f.write("\n")

        f.write("# Native library exports (edit libname.so)\n")
        f.write("# frida-trace -H $HOST -n $PROC -I 'libTARGET.so'\n")
    os.chmod(trace_path, 0o755)
    print(f"[*] Wrote trace command reference -> {trace_path}")
    return trace_path


def write_hooks_js(out_dir: Path, findings: list, sources_dir_name: str = "sources"):
    hooks_path = out_dir / "hooks.js"
    # Build one hook skeleton per unique class that had a finding
    classes = {}
    for fdg in findings:
        cls = guess_class_name(fdg["file"])
        classes.setdefault(cls, []).append(fdg["label"])

    with hooks_path.open("w") as f:
        f.write("/*\n * hooks.js — auto-generated starter hooks for flagged classes.\n")
        f.write(" * Review findings_report.md first; fill in real method names/overloads\n")
        f.write(" * before running. Use only on authorized targets.\n */\n\n")
        f.write("Java.perform(() => {\n")
        for cls, labels in classes.items():
            f.write(f"  // Flagged for: {', '.join(sorted(set(labels)))}\n")
            f.write(f"  try {{\n")
            f.write(f"    const C_{abs(hash(cls)) % 100000} = Java.use(\"{cls}\");\n")
            f.write(f"    console.log(\"[*] Loaded {cls}\");\n")
            f.write(f"    // TODO: pick a method from this class and hook it, e.g.:\n")
            f.write(f"    // const m = C_{abs(hash(cls)) % 100000}.methodName.overload();\n")
            f.write(f"    // m.implementation = function (...args) {{\n")
            f.write(f"    //   const result = m.call(this, ...args);\n")
            f.write(f"    //   console.log('[*] {cls}.methodName ->', result);\n")
            f.write(f"    //   return result;\n")
            f.write(f"    // }};\n")
            f.write(f"  }} catch (e) {{\n")
            f.write(f"    console.log(\"[!] Could not load {cls}:\", e);\n")
            f.write(f"  }}\n\n")
        f.write("});\n")

    print(f"[*] Wrote hook skeletons -> {hooks_path} ({len(classes)} classes)")
    return hooks_path


def main():
    ap = argparse.ArgumentParser(description="Automated Android static recon + Frida prep.")
    ap.add_argument("apk", type=Path, help="Path to the target .apk")
    ap.add_argument("--out", type=Path, default=None, help="Output directory (default: ./<apk-stem>_recon)")
    ap.add_argument("--process", default="FridaTarget", help="Process name for generated frida-trace commands")
    args = ap.parse_args()

    if not args.apk.exists():
        sys.exit(f"[x] APK not found: {args.apk}")

    out_dir = args.out or Path(f"{args.apk.stem}_recon")
    out_dir.mkdir(parents=True, exist_ok=True)

    decompiled_dir = run_jadx(args.apk, out_dir)
    package, activities, exported = parse_manifest(decompiled_dir)
    findings = scan_sources(decompiled_dir)

    write_report(out_dir, package or "", activities, exported, findings)
    write_trace_commands(out_dir, args.process, activities, package or "")
    write_hooks_js(out_dir, findings)

    print("\n[*] Done. Review findings_report.md before acting on anything in hooks.js.")


if __name__ == "__main__":
    main()
