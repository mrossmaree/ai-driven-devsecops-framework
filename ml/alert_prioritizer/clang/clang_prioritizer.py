import csv
import html
import os
import plistlib
import re
import sys
from pathlib import Path
from typing import Any

import joblib
import pandas as pd


CLANG_REPORT_DIR = "reports/clang-report"
SCAN_STATUS_FILE = os.path.join(CLANG_REPORT_DIR, "scan-status.txt")
OUTPUT_FILE = "reports/alert_prioritizer/clang/prioritised-alerts.csv"

ACTION_PATH = os.environ.get("GITHUB_ACTION_PATH", ".")
MODEL_PATH = os.path.join(
    ACTION_PATH,
    "models",
    "alert_prioritizer",
    "clang",
    "clang_priority_model.pkl",
)

LABEL_MAP = {
    0: "LOW",
    1: "MEDIUM",
    2: "HIGH",
}

REQUIRED_FEATURE_COLUMNS = [
    "severity_score",
    "has_cwe",
    "is_null_pointer",
    "is_buffer_issue",
    "is_memory_issue",
    "is_obsolete_function",
    "is_clang",
    "alert_id",
    "severity",
    "message",
]

# Conservative checker/CWE mappings. Only map checkers where the relationship is
# reasonably direct. Unknown checkers remain without a CWE.
CHECKER_CWE_MAP = {
    "core.NullDereference": "CWE-476",
    "core.CallAndMessage": "CWE-476",
    "cplusplus.NewDelete": "CWE-415",
    "cplusplus.NewDeleteLeaks": "CWE-401",
    "unix.Malloc": "CWE-401",
    "unix.MismatchedDeallocator": "CWE-762",
    "security.insecureAPI.gets": "CWE-242",
    "security.insecureAPI.strcpy": "CWE-120",
    "security.insecureAPI.DeprecatedOrUnsafeBufferHandling": "CWE-120",
    "alpha.security.ArrayBoundV2": "CWE-125",
    "alpha.security.MallocOverflow": "CWE-190",
}

HIGH_RISK_CHECKER_TERMS = (
    "arraybound",
    "buffer",
    "overflow",
    "useafterfree",
    "newdelete",
    "doublefree",
    "insecureapi",
)

ERROR_CATEGORY_TERMS = (
    "memory error",
    "logic error",
    "security",
    "unix api",
)


def fail(message: str, exit_code: int = 1) -> None:
    print(f"FAILED: {message}", file=sys.stderr)
    sys.exit(exit_code)


def extract_html_reports() -> list[str]:
    html_files: list[str] = []

    for root, _, files in os.walk(CLANG_REPORT_DIR):
        for file_name in files:
            if file_name.endswith(".html") and file_name.startswith("report-"):
                html_files.append(os.path.join(root, file_name))

    return sorted(html_files)


def extract_plist_reports() -> list[str]:
    plist_files: list[str] = []

    for root, _, files in os.walk(CLANG_REPORT_DIR):
        for file_name in files:
            if file_name.endswith(".plist"):
                plist_files.append(os.path.join(root, file_name))

    return sorted(plist_files)


def read_scan_status() -> str:
    if not os.path.exists(SCAN_STATUS_FILE):
        return ""

    try:
        with open(SCAN_STATUS_FILE, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def clean_text(value: Any) -> str:
    if value is None:
        return ""

    cleaned = html.unescape(str(value))
    cleaned = re.sub(r"<[^>]+>", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def extract_with_patterns(content: str, patterns: list[str]) -> str:
    for pattern in patterns:
        match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
        if match:
            return clean_text(match.group(1))

    return ""


def severity_to_score(severity: Any) -> int:
    mapping = {
        "critical": 4,
        "error": 3,
        "warning": 2,
        "note": 1,
        "information": 1,
    }
    return mapping.get(str(severity).strip().lower(), 0)


def has_value(value: Any) -> int:
    if value is None:
        return 0

    normalized = str(value).strip().lower()
    return 0 if normalized in {"", "nan", "none", "null"} else 1


def keyword_feature(text: Any, keywords: list[str]) -> int:
    lowered = str(text).lower()
    return int(any(keyword in lowered for keyword in keywords))


def checker_to_cwe(checker_name: Any, message: Any = "") -> str:
    checker = str(checker_name or "").strip()
    if checker in CHECKER_CWE_MAP:
        return CHECKER_CWE_MAP[checker]

    combined = f"{checker} {message}".lower()

    if "null" in combined and "derefer" in combined:
        return "CWE-476"
    if "use after free" in combined or "use-after-free" in combined:
        return "CWE-416"
    if "double free" in combined:
        return "CWE-415"
    if "memory leak" in combined or "leak" in combined:
        return "CWE-401"
    if "out of bounds" in combined or "array bound" in combined:
        return "CWE-125"
    if "strcpy" in combined or "gets(" in combined or "buffer overflow" in combined:
        return "CWE-120"

    return ""


def derive_severity(category: Any, checker_name: Any, message: Any) -> str:
    combined = " ".join(
        [
            str(category or ""),
            str(checker_name or ""),
            str(message or ""),
        ]
    ).lower()

    if any(term in combined for term in HIGH_RISK_CHECKER_TERMS):
        return "error"

    if any(term in combined for term in ERROR_CATEGORY_TERMS):
        return "error"

    if "note" in combined:
        return "note"

    return "warning"


def build_features(
    message: Any,
    alert_id: Any,
    severity: Any,
    cwe: Any,
) -> dict[str, Any]:
    features = {
        "severity_score": severity_to_score(severity),
        "has_cwe": has_value(cwe),
        "is_null_pointer": keyword_feature(
            f"{alert_id} {message}",
            ["null pointer", "nullpointer", "nulldereference", "null dereference"],
        ),
        "is_buffer_issue": keyword_feature(
            f"{alert_id} {message}",
            ["buffer", "overflow", "overrun", "out of bounds", "arraybound"],
        ),
        "is_memory_issue": keyword_feature(
            f"{alert_id} {message}",
            [
                "memory",
                "leak",
                "free",
                "dereference",
                "use after free",
                "use-after-free",
                "double free",
                "newdelete",
            ],
        ),
        "is_obsolete_function": keyword_feature(
            f"{alert_id} {message}",
            ["gets", "strcpy", "strcat", "sprintf"],
        ),
        "is_clang": 1,
        "alert_id": str(alert_id or ""),
        "severity": str(severity or ""),
        "message": str(message or ""),
    }

    if list(features.keys()) != REQUIRED_FEATURE_COLUMNS:
        raise RuntimeError(
            "Runtime feature schema mismatch. "
            f"Expected {REQUIRED_FEATURE_COLUMNS}, got {list(features.keys())}."
        )

    return features


def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Trained model not found at {MODEL_PATH}. "
            "Run train_clang_model.py first."
        )

    try:
        model = joblib.load(MODEL_PATH)
    except Exception as exc:
        raise RuntimeError(
            f"Unable to load model at {MODEL_PATH}: {exc}"
        ) from exc

    if not hasattr(model, "predict"):
        raise RuntimeError("Loaded model object does not support predict().")

    return model


def validate_model_feature_compatibility(model) -> None:
    try:
        preprocessor = model.named_steps["preprocessor"]
        transformers = preprocessor.transformers
    except Exception as exc:
        raise RuntimeError(
            f"Unable to inspect model feature schema: {exc}"
        ) from exc

    model_columns: list[str] = []

    for transformer_name, _, columns in transformers:
        # Ignore any remainder/drop bookkeeping entry.
        if transformer_name == "remainder":
            continue

        if isinstance(columns, str):
            model_columns.append(columns)
        else:
            model_columns.extend(list(columns))

    if model_columns != REQUIRED_FEATURE_COLUMNS:
        raise RuntimeError(
            "Model expects a different feature schema. "
            f"Expected {REQUIRED_FEATURE_COLUMNS}, model has {model_columns}."
        )


def validate_runtime_environment() -> tuple[list[str], list[str], str]:
    if not os.path.isdir(CLANG_REPORT_DIR):
        raise FileNotFoundError(
            f"Clang report directory is missing: {CLANG_REPORT_DIR}"
        )

    html_reports = extract_html_reports()
    plist_reports = extract_plist_reports()
    scan_status = read_scan_status()

    if scan_status == "SCAN_FAILED":
        raise RuntimeError(
            "Clang scan status indicates analyzer execution/configuration failure."
        )

    if not html_reports and not plist_reports:
        if scan_status in {
            "SCAN_COMPLETED_NO_SOURCE",
            "SCAN_COMPLETED_NO_FINDINGS",
        }:
            return html_reports, plist_reports, scan_status

        raise RuntimeError(
            "No valid Clang analyzer outputs found. "
            "Expected report-*.html or *.plist files in reports/clang-report/."
        )

    return html_reports, plist_reports, scan_status


def resolve_plist_file(files: list[Any], file_reference: Any) -> str:
    if isinstance(file_reference, int):
        if 0 <= file_reference < len(files):
            return str(files[file_reference])
        return ""

    if isinstance(file_reference, str):
        return file_reference

    return ""


def parse_location(
    location: Any,
    files: list[Any],
) -> tuple[str, str, str]:
    if not isinstance(location, dict):
        return "", "", ""

    file_name = resolve_plist_file(files, location.get("file"))
    line = str(location.get("line", "") or "")
    column = str(location.get("col", location.get("column", "")) or "")
    return file_name, line, column


def extract_path_length(path_entries: Any) -> int:
    return len(path_entries) if isinstance(path_entries, list) else 0


def parse_plist_report(report_file: str, model) -> list[dict[str, Any]]:
    try:
        with open(report_file, "rb") as handle:
            document = plistlib.load(handle)
    except Exception as exc:
        raise RuntimeError(f"Unable to read plist report: {exc}") from exc

    if not isinstance(document, dict):
        raise RuntimeError("Unexpected plist root structure; expected a dictionary.")

    files = document.get("files", [])
    diagnostics = document.get("diagnostics", [])

    if diagnostics is None:
        diagnostics = []

    if not isinstance(diagnostics, list):
        raise RuntimeError("Unexpected plist diagnostics structure; expected a list.")

    alerts: list[dict[str, Any]] = []

    for diagnostic in diagnostics:
        if not isinstance(diagnostic, dict):
            continue

        message = clean_text(
            diagnostic.get("description")
            or diagnostic.get("message")
            or "Unknown Clang issue"
        )
        checker_name = clean_text(
            diagnostic.get("check_name")
            or diagnostic.get("checker_name")
            or diagnostic.get("type")
            or "clang-static-analyzer"
        )
        category = clean_text(diagnostic.get("category") or "")
        diagnostic_type = clean_text(diagnostic.get("type") or "")
        location = diagnostic.get("location", {})
        file_name, line_number, column_number = parse_location(location, files)

        if not file_name:
            file_name = report_file

        path_entries = diagnostic.get("path", [])
        path_length = extract_path_length(path_entries)

        cwe = checker_to_cwe(checker_name, message)
        severity = derive_severity(category, checker_name, message)

        features = build_features(
            message=message,
            alert_id=checker_name,
            severity=severity,
            cwe=cwe,
        )
        label = predict_label(model, features)
        priority = LABEL_MAP[label]

        alerts.append(
            {
                "tool": "clang",
                "file": file_name,
                "line": line_number,
                "column": column_number,
                "alert_id": checker_name,
                "category": category,
                "diagnostic_type": diagnostic_type,
                "cwe": cwe,
                "severity": severity,
                "message": message,
                "path_length": path_length,
                "priority": priority,
                "label": label,
                "source_report": report_file,
            }
        )

    return alerts


def parse_html_report(report_file: str, model) -> dict[str, Any]:
    try:
        with open(report_file, "r", encoding="utf-8", errors="ignore") as handle:
            content = handle.read()
    except OSError as exc:
        raise RuntimeError(f"Unable to read HTML report: {exc}") from exc

    message = extract_with_patterns(
        content,
        [
            r"<!--\s*BUGDESC\s*(.*?)\s*-->",
            r"<h3[^>]*>(.*?)</h3>",
            r"<title>(.*?)</title>",
        ],
    ) or "Unknown Clang issue"

    file_name = extract_with_patterns(
        content,
        [
            r"<!--\s*BUGFILE\s*(.*?)\s*-->",
            r"File:\s*</td>\s*<td[^>]*>(.*?)</td>",
            r"File:\s*(.*?)<",
        ],
    ) or report_file

    line_number = extract_with_patterns(
        content,
        [
            r"<!--\s*BUGLINE\s*(\d+)\s*-->",
            r"Line:\s*</td>\s*<td[^>]*>(\d+)</td>",
            r"Line:\s*(\d+)",
        ],
    )

    checker_name = extract_with_patterns(
        content,
        [
            r"<!--\s*BUGTYPE\s*(.*?)\s*-->",
            r"<!--\s*CHECKER\s*(.*?)\s*-->",
            r"Checker Name:\s*</td>\s*<td[^>]*>(.*?)</td>",
        ],
    ) or "clang-static-analyzer"

    category = extract_with_patterns(
        content,
        [
            r"<!--\s*BUGCATEGORY\s*(.*?)\s*-->",
            r"Category:\s*</td>\s*<td[^>]*>(.*?)</td>",
        ],
    )

    cwe = checker_to_cwe(checker_name, message)
    severity = derive_severity(category, checker_name, message)

    features = build_features(
        message=message,
        alert_id=checker_name,
        severity=severity,
        cwe=cwe,
    )
    label = predict_label(model, features)

    return {
        "tool": "clang",
        "file": file_name,
        "line": line_number,
        "column": "",
        "alert_id": checker_name,
        "category": category,
        "diagnostic_type": "",
        "cwe": cwe,
        "severity": severity,
        "message": message,
        "path_length": 0,
        "priority": LABEL_MAP[label],
        "label": label,
        "source_report": report_file,
    }


def predict_label(model, features: dict[str, Any]) -> int:
    feature_frame = pd.DataFrame([features])
    missing_columns = [
        column
        for column in REQUIRED_FEATURE_COLUMNS
        if column not in feature_frame.columns
    ]

    if missing_columns:
        raise RuntimeError(
            f"Required runtime feature columns missing: {missing_columns}"
        )

    feature_frame = feature_frame[REQUIRED_FEATURE_COLUMNS]
    raw_label = model.predict(feature_frame)[0]

    try:
        label = int(raw_label)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            f"Unexpected non-integer prediction label returned by model: {raw_label}"
        ) from exc

    if label not in LABEL_MAP:
        raise RuntimeError(
            f"Unexpected prediction label returned by model: {label}"
        )

    return label


def parse_clang_reports(model) -> tuple[pd.DataFrame, str]:
    html_reports, plist_reports, scan_status = validate_runtime_environment()

    print(
        f"Found {len(plist_reports)} plist report(s) and "
        f"{len(html_reports)} HTML report(s)."
    )

    alerts: list[dict[str, Any]] = []
    parse_errors: list[tuple[str, str]] = []

    # Prefer plist because it contains structured diagnostics. HTML is only used
    # when no plist output is available, preventing duplicate findings.
    if plist_reports:
        for report_file in plist_reports:
            try:
                alerts.extend(parse_plist_report(report_file, model))
            except Exception as exc:
                parse_errors.append((report_file, str(exc)))
    else:
        for report_file in html_reports:
            try:
                alerts.append(parse_html_report(report_file, model))
            except Exception as exc:
                parse_errors.append((report_file, str(exc)))

    if parse_errors and not alerts:
        first_file, first_error = parse_errors[0]
        raise RuntimeError(
            "Malformed or unreadable Clang report. "
            f"Example failure in {first_file}: {first_error}"
        )

    for report_file, error in parse_errors:
        print(
            f"Warning: could not parse {report_file}: {error}",
            file=sys.stderr,
        )

    return pd.DataFrame(alerts), scan_status


def write_prioritised_alerts(df: pd.DataFrame) -> None:
    Path(OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)

    output_columns = [
        "priority",
        "tool",
        "file",
        "line",
        "column",
        "alert_id",
        "category",
        "diagnostic_type",
        "cwe",
        "severity",
        "message",
        "path_length",
    ]

    if df.empty:
        with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(output_columns)

        print("No Clang alerts found.")
        return

    priority_order = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    output_df = df.copy()
    output_df["priority_rank"] = output_df["priority"].map(priority_order).fillna(0)

    output_df = output_df.sort_values(
        by=["priority_rank", "file", "line"],
        ascending=[False, True, True],
        kind="stable",
    )

    output_df[output_columns].to_csv(OUTPUT_FILE, index=False)
    print(f"Clang prioritised alerts generated: {OUTPUT_FILE}")


def main() -> None:
    try:
        model = load_model()
        validate_model_feature_compatibility(model)

        df, scan_status = parse_clang_reports(model)
        write_prioritised_alerts(df)

        print("===== Clang Prioritised Alerts =====")

        if df.empty:
            print("COMPLETED WITH ZERO ALERTS")

            if scan_status == "SCAN_COMPLETED_NO_SOURCE":
                print("Clang scan completed with no C/C++ source files to analyze.")
            elif scan_status == "SCAN_COMPLETED_NO_FINDINGS":
                print("Clang analyzer completed successfully with no findings.")
            else:
                print(
                    "Valid Clang report structure found, "
                    "but no usable alerts were parsed."
                )
            return

        print("COMPLETED WITH ALERTS")

        for _, alert in df.iterrows():
            location = str(alert["file"])
            if alert.get("line"):
                location += f":{alert['line']}"
            if alert.get("column"):
                location += f":{alert['column']}"

            print(
                f"{alert['priority']} | "
                f"{alert['tool']} | "
                f"{location} | "
                f"{alert['alert_id']} | "
                f"{alert['message']}"
            )

    except Exception as exc:
        fail(str(exc))


if __name__ == "__main__":
    main()
