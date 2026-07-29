from pathlib import Path
from typing import Any

import pandas as pd


ANNOTATION_FILE = Path(
    "data/processed/alert_prioritizer/clang/clang_alert_annotation.csv"
)
TRAINING_OUTPUT_FILE = Path(
    "data/processed/alert_prioritizer/clang/clang_alert_training.csv"
)
FEATURE_OUTPUT_FILE = Path(
    "data/processed/alert_prioritizer/clang/clang_alert_features.csv"
)

HIGH_CWE_FAMILIES = {
    "CWE121_Stack_Based_Buffer_Overflow",
    "CWE122_Heap_Based_Buffer_Overflow",
    "CWE415_Double_Free",
    "CWE416_Use_After_Free",
}
MEDIUM_CWE_FAMILY = "CWE476_NULL_Pointer_Dereference"

REQUIRED_MODEL_FEATURE_COLUMNS = [
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


def normalize_text(value: Any) -> str:
    if pd.isna(value):
        return ""
    return str(value).strip()


def severity_to_score(severity: Any) -> int:
    mapping = {
        "critical": 4,
        "error": 3,
        "warning": 2,
        "note": 1,
        "information": 1,
    }
    return mapping.get(normalize_text(severity).lower(), 0)


def has_value(value: Any) -> int:
    normalized = normalize_text(value).lower()
    return 0 if normalized in {"", "nan", "none", "null"} else 1


def keyword_feature(text: Any, keywords: list[str]) -> int:
    lowered = normalize_text(text).lower()
    return int(any(keyword in lowered for keyword in keywords))


def checker_to_cwe(checker_name: Any, message: Any = "") -> str:
    checker = normalize_text(checker_name)
    if checker in CHECKER_CWE_MAP:
        return CHECKER_CWE_MAP[checker]

    combined = f"{checker} {normalize_text(message)}".lower()

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
            normalize_text(category),
            normalize_text(checker_name),
            normalize_text(message),
        ]
    ).lower()

    if any(term in combined for term in HIGH_RISK_CHECKER_TERMS):
        return "error"

    if any(term in combined for term in ERROR_CATEGORY_TERMS):
        return "error"

    if "note" in combined:
        return "note"

    return "warning"


def derive_priority_and_label(row: pd.Series) -> tuple[str, Any]:
    ground_truth = normalize_text(
        row.get("ground_truth_status", "")
    ).lower()
    cwe_family = normalize_text(row.get("juliet_cwe_family", ""))

    if ground_truth == "good":
        return "LOW", 0

    if ground_truth == "bad" and cwe_family == MEDIUM_CWE_FAMILY:
        return "MEDIUM", 1

    if ground_truth == "bad" and cwe_family in HIGH_CWE_FAMILIES:
        return "HIGH", 2

    return "UNKNOWN", pd.NA


def enrich_structured_fields(df: pd.DataFrame) -> pd.DataFrame:
    enriched = df.copy()

    # Support both the older annotation schema and a newer plist-derived schema.
    if "checker_name" in enriched.columns:
        enriched["alert_id"] = enriched["alert_id"].where(
            enriched["alert_id"].notna()
            & enriched["alert_id"].astype(str).str.strip().ne(""),
            enriched["checker_name"],
        )

    if "category" not in enriched.columns:
        enriched["category"] = ""

    enriched["message"] = enriched["message"].apply(normalize_text)
    enriched["alert_id"] = enriched["alert_id"].apply(normalize_text)
    enriched["severity"] = enriched["severity"].apply(normalize_text)
    enriched["cwe"] = enriched["cwe"].apply(normalize_text)
    enriched["category"] = enriched["category"].apply(normalize_text)

    # Fill missing CWE values from conservative checker/message mappings.
    missing_cwe = enriched["cwe"].eq("")
    enriched.loc[missing_cwe, "cwe"] = enriched.loc[missing_cwe].apply(
        lambda row: checker_to_cwe(row["alert_id"], row["message"]),
        axis=1,
    )

    # Fill missing severity values using category/checker/message context.
    missing_severity = enriched["severity"].eq("")
    enriched.loc[missing_severity, "severity"] = enriched.loc[
        missing_severity
    ].apply(
        lambda row: derive_severity(
            row.get("category", ""),
            row["alert_id"],
            row["message"],
        ),
        axis=1,
    )

    return enriched


def add_model_features(df: pd.DataFrame) -> pd.DataFrame:
    featured = df.copy()
    combined_text = (
        featured["alert_id"].fillna("").astype(str)
        + " "
        + featured["message"].fillna("").astype(str)
    )

    featured["severity_score"] = featured["severity"].apply(severity_to_score)
    featured["has_cwe"] = featured["cwe"].apply(has_value)
    featured["is_null_pointer"] = combined_text.apply(
        lambda value: keyword_feature(
            value,
            [
                "null pointer",
                "nullpointer",
                "nulldereference",
                "null dereference",
            ],
        )
    )
    featured["is_buffer_issue"] = combined_text.apply(
        lambda value: keyword_feature(
            value,
            [
                "buffer",
                "overflow",
                "overrun",
                "out of bounds",
                "arraybound",
            ],
        )
    )
    featured["is_memory_issue"] = combined_text.apply(
        lambda value: keyword_feature(
            value,
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
        )
    )
    featured["is_obsolete_function"] = combined_text.apply(
        lambda value: keyword_feature(
            value,
            ["gets", "strcpy", "strcat", "sprintf"],
        )
    )
    featured["is_clang"] = 1

    missing_features = [
        column
        for column in REQUIRED_MODEL_FEATURE_COLUMNS
        if column not in featured.columns
    ]
    if missing_features:
        raise RuntimeError(
            f"Feature preparation failed; missing columns: {missing_features}"
        )

    return featured


def main() -> None:
    if not ANNOTATION_FILE.exists():
        raise FileNotFoundError(
            f"Annotation dataset not found: {ANNOTATION_FILE}"
        )

    df = pd.read_csv(ANNOTATION_FILE)

    if df.empty:
        raise ValueError(f"Annotation dataset is empty: {ANNOTATION_FILE}")

    required_annotation_columns = [
        "message",
        "alert_id",
        "severity",
        "cwe",
        "juliet_cwe_family",
        "ground_truth_status",
    ]

    missing_columns = [
        column
        for column in required_annotation_columns
        if column not in df.columns
    ]
    if missing_columns:
        raise ValueError(
            "Required column(s) missing from annotation dataset: "
            f"{missing_columns}"
        )

    priorities = df.apply(
        derive_priority_and_label,
        axis=1,
        result_type="expand",
    )
    priorities.columns = ["priority", "label"]
    df = pd.concat([df, priorities], axis=1)

    df = enrich_structured_fields(df)
    df = add_model_features(df)

    TRAINING_OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Keep the full enriched dataset for traceability and training.
    df.to_csv(TRAINING_OUTPUT_FILE, index=False)
    df.to_csv(FEATURE_OUTPUT_FILE, index=False)

    priority_counts = df["priority"].value_counts(dropna=False)
    unknown_count = int((df["priority"] == "UNKNOWN").sum())

    print(f"Labeled training dataset created: {TRAINING_OUTPUT_FILE}")
    print(f"Feature dataset created: {FEATURE_OUTPUT_FILE}")
    print(f"Total rows: {len(df)}")
    print("Priority distribution:")
    print(priority_counts)
    print(f"Excluded unknown count (for model training): {unknown_count}")
    print("Model feature columns:")
    print(REQUIRED_MODEL_FEATURE_COLUMNS)


if __name__ == "__main__":
    main()
