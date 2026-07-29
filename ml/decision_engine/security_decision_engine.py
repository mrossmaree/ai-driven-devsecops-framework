import os

import pandas as pd


COMMIT_RISK_REPORT = (
    "reports/commit_risk/commit_risk_report.csv"
)

CPPCHECK_REPORT = (
    "reports/alert_prioritizer/cppcheck/prioritised-alerts.csv"
)

CLANG_REPORT = (
    "reports/alert_prioritizer/clang/prioritised-alerts.csv"
)

ANOMALY_REPORT = (
    "reports/anomaly_detection/anomaly_report.csv"
)

OUTPUT_FILE = (
    "reports/final_decision/security_decision.csv"
)


def load_report(path, report_name):
    if not os.path.exists(path):
        print(f"{report_name} report not found: {path}")
        return pd.DataFrame()

    try:
        df = pd.read_csv(path)
    except Exception as exc:
        print(
            f"{report_name} report is malformed "
            f"and could not be parsed: {exc}"
        )
        return pd.DataFrame()

    if df.empty:
        print(f"{report_name} report is empty.")
        return pd.DataFrame()

    return df


def build_alert_summary(df, priority, max_items=5):
    if df.empty:
        return ""

    if "priority" not in df.columns:
        return ""

    selected = df[
        df["priority"].eq(priority)
    ].head(max_items)

    summaries = []

    for _, row in selected.iterrows():
        tool = row.get("tool", "unknown")
        file_path = row.get("file", "")
        line = row.get("line", "")
        alert_id = row.get("alert_id", "")
        message = row.get("message", "")

        location = file_path

        if pd.notna(line) and str(line).strip() != "":
            location = f"{file_path}:{line}"

        summaries.append(
            f"{tool} | {alert_id} | {location} | {message}"
        )

    return " ; ".join(summaries)


def build_commit_risk_summary(
    df,
    risk_level,
    max_items=5
):
    if df.empty:
        return ""

    if "risk_level" not in df.columns:
        return ""

    selected = df[
        df["risk_level"].eq(risk_level)
    ].head(max_items)

    summaries = []

    for _, row in selected.iterrows():
        file_path = row.get("file_path", "")
        function_name = row.get("function_name", "")
        risk_score = row.get("risk_score", "")

        location = file_path

        if (
            pd.notna(function_name)
            and str(function_name).strip() != ""
        ):
            location = (
                f"{file_path} | function: {function_name}"
            )

        summaries.append(
            f"commit-risk | {location} | "
            f"risk score: {risk_score}"
        )

    return " ; ".join(summaries)


def get_anomaly_summary(anomaly_df):
    if anomaly_df.empty:
        return {
            "anomaly_status": "NOT_AVAILABLE",
            "anomaly_score": "",
            "anomaly_reason": (
                "ML3 anomaly report not available"
            )
        }

    row = anomaly_df.iloc[0]

    anomaly_status = row.get(
        "anomaly_status",
        "NOT_AVAILABLE"
    )

    anomaly_score = row.get(
        "anomaly_score",
        ""
    )

    default_reason = (
        f"ML3 pipeline anomaly status: "
        f"{anomaly_status}, "
        f"score: {anomaly_score}"
    )

    anomaly_reason = str(
        row.get(
            "reason",
            default_reason
        )
    )

    return {
        "anomaly_status": anomaly_status,
        "anomaly_score": anomaly_score,
        "anomaly_reason": anomaly_reason
    }


def count_commit_risk_levels(commit_df):
    counts = {
        "HIGH": 0,
        "REVIEW_REQUIRED": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    if commit_df.empty:
        return counts

    if "risk_level" not in commit_df.columns:
        print(
            "Commit risk report does not contain "
            "the required 'risk_level' column."
        )
        return counts

    normalised_risk_levels = (
        commit_df["risk_level"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.upper()
    )

    for risk_level in counts:
        counts[risk_level] = int(
            normalised_risk_levels
            .eq(risk_level)
            .sum()
        )

    return counts


def count_alert_priorities(alerts_combined):
    counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    if alerts_combined.empty:
        return counts

    if "priority" not in alerts_combined.columns:
        print(
            "Combined SAST report does not contain "
            "the required 'priority' column."
        )
        return counts

    normalised_priorities = (
        alerts_combined["priority"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.upper()
    )

    for priority in counts:
        counts[priority] = int(
            normalised_priorities
            .eq(priority)
            .sum()
        )

    return counts


def calculate_decision(
    commit_df,
    cppcheck_df,
    clang_df,
    anomaly_df
):
    alerts_combined = pd.concat(
        [cppcheck_df, clang_df],
        ignore_index=True
    )

    alert_counts = count_alert_priorities(
        alerts_combined
    )

    alert_high_count = alert_counts["HIGH"]
    alert_medium_count = alert_counts["MEDIUM"]
    alert_low_count = alert_counts["LOW"]

    commit_counts = count_commit_risk_levels(
        commit_df
    )

    commit_high_count = commit_counts["HIGH"]

    commit_review_required_count = (
        commit_counts["REVIEW_REQUIRED"]
    )

    commit_medium_count = commit_counts["MEDIUM"]
    commit_low_count = commit_counts["LOW"]

    anomaly_summary = get_anomaly_summary(
        anomaly_df
    )

    anomaly_status = str(
        anomaly_summary["anomaly_status"]
    ).strip().upper()

    anomaly_reason = str(
        anomaly_summary.get(
            "anomaly_reason",
            ""
        )
    )

    anomaly_reason_upper = (
        anomaly_reason.upper()
    )

    malformed_or_schema_not_available = (
        anomaly_status == "NOT_AVAILABLE"
        and (
            "MISSING" in anomaly_reason_upper
            or "MALFORMED" in anomaly_reason_upper
            or "SCHEMA_MISMATCH"
            in anomaly_reason_upper
            or "SCHEMA-INCOMPATIBLE"
            in anomaly_reason_upper
            or "CURRENT_METRICS_SCHEMA_INCOMPATIBLE"
            in anomaly_reason_upper
        )
    )

    ml3_failed = (
        anomaly_status == "FAILED"
    )

    # -------------------------------------------------
    # Final decision policy
    # -------------------------------------------------
    #
    # ML2 HIGH:
    #     BLOCK because a static-analysis tool has
    #     detected high-severity security evidence.
    #
    # ML1 HIGH alone:
    #     REVIEW because ML1 is a risk predictor and
    #     may produce false-positive predictions.
    #
    # ML1 HIGH + ML2 HIGH:
    #     BLOCK because the ML1 prediction is supported
    #     by high-severity static-analysis evidence.
    #
    # ML1 HIGH + ML2 MEDIUM:
    #     REVIEW because additional manual validation
    #     is required.
    #
    # ML1 LOW + no SAST alerts:
    #     PASS.
    # -------------------------------------------------

    if alert_high_count > 0:
        decision = "BLOCK"

        if commit_high_count > 0:
            reason = (
                "High commit risk supported by "
                "high-severity static-analysis findings"
            )
        else:
            reason = (
                "High-severity static-analysis "
                "findings detected"
            )

    elif commit_high_count > 0:
        decision = "REVIEW"

        if alert_medium_count > 0:
            reason = (
                "High commit risk with "
                "medium-severity static-analysis "
                "findings requires manual review"
            )

        elif alert_low_count > 0:
            reason = (
                "High commit risk with low-severity "
                "static-analysis findings requires "
                "manual review"
            )

        else:
            reason = (
                "High commit risk detected without "
                "confirming high-severity "
                "static-analysis evidence"
            )

    elif commit_review_required_count > 0:
        decision = "REVIEW"
        reason = (
            "Low-confidence ML1 predictions "
            "require manual review"
        )

    elif anomaly_status == "ANOMALOUS":
        decision = "REVIEW"
        reason = (
            "Anomalous CI/CD pipeline behaviour "
            "detected by ML3"
        )

    elif malformed_or_schema_not_available:
        decision = "REVIEW"
        reason = (
            "ML3 anomaly detection unavailable "
            "due to malformed or schema-incompatible "
            "upstream input"
        )

    elif ml3_failed:
        decision = "REVIEW"
        reason = (
            "ML3 anomaly detection runtime failed"
        )

    elif (
        commit_medium_count > 0
        or alert_medium_count > 0
    ):
        decision = "REVIEW"

        if (
            commit_medium_count > 0
            and alert_medium_count > 0
        ):
            reason = (
                "Medium commit risk and "
                "medium-severity static-analysis "
                "findings detected"
            )

        elif commit_medium_count > 0:
            reason = (
                "Medium commit risk detected"
            )

        else:
            reason = (
                "Medium-severity static-analysis "
                "findings detected"
            )

    else:
        decision = "PASS"

        if (
            commit_low_count > 0
            or alert_low_count > 0
        ):
            reason = (
                "Only low-risk findings detected"
            )
        else:
            reason = (
                "No commit risk, security alerts, "
                "or anomaly detected"
            )

    return {
        "decision": decision,
        "reason": reason,

        "commit_high_count": (
            commit_high_count
        ),

        "commit_review_required_count": (
            commit_review_required_count
        ),

        "commit_medium_count": (
            commit_medium_count
        ),

        "commit_low_count": (
            commit_low_count
        ),

        "alert_high_count": (
            alert_high_count
        ),

        "alert_medium_count": (
            alert_medium_count
        ),

        "alert_low_count": (
            alert_low_count
        ),

        "anomaly_status": (
            anomaly_summary["anomaly_status"]
        ),

        "anomaly_score": (
            anomaly_summary["anomaly_score"]
        ),

        "anomaly_reason": (
            anomaly_summary["anomaly_reason"]
        ),

        "commit_high_issues": (
            build_commit_risk_summary(
                commit_df,
                "HIGH"
            )
        ),

        "commit_review_required_issues": (
            build_commit_risk_summary(
                commit_df,
                "REVIEW_REQUIRED"
            )
        ),

        "commit_medium_issues": (
            build_commit_risk_summary(
                commit_df,
                "MEDIUM"
            )
        ),

        "commit_low_issues": (
            build_commit_risk_summary(
                commit_df,
                "LOW"
            )
        ),

        "alert_high_issues": (
            build_alert_summary(
                alerts_combined,
                "HIGH"
            )
        ),

        "alert_medium_issues": (
            build_alert_summary(
                alerts_combined,
                "MEDIUM"
            )
        ),

        "alert_low_issues": (
            build_alert_summary(
                alerts_combined,
                "LOW"
            )
        )
    }


def write_decision(result):
    os.makedirs(
        "reports/final_decision",
        exist_ok=True
    )

    decision_df = pd.DataFrame(
        [result]
    )

    decision_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(
        "\n===== FINAL SECURITY DECISION ====="
    )

    print(
        f"Decision: {result['decision']}"
    )

    print(
        f"Reason: {result['reason']}"
    )

    print(
        "\n===== ML 1 COMMIT RISK SUMMARY ====="
    )

    print(
        "HIGH commit risk functions: "
        f"{result['commit_high_count']}"
    )

    print(
        "REVIEW_REQUIRED functions: "
        f"{result['commit_review_required_count']}"
    )

    print(
        "MEDIUM commit risk functions: "
        f"{result['commit_medium_count']}"
    )

    print(
        "LOW commit risk functions: "
        f"{result['commit_low_count']}"
    )

    print(
        "\n===== ML 2 SAST ALERT SUMMARY ====="
    )

    print(
        f"HIGH alerts: "
        f"{result['alert_high_count']}"
    )

    print(
        f"MEDIUM alerts: "
        f"{result['alert_medium_count']}"
    )

    print(
        f"LOW alerts: "
        f"{result['alert_low_count']}"
    )

    print(
        "\n===== ML 3 PIPELINE "
        "ANOMALY SUMMARY ====="
    )

    print(
        "Anomaly status: "
        f"{result['anomaly_status']}"
    )

    print(
        "Anomaly score: "
        f"{result['anomaly_score']}"
    )

    print(
        "Anomaly reason: "
        f"{result['anomaly_reason']}"
    )

    if result["commit_high_issues"]:
        print(
            "\nHIGH commit risk functions:"
        )

        print(
            result["commit_high_issues"]
        )

    if result[
        "commit_review_required_issues"
    ]:
        print(
            "\nREVIEW_REQUIRED functions:"
        )

        print(
            result[
                "commit_review_required_issues"
            ]
        )

    if result["commit_medium_issues"]:
        print(
            "\nMEDIUM commit risk functions:"
        )

        print(
            result["commit_medium_issues"]
        )

    if result["commit_low_issues"]:
        print(
            "\nLOW commit risk functions:"
        )

        print(
            result["commit_low_issues"]
        )

    if result["alert_high_issues"]:
        print(
            "\nHIGH SAST issues:"
        )

        print(
            result["alert_high_issues"]
        )

    if result["alert_medium_issues"]:
        print(
            "\nMEDIUM SAST issues:"
        )

        print(
            result["alert_medium_issues"]
        )

    if result["alert_low_issues"]:
        print(
            "\nLOW SAST issues:"
        )

        print(
            result["alert_low_issues"]
        )

    print(
        f"\nDecision report saved: "
        f"{OUTPUT_FILE}"
    )


def main():
    commit_df = load_report(
        COMMIT_RISK_REPORT,
        "Commit risk"
    )

    cppcheck_df = load_report(
        CPPCHECK_REPORT,
        "Cppcheck"
    )

    clang_df = load_report(
        CLANG_REPORT,
        "Clang"
    )

    anomaly_df = load_report(
        ANOMALY_REPORT,
        "ML3 anomaly"
    )

    result = calculate_decision(
        commit_df,
        cppcheck_df,
        clang_df,
        anomaly_df
    )

    write_decision(result)

    if result["decision"] == "BLOCK":
        print(
            "\n=============================="
        )

        print(
            "SECURITY GATE: BLOCK"
        )

        print(
            "=============================="
        )

        print(
            "This commit is blocked from "
            "merging into the protected "
            "main branch."
        )

        print(
            f"Reason: {result['reason']}"
        )

        print(
            "Action required: Fix the "
            "security issue or request "
            "manual security review."
        )

        raise SystemExit(1)

    if result["decision"] == "REVIEW":
        print(
            "\n=============================="
        )

        print(
            "SECURITY GATE: REVIEW"
        )

        print(
            "=============================="
        )

        print(
            "Pipeline requires manual "
            "security review."
        )

        print(
            f"Reason: {result['reason']}"
        )

        return

    print(
        "\n=============================="
    )

    print(
        "SECURITY GATE: PASS"
    )

    print(
        "=============================="
    )

    print(
        "Pipeline passed security decision."
    )


if __name__ == "__main__":
    main()