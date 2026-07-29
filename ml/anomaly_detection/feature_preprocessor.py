import math
from typing import Iterable

import pandas as pd


FEATURE_COLUMNS = [
    "total_files_scanned",
    "total_alerts",
    "high_alerts",
    "medium_alerts",
    "low_alerts",
    "high_commit_risk",
    "medium_commit_risk",
    "low_commit_risk",
    "alerts_per_file",
]

# Count features must be non-negative.
NON_NEGATIVE_COUNT_FEATURES = [
    "total_files_scanned",
    "total_alerts",
    "high_alerts",
    "medium_alerts",
    "low_alerts",
    "high_commit_risk",
    "medium_commit_risk",
    "low_commit_risk",
]


class FeaturePreprocessingError(ValueError):
    pass


def _validate_feature_columns(df: pd.DataFrame, required_features: Iterable[str]) -> None:
    missing = [feature for feature in required_features if feature not in df.columns]
    if missing:
        raise FeaturePreprocessingError(
            "Missing required ML3 feature columns: " + ", ".join(missing)
        )


def preprocess_features(
    df: pd.DataFrame,
    required_features: Iterable[str] = FEATURE_COLUMNS,
) -> pd.DataFrame:
    if df is None or df.empty:
        raise FeaturePreprocessingError("No ML3 feature rows were provided")

    required_features = list(required_features)
    _validate_feature_columns(df, required_features)

    feature_df = df[required_features].copy()

    for feature in required_features:
        numeric_col = pd.to_numeric(feature_df[feature], errors="coerce")

        if numeric_col.isna().any():
            raise FeaturePreprocessingError(
                f"Feature column contains missing or non-numeric values: {feature}"
            )

        if (~numeric_col.apply(math.isfinite)).any():
            raise FeaturePreprocessingError(
                f"Feature column contains infinite values: {feature}"
            )

        feature_df[feature] = numeric_col.astype(float)

    for feature in NON_NEGATIVE_COUNT_FEATURES:
        if (feature_df[feature] < 0).any():
            raise FeaturePreprocessingError(
                f"Feature column contains negative count values: {feature}"
            )

    return feature_df
