import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    fbeta_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.neural_network import MLPClassifier
from sklearn.svm import LinearSVC


FEATURE_DIR = Path("data/features/commit_risk")
MODEL_DIR = Path("models/commit_risk")
REPORT_DIR = Path("reports/commit_risk")

MODEL_PATH = MODEL_DIR / "commit_risk_model.pkl"
METADATA_PATH = MODEL_DIR / "model_metadata.json"
VALIDATION_REPORT_PATH = (
    REPORT_DIR / "validation_model_comparison.csv"
)
TEST_REPORT_PATH = REPORT_DIR / "test_evaluation.csv"

# Model selection requirements.
#
# These values must be justified using validation results only.
# Do not lower them based on test-set performance.
MINIMUM_VALIDATION_PRECISION = 0.15
MINIMUM_VALIDATION_RECALL = 0.30

# Thresholds applied to positive-class scores for every trained candidate.
#
# Logistic Regression, Random Forest and ANN return probabilities.
# LinearSVC decision scores are mapped through a sigmoid so they can be
# evaluated on this common 0-1 threshold grid. Those SVM scores are ranking
# scores, not calibrated probabilities.
CANDIDATE_THRESHOLDS = (
    0.20,
    0.30,
    0.40,
    0.50,
    0.60,
    0.70,
    0.80,
    0.90,
)

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def load_features():
    """Load the prepared ML1 feature matrices and labels."""
    required_files = [
        FEATURE_DIR / "X_train.pkl",
        FEATURE_DIR / "X_valid.pkl",
        FEATURE_DIR / "X_test.pkl",
        FEATURE_DIR / "y_train.pkl",
        FEATURE_DIR / "y_valid.pkl",
        FEATURE_DIR / "y_test.pkl",
    ]

    missing_files = [
        str(path) for path in required_files if not path.exists()
    ]

    if missing_files:
        raise FileNotFoundError(
            "Missing prepared ML1 feature files:\n- "
            + "\n- ".join(missing_files)
        )

    X_train = joblib.load(FEATURE_DIR / "X_train.pkl")
    X_valid = joblib.load(FEATURE_DIR / "X_valid.pkl")
    X_test = joblib.load(FEATURE_DIR / "X_test.pkl")

    y_train = joblib.load(FEATURE_DIR / "y_train.pkl")
    y_valid = joblib.load(FEATURE_DIR / "y_valid.pkl")
    y_test = joblib.load(FEATURE_DIR / "y_test.pkl")

    return X_train, X_valid, X_test, y_train, y_valid, y_test


def json_safe(value):
    """Convert model parameters into JSON-serialisable values."""
    if isinstance(value, dict):
        return {
            str(key): json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]

    if isinstance(value, (np.integer,)):
        return int(value)

    if isinstance(value, (np.floating,)):
        return float(value)

    if isinstance(value, np.ndarray):
        return value.tolist()

    return value


def positive_scores(model, X):
    """
    Return continuous positive-class scores in the range 0-1.

    Models exposing predict_proba return positive-class probabilities.
    LinearSVC exposes decision_function; its raw values are transformed with
    a sigmoid for consistent threshold experiments. The transformed SVM
    scores are not calibrated probabilities.
    """
    if hasattr(model, "predict_proba"):
        probabilities = np.asarray(
            model.predict_proba(X),
            dtype=float,
        )

        if probabilities.ndim != 2 or probabilities.shape[1] < 2:
            raise ValueError(
                "predict_proba() did not return two-class probabilities."
            )

        return probabilities[:, 1]

    if hasattr(model, "decision_function"):
        raw_scores = np.asarray(
            model.decision_function(X),
            dtype=float,
        )

        raw_scores = np.clip(raw_scores, -500, 500)
        return 1.0 / (1.0 + np.exp(-raw_scores))

    return np.asarray(model.predict(X), dtype=float)


def calculate_metrics(y_true, y_pred, scores):
    """Calculate threshold-dependent and score-based metrics."""
    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    ).ravel()

    negative_count = tn + fp
    false_positive_rate = (
        fp / negative_count
        if negative_count > 0
        else 0.0
    )

    try:
        roc_auc = roc_auc_score(y_true, scores)
    except ValueError:
        roc_auc = np.nan

    try:
        average_precision = average_precision_score(
            y_true,
            scores,
        )
    except ValueError:
        average_precision = np.nan

    return {
        "accuracy": float(
            accuracy_score(y_true, y_pred)
        ),
        "precision": float(
            precision_score(
                y_true,
                y_pred,
                zero_division=0,
            )
        ),
        "recall": float(
            recall_score(
                y_true,
                y_pred,
                zero_division=0,
            )
        ),
        "f1_score": float(
            f1_score(
                y_true,
                y_pred,
                zero_division=0,
            )
        ),
        "f2_score": float(
            fbeta_score(
                y_true,
                y_pred,
                beta=2,
                zero_division=0,
            )
        ),
        "average_precision": float(average_precision),
        "roc_auc": float(roc_auc),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "false_positive_rate": float(
            false_positive_rate
        ),
    }


def evaluate_threshold(
    candidate_id,
    model_family,
    configuration_name,
    configuration,
    scores,
    y,
    threshold,
    training_time,
    score_time,
):
    """Evaluate one trained candidate at one validation threshold."""
    start_threshold_inference = time.perf_counter()
    y_pred = (scores >= threshold).astype(int)
    threshold_inference_time = (
        time.perf_counter() - start_threshold_inference
    )

    metrics = calculate_metrics(y, y_pred, scores)

    return {
        "candidate_id": candidate_id,
        "model_family": model_family,
        "configuration_name": configuration_name,
        "configuration": json.dumps(
            json_safe(configuration),
            sort_keys=True,
        ),
        "threshold": float(threshold),
        **metrics,
        "score_time": float(score_time),
        "threshold_inference_time": float(
            threshold_inference_time
        ),
        "training_time": float(training_time),
        "precision_eligible": (
            metrics["precision"]
            >= MINIMUM_VALIDATION_PRECISION
        ),
        "recall_eligible": (
            metrics["recall"]
            >= MINIMUM_VALIDATION_RECALL
        ),
        "selection_eligible": (
            metrics["precision"]
            >= MINIMUM_VALIDATION_PRECISION
            and metrics["recall"]
            >= MINIMUM_VALIDATION_RECALL
        ),
        "selected": False,
    }


def select_best_candidate(results_df):
    """
    Select the highest-F2 model-and-threshold combination satisfying
    validation precision and recall requirements.
    """
    required_columns = {
        "candidate_id",
        "threshold",
        "precision",
        "recall",
        "f2_score",
        "average_precision",
        "false_positive_rate",
        "selection_eligible",
    }

    missing_columns = required_columns.difference(
        results_df.columns
    )

    if missing_columns:
        raise ValueError(
            "Missing selection columns: "
            + ", ".join(sorted(missing_columns))
        )

    eligible = results_df[
        results_df["selection_eligible"]
    ].copy()

    if eligible.empty:
        raise RuntimeError(
            "No model-and-threshold candidate satisfies the "
            "minimum validation requirements. "
            f"Required precision >= "
            f"{MINIMUM_VALIDATION_PRECISION:.2%} and "
            f"recall >= {MINIMUM_VALIDATION_RECALL:.2%}. "
            "The existing production model will not be overwritten. "
            f"Review {VALIDATION_REPORT_PATH}."
        )

    # F2 is the primary metric because recall is important for security
    # screening. Average precision, lower false-positive rate, recall and
    # precision are deterministic tie-breakers.
    selected = eligible.sort_values(
        by=[
            "f2_score",
            "average_precision",
            "false_positive_rate",
            "recall",
            "precision",
        ],
        ascending=[
            False,
            False,
            True,
            False,
            False,
        ],
        na_position="last",
    ).iloc[0]

    return selected


def build_model_candidates():
    """
    Create controlled candidate configurations for all four algorithms.

    The first experiment focuses on parameters most directly related to
    imbalance, capacity and convergence. Wider hyperparameter searches can
    be introduced later if no candidate meets the operational requirements.
    """
    candidates = []

    logistic_weights = [
        ("none", None),
        ("1_to_2", {0: 1, 1: 2}),
        ("1_to_3", {0: 1, 1: 3}),
        ("1_to_5", {0: 1, 1: 5}),
        ("1_to_10", {0: 1, 1: 10}),
        ("balanced", "balanced"),
    ]

    for weight_name, class_weight in logistic_weights:
        configuration = {
            "class_weight": class_weight,
            "C": 1.0,
            "max_iter": 1000,
            "random_state": 42,
        }
        candidates.append(
            {
                "candidate_id": f"lr_{weight_name}",
                "model_family": "Logistic Regression",
                "configuration_name": (
                    f"class_weight={weight_name}"
                ),
                "configuration": configuration,
                "model": LogisticRegression(
                    class_weight=class_weight,
                    C=1.0,
                    max_iter=1000,
                    random_state=42,
                ),
            }
        )

    svm_weights = [
        ("none", None),
        ("1_to_2", {0: 1, 1: 2}),
        ("1_to_3", {0: 1, 1: 3}),
        ("1_to_5", {0: 1, 1: 5}),
        ("1_to_10", {0: 1, 1: 10}),
        ("balanced", "balanced"),
    ]

    for weight_name, class_weight in svm_weights:
        configuration = {
            "class_weight": class_weight,
            "C": 1.0,
            "max_iter": 5000,
            "random_state": 42,
        }
        candidates.append(
            {
                "candidate_id": f"svm_{weight_name}",
                "model_family": "Linear SVM",
                "configuration_name": (
                    f"class_weight={weight_name}"
                ),
                "configuration": configuration,
                "model": LinearSVC(
                    class_weight=class_weight,
                    C=1.0,
                    max_iter=5000,
                    random_state=42,
                ),
            }
        )

    random_forest_configs = [
        {
            "name": "100_none",
            "n_estimators": 100,
            "class_weight": None,
            "max_depth": None,
            "min_samples_leaf": 1,
        },
        {
            "name": "100_balanced",
            "n_estimators": 100,
            "class_weight": "balanced",
            "max_depth": None,
            "min_samples_leaf": 1,
        },
        {
            "name": "300_balanced",
            "n_estimators": 300,
            "class_weight": "balanced",
            "max_depth": None,
            "min_samples_leaf": 1,
        },
        {
            "name": "300_balanced_subsample",
            "n_estimators": 300,
            "class_weight": "balanced_subsample",
            "max_depth": None,
            "min_samples_leaf": 1,
        },
        {
            "name": "300_depth_20_leaf_2",
            "n_estimators": 300,
            "class_weight": "balanced",
            "max_depth": 20,
            "min_samples_leaf": 2,
        },
    ]

    for item in random_forest_configs:
        configuration = {
            "n_estimators": item["n_estimators"],
            "class_weight": item["class_weight"],
            "max_depth": item["max_depth"],
            "min_samples_leaf": item[
                "min_samples_leaf"
            ],
            "random_state": 42,
            "n_jobs": -1,
        }
        candidates.append(
            {
                "candidate_id": f"rf_{item['name']}",
                "model_family": "Random Forest",
                "configuration_name": item["name"],
                "configuration": configuration,
                "model": RandomForestClassifier(
                    n_estimators=item["n_estimators"],
                    class_weight=item["class_weight"],
                    max_depth=item["max_depth"],
                    min_samples_leaf=item[
                        "min_samples_leaf"
                    ],
                    random_state=42,
                    n_jobs=-1,
                ),
            }
        )

    ann_configs = [
        {
            "name": "64_iter_50",
            "hidden_layer_sizes": (64,),
            "max_iter": 50,
            "alpha": 0.0001,
        },
        {
            "name": "64_iter_100",
            "hidden_layer_sizes": (64,),
            "max_iter": 100,
            "alpha": 0.0001,
        },
        {
            "name": "128_iter_100",
            "hidden_layer_sizes": (128,),
            "max_iter": 100,
            "alpha": 0.0001,
        },
        {
            "name": "64_32_iter_100",
            "hidden_layer_sizes": (64, 32),
            "max_iter": 100,
            "alpha": 0.0001,
        },
        {
            "name": "64_iter_100_alpha_001",
            "hidden_layer_sizes": (64,),
            "max_iter": 100,
            "alpha": 0.001,
        },
    ]

    for item in ann_configs:
        configuration = {
            "hidden_layer_sizes": item[
                "hidden_layer_sizes"
            ],
            "max_iter": item["max_iter"],
            "alpha": item["alpha"],
            "early_stopping": True,
            "validation_fraction": 0.1,
            "n_iter_no_change": 10,
            "random_state": 42,
        }
        candidates.append(
            {
                "candidate_id": f"ann_{item['name']}",
                "model_family": "ANN",
                "configuration_name": item["name"],
                "configuration": configuration,
                "model": MLPClassifier(
                    hidden_layer_sizes=item[
                        "hidden_layer_sizes"
                    ],
                    max_iter=item["max_iter"],
                    alpha=item["alpha"],
                    early_stopping=True,
                    validation_fraction=0.1,
                    n_iter_no_change=10,
                    random_state=42,
                ),
            }
        )

    return candidates


def save_validation_report(results_df):
    """Save all candidate and threshold results."""
    report_columns = [
        "candidate_id",
        "model_family",
        "configuration_name",
        "configuration",
        "threshold",
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "f2_score",
        "average_precision",
        "roc_auc",
        "true_negatives",
        "false_positives",
        "false_negatives",
        "true_positives",
        "false_positive_rate",
        "score_time",
        "threshold_inference_time",
        "training_time",
        "precision_eligible",
        "recall_eligible",
        "selection_eligible",
        "selected",
    ]

    results_df.to_csv(
        VALIDATION_REPORT_PATH,
        columns=report_columns,
        index=False,
    )


def print_selected_evaluation(
    title,
    candidate_id,
    threshold,
    y_true,
    scores,
):
    """Print a readable evaluation for the selected operating point."""
    y_pred = (scores >= threshold).astype(int)

    print(f"\n===== {title} =====")
    print(f"Candidate: {candidate_id}")
    print(f"Threshold: {threshold:.2f}")
    print("Confusion Matrix:")
    print(
        confusion_matrix(
            y_true,
            y_pred,
            labels=[0, 1],
        )
    )
    print("\nClassification Report:")
    print(
        classification_report(
            y_true,
            y_pred,
            labels=[0, 1],
            zero_division=0,
        )
    )


def main():
    (
        X_train,
        X_valid,
        X_test,
        y_train,
        y_valid,
        y_test,
    ) = load_features()

    candidates = build_model_candidates()

    validation_results = []
    trained_candidates = {}

    for candidate in candidates:
        candidate_id = candidate["candidate_id"]
        model = candidate["model"]

        print(
            f"\nTraining {candidate_id} "
            f"({candidate['model_family']}, "
            f"{candidate['configuration_name']})..."
        )

        start_train = time.perf_counter()
        model.fit(X_train, y_train)
        training_time = (
            time.perf_counter() - start_train
        )

        start_score = time.perf_counter()
        validation_scores = positive_scores(
            model,
            X_valid,
        )
        score_time = time.perf_counter() - start_score

        trained_candidates[candidate_id] = {
            **candidate,
            "training_time": float(training_time),
        }

        for threshold in CANDIDATE_THRESHOLDS:
            result = evaluate_threshold(
                candidate_id=candidate_id,
                model_family=candidate["model_family"],
                configuration_name=(
                    candidate["configuration_name"]
                ),
                configuration=candidate[
                    "configuration"
                ],
                scores=validation_scores,
                y=y_valid,
                threshold=threshold,
                training_time=training_time,
                score_time=score_time,
            )
            validation_results.append(result)

        candidate_rows = [
            row
            for row in validation_results
            if row["candidate_id"] == candidate_id
        ]
        candidate_df = pd.DataFrame(candidate_rows)
        best_candidate_row = candidate_df.sort_values(
            by=["f2_score", "precision", "recall"],
            ascending=[False, False, False],
        ).iloc[0]

        print(
            "Best validation operating point for this "
            f"candidate: threshold="
            f"{best_candidate_row['threshold']:.2f}, "
            f"precision="
            f"{best_candidate_row['precision']:.2%}, "
            f"recall="
            f"{best_candidate_row['recall']:.2%}, "
            f"F2="
            f"{best_candidate_row['f2_score']:.6f}, "
            f"false positives="
            f"{int(best_candidate_row['false_positives'])}"
        )

    results_df = pd.DataFrame(validation_results)

    # Preserve all experimental evidence before model selection.
    save_validation_report(results_df)

    try:
        selected_row = select_best_candidate(results_df)
    except RuntimeError:
        print(
            "\nNo model-and-threshold combination was selected. "
            "Validation results were saved to:"
        )
        print(VALIDATION_REPORT_PATH)
        raise

    selected_candidate_id = str(
        selected_row["candidate_id"]
    )
    selected_threshold = float(
        selected_row["threshold"]
    )

    selected_mask = (
        (results_df["candidate_id"]
         == selected_candidate_id)
        & np.isclose(
            results_df["threshold"],
            selected_threshold,
        )
    )
    results_df.loc[selected_mask, "selected"] = True

    save_validation_report(results_df)

    selected_candidate = trained_candidates[
        selected_candidate_id
    ]
    best_model = selected_candidate["model"]

    validation_scores = positive_scores(
        best_model,
        X_valid,
    )
    print_selected_evaluation(
        title="Selected Validation Evaluation",
        candidate_id=selected_candidate_id,
        threshold=selected_threshold,
        y_true=y_valid,
        scores=validation_scores,
    )

    print("\n===== Model Selection =====")
    print(
        f"Selected candidate: {selected_candidate_id}"
    )
    print(
        "Selected model family: "
        f"{selected_candidate['model_family']}"
    )
    print(
        "Selected configuration: "
        f"{selected_candidate['configuration_name']}"
    )
    print(
        f"Selected threshold: {selected_threshold:.2f}"
    )
    print(
        "Selection rule: highest validation F2 among "
        "model-and-threshold combinations meeting the "
        "minimum validation precision and recall requirements"
    )
    print(
        "Validation precision: "
        f"{selected_row['precision']:.2%}"
    )
    print(
        "Validation recall: "
        f"{selected_row['recall']:.2%}"
    )
    print(
        "Validation F2: "
        f"{selected_row['f2_score']:.6f}"
    )
    print(
        "Validation false-positive rate: "
        f"{selected_row['false_positive_rate']:.6f}"
    )

    # The test set is evaluated once, after selection is final.
    start_test_score = time.perf_counter()
    test_scores = positive_scores(best_model, X_test)
    test_score_time = (
        time.perf_counter() - start_test_score
    )

    start_test_threshold = time.perf_counter()
    test_predictions = (
        test_scores >= selected_threshold
    ).astype(int)
    test_threshold_time = (
        time.perf_counter() - start_test_threshold
    )

    test_metrics = calculate_metrics(
        y_test,
        test_predictions,
        test_scores,
    )

    print_selected_evaluation(
        title="Final Test Evaluation",
        candidate_id=selected_candidate_id,
        threshold=selected_threshold,
        y_true=y_test,
        scores=test_scores,
    )

    test_result = {
        "candidate_id": selected_candidate_id,
        "model_family": selected_candidate[
            "model_family"
        ],
        "configuration_name": selected_candidate[
            "configuration_name"
        ],
        "configuration": json.dumps(
            json_safe(
                selected_candidate["configuration"]
            ),
            sort_keys=True,
        ),
        "threshold": selected_threshold,
        **test_metrics,
        "score_time": float(test_score_time),
        "threshold_inference_time": float(
            test_threshold_time
        ),
        "training_time": float(
            selected_candidate["training_time"]
        ),
        "selected": True,
    }

    pd.DataFrame([test_result]).to_csv(
        TEST_REPORT_PATH,
        index=False,
    )

    # Save only after a validation-eligible candidate has been selected.
    joblib.dump(best_model, MODEL_PATH)

    metadata = {
        "candidate_id": selected_candidate_id,
        "model_name": selected_candidate[
            "model_family"
        ],
        "model_configuration_name": (
            selected_candidate["configuration_name"]
        ),
        "model_configuration": json_safe(
            selected_candidate["configuration"]
        ),
        "dataset": "PRIMEVUL",
        "input_level": "function-level",
        "feature_type": "TF-IDF",
        "selection_split": "validation",
        "selection_metric": "f2_score",
        "selected_threshold": selected_threshold,
        "threshold_score_type": (
            "probability"
            if hasattr(best_model, "predict_proba")
            else "sigmoid_transformed_decision_score"
        ),
        "minimum_validation_precision": (
            MINIMUM_VALIDATION_PRECISION
        ),
        "minimum_validation_recall": (
            MINIMUM_VALIDATION_RECALL
        ),
        "selected_reason": (
            "Highest validation F2 score among candidate "
            "model configurations and thresholds satisfying "
            "the minimum validation precision and recall "
            "requirements"
        ),
        "validation_metrics": {
            "accuracy": float(
                selected_row["accuracy"]
            ),
            "precision": float(
                selected_row["precision"]
            ),
            "recall": float(
                selected_row["recall"]
            ),
            "f1_score": float(
                selected_row["f1_score"]
            ),
            "f2_score": float(
                selected_row["f2_score"]
            ),
            "average_precision": float(
                selected_row["average_precision"]
            ),
            "roc_auc": float(
                selected_row["roc_auc"]
            ),
            "false_positive_rate": float(
                selected_row["false_positive_rate"]
            ),
            "true_negatives": int(
                selected_row["true_negatives"]
            ),
            "false_positives": int(
                selected_row["false_positives"]
            ),
            "false_negatives": int(
                selected_row["false_negatives"]
            ),
            "true_positives": int(
                selected_row["true_positives"]
            ),
        },
        "test_metrics": {
            key: json_safe(value)
            for key, value in test_metrics.items()
        },
    }

    with METADATA_PATH.open(
        "w",
        encoding="utf-8",
    ) as meta_file:
        json.dump(metadata, meta_file, indent=2)

    print("\nCommit risk model training completed successfully")
    print(f"Best model saved to: {MODEL_PATH}")
    print(f"Model metadata saved to: {METADATA_PATH}")
    print(
        "Validation comparison saved to: "
        f"{VALIDATION_REPORT_PATH}"
    )
    print(
        f"Test evaluation saved to: {TEST_REPORT_PATH}"
    )


if __name__ == "__main__":
    main()
