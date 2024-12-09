import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder
import joblib

MODEL_PATH = 'zap_classifier_model.pkl'

def train_model(csv_file):
    print("Training model on real-time data...")
    
    # Load the CSV file
    data = pd.read_csv(csv_file)
    if data.empty:
        print("No data available for training.")
        return None
    
    # Convert risk levels to numeric values
    risk_encoder = LabelEncoder()
    data['risk_numeric'] = risk_encoder.fit_transform(data['risk'])
    
    # Map classification to numeric labels
    data['label'] = data['classification'].apply(lambda x: 1 if x == 'malicious' else 0)
    
    # Features and labels
    X = data[['risk_numeric']]
    y = data['label']
    
    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train the model
    model = LogisticRegression()  # Use RandomForestClassifier() for more complex scenarios
    model.fit(X_train, y_train)
    
    # Test the model
    y_pred = model.predict(X_test)
    print(f"Model Accuracy: {accuracy_score(y_test, y_pred)}")
    
    # Save the model
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")
    
    return model

def classify_data(csv_file, model):
    print("Classifying new data in real-time...")
    
    # Load the CSV file
    data = pd.read_csv(csv_file)
    if data.empty:
        print("No data available for classification.")
        return
    
    # Check if the model is loaded
    if model is None:
        print("Model is not loaded. Cannot classify data.")
        return
    
    # Convert risk levels to numeric values using the same encoder as in training
    risk_encoder = LabelEncoder()
    data['risk_numeric'] = risk_encoder.fit_transform(data['risk'])
    
    # Features for classification
    X = data[['risk_numeric']]
    
    # Predict classifications
    predictions = model.predict(X)
    data['prediction'] = predictions
    data['classification'] = data['prediction'].apply(lambda x: 'malicious' if x == 1 else 'benign')
    
    # Save classified data to a new CSV file
    classified_file = 'classified_data.csv'
    data.to_csv(classified_file, index=False)
    print(f"Classified data saved to {classified_file}")
