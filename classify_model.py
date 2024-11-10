import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, KFold, cross_val_score
from sklearn.preprocessing import StandardScaler
import numpy as np
import joblib  # For saving and loading models and other artifacts

# Function to train and return a Logistic Regression model
def train_model():
    # Load dataset
    data = pd.read_csv('captured_and_classified_packets.csv')

    # Define features and target variable
    X = data[['src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port', 'packet_length', 'flags']]
    y = data['classification']

    # Convert categorical features to numerical (one-hot encoding)
    X = pd.get_dummies(X)

    # Handle NaN and infinite values in features
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    # Save the columns of the one-hot encoded features for future prediction
    column_order = X.columns
    joblib.dump(column_order, 'column_order.pkl')  # Save the column order

    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    # Standardize the features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Save the scaler to be reused during classification
    joblib.dump(scaler, 'scaler.pkl')

    # Train the Logistic Regression model
    lr_model = LogisticRegression(random_state=42)
    lr_model.fit(X_train_scaled, y_train)

    # Perform cross-validation and return the trained model
    kf = KFold(n_splits=5, random_state=42, shuffle=True)
    cv_scores = cross_val_score(lr_model, X_train_scaled, y_train, cv=kf)
    
    print(f"Model trained. Mean cross-validation score: {cv_scores.mean():.4f}")
    
    # Save the trained model to a file
    joblib.dump(lr_model, 'logistic_regression_model.pkl')

    return lr_model

# Function to classify new batch of packets using trained model
def classify_packets(model):
    # Load the column order and scaler
    column_order = joblib.load('column_order.pkl')
    scaler = joblib.load('scaler.pkl')

    # Load new data
    data = pd.read_csv('captured_and_classified_packets.csv')
    
    # Convert data to match model format (one-hot encode)
    X = data[['src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port', 'packet_length', 'flags']]
    X = pd.get_dummies(X)

    # Align the columns of the new data with the original training data
    X = X.reindex(columns=column_order, fill_value=0)  # Missing columns filled with 0

    # Handle NaN and infinite values in features
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    # Standardize using saved scaler
    X_scaled = scaler.transform(X)
    
    # Make predictions
    predictions = model.predict(X_scaled)
    data['predictions'] = predictions
    
    # Write predictions to the same file (optional, can save elsewhere)
    data.to_csv('captured_and_classified_packets.csv', index=False)
   