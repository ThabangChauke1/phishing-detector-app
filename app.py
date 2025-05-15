from flask import Flask, request, jsonify, render_template
import joblib
import re
import numpy as np
import os
from utils.email_processor import clean_text, extract_email_features

app = Flask(__name__)

# Load model and components
model_dir = os.path.join(os.path.dirname(__file__), 'models')
model = joblib.load(os.path.join(model_dir, 'optimized_rf_model.joblib'))
vectorizer = joblib.load(os.path.join(model_dir, 'tfidf_vectorizer.joblib'))
feature_names = joblib.load(os.path.join(model_dir, 'feature_names.joblib'))

# Security threshold
SECURITY_THRESHOLD = 0.3

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        email_text = request.form.get('email_text', '')
        
        if not email_text:
            return render_template('index.html', error="Please provide email content")
        
        result = analyze_email(email_text)
        
        return render_template('result.html', 
                              email_snippet=email_text[:200] + '...' if len(email_text) > 200 else email_text,
                              result=result)

@app.route('/api/predict', methods=['POST'])
def api_predict():
    if request.is_json:
        data = request.json
        email_text = data.get('email_text', '')
        
        if not email_text:
            return jsonify({'error': 'No email content provided'}), 400
        
        result = analyze_email(email_text)
        return jsonify(result)
    else:
        return jsonify({'error': 'Request must be JSON'}), 400

def analyze_email(email_text):
    # Clean text
    cleaned_text = clean_text(email_text)
    
    # Extract features
    features = extract_email_features(email_text)
    
    # Extract feature values in the correct order
    feature_values = []
    for feature in feature_names[3000:]:  # Skip TF-IDF features which will be handled by vectorizer
        if feature in features:
            feature_values.append(features[feature])
        else:
            feature_values.append(0)
    
    # Vectorize text
    text_features = vectorizer.transform([cleaned_text]).toarray()
    
    # Combine features
    combined_features = np.hstack((text_features, np.array(feature_values).reshape(1, -1)))
    
    # Get probability
    probability = float(model.predict_proba(combined_features)[0, 1])
    
    # Determine prediction and threat level
    if probability >= 0.7:
        threat_level = "High"
        action = "Block"
    elif probability >= SECURITY_THRESHOLD:
        threat_level = "Medium" 
        action = "Flag for review"
    else:
        threat_level = "Low"
        action = "Allow"
    
    # Apply security threshold
    prediction = 1 if probability >= SECURITY_THRESHOLD else 0
    
    return {
        "prediction": "Phishing" if prediction == 1 else "Legitimate",
        "probability": round(probability * 100, 2),
        "threat_level": threat_level,
        "action": action,
        "indicators": extract_risk_indicators(features, probability)
    }

def extract_risk_indicators(features, probability):
    """Extract key risk indicators to explain the prediction"""
    indicators = []
    
    if features.get('url_count', 0) > 0:
        indicators.append(f"Contains {features['url_count']} URLs")
    
    if features.get('suspicious_url', 0) > 0:
        indicators.append("Contains suspicious shortened URLs")
    
    if features.get('urgent_words', 0) > 1:
        indicators.append("Uses urgent language")
    
    if features.get('money_references', 0) > 0:
        indicators.append("References money or payment")
    
    if features.get('text_length', 0) < 100:
        indicators.append("Unusually short email")
    
    suspicious_count = sum(1 for k, v in features.items() if 'suspicious_phrase' in k and v > 0)
    if suspicious_count > 0:
        indicators.append(f"Contains {suspicious_count} suspicious phrases")
    
    return indicators

if __name__ == '__main__':
    app.run(debug=True)