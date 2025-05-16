from flask import Flask, request, jsonify, render_template, flash, redirect, url_for
import joblib
import re
import numpy as np
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "phishing_detection_secret_key"

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'eml'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-limit

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load model and components
model_dir = os.path.join(os.path.dirname(__file__), 'models')
model = joblib.load(os.path.join(model_dir, 'optimized_rf_model.joblib'))
vectorizer = joblib.load(os.path.join(model_dir, 'tfidf_vectorizer.joblib'))
feature_names = joblib.load(os.path.join(model_dir, 'feature_names.joblib'))

# Security threshold
SECURITY_THRESHOLD = 0.3

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def clean_text(text):
    """Clean and normalize email text"""
    text = str(text).lower()
    text = re.sub(r'<.*?>', ' ', text)  # Remove HTML tags
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def extract_email_features(text):
    """Extract features that might indicate phishing"""
    text = str(text)
    features = {}
    
    # Enhanced text length features
    features['text_length'] = len(text)
    features['text_length_log'] = np.log1p(len(text))
    features['text_length_short'] = 1 if len(text) < 100 else 0
    features['text_length_long'] = 1 if len(text) > 1000 else 0
    
    # URL detection
    features['url_count'] = len(re.findall(r'http\S+|www\S+|https\S+', text))
    features['http_count'] = len(re.findall(r'http', text.lower()))
    features['suspicious_url'] = len(re.findall(r'bit\.ly|tinyurl|goo\.gl', text.lower()))
    features['url_to_text_ratio'] = features['url_count'] / max(len(text), 1)
    
    # Email address detection
    features['email_count'] = len(re.findall(r'\S+@\S+', text))
    
    # Currency and money references
    features['currency_count'] = len(re.findall(r'[$€£¥]', text))
    features['money_references'] = len(re.findall(r'[$€£¥]\s*\d+|\d+\s*[$€£¥]|money|payment|account|bank|credit|debit', text.lower()))
    
    # Click-related terms
    features['click_references'] = len(re.findall(r'click|press|follow|open|access', text.lower()))
    
    # Date and time patterns
    features['date_references'] = len(re.findall(r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}', text))
    features['weekday_references'] = len(re.findall(r'mon|tue|wed|thu|fri|sat|sun', text.lower()))
    features['aug_references'] = len(re.findall(r'aug', text.lower()))
    features['year_2008_references'] = len(re.findall(r'2008', text))
    
    # Other potentially phishing indicators
    features['exclamation_count'] = text.count('!')
    features['question_count'] = text.count('?')
    features['urgent_words'] = len(re.findall(r'urgent|immediate|attention|important|critical', text.lower()))
    
    # Common words appearing in phishing
    features['enron_mentions'] = len(re.findall(r'enron', text.lower()))
    features['wrote_mentions'] = len(re.findall(r'wrote', text.lower()))
    features['dear_mentions'] = len(re.findall(r'dear', text.lower()))
    
    # Count suspicious phrases
    suspicious_phrases = [
        'account.*verify', 'verify.*account', 'confirm.*details', 
        'update.*account', 'security.*alert', 'login.*details',
        'your.*password', 'click.*link', 'urgent', 'important',
        'suspend.*account', 'unusual.*activity', 'verify.*identity',
        'limited.*time', 'act.*now', 'gift.*card', 'won.*prize',
        'inheritance', 'lottery', 'reset.*password', 'problem.*account'
    ]
    
    for i, phrase in enumerate(suspicious_phrases):
        features[f'suspicious_phrase_{i}'] = 1 if re.search(phrase, text.lower()) is not None else 0
    
    return features, suspicious_phrases

def find_suspicious_phrases(text, suspicious_phrases):
    """Find instances of suspicious phrases in the text for highlighting"""
    highlighted_text = text
    suspicious_instances = []
    
    for phrase in suspicious_phrases:
        # Convert regex pattern to something we can search for
        search_phrase = phrase.replace('.*', '.{0,20}')
        pattern = re.compile(search_phrase, re.IGNORECASE)
        
        for match in pattern.finditer(text):
            start, end = match.span()
            suspicious_instances.append({
                'phrase': match.group(),
                'start': start,
                'end': end
            })
    
    return suspicious_instances

def highlight_suspicious_content(text, suspicious_instances):
    """Generate HTML with highlighted suspicious content"""
    # Sort instances by start position (reversed to avoid index issues when inserting HTML)
    suspicious_instances.sort(key=lambda x: x['start'], reverse=True)
    
    # Convert text to HTML-safe
    html_text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    
    # Insert highlighting tags
    for instance in suspicious_instances:
        start, end = instance['start'], instance['end']
        html_text = html_text[:start] + f'<span class="suspicious-highlight">{html_text[start:end]}</span>' + html_text[end:]
    
    # Convert newlines to <br> tags
    html_text = html_text.replace('\n', '<br>')
    
    return html_text

def extract_risk_indicators(features, probability):
    """Extract key risk indicators to explain the prediction"""
    indicators = []
    
    if features.get('url_count', 0) > 0:
        indicators.append({
            'name': 'URLs',
            'description': f"Contains {features['url_count']} URLs",
            'severity': 'high' if features['url_count'] > 2 else 'medium'
        })
    
    if features.get('suspicious_url', 0) > 0:
        indicators.append({
            'name': 'Shortened URLs',
            'description': "Contains suspicious shortened URLs",
            'severity': 'high'
        })
    
    if features.get('urgent_words', 0) > 1:
        indicators.append({
            'name': 'Urgency',
            'description': "Uses urgent language",
            'severity': 'medium'
        })
    
    if features.get('money_references', 0) > 0:
        indicators.append({
            'name': 'Financial',
            'description': "References money or payment",
            'severity': 'medium'
        })
    
    if features.get('text_length', 0) < 100:
        indicators.append({
            'name': 'Short Email',
            'description': "Unusually short email",
            'severity': 'low'
        })
    
    suspicious_count = sum(1 for k, v in features.items() if 'suspicious_phrase' in k and v > 0)
    if suspicious_count > 0:
        indicators.append({
            'name': 'Suspicious Phrases',
            'description': f"Contains {suspicious_count} suspicious phrases",
            'severity': 'high' if suspicious_count > 2 else 'medium'
        })
    
    if features.get('exclamation_count', 0) > 3:
        indicators.append({
            'name': 'Exclamations',
            'description': f"Contains {features['exclamation_count']} exclamation marks",
            'severity': 'medium'
        })
    
    return indicators

def analyze_email(email_text):
    # Clean text
    cleaned_text = clean_text(email_text)
    
    # Extract features and get suspicious phrases list
    features, suspicious_phrases = extract_email_features(email_text)
    
    # Find suspicious phrases in the original text for highlighting
    suspicious_instances = find_suspicious_phrases(email_text, suspicious_phrases)
    
    # Prepare highlighted text for display
    highlighted_text = highlight_suspicious_content(email_text, suspicious_instances)
    
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
    
    # Get risk indicators for explainability
    indicators = extract_risk_indicators(features, probability)
    
    # Extract feature importance if available
    top_features = []
    if hasattr(model, 'feature_importances_'):
        # Get indices of the top 5 features for this prediction
        feature_importance = model.feature_importances_
        sorted_indices = np.argsort(feature_importance)[::-1][:5]
        for idx in sorted_indices:
            if idx < len(feature_names):
                top_features.append({
                    'name': feature_names[idx],
                    'importance': float(feature_importance[idx])
                })
    
    return {
        "prediction": "Phishing" if prediction == 1 else "Legitimate",
        "probability": round(probability * 100, 2),
        "threat_level": threat_level,
        "action": action,
        "indicators": indicators,
        "highlighted_text": highlighted_text,
        "suspicious_count": len(suspicious_instances),
        "top_features": top_features
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'email_file' in request.files:
            file = request.files['email_file']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Read file content
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        email_text = f.read()
                except Exception as e:
                    flash(f"Error reading file: {str(e)}")
                    return redirect(request.url)
            else:
                # If no valid file, check for text input
                email_text = request.form.get('email_text', '')
        else:
            # No file was uploaded, use text from form
            email_text = request.form.get('email_text', '')
        
        if not email_text:
            flash("Please provide email content or upload a file")
            return redirect(request.url)
        
        result = analyze_email(email_text)
        
        return render_template('result.html', 
                              email_snippet=email_text[:500] + '...' if len(email_text) > 500 else email_text,
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
@app.route('/api')
def api_docs():
    return render_template('api.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)