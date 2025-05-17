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
    """Find instances of suspicious phrases and elements in the text for highlighting"""
    suspicious_instances = []
    
    # Check for suspicious phrases from our list
    for phrase in suspicious_phrases:
        # Convert regex pattern to something we can search for
        search_phrase = phrase.replace('.*', '.{0,20}')
        pattern = re.compile(search_phrase, re.IGNORECASE)
        
        for match in pattern.finditer(text):
            start, end = match.span()
            suspicious_instances.append({
                'phrase': match.group(),
                'start': start,
                'end': end,
                'type': 'suspicious_phrase',
                'description': f'Common phishing phrase pattern: "{phrase}"'
            })
    
    # Find and mark URLs
    for match in re.finditer(r'(https?://\S+|www\.\S+)', text):
        start, end = match.span()
        url = match.group()
        url_type = 'suspicious_url' if re.search(r'bit\.ly|tinyurl|goo\.gl', url.lower()) else 'url'
        description = 'Shortened URL (often used to hide malicious destinations)' if url_type == 'suspicious_url' else 'URL in email'
        
        suspicious_instances.append({
            'phrase': url,
            'start': start,
            'end': end,
            'type': url_type,
            'description': description
        })
    
    # Find and mark email addresses
    for match in re.finditer(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text):
        start, end = match.span()
        email = match.group()
        
        # Check if domain seems suspicious (non-standard TLD or mismatched brand)
        is_suspicious = re.search(r'\.(xyz|info|top|club|pw|tk)$', email.lower()) is not None
        email_type = 'suspicious_email' if is_suspicious else 'email'
        description = 'Email with suspicious domain' if is_suspicious else 'Email address'
        
        suspicious_instances.append({
            'phrase': email,
            'start': start,
            'end': end,
            'type': email_type,
            'description': description
        })
    
    # Find and mark urgent language
    urgent_words = ['urgent', 'immediate', 'alert', 'warning', 'attention', 'important', 'critical']
    for word in urgent_words:
        for match in re.finditer(r'\b' + word + r'\b', text, re.IGNORECASE):
            start, end = match.span()
            suspicious_instances.append({
                'phrase': match.group(),
                'start': start,
                'end': end,
                'type': 'urgent_language',
                'description': 'Urgency language often used to pressure recipients'
            })
    
    # Find and mark money/financial references
    for match in re.finditer(r'(\$\d+|\d+\s*dollars|payment|account|bank|credit|debit|card)', text, re.IGNORECASE):
        start, end = match.span()
        suspicious_instances.append({
            'phrase': match.group(),
            'start': start,
            'end': end,
            'type': 'financial',
            'description': 'Financial terms often used in phishing to create concern'
        })
    
    return suspicious_instances

def highlight_suspicious_content(text, suspicious_instances):
    """Generate HTML with highlighted suspicious content with different colors by type"""
    # Sort instances by start position (reversed to avoid index issues when inserting HTML)
    suspicious_instances.sort(key=lambda x: x['start'], reverse=True)
    
    # Convert text to HTML-safe
    html_text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    
    # Define CSS classes for different types
    type_classes = {
        'suspicious_phrase': 'suspicious-highlight',
        'suspicious_url': 'suspicious-url-highlight',
        'url': 'url-highlight',
        'suspicious_email': 'suspicious-email-highlight',
        'email': 'email-highlight',
        'urgent_language': 'urgent-highlight',
        'financial': 'financial-highlight'
    }
    
    # Insert highlighting tags with specific classes and data attributes for tooltips
    for instance in suspicious_instances:
        start, end = instance['start'], instance['end']
        highlight_class = type_classes.get(instance['type'], 'suspicious-highlight')
        
        html_text = html_text[:start] + f'<span class="{highlight_class}" data-description="{instance["description"]}">{html_text[start:end]}</span>' + html_text[end:]
    
    # Convert newlines to <br> tags
    html_text = html_text.replace('\n', '<br>')
    
    return html_text

def extract_risk_indicators(features, probability):
    """Extract key risk indicators to explain the prediction with detailed descriptions"""
    indicators = []
    
    # Check for URLs
    if features.get('url_count', 0) > 0:
        severity = 'high' if features['url_count'] > 2 else 'medium'
        indicators.append({
            'name': 'URLs',
            'description': f"Contains {features['url_count']} URLs",
            'explanation': "Phishing emails often contain links to fake websites. Multiple URLs can indicate an attempt to direct you to a malicious site.",
            'severity': severity
        })
    
    # Check for shortened URLs
    if features.get('suspicious_url', 0) > 0:
        indicators.append({
            'name': 'Shortened URLs',
            'description': "Contains suspicious shortened URLs",
            'explanation': "URL shorteners (like bit.ly) hide the actual destination, making it easier to disguise malicious websites.",
            'severity': 'high'
        })
    
    # Check for urgent language
    if features.get('urgent_words', 0) > 0:
        severity = 'high' if features['urgent_words'] > 2 else 'medium'
        indicators.append({
            'name': 'Urgency',
            'description': f"Uses urgent language ({features['urgent_words']} instances)",
            'explanation': "Creating a false sense of urgency is a common social engineering tactic to push recipients into acting without thinking.",
            'severity': severity
        })
    
    # Check for money references
    if features.get('money_references', 0) > 0:
        indicators.append({
            'name': 'Financial',
            'description': "References money or payment",
            'explanation': "References to financial terms often aim to trigger concern about money, making you more likely to act hastily.",
            'severity': 'medium'
        })
    
    # Check email length
    if features.get('text_length', 0) < 100:
        indicators.append({
            'name': 'Short Email',
            'description': "Unusually short email",
            'explanation': "Very short emails with links are suspicious as they provide minimal context, focusing on getting you to click.",
            'severity': 'medium'
        })
    elif features.get('text_length', 0) > 3000:
        indicators.append({
            'name': 'Long Email',
            'description': "Unusually long email",
            'explanation': "Extremely long emails can be attempts to overwhelm with information or hide suspicious content in a lot of text.",
            'severity': 'low'
        })
    
    # Check suspicious phrases
    suspicious_count = sum(1 for k, v in features.items() if 'suspicious_phrase' in k and v > 0)
    if suspicious_count > 0:
        severity = 'high' if suspicious_count > 2 else 'medium'
        indicators.append({
            'name': 'Suspicious Phrases',
            'description': f"Contains {suspicious_count} suspicious phrases",
            'explanation': "Certain phrase patterns are commonly used in phishing, such as 'verify your account' or 'unusual activity'.",
            'severity': severity
        })
    
    # Check exclamation marks
    if features.get('exclamation_count', 0) > 3:
        indicators.append({
            'name': 'Exclamations',
            'description': f"Contains {features['exclamation_count']} exclamation marks",
            'explanation': "Excessive exclamation marks often indicate attempts to create emotional responses or urgency.",
            'severity': 'medium'
        })
    
    # Check for attachment references
    if re.search(r'attach|file|document|pdf|doc|docx|xls|xlsx|zip', str(features)):
        indicators.append({
            'name': 'Attachment References',
            'description': "References to attachments or files",
            'explanation': "Emails mentioning attachments without actual attachments may be trying to get you to click links to 'view' these non-existent files.",
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
    
    # Add feature explanations for better interpretability
    feature_explanations = {
        'text_length': 'Total length of the email text. Very short emails are often suspicious.',
        'text_length_log': 'Mathematical transformation of text length to better handle variations.',
        'url_count': 'Number of URLs in the email. Phishing emails often contain links to fake websites.',
        'suspicious_url': 'URLs using shorteners (bit.ly, etc.) which can disguise malicious destinations.',
        'email_count': 'Number of email addresses found in the content.',
        'money_references': 'Mentions of money, payments, accounts, or financial terms.',
        'click_references': 'Instructions to click links or buttons, common in phishing.',
        'urgent_words': 'Words conveying urgency or time pressure to force hasty actions.',
        'exclamation_count': 'Excessive punctuation often indicates attempts to create emotional responses.'
    }
    
    # Add explanations to top features
    for feature in top_features:
        if feature['name'] in feature_explanations:
            feature['explanation'] = feature_explanations[feature['name']]
    
    # Categorize highlighted elements for presentation
    highlighted_elements = {
        "urls": [i['phrase'] for i in suspicious_instances if i.get('type') == 'url' or i.get('type') == 'suspicious_url'],
        "suspicious_phrases": [i['phrase'] for i in suspicious_instances if i.get('type') == 'suspicious_phrase'],
        "urgent_language": [i['phrase'] for i in suspicious_instances if i.get('type') == 'urgent_language'],
        "financial_terms": [i['phrase'] for i in suspicious_instances if i.get('type') == 'financial']
    }
    
    return {
        "prediction": "Phishing" if prediction == 1 else "Legitimate",
        "probability": round(probability * 100, 2),
        "threat_level": threat_level,
        "action": action,
        "indicators": indicators,
        "highlighted_text": highlighted_text,
        "suspicious_count": len(suspicious_instances),
        "top_features": top_features,
        "highlighted_elements": highlighted_elements
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

def get_feature_explanations():
    """Provide explanations for technical features used in the model"""
    return {
        'text_length': {
            'name': 'Text Length',
            'description': 'The total number of characters in the email',
            'significance': 'Very short emails are often suspicious, while legitimate business emails tend to have moderate length'
        },
        'text_length_log': {
            'name': 'Log-transformed Text Length',
            'description': 'Mathematical transformation of text length to reduce the impact of outliers',
            'significance': 'Helps the model handle both very short and very long emails more effectively'
        },
        'url_count': {
            'name': 'URL Count',
            'description': 'Number of web links found in the email',
            'significance': 'Phishing emails often contain links to fake websites'
        },
        'suspicious_url': {
            'name': 'Suspicious URL Count',
            'description': 'Number of shortened or suspicious URLs',
            'significance': 'URL shorteners are frequently used to hide malicious destinations'
        },
        'email_count': {
            'name': 'Email Address Count',
            'description': 'Number of email addresses found in the content',
            'significance': 'Multiple email addresses or mismatched addresses can indicate spoofing'
        },
        'money_references': {
            'name': 'Financial References',
            'description': 'Mentions of money, payments, accounts, or financial terms',
            'significance': 'Phishing often targets financial concerns to create urgency'
        },
        'click_references': {
            'name': 'Click References',
            'description': 'Instructions to click links or buttons',
            'significance': 'Pushing users to click is a common phishing tactic'
        },
        'urgent_words': {
            'name': 'Urgency Language',
            'description': 'Words conveying urgency or time pressure',
            'significance': 'Creates pressure to act without thinking'
        },
        'exclamation_count': {
            'name': 'Exclamation Marks',
            'description': 'Number of exclamation points in the email',
            'significance': 'Excessive punctuation often indicates attempts to create emotional responses'
        },
    }

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)