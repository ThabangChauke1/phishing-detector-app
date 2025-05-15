import re
import numpy as np

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
    
    # Enhanced text length features (top important feature)
    features['text_length'] = len(text)
    features['text_length_log'] = np.log1p(len(text))  # Log transform
    features['text_length_short'] = 1 if len(text) < 100 else 0  # Flag for very short emails
    features['text_length_long'] = 1 if len(text) > 1000 else 0  # Flag for very long emails
    
    # URL detection (important features from the chart)
    features['url_count'] = len(re.findall(r'http\S+|www\S+|https\S+', text))
    features['http_count'] = len(re.findall(r'http', text.lower()))
    features['suspicious_url'] = len(re.findall(r'bit\.ly|tinyurl|goo\.gl', text.lower()))
    features['url_to_text_ratio'] = features['url_count'] / max(len(text), 1)
    
    # Email address detection
    features['email_count'] = len(re.findall(r'\S+@\S+', text))
    
    # Currency and money references (from chart)
    features['currency_count'] = len(re.findall(r'[$€£¥]', text))
    features['money_references'] = len(re.findall(r'[$€£¥]\s*\d+|\d+\s*[$€£¥]|money|payment|account|bank|credit|debit', text.lower()))
    
    # Click-related terms (from chart)
    features['click_references'] = len(re.findall(r'click|press|follow|open|access', text.lower()))
    
    # Date and time patterns (many appear in top features)
    features['date_references'] = len(re.findall(r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}', text))
    features['weekday_references'] = len(re.findall(r'mon|tue|wed|thu|fri|sat|sun', text.lower()))
    features['aug_references'] = len(re.findall(r'aug', text.lower()))  # Specific month that appears important
    features['year_2008_references'] = len(re.findall(r'2008', text))  # Specific year from chart
    
    # Other potentially phishing indicators
    features['exclamation_count'] = text.count('!')
    features['question_count'] = text.count('?')
    features['urgent_words'] = len(re.findall(r'urgent|immediate|attention|important|critical', text.lower()))
    
    # Common words appearing in the chart
    features['enron_mentions'] = len(re.findall(r'enron', text.lower()))
    features['wrote_mentions'] = len(re.findall(r'wrote', text.lower()))
    features['dear_mentions'] = len(re.findall(r'dear', text.lower()))
    
    # Count suspicious phrases
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
    
    return features