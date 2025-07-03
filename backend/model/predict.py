import torch
import torch.nn as nn
import joblib
import numpy as np
import re
from urllib.parse import urlparse, parse_qs
from difflib import SequenceMatcher
import tldextract
import os
import requests
from datetime import datetime
import socket
import whois
from bs4 import BeautifulSoup
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd

# Placeholders for advanced features
# from xgboost import XGBClassifier  # For ensemble (install if using)
# import shap  # For explainable AI (install if using)

# Define paths (ensure they are correct for your project structure)
MODEL_PATH = 'model/phishing_model.pt'
SCALER_PATH = 'model/scaler.pkl'
FEATURE_COLUMNS_PATH = 'model/feature_columns.pkl'
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY") # Placeholder for API Key

# Load the scaler and feature columns
scaler = joblib.load(SCALER_PATH)
feature_names = joblib.load(FEATURE_COLUMNS_PATH)

class PhishingNet(nn.Module):
    def __init__(self, input_dim):
        super(PhishingNet, self).__init__()
        self.fc1 = nn.Linear(input_dim, 128)
        self.batch_norm1 = nn.BatchNorm1d(128)
        self.dropout1 = nn.Dropout(0.5)
        self.fc2 = nn.Linear(128, 64)
        self.batch_norm2 = nn.BatchNorm1d(64)
        self.dropout2 = nn.Dropout(0.3)
        self.fc3 = nn.Linear(64, 32)
        self.batch_norm3 = nn.BatchNorm1d(32)
        self.fc4 = nn.Linear(32, 1)
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        x = self.relu(self.batch_norm1(self.fc1(x)))
        x = self.dropout1(x)
        x = self.relu(self.batch_norm2(self.fc2(x)))
        x = self.dropout2(x)
        x = self.relu(self.batch_norm3(self.fc3(x)))
        x = self.fc4(x)
        return x

def get_domain_age(domain):
    try:
        w = whois(domain)
        if w.creation_date is None:
            return -1
        if isinstance(w.creation_date, list):
            creation_date = w.creation_date[0]
        else:
            creation_date = w.creation_date
        age = (datetime.now() - creation_date).days
        return age
    except Exception:
        return -1

def get_ssl_certificate(url):
    try:
        requests.get(url, verify=True, timeout=5)
        return 1
    except requests.exceptions.SSLError:
        return -1
    except Exception:
        return 0

def extract_features(url):
    try:
        features = {}
        parsed_url = urlparse(url)
        extracted_domain = tldextract.extract(url)
        domain = extracted_domain.domain + '.' + extracted_domain.suffix
        
        features['UrlLength'] = len(url)
        features['DomainLength'] = len(domain)
        features['HasIpAddress'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_url.netloc) else 0
        features['NumDots'] = url.count('.')
        features['NumHyphens'] = url.count('-')
        features['NumSlashes'] = url.count('/')
        features['NumQueryComponents'] = len(parse_qs(parsed_url.query))
        features['HasAtSymbol'] = 1 if '@' in url else 0
        features['HasHttps'] = 1 if parsed_url.scheme == 'https' else 0
        
        # Advanced Features
        features['DomainAge'] = get_domain_age(domain)
        features['SSLValid'] = get_ssl_certificate(url)
        features['BrandInSubdomain'] = 1 if any(brand in extracted_domain.subdomain for brand in ['paypal', 'ebay', 'google', 'amazon', 'apple']) else 0
        features['SuspiciousKeywordInSubdomain'] = 1 if any(keyword in extracted_domain.subdomain for keyword in ['secure', 'login', 'verify', 'account']) else 0
        features['SuspiciousKeywordInPath'] = 1 if any(keyword in parsed_url.path for keyword in ['secure', 'login', 'verify', 'account', '.php', '.html', '.js']) else 0
        features['TypoSquatting'] = 0 # Placeholder
        features['SuspiciousTLD'] = 1 if extracted_domain.suffix in ['xyz', 'top', 'pw', 'loan', 'gq'] else 0
        features['MultipleHyphensDomain'] = 1 if domain.count('-') > 2 else 0
        features['MultipleHyphensSubdomain'] = 1 if extracted_domain.subdomain.count('-') > 2 else 0
        features['CommaInDomain'] = 1 if ',' in domain else 0
        features['CommaInSubdomain'] = 1 if ',' in extracted_domain.subdomain else 0
        features['MultipleHyphensPath'] = 1 if parsed_url.path.count('-') > 3 else 0
        features['CommaInPath'] = 1 if ',' in parsed_url.path else 0
        features['PunycodeDomain'] = 1 if 'xn--' in domain else 0
        features['UnusualPort'] = 1 if parsed_url.port not in [None, 80, 443] else 0
        features['ManyQueryParams'] = 1 if len(parse_qs(parsed_url.query)) > 5 else 0
        features['SuspiciousFileExt'] = 1 if any(ext in parsed_url.path for ext in ['.exe', '.zip', '.rar', '.dmg']) else 0
        features['ShortenedURL'] = 1 if any(shortener in domain for shortener in ['bit.ly', 't.co', 'goo.gl']) else 0
        features['SuspiciousPathPattern'] = 1 if re.search(r'/(.php|.html|.js|/account/|/login/)$', parsed_url.path) else 0

        # Ensure all feature names are present
        for col in feature_names:
            if col not in features:
                features[col] = 0
                
        return features

    except Exception:
        return None

def predict_url(url: str):
    input_dim = len(feature_names)
    model = PhishingNet(input_dim)
    model.load_state_dict(torch.load(MODEL_PATH))
    model.eval()

    features = extract_features(url)
    if features is None:
        return {
            "url": url,
            "classification": "error",
            "error": "Error extracting features",
            "security_score": 100,
            "explanations": ["Error analyzing URL"],
            "risk_level": "High"
        }

    features_df = pd.DataFrame([features])
    # Reorder columns to match training
    features_df = features_df[feature_names] 
    features_tensor = torch.tensor(scaler.transform(features_df).astype(np.float32))

    with torch.no_grad():
        output = model(features_tensor)
        probability = torch.sigmoid(output).item()
        prediction = (probability > 0.5)

    is_phishing = bool(prediction)
    
    explanations = []
    security_score = 0

    if features['HasIpAddress']:
        explanations.append("URL is an IP address, which can be suspicious.")
        security_score += 20
    if not features['HasHttps'] or features['SSLValid'] == -1:
        explanations.append("Lacks a valid SSL certificate (HTTPS).")
        security_score += 20
    if features['DomainAge'] != -1 and features['DomainAge'] < 90:
        explanations.append(f"Domain is very new ({features['DomainAge']} days old).")
        security_score += 15
    if features['BrandInSubdomain']:
        explanations.append("Contains a brand name in the subdomain, a common phishing tactic.")
        security_score += 20
    if is_phishing:
        explanations.append("The AI model detected patterns consistent with phishing attempts.")
        security_score += (probability - 0.5) * 2 * 30 # Add up to 30 points from model
    
    security_score = min(100, int(security_score + (probability * 100)))

    if security_score > 70:
        risk_level = "High"
    elif security_score > 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "url": url,
        "classification": "Phishing" if is_phishing else "Legitimate",
        "is_phishing": is_phishing,
        "confidence": probability if is_phishing else 1 - probability,
        "security_score": security_score,
        "explanations": explanations,
        "features": features,
        "risk_level": risk_level
    }

app = FastAPI(
    title="PhishGuard AI",
    description="Detect phishing URLs using an AI model.",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ... your routes here ...

# Placeholders for ensemble, explainable AI, and threat intelligence integration
# def ensemble_predict(...): ...
# def explain_with_shap(...): ...
# def check_threat_feeds(...): ...

def nlp_phishing_content(url):
    try:
        resp = requests.get(url, timeout=5)
        soup = BeautifulSoup(resp.text, 'html.parser')
        text = soup.get_text().lower()
        phishing_keywords = ['login', 'password', 'verify', 'update', 'account', 'bank', 'secure', 'ssn']
        found = [kw for kw in phishing_keywords if kw in text]
        return 1 if found else -1
    except Exception:
        return -1

def whois_brand_match(domain, brand):
    try:
        info = whois.whois(domain)
        registrant = str(info.get('org', '')).lower()
        return 1 if brand.lower() in registrant else -1
    except Exception:
        return -1

def check_google_safe_browsing(url):
    api_key = SAFE_BROWSING_API_KEY
    if not api_key:
        return -1  # or handle error
    endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
    body = {
        "client": {"clientId": "yourcompany", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    resp = requests.post(f"{endpoint}?key={api_key}", json=body)
    matches = resp.json().get('matches')
    return 1 if matches else -1