import joblib
import pandas as pd
import re
import os
from sklearn.base import BaseEstimator, TransformerMixin
from ml_module.transformers import TextCombiner 
# Path to your saved pipeline
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model', 'api_security_pipeline.pkl')

# Load the trained ML pipeline
pipeline = joblib.load(MODEL_PATH)

DECISION_THRESHOLD = 0.25
SIMPLE_HEADERS = [
    'request.headers.Accept-Encoding',
    'request.headers.Connection',
    'request.headers.Host',
    'request.headers.Accept',
    'request.method',
    'request.headers.Accept-Language',
    'request.headers.Sec-Fetch-Site',
    'request.headers.Sec-Fetch-Mode',
    'request.headers.Sec-Fetch-Dest',
    'request.headers.Sec-Fetch-User',
    'response.status',
]

def build_sample(request_dict):
    header_mapping = {
        'request.headers.Accept-Encoding': request_dict.get('accept_encoding', ''),
        'request.headers.Connection': request_dict.get('connection', ''),
        'request.headers.Host': request_dict.get('host', ''),
        'request.headers.Accept': request_dict.get('accept', ''),
        'request.method': request_dict.get('method', ''),
        'request.headers.Accept-Language': request_dict.get('accept_language', ''),
        'request.headers.Sec-Fetch-Site': request_dict.get('sec_fetch_site', ''),
        'request.headers.Sec-Fetch-Mode': request_dict.get('sec_fetch_mode', ''),
        'request.headers.Sec-Fetch-Dest': request_dict.get('sec_fetch_dest', ''),
        'request.headers.Sec-Fetch-User': request_dict.get('sec_fetch_user', ''),
        'response.status': request_dict.get('status', ''),
    }

    sample = pd.DataFrame([{
        'request.url': request_dict.get('url', ''),
        'request.body': request_dict.get('body', ''),
        'request.headers.Cookie': request_dict.get('cookie', ''),
        'request.headers.User-Agent': request_dict.get('user_agent', ''),
        **header_mapping
    }])

    return sample


def predict_request(request_dict: dict) -> dict:
    sample = build_sample(request_dict)

    # ---- HARD RULE LAYER ----
    text = (
        sample['request.url'].fillna('') + ' ' +
        sample['request.body'].fillna('') + ' ' +
        sample['request.headers.Cookie'].fillna('') + ' ' +
        sample['request.headers.User-Agent'].fillna('')
    ).str.lower().iloc[0]

    hard_rules = {
        'sqli_tautology': bool(re.search(r"(?:or|and)\s+\d+\s*=\s*\d+", text)),
        'sqli_comment':   bool(re.search(r'--|#|/\*', text)),
        'sqli_union':     bool(re.search(r'\bunion\b.{0,20}\bselect\b', text)),
        'sqli_quote':     bool(re.search(r"'\s*(?:or|and|;|--)", text)),
        'xss_script':     bool(re.search(r'<script|javascript:', text)),
        'xss_event':      bool(re.search(r'on(?:error|load|click|mouseover)\s*=', text)),
        'traversal':      bool(re.search(r'\.\./|%2e%2e', text)),
        'log4j':          bool(re.search(r'\$\{jndi:', text)),
        'cmd_inject':     bool(re.search(r';\s*(?:ls|cat|wget|curl|bash|sh)\b', text)),
    }

    if any(hard_rules.values()):
        return {'label': 'Attack', 'confidence': 1.0, 'attack_prob': 1.0}

    # ---- ML LAYER ----
    proba = pipeline.predict_proba(sample)[0]
    attack_prob = float(proba[1])

    return {
        'label': 'Attack' if attack_prob >= DECISION_THRESHOLD else 'Benign',
        'confidence': float(max(proba)),
        'attack_prob': attack_prob
    }
