from flask import Flask, request, jsonify
from transformers import pipeline
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Load pipeline (this will download the model on first use)
# Using a model capable of zero-shot classification or sentiment could be useful.
# For "malicious" context, we might look for "prompt injection" or "social engineering" intent.
# Since we don't have a fine-tuned model, we'll use a generic sentiment/text-classification model 
# and maybe a zero-shot classifier for specific labels.

try:
    # classifier = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")
    # Using a zero-shot classifier requires more resources but is more flexible.
    # Let's start with a smaller, faster model for sentiment as a placeholder for "semantic analysis".
    classifier = pipeline("sentiment-analysis") 
    logging.info("NLP Model loaded successfully.")
except Exception as e:
    logging.error(f"Failed to load NLP model: {e}")
    classifier = None

@app.route('/analyze', methods=['POST'])
def analyze():
    if not classifier:
        return jsonify({'error': 'Model not loaded'}), 500

    data = request.json
    text = data.get('text', '')

    if not text:
        return jsonify({'error': 'No text provided'}), 400

    # limit text length for performance
    truncated_text = text[:512] 
    
    try:
        result = classifier(truncated_text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
