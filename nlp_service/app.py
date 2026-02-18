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
    # Use the specialized prompt injection detection model
    # Labels are typically "INJECTION" and "SAFE" (or similar, checking output structure)
    classifier = pipeline("text-classification", model="protectai/deberta-v3-base-prompt-injection")
    logging.info("NLP Model (protectai/deberta-v3-base-prompt-injection) loaded successfully.")
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

    # Truncate to 512 tokens (DeBERTa limit)
    # Note: simple char truncation might cut tokens mid-way but is safer than crashing
    truncated_text = text[:1024] 
    
    try:
        # Classifier returns list of dicts: [{'label': 'INJECTION', 'score': 0.99}]
        # or [{'label': 'SAFE', 'score': 0.99}]
        result = classifier(truncated_text)
        
        # Log the result for debugging/verification
        logging.info(f"Analysis result: {result}")
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
