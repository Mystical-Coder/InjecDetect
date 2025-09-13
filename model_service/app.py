import os
import pickle
from fastapi import FastAPI
from pydantic import BaseModel
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

# --- Load Model and Tokenizer at Startup ---
# This ensures they are loaded only once, not on every request.
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'sql_injection_detection.h5')
TOKENIZER_PATH = os.path.join(os.path.dirname(__file__), 'tokenizer.pkl')

model = load_model(MODEL_PATH)
with open(TOKENIZER_PATH, 'rb') as handle:
    tokenizer = pickle.load(handle)

app = FastAPI()

# --- Define the request body structure ---
class RequestData(BaseModel):
    payload: str

@app.post("/predict")
async def predict(data: RequestData):
    """
    Receives a payload string, tokenizes it, and returns the
    SQL injection probability score from the loaded Keras model.
    """
    # Preprocess the input payload
    # This should match the preprocessing you did during training
    sequence = tokenizer.texts_to_sequences([data.payload])
    padded_sequence = pad_sequences(sequence, maxlen=100) # Ensure maxlen matches your training

    # Get prediction from the model
    prediction = model.predict(padded_sequence)
    score = float(prediction[0][0])

    return {"sql_injection_score": score}