import os
import pickle
from fastapi import FastAPI
from pydantic import BaseModel
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'sql_injection_detection.h5')
TOKENIZER_PATH = os.path.join(os.path.dirname(__file__), 'tokenizer.pkl')

model = load_model(MODEL_PATH)
with open(TOKENIZER_PATH, 'rb') as handle:
    tokenizer = pickle.load(handle)

app = FastAPI()
class RequestData(BaseModel):
    payload: str

@app.post("/predict")
async def predict(data: RequestData):
   
    sequence = tokenizer.texts_to_sequences([data.payload])
    padded_sequence = pad_sequences(sequence, maxlen=100)

    prediction = model.predict(padded_sequence)
    score = float(prediction[0][0])

    return {"sql_injection_score": score}