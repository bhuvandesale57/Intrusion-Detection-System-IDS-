import subprocess
import time
from flask import Flask, render_template, request, jsonify
import pickle
import numpy as np
import pandas as pd
from collections import deque
import tensorflow as tf
from tensorflow.keras.layers import Normalization # type: ignore
import tensorflow as tf
from tensorflow.keras.layers import Input, Dense, LSTM, Softmax, Layer, Concatenate # type: ignore
from tensorflow.keras.models import Model # type: ignore
from tensorflow.keras.optimizers import Adam # type: ignore
from tensorflow.keras import initializers # type: ignore
import tensorflow.keras.backend as K # type: ignore
import os
import time
from scapy.all import sniff, IP, TCP, UDP, ARP
import requests
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

app = Flask(__name__)

predictions_history = []
class MultiHeadAttentionLayer(Layer):
    def __init__(self, features, num_heads, **kwargs):
        super(MultiHeadAttentionLayer, self).__init__(**kwargs)
        assert features % num_heads == 0, "features must be divisible by num_heads"
        self.features = features
        self.num_heads = num_heads
        self.depth = features // num_heads

        self.query_dense = Dense(features, kernel_initializer=initializers.GlorotUniform(), activation=None)
        self.key_dense = Dense(features, kernel_initializer=initializers.GlorotUniform(), activation=None)
        self.value_dense = Dense(features, kernel_initializer=initializers.GlorotUniform(), activation=None)

        self.output_dense = Dense(features, kernel_initializer=initializers.GlorotUniform(), activation=None)
        self.softmax = Softmax(axis=-1)

    def split_heads(self, x, batch_size):
        x = K.reshape(x, (batch_size, -1, self.num_heads, self.depth))
        return K.permute_dimensions(x, (0, 2, 1, 3))  # (batch_size, num_heads, seq_len, depth)

    def call(self, inputs):
        query, key, value = inputs  # Assuming inputs is a list of [query, key, value]
        batch_size = K.shape(query)[0]

        query = self.query_dense(query)
        key = self.key_dense(key)
        value = self.value_dense(value)

        # Split heads
        query = self.split_heads(query, batch_size)
        key = self.split_heads(key, batch_size)
        value = self.split_heads(value, batch_size)

        # Scaled dot-product attention using tf.einsum
        scores = tf.einsum('bhqd,bhkd->bhqk', query, key)
        scores = scores / K.sqrt(K.cast(self.depth, dtype=K.floatx()))
        attention_weights = self.softmax(scores)

        # Compute weighted sum of values
        attention_output = K.batch_dot(attention_weights, value, axes=[3, 2])

        # Reshape to original shape before applying final dense layer
        attention_output = K.reshape(attention_output, (batch_size, -1, self.features))

        # Final output projection
        return self.output_dense(attention_output)

    def get_config(self):
        config = super().get_config().copy()
        config.update({
            'features': self.features,
            'num_heads': self.num_heads
        })
        return config
    
custom_objects = {'MultiHeadAttentionLayer': MultiHeadAttentionLayer}

Attention_lstm_model = tf.keras.models.load_model('attention_model_1.h5',custom_objects=custom_objects)

packet_window = deque(maxlen=10)

def extract_features(packet_data):

    features = {
        'Rate': packet_data.get('Rate'),
        'Source_Bytes': packet_data.get('Source_Bytes'),
        'Duration': packet_data.get('Duration'),
        'Destination_Bytes': packet_data.get('Destination_Bytes'),
        'Destination_Packets': packet_data.get('Destination_Packets'),
        'Total_Packets': packet_data.get('Total_Packets'),
        'Source_Packets': packet_data.get('Source_Packets'),
        'State_CON': packet_data.get('State_CON'),
        'Protocol_udp': packet_data.get('Protocol_udp'),
        'Protocol_arp': packet_data.get('Protocol_arp'),
        'State_INT': packet_data.get('State_INT'),
        'Protocol_tcp': packet_data.get('Protocol_tcp'),
        'State_FIN': packet_data.get('State_FIN'),
        'State_RST': packet_data.get('State_RST'),
        'State_REQ': packet_data.get('State_REQ')
    }
    return features

def preprocess_window(window):
    df = pd.DataFrame(window)
    
    normalizer = Normalization(axis=-1)
    normalizer.adapt(np.array(df))
    normalized_array = normalizer(np.array(df))
    
    df_normalized = pd.DataFrame(normalized_array.numpy(), columns=df.columns)
    
    return df_normalized

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    global latest_prediction
    data = request.get_json(force=True)
    raw_features = extract_features(data)
    packet_window.append(raw_features)
    # Only make a prediction if we have 10 packets
    if len(packet_window) < 10:
        return jsonify({"message": "Collecting packets, waiting for 10 packets."})
    raw_window = list(packet_window)
    preprocessed_window = preprocess_window(raw_window)
    sequence = preprocessed_window.values.reshape(1, 10, -1)
    prediction = Attention_lstm_model.predict(sequence)
    source_ip = data.get('source_ip', 'N/A')
    destination_ip = data.get('destination_ip', 'N/A')
    protocol = data.get('protocol', 'N/A')
    result = {
        "prediction": prediction.tolist(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    predictions_history.append(result)
    return jsonify(result)

@app.route('/predictions', methods=['GET'])
def get_predictions():
    return jsonify(predictions_history)


if __name__ == '__main__':
    # subprocess.Popen(["python", "sniffer.py"])
    # # Optional: wait a moment for the client to start up
    # time.sleep(2)
    app.run(debug=True)
 
