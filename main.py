from flask import Flask, request, jsonify
import joblib
import pandas as pd
import logging
WHITELISTED_IPS = {"54.255.64.173"}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler("api_log.log"),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)

# Load model
model_path = "syn_flood_model.joblib"
model = joblib.load(model_path)
logging.info("Model loaded.")

# Fitur yang dibutuhkan oleh model
required_features = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Flow Bytes/s', 'Flow Packets/s',
    'SYN Flag Count', 'ACK Flag Count', 'RST Flag Count',
    'Fwd Packets/s', 'Bwd Packets/s',
    'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
    'Avg Packet Size', 'Down/Up Ratio'
]

# Mapping dari nama JSON ke nama feature model
feature_mapping = {
    'flow_duration': 'Flow Duration',
    'tot_fwd_pkts': 'Total Fwd Packets',
    'tot_bwd_pkts': 'Total Backward Packets',
    'flow_byts_s': 'Flow Bytes/s',
    'flow_pkts_s': 'Flow Packets/s',
    'syn_flag_cnt': 'SYN Flag Count',
    'ack_flag_cnt': 'ACK Flag Count',
    'rst_flag_cnt': 'RST Flag Count',
    'fwd_pkts_s': 'Fwd Packets/s',
    'bwd_pkts_s': 'Bwd Packets/s',
    'fwd_pkt_len_mean': 'Fwd Packet Length Mean',
    'bwd_pkt_len_mean': 'Bwd Packet Length Mean',
    'pkt_size_avg': 'Avg Packet Size',
    'down_up_ratio': 'Down/Up Ratio'
}

@app.route('/predict', methods=['POST'])
def predict():
    try:
        json_data = request.get_json()
        logging.info(f"Incoming data: {json_data}")

        # Cek port 22 untuk pengecualian manual
        # dst_port = int(json_data.get("dst_port", -1))
        # if dst_port == 22:
        #     logging.info("Port 22 detected — returning Benign without prediction.")
        #     return jsonify({"ip":[json_data.get("dst_ip"), json_data.get("src_ip")],"prediction": 0, "label": "Benign (SSH)"})

        ip_src = json_data.get("src_ip", "")
        ip_dst = json_data.get("dst_ip", "")

        # Jika IP TIDAK dalam whitelist, maka pengecekan port berlaku
        if ip_src in WHITELISTED_IPS or ip_dst in WHITELISTED_IPS:
            logging.info("Whitelisted IP detected — skipping prediction, marked as Benign.")
            return jsonify({
                "ip": [ip_dst, ip_src],
                "prediction": 0,
                "label": "Benign (Whitelisted IP)"
            })
        dst_port = int(json_data.get("dst_port", -1))
        if dst_port in (22, 3000):
            logging.info(f"Ignored port {dst_port} detected — returning Benign.")
            return jsonify({
                "ip": [ip_dst, ip_src],
                "prediction": 0,
                "label": "Benign (Ignored Port)"
            })
        # Ekstrak fitur yang dibutuhkan
        extracted = {}
        for json_key, model_key in feature_mapping.items():
            if json_key not in json_data:
                return jsonify({"error": f"Missing feature: {json_key}"}), 400
            extracted[model_key] = json_data[json_key]

        # Buat dataframe 1 baris
        df = pd.DataFrame([extracted])
        prediction = model.predict(df)[0]
        label = "Benign" if prediction == 0 else "Syn Attack"

        logging.info(f"Prediction result: {label} ({prediction})")
        return jsonify({"ip":[json_data.get("dst_ip"), json_data.get("src_ip")],"prediction": int(prediction), "label": label})

    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    logging.info("API running at http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000)
