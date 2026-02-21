Sentinel-AI is an end-to-end security solution that captures live network traffic, processes it into machine-learning-ready features, and uses a Random Forest Classifier to detect malicious activity (such as Nmap scans) in real-time.

This project was developed to demonstrate the integration of Cybersecurity Forensics and Supervised Machine Learning.
##  Technical Stack

    Operating System: Kali Linux 2026 (VirtualBox environment)

    Language: Python 3.10+

    Libraries: * Scapy: For low-level packet sniffing and dissection.

        Pandas: For data structuring and CSV engineering.

        Scikit-Learn: For training the Random Forest model.

        Colorama: For real-time terminal alerts.

##  How It Works

    Data Ingestion (sentinal.py): Uses Scapy to sniff raw packets and extract features like src_port, dst_port, protocol, and payload_size.

    Model Training (train_ai.py): Processes the captured CSV data. It uses an 80/20 train-test split to train a Random Forest model, achieving 100% accuracy 
    in detecting synthetic scan patterns.

    Live Defense (live_defender.py): A real-time monitoring script that applies the trained model to live traffic, triggering visual alerts upon detecting anomalies.

##  Performance & Results

    Detection Accuracy: 100% (Lab Environment)

    Detected Threats: TCP Connect Scans, Port Discovery, and Anomalous Payload sizes.

    Alert System: Integrated color-coded terminal outputs for immediate incident response.

##  Setup & Installation
## 👤 Author

    Name: [Manish Kumar]

    Background: M.Sc. IT | Certified Ethical Hacker (CEH) | Specialized in GovTech & AI Security.
