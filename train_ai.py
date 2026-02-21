import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# 1. Load your captured data
df = pd.read_csv("network_data.csv")

# 2. Logic to Label Data (In 2026, we call this 'Feature Labeling')
# Real scans often hit many different ports rapidly.
df['is_attack'] = [1 if (x > 1024 or y > 100) else 0 for x, y in zip(df['dst_port'], df['payload_size'])]

X = df[['src_port', 'dst_port', 'payload_size', 'protocol']]
y = df['is_attack']

# 3. Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)

# 4. Train the AI
clf = RandomForestClassifier(n_estimators=100)
clf.fit(X_train, y_train)

# 5. Review the results
predictions = clf.predict(X_test)
print(classification_report(y_test, predictions))