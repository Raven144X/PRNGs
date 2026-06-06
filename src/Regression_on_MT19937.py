# Regression Approach
# Final Test MSE: 0.083512 (Theoretical Random Baseline: 0.083333)

import random
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout

# 1. GENERATE NATIVE MT19937 FLOATS
N_SAMPLES = 50000
WINDOW_SIZE = 50

random.seed(42)
# random.random() returns uniform floats in [0.0, 1.0) directly from the Twister
raw_floats = [random.random() for _ in range(N_SAMPLES)]
data = np.array(raw_floats, dtype=np.float32)

# 2. CREATE SLIDING WINDOWS FOR REGRESSION
X, y = [], []
for i in range(len(data) - WINDOW_SIZE):
    X.append(data[i : i + WINDOW_SIZE])
    y.append(data[i + WINDOW_SIZE])

X, y = np.array(X), np.array(y)
X = np.reshape(X, (X.shape[0], X.shape[1], 1))

split = int(len(X) * 0.8)
X_train, X_test = X[:split], X[split:]
y_train, y_test = y[:split], y[split:]

# 3. CONSTRUCT THE REGRESSION MODEL
model = Sequential([
    LSTM(64, input_shape=(WINDOW_SIZE, 1), return_sequences=False),
    Dropout(0.2),
    Dense(1) # Linear output layer
])

model.compile(optimizer='adam', loss='mean_squared_error')

print("\nTraining LSTM on Raw Mersenne Twister Trajectories...")
model.fit(X_train, y_train, epochs=3, batch_size=64, validation_data=(X_test, y_test))

final_mse = model.evaluate(X_test, y_test, verbose=0)
print(f"\nFinal Test MSE: {final_mse:.6f} (Theoretical Random Baseline: 0.083333)")