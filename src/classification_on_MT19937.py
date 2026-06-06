## classification approach
# Final Test Accuracy on MT19937 Bitstream: 50.03%

import random
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout

# 1. GENERATE MERSENNE TWISTER BIT DATA
N_SAMPLES = 50000
WINDOW_SIZE = 50

# Seed the Mersenne Twister engine
random.seed(42)

lsb_bits = []
msb_bits = []

for _ in range(N_SAMPLES):
    # Get a 32-bit random integer from the Mersenne Twister
    num = random.getrandbits(32)

    # Extract Least Significant Bit (Bit 0)
    lsb_bits.append(num & 1)

    # Extract Most Significant Bit (Bit 31)
    msb_bits.append((num >> 31) & 1)

# CHANGE THIS LINE TO TEST EITHER: np.array(lsb_bits) OR np.array(msb_bits)
target_bit_stream = np.array(lsb_bits)

# 2. CREATE SLIDING WINDOWS
X, y = [], []
for i in range(len(target_bit_stream) - WINDOW_SIZE):
    X.append(target_bit_stream[i : i + WINDOW_SIZE])
    y.append(target_bit_stream[i + WINDOW_SIZE])

X, y = np.array(X), np.array(y)
X = np.reshape(X, (X.shape[0], X.shape[1], 1))

# Split into 80% Train, 20% Test
split = int(len(X) * 0.8)
X_train, X_test = X[:split], X[split:]
y_train, y_test = y[:split], y[split:]

# 3. CONSTRUCT THE BINARY CLASSIFICATION MODEL
model = Sequential([
    LSTM(64, input_shape=(WINDOW_SIZE, 1), return_sequences=False),
    Dropout(0.2),
    Dense(1, activation='sigmoid') # Binary probability output
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

print("Training LSTM on Mersenne Twister Bits...")
model.fit(X_train, y_train, epochs=3, batch_size=64, validation_data=(X_test, y_test))

# Evaluate baseline predictability
_, test_acc = model.evaluate(X_test, y_test, verbose=0)
print(f"\nFinal Test Accuracy on MT19937 Bitstream: {test_acc*100:.2f}%")


