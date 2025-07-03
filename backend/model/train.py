# backend/model/train.py

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import joblib
import os
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt  # type: ignore
import seaborn as sns  # type: ignore

# Create model directory if it doesn't exist
os.makedirs("model", exist_ok=True)

# Custom dataset class
class PhishingDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.long)
    
    def __len__(self):
        return len(self.y)
    
    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]

# Enhanced model architecture
class PhishingNet(nn.Module):
    def __init__(self, input_dim):
        super(PhishingNet, self).__init__()
        self.fc1 = nn.Linear(input_dim, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 32)
        self.fc4 = nn.Linear(32, 2)
        self.dropout = nn.Dropout(0.4)
        self.relu = nn.ReLU()
        self.batch_norm1 = nn.BatchNorm1d(128)
        self.batch_norm2 = nn.BatchNorm1d(64)
        self.batch_norm3 = nn.BatchNorm1d(32)

    def forward(self, x):
        x = self.relu(self.batch_norm1(self.fc1(x)))
        x = self.dropout(x)
        x = self.relu(self.batch_norm2(self.fc2(x)))
        x = self.dropout(x)
        x = self.relu(self.batch_norm3(self.fc3(x)))
        x = self.dropout(x)
        x = self.fc4(x)
        return x

def train_model(model, train_loader, val_loader, criterion, optimizer, num_epochs=100):
    best_val_acc = 0
    best_model_state = None
    train_losses = []
    val_losses = []
    
    for epoch in range(num_epochs):
        # Training phase
        model.train()
        train_loss = 0
        correct = 0
        total = 0
        
        for inputs, labels in train_loader:
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            _, predicted = outputs.max(1)
            total += labels.size(0)
            correct += predicted.eq(labels).sum().item()
        
        train_loss = train_loss / len(train_loader)
        train_acc = 100. * correct / total
        train_losses.append(train_loss)
        
        # Validation phase
        model.eval()
        val_loss = 0
        correct = 0
        total = 0
        
        with torch.no_grad():
            for inputs, labels in val_loader:
                outputs = model(inputs)
                loss = criterion(outputs, labels)
                
                val_loss += loss.item()
                _, predicted = outputs.max(1)
                total += labels.size(0)
                correct += predicted.eq(labels).sum().item()
        
        val_loss = val_loss / len(val_loader)
        val_acc = 100. * correct / total
        val_losses.append(val_loss)
        
        # Save best model
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            best_model_state = model.state_dict()
        
        if (epoch + 1) % 10 == 0:
            print(f'Epoch [{epoch+1}/{num_epochs}]')
            print(f'Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.2f}%')
            print(f'Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.2f}%')
    
    return best_model_state, train_losses, val_losses

# Load and preprocess data
print("Loading dataset...")
if os.path.exists("E:/New folder/phishguard-ai/backend/data/phishing_dataset.csv"):
    df = pd.read_csv("E:/New folder/phishguard-ai/backend/data/phishing_dataset.csv")
else:
    raise FileNotFoundError("The file 'phishing_dataset.csv' does not exist.")

print(f"Dataset shape: {df.shape}")

# Prepare features and target
feature_columns = [col for col in df.columns if col not in ['Index', 'class']]
X = df[feature_columns].values
y = df['class'].values

# Convert labels: -1 -> 0 (legitimate), 1 -> 1 (phishing)
y = np.where(y == -1, 0, y)

# Split data into train, validation, and test sets
X_temp, X_test, y_temp, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
X_train, X_val, y_train, y_val = train_test_split(X_temp, y_temp, test_size=0.2, random_state=42)

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)

# Create data loaders
train_dataset = PhishingDataset(X_train_scaled, y_train)
val_dataset = PhishingDataset(X_val_scaled, y_val)
test_dataset = PhishingDataset(X_test_scaled, y_test)

train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=32)
test_loader = DataLoader(test_dataset, batch_size=32)

# Initialize model and training components
print("Initializing model...")
input_dim = X_train_scaled.shape[1]
model = PhishingNet(input_dim)
criterion = nn.CrossEntropyLoss()
optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-5)

# Train model
print("Starting training...")
best_model_state, train_losses, val_losses = train_model(
    model, train_loader, val_loader, criterion, optimizer, num_epochs=100
)

# Load best model state
model.load_state_dict(best_model_state)

# Evaluate on test set
print("\nEvaluating on test set...")
model.eval()
test_predictions = []
test_labels = []

with torch.no_grad():
    for inputs, labels in test_loader:
        outputs = model(inputs)
        _, predicted = outputs.max(1)
        test_predictions.extend(predicted.numpy())
        test_labels.extend(labels.numpy())

# Print classification report
print("\nClassification Report:")
print(classification_report(test_labels, test_predictions, target_names=['Legitimate', 'Phishing']))

# Save model and components
print("\nSaving model and components...")
torch.save(model.state_dict(), "model/phishing_model.pt")
joblib.dump(scaler, "model/scaler.pkl")
joblib.dump(feature_columns, "model/feature_columns.pkl")

print("Training complete! Model and components saved successfully.")
