
# 🛡️ PhishGuard AI

<div align="center">

### AI-Powered Phishing URL Detection System

Detect suspicious URLs using Machine Learning and receive explainable security insights through a modern web interface.

<br>

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-000000?style=for-the-badge&logo=next.js&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)

</div>

---

## 📖 Overview

PhishGuard AI is a machine learning-powered phishing URL detection platform designed to identify potentially malicious links before users interact with them.

The application combines machine learning, URL feature extraction, and modern web technologies to provide:

- 🔍 URL Security Analysis
- 🧠 AI-Powered Threat Detection
- 📊 Explainable Risk Assessment
- ⚡ Fast REST API
- 🎨 Responsive Modern UI

Rather than simply classifying URLs as safe or unsafe, PhishGuard AI provides a detailed breakdown of risk indicators, security scores, and detected threats.

---

## ✨ Features

### 🧠 AI-Based Detection

- PyTorch Neural Network Model
- Real-Time URL Classification
- Trained on Phishing Detection Dataset
- Security-Focused Feature Engineering

### 🔍 URL Security Analysis

Analyzes:

- URL Structure
- Domain Characteristics
- SSL Presence
- Suspicious Keywords
- URL Length
- Domain Information
- Security Indicators

### 📊 Explainable Results

Returns:

- Risk Level
- Security Score
- Classification Result
- Security Warnings
- Threat Indicators

### 🚀 Modern User Experience

- Responsive Design
- Real-Time Analysis
- Toast Notifications
- Detailed Reports
- Clean Dashboard Interface

### 🔒 API Protection

- Request Validation
- Rate Limiting
- Structured Error Handling

---

## 🏗️ Architecture

```mermaid
flowchart LR

    User --> Frontend
    Frontend --> API
    API --> Backend
    Backend --> FeatureExtraction
    FeatureExtraction --> MLModel
    MLModel --> RiskAnalysis
    RiskAnalysis --> Frontend
````

### Workflow

1. User submits a URL.
2. Frontend sends the request to the backend.
3. Backend extracts security-related features.
4. PyTorch model performs classification.
5. Risk score and threat indicators are generated.
6. Results are displayed on the frontend.

---

## 📸 Screenshot

<div align="center">

![PhishGuard AI Screenshot](Screenshot.png)

</div>

---

## 🛠️ Tech Stack

### Backend

| Technology    | Purpose              |
| ------------- | -------------------- |
| FastAPI       | REST API Framework   |
| PyTorch       | Neural Network Model |
| scikit-learn  | Data Processing      |
| Pandas        | Dataset Handling     |
| Joblib        | Model Serialization  |
| tldextract    | URL Parsing          |
| Requests      | HTTP Requests        |
| BeautifulSoup | Content Analysis     |
| python-whois  | Domain Information   |

### Frontend

| Technology   | Purpose              |
| ------------ | -------------------- |
| Next.js      | React Framework      |
| TypeScript   | Type Safety          |
| Tailwind CSS | Styling              |
| Radix UI     | UI Components        |
| React        | Frontend Development |

---

## 📂 Project Structure

```text
PhishGuard-AI
│
├── backend
│   ├── data
│   ├── model
│   ├── services
│   ├── utils
│   ├── main.py
│   └── requirements.txt
│
├── frontend
│   ├── app
│   ├── components
│   ├── lib
│   ├── public
│   └── package.json
│
├── Screenshot.png
└── README.md
```

---

## ⚙️ Installation

### Prerequisites

* Python 3.8+
* Node.js 18+
* npm
* Optional CUDA-enabled GPU

---

## 🔧 Backend Setup

```bash
cd backend

pip install -r requirements.txt

uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Backend URL:

```text
http://localhost:8000
```

---

## 🎨 Frontend Setup

```bash
cd frontend

npm install

npm run dev
```

Frontend URL:

```text
http://localhost:3000
```

---

## 🚀 Usage

1. Start Backend Server
2. Start Frontend Application
3. Open the frontend in your browser
4. Enter a URL for analysis
5. Click **Analyze**
6. View:

* Security Score
* Risk Level
* Classification Result
* Threat Indicators
* Security Warnings

---

## 🤖 Model Training

The machine learning model can be retrained using a custom dataset.

### Dataset Location

```text
backend/data/phishing_dataset.csv
```

### Train Model

```bash
python backend/model/train.py
```

Generated files:

```text
backend/model/model.pth
backend/model/scaler.pkl
```

---

## 📈 Future Improvements

Potential enhancements:

* Browser Extension
* Email Phishing Detection
* Threat Intelligence Integration
* Historical Scan Reports
* User Authentication
* Security Dashboard

---

## 🤝 Contributing

Contributions are welcome.

### Steps

```bash
# Fork Repository

# Create Branch
git checkout -b feature/new-feature

# Commit Changes
git commit -m "Add new feature"

# Push Changes
git push origin feature/new-feature
```

Create a Pull Request describing your changes.

---

## ⚠️ Disclaimer

PhishGuard AI is a machine learning–based phishing detection system.

While trained on phishing datasets and engineered to identify suspicious URLs, predictions may occasionally produce false positives or false negatives.

Users should always apply additional verification methods when evaluating potentially malicious websites.

---

<div align="center">

### 🛡️ Detect • Analyze • Protect

Built with FastAPI, PyTorch, Next.js, TypeScript, and Tailwind CSS.

⭐ If you found this project useful, consider giving it a star.

</div>
