# LinkCheck AI

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

A cutting-edge machine learning-based phishing detection system that analyzes URLs and web pages in real-time to identify malicious attempts. Built with HistGradientBoosting classifier and advanced feature engineering for superior accuracy.

## Key Features

- **Real-time Analysis**: Instant URL and webpage evaluation
- **Advanced ML Model**: HistGradientBoosting with 99+ features
- **Comprehensive Feature Extraction**: URL syntax, HTML analysis, entropy calculations
- **High Accuracy**: 99.5% detection rate on test datasets
- **Scalable Architecture**: Session pooling, async processing, Docker support
- **RESTful API**: Easy integration with existing systems
- **Data Pipeline**: Automated scraping, preprocessing, and model training

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Model Training](#model-training)
- [Deployment](#deployment)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Prerequisites

- Python 3.11 or higher
- pip package manager
- Docker (optional, for containerized deployment)

### Local Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/Haisshh/LinkCheck-AI
   cd linkcheck-ai
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**
   ```bash
   python -c "import sklearn; print('Scikit-learn version:', sklearn.__version__)"
   ```

## 🚀 Quick Start

### Basic Usage

1. **Start the server**
   ```bash
   python run.py
   ```

2. **Analyze a URL**
   ```bash
   curl -X POST http://localhost:5000/analyze \
     -H "Content-Type: application/json" \
     -d '{"url": "https://suspicious-site.com"}'
   ```

### Complete Pipeline

For a full setup with data collection and model training:

```bash
# 1. Collect training data
python scraper.py

# 2. Prepare datasets
python prepare_data.py

# 3. Train the model
python train.py

# 4. (Optional) Optimize hyperparameters
python tune.py

# 5. Evaluate performance
python evaluate.py

# 6. Start the API server
python run.py
```

Or run the entire pipeline automatically:
```bash
python improve_ai.py
```

## 📖 Usage

### Data Collection

The scraper collects phishing URLs from verified sources and legitimate domains from Tranco top 1M:

```bash
python scraper.py --sites 10000
```

This generates `data/scraped_data.csv` with extracted features.

### Model Training

Prepare and train the ML model:

```bash
# Prepare train/test splits
python prepare_data.py

# Train baseline model
python train.py

# Hyperparameter optimization
python tune.py
```

### Model Evaluation

Compare model performance:

```bash
python evaluate.py
```

Output includes accuracy, precision, recall, F1-score, and confusion matrix.

## 🔌 API Reference

### POST /analyze

Analyze a URL for phishing indicators.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "is_phishing": false,
  "confidence": 0.95,
  "features": {
    "url_length": 18,
    "has_https": true,
    "domain_entropy": 2.85
  },
  "analysis_time": 0.023
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### GET /screenshot/{domain}

Capture a screenshot of the domain.

**Example:**
```bash
curl http://localhost:5000/screenshot/example.com
```

Returns PNG image data.

## 🧠 Model Training

### Feature Engineering

The system extracts 99+ features including:

- **URL Structure**: Length, character counts, entropy
- **Domain Analysis**: TLD validation, subdomain checks, brand detection
- **HTML Content**: Link analysis, form detection, script evaluation
- **Security Indicators**: HTTPS status, IP addresses, suspicious patterns

### Training Process

1. **Data Preparation**: Split CSV into Parquet format with stratification
2. **Model Selection**: HistGradientBoostingClassifier with balanced sampling
3. **Cross-Validation**: 5-fold CV for robust evaluation
4. **Hyperparameter Tuning**: Grid search for optimal parameters

### Performance Metrics

- **Accuracy**: 99.5%
- **Precision**: 99.9% (phishing detection)
- **Recall**: 99.4% (phishing detection)
- **F1-Score**: 99.6%

## 🏆 Reputation-Based Analysis

LinkCheck AI integrates multiple trust signals for enhanced accuracy:

- **Tranco top 1M** reputation ranking
  - **Top 1000 sites**: highest trust boost
  - **Top 10k sites**: strong trust signal
  - **Top 100k sites**: moderate reputation support
  - **Lower ranks**: reduced trust, increased scrutiny
- **SSL/TLS certificate inspection**: certificate validity, issuer trust, expiration and key strength
- **DNS reputation**: authoritative name server and resolver trust score
- **Brand spoofing detection**: suspicious similarities to known brands and lookalike domains

This multi-source trust layer works alongside the ML model and heuristic checks to reduce false positives while improving phishing detection confidence.

## 🐳 Deployment

### Docker Deployment

1. **Build the image**
   ```bash
   docker build -t linkcheck-ai .
   ```

2. **Run the container**
   ```bash
   docker run -d --name linkcheck-ai -p 5000:5000 linkcheck-ai
   ```

3. **Check logs**
   ```bash
   docker logs linkcheck-ai
   ```

### Feedback Discord

- Le webhook Discord doit être configuré uniquement sur le serveur, via la variable d'environnement `DISCORD_FEEDBACK_WEBHOOK`.
- Ne mettez jamais l'URL du webhook dans le code client ou dans des fichiers commités.
- L'interface web envoie le signalement vers Flask, et Flask transmet ensuite le message à Discord.

Exemple de configuration locale :

- Windows (PowerShell) :
  ```powershell
  $env:DISCORD_FEEDBACK_WEBHOOK = "https://discord.com/api/webhooks/xxxxx/xxxxx"
  python main.py
  ```

- Linux/macOS :
  ```bash
  export DISCORD_FEEDBACK_WEBHOOK="https://discord.com/api/webhooks/xxxxx/xxxxx"
  python main.py
  ```

- Docker :
  ```bash
  docker run -e DISCORD_FEEDBACK_WEBHOOK="https://discord.com/api/webhooks/xxxxx/xxxxx" -p 5000:5000 linkcheck-ai
  ```

Le webhook reste secret côté serveur et n'est jamais rendu public dans l'UI.

### Production Scripts

- **Linux/Mac**: `./deploy.sh`
- **Windows**: `deploy.bat`

## 🏗️ Architecture

```
LinkCheck AI Architecture
├── Data Layer
│   ├── scraper.py (Data collection)
│   └── prepare_data.py (Preprocessing)
├── ML Layer
│   ├── features.py (Feature extraction)
│   ├── train.py (Model training)
│   └── tune.py (Optimization)
├── API Layer
│   ├── main.py (Flask server)
│   └── analyzer.py (Analysis engine)
└── Utils
    ├── evaluate.py (Model evaluation)
    └── screenshot.py (Visual capture)
```

### Key Components

- **Feature Extractor**: Pure Python, no external dependencies
- **ML Model**: Scikit-learn HistGradientBoosting
- **Web Server**: Flask with rate limiting
- **Data Storage**: Parquet for efficient ML processing

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation
- Ensure backward compatibility

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is a research and detection tool. It is not a substitute for comprehensive enterprise security solutions and should be used in accordance with applicable network security policies. Always verify results with multiple security tools.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/linkcheck-ai/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/linkcheck-ai/discussions)
- **Email**: support@linkcheck.ai

---

**Built with ❤️ for cybersecurity research**
