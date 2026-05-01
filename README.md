# LinkCheck AI: Supervised Learning Phishing Detection System

## Project Overview
LinkCheck AI is a specialized threat analysis solution designed to identify phishing attempts through machine learning. Unlike traditional blacklisting methods, this system utilizes a **HistGradientBoosting** classification model to evaluate the risk level of a domain in real-time.

The engine extracts over 50 structural and semantic features from both the URL syntax and the HTML source code of the target page to determine its legitimacy.

## Technical Architecture
The project is built on a cumulative learning cycle, allowing the model's accuracy to improve as it encounters new threats.

* **Feature Extraction**: Analyzes URL syntax (length, special characters, security tokens), domain structure, and page content (external links, suspicious forms, redirection patterns).
* **Learning Engine**: Implements a HistGradientBoosting classifier via Scikit-Learn to handle multidimensional security data.
* **Data Persistence**: Feature vectors are stored in a local CSV database (`scraped_data.csv`), enabling rapid retraining without redundant web scraping.
* **Performance**: Optimized with session pooling, caching, and async operations for high throughput.

## Installation & Setup

### Prerequisites
* Python 3.11 or higher
* Docker (for deployment)

### Local Development
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Train the model: `python train.py`
4. Run the server: `python run.py`

### Production Deployment
1. Ensure Docker is installed
2. Run the deployment script:
   - Linux/Mac: `./deploy.sh`
   - Windows: `deploy.bat`

   Or manually:
   ```bash
   docker build -t linkcheck-ai .
   docker run -d --name linkcheck-ai -p 5000:5000 linkcheck-ai
   ```

3. Access the API at `http://localhost:5000`

## API Usage

### Analyze URL
```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Get Screenshot
```bash
curl http://localhost:5000/screenshot/example.com
```

## Repository Structure
* **main.py**: Flask web server with rate limiting
* **analyzer.py**: Core analysis engine with ML and heuristics
* **features.py**: Feature extraction module
* **train.py**: Model training script
* **scraper.py**: Data collection tool
* **screenshot.py**: Async screenshot capture
* **Dockerfile**: Container configuration
* **requirements.txt**: Python dependencies

## Performance Optimizations
- HTTP session pooling for efficient requests
- LRU caching for feature extraction
- Async screenshot processing
- Parallel data scraping
- Optimized ML model with cross-validation

## Disclaimer
This software is a research and detection tool. It is not a substitute for a full enterprise security suite and should be used in accordance with applicable network security policies.
