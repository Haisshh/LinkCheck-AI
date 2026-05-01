# LinkCheck AI: Supervised Learning Phishing Detection System

## Project Overview
LinkCheck AI is a specialized threat analysis solution designed to identify phishing attempts through machine learning. Unlike traditional blacklisting methods, this system utilizes a **Random Forest** classification model to evaluate the risk level of a domain in real-time. 

The engine extracts over 50 structural and semantic features from both the URL syntax and the HTML source code of the target page to determine its legitimacy.

## Technical Architecture
The project is built on a cumulative learning cycle, allowing the model's accuracy to improve as it encounters new threats.

* **Feature Extraction**: Analyzes URL syntax (length, special characters, security tokens), domain structure, and page content (external links, suspicious forms, redirection patterns).
* **Learning Engine**: Implements a Random Forest classifier via Scikit-Learn to handle multidimensional security data.
* **Data Persistence**: Feature vectors are stored in a local CSV database (`memoire_ia.csv`), enabling rapid retraining without redundant web scraping.

## Installation & Setup

### Prerequisites
* Python 3.8 or higher
* Pip (Python package manager)

### Dependency Installation
The project requires several libraries for data processing and network analysis. Install them using the provided requirements file:

    pip install -r requirements.txt

## Usage: Training the Model
To train the model on new datasets, place your ZIP archives (containing phishing and legitimate sources) into the data/ directory, then execute the training script:

    python train.py
The script performs the following operations:

* **Memory Loading**: Loads existing training data from the local database.

* **Selective Extraction**: Scans new URLs from raw data sources.

* **Data Fusion**: Merges new features with existing memory while removing duplicates.

* **Model Generation**: Exports a serialized model.pkl file ready for production analysis.

## Repository Structure
* **features.py**: Core module containing the feature extraction algorithms.

* **train.py**: Automation script for model training and memory management.

* **requirements.txt**: Comprehensive list of software dependencies.

* **.gitignore**: Configuration to prevent indexing of large data files and local environments.

## Disclaimer
This software is a research and detection tool. It is not a substitute for a full enterprise security suite and should be used in accordance with applicable network security policies.
