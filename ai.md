# AI Recap

## Table of Contents

1. [AI Fundamentals](#ai-fundamentals)
   1. [Definition and History](#definition-and-history)
   2. [Types of AI](#types-of-ai)
   3. [AI vs ML vs DL](#ai-vs-ml-vs-dl)
   4. [Problem Types](#problem-types)
2. [Machine Learning](#machine-learning)
   1. [Data Preparation and Splitting](#data-preparation-and-splitting)
   2. [ML Workflow](#ml-workflow)
   3. [Supervised Learning](#supervised-learning)
      1. [Classification Algorithms](#classification-algorithms)
      2. [Regression Algorithms](#regression-algorithms)
   4. [Unsupervised Learning](#unsupervised-learning)
      1. [Clustering](#clustering)
      2. [Dimensionality Reduction](#dimensionality-reduction)
   5. [Reinforcement Learning](#reinforcement-learning)
   6. [Model Evaluation and Validation](#model-evaluation-and-validation)
   7. [Overfitting and Underfitting](#overfitting-and-underfitting)
   8. [Hyperparameter Tuning](#hyperparameter-tuning)
   9. [Feature Engineering](#feature-engineering)
3. [Deep Learning](#deep-learning)
   1. [Neural Network Fundamentals](#neural-network-fundamentals)
   2. [Activation Functions](#activation-functions)
   3. [Loss Functions](#loss-functions)
   4. [Optimization Algorithms](#optimization-algorithms)
   5. [CNN (Convolutional Neural Networks)](#cnn-convolutional-neural-networks)
   6. [RNN (Recurrent Neural Networks)](#rnn-recurrent-neural-networks)
   7. [Transformer Architecture](#transformer-architecture)
   8. [GANs (Generative Adversarial Networks)](#gans-generative-adversarial-networks)
4. [Natural Language Processing](#natural-language-processing)
   1. [Text Preprocessing](#text-preprocessing)
   2. [Language Models](#language-models)
   3. [Named Entity Recognition](#named-entity-recognition)
   4. [Sentiment Analysis](#sentiment-analysis)
   5. [Machine Translation](#machine-translation)
   6. [Large Language Models](#large-language-models)
5. [Computer Vision](#computer-vision)
   1. [Image Processing](#image-processing)
   2. [Object Detection](#object-detection)
   3. [Face Recognition](#face-recognition)
   4. [Optical Character Recognition](#optical-character-recognition)
   5. [Medical Imaging](#medical-imaging)
6. [AI Ethics and Safety](#ai-ethics-and-safety)
   1. [Bias and Fairness](#bias-and-fairness)
   2. [Privacy Concerns](#privacy-concerns)
   3. [Explainable AI](#explainable-ai)
   4. [AI Alignment](#ai-alignment)
   5. [Adversarial Attacks](#adversarial-attacks)
7. [AI Tools and Frameworks](#ai-tools-and-frameworks)
   1. [Python Libraries](#python-libraries)
   2. [Cloud Platforms](#cloud-platforms)
   3. [Development Environments](#development-environments)
   4. [Model Deployment](#model-deployment)
8. [Data Science](#data-science)
   1. [Data Collection](#data-collection)
   2. [Data Cleaning](#data-cleaning)
   3. [Exploratory Data Analysis](#exploratory-data-analysis)
   4. [Statistical Methods](#statistical-methods)
9. [AI Applications](#ai-applications)
   1. [Healthcare](#healthcare)
   2. [Finance](#finance)
   3. [Autonomous Vehicles](#autonomous-vehicles)
   4. [Recommendation Systems](#recommendation-systems)
   5. [Chatbots and Virtual Assistants](#chatbots-and-virtual-assistants)
10. [Emerging Trends](#emerging-trends)
    1. [Quantum Machine Learning](#quantum-machine-learning)
    2. [Federated Learning](#federated-learning)
    3. [AutoML](#automl)
    4. [AI Hardware](#ai-hardware)

---

## AI Fundamentals

### Definition and History

**Artificial Intelligence (AI)** is the simulation of human intelligence in machines that are programmed to think and learn like humans. The field encompasses various approaches to creating intelligent systems.

**Key Historical Milestones:**
- **1950**: Alan Turing proposes the Turing Test
- **1956**: Dartmouth Conference - AI term coined
- **1997**: IBM Deep Blue defeats chess champion Garry Kasparov
- **2012**: AlexNet wins ImageNet competition
- **2016**: AlphaGo defeats Go champion Lee Sedol
- **2017**: Transformer architecture introduced
- **2022**: ChatGPT released, popularizing conversational AI

### Types of AI

1. **Narrow AI (Weak AI)**
   - Designed for specific tasks
   - Examples: Siri, recommendation systems, chess engines

2. **General AI (Strong AI)**
   - Human-level intelligence across all domains
   - Currently theoretical

3. **Artificial Superintelligence (ASI)**
   - Surpasses human intelligence
   - Future concept with significant implications

### AI vs ML vs DL

```
AI (Artificial Intelligence)
├── ML (Machine Learning)
    ├── DL (Deep Learning)
    └── Traditional ML
```

- **AI**: Broad field of creating intelligent machines
- **ML**: Subset of AI using algorithms to learn from data
- **DL**: Subset of ML using neural networks with multiple layers

### Problem Types

1. **Classification**: Categorizing data into discrete classes
2. **Regression**: Predicting continuous numerical values
3. **Clustering**: Grouping similar data points
4. **Reinforcement**: Learning through interaction with environment

---

## Machine Learning

### Data Preparation and Splitting

**Data Splitting Fundamentals**
```python
from sklearn.model_selection import train_test_split

# Basic train-test split (80-20)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Train-validation-test split (60-20-20)
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.4, random_state=42, stratify=y
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.5, random_state=42, stratify=y
)
```

**Split Types:**
- **Training Set (60-80%)**: Model learns patterns
- **Validation Set (10-20%)**: Hyperparameter tuning, model selection
- **Test Set (10-20%)**: Final unbiased evaluation

**Key Considerations:**
- **Stratification**: Maintain class distribution across splits
- **Random State**: Reproducible splits
- **Time Series**: Use temporal splits (no shuffling)
- **Data Leakage**: Ensure no future information in training

### ML Workflow

**Complete Training Pipeline:**
```python
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# 1. Data Preprocessing
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)

# 2. Model Selection with Hyperparameter Tuning
param_grid = {
    'n_estimators': [100, 200, 300],
    'max_depth': [3, 5, 7, None],
    'min_samples_split': [2, 5, 10]
}

model = RandomForestClassifier(random_state=42)
grid_search = GridSearchCV(
    model, param_grid, cv=5, scoring='f1_weighted'
)

# 3. Training
grid_search.fit(X_train_scaled, y_train)
best_model = grid_search.best_estimator_

# 4. Validation
val_predictions = best_model.predict(X_val_scaled)
print("Validation Results:")
print(classification_report(y_val, val_predictions))

# 5. Final Evaluation
test_predictions = best_model.predict(X_test_scaled)
print("Test Results:")
print(classification_report(y_test, test_predictions))
```

### Supervised Learning

Learning from labeled training data to make predictions on new, unseen data.

#### Classification Algorithms

**Logistic Regression**
```python
from sklearn.linear_model import LogisticRegression
model = LogisticRegression()
model.fit(X_train, y_train)
predictions = model.predict(X_test)
```

**Decision Trees**
- Easy to interpret
- Handles both numerical and categorical features
- Prone to overfitting

**Random Forest**
- Ensemble of decision trees
- Reduces overfitting
- Feature importance ranking

**Support Vector Machines (SVM)**
- Effective for high-dimensional data
- Kernel trick for non-linear classification
- Memory efficient

**k-Nearest Neighbors (k-NN)**
- Instance-based learning
- No training phase
- Sensitive to feature scaling

#### Regression Algorithms

**Linear Regression**
```python
from sklearn.linear_model import LinearRegression
model = LinearRegression()
model.fit(X_train, y_train)
y_pred = model.predict(X_test)
```

**Polynomial Regression**
- Captures non-linear relationships
- Risk of overfitting with high degrees

**Ridge Regression**
- L2 regularization
- Prevents overfitting

**Lasso Regression**
- L1 regularization
- Feature selection capability

### Unsupervised Learning

Learning patterns from unlabeled data.

#### Clustering

**K-Means**
```python
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3)
clusters = kmeans.fit_predict(X)
```

**Hierarchical Clustering**
- Creates tree of clusters
- No need to specify number of clusters upfront

**DBSCAN**
- Density-based clustering
- Handles noise and outliers

#### Dimensionality Reduction

**Principal Component Analysis (PCA)**
```python
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
X_reduced = pca.fit_transform(X)
```

**t-SNE**
- Non-linear dimensionality reduction
- Excellent for visualization

**UMAP**
- Preserves global structure better than t-SNE
- Faster than t-SNE

### Reinforcement Learning

Learning through interaction with environment using rewards and penalties.

**Key Components:**
- **Agent**: The learner/decision maker
- **Environment**: The world the agent interacts with
- **State**: Current situation of the agent
- **Action**: Choices available to the agent
- **Reward**: Feedback from environment

**Q-Learning**
```python
Q[state, action] = Q[state, action] + α * (reward + γ * max(Q[next_state]) - Q[state, action])
```

**Deep Q-Network (DQN)**
- Combines Q-learning with deep neural networks
- Used in game playing (Atari, Go)

### Model Evaluation and Validation

**Classification Metrics:**
```python
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score

# Basic metrics
accuracy = accuracy_score(y_true, y_pred)
precision = precision_score(y_true, y_pred, average='weighted')
recall = recall_score(y_true, y_pred, average='weighted')
f1 = f1_score(y_true, y_pred, average='weighted')

# Confusion Matrix
cm = confusion_matrix(y_true, y_pred)
print("Confusion Matrix:\n", cm)

# ROC-AUC for binary classification
auc = roc_auc_score(y_true, y_pred_proba[:, 1])
```

**Formulas:**
- **Accuracy**: (TP + TN) / (TP + TN + FP + FN)
- **Precision**: TP / (TP + FP)
- **Recall**: TP / (TP + FN)
- **F1-Score**: 2 * (Precision * Recall) / (Precision + Recall)

**Regression Metrics:**
```python
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
import numpy as np

mae = mean_absolute_error(y_true, y_pred)
mse = mean_squared_error(y_true, y_pred)
rmse = np.sqrt(mse)
r2 = r2_score(y_true, y_pred)

print(f"MAE: {mae:.4f}")
print(f"RMSE: {rmse:.4f}")
print(f"R²: {r2:.4f}")
```

**Cross-Validation Techniques**
```python
from sklearn.model_selection import cross_val_score, StratifiedKFold, TimeSeriesSplit

# K-Fold Cross-Validation
scores = cross_val_score(model, X, y, cv=5, scoring='f1_weighted')
print(f"CV Scores: {scores}")
print(f"Mean CV Score: {scores.mean():.4f} (+/- {scores.std() * 2:.4f})")

# Stratified K-Fold (maintains class distribution)
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
stratified_scores = cross_val_score(model, X, y, cv=skf, scoring='accuracy')

# Time Series Split (for temporal data)
tscv = TimeSeriesSplit(n_splits=5)
ts_scores = cross_val_score(model, X, y, cv=tscv, scoring='neg_mean_squared_error')
```

**Learning Curves**
```python
from sklearn.model_selection import learning_curve
import matplotlib.pyplot as plt

train_sizes, train_scores, val_scores = learning_curve(
    model, X, y, cv=5, n_jobs=-1,
    train_sizes=np.linspace(0.1, 1.0, 10)
)

plt.figure(figsize=(10, 6))
plt.plot(train_sizes, np.mean(train_scores, axis=1), 'o-', label='Training score')
plt.plot(train_sizes, np.mean(val_scores, axis=1), 'o-', label='Validation score')
plt.xlabel('Training Set Size')
plt.ylabel('Score')
plt.legend()
plt.title('Learning Curve')
plt.show()
```

### Overfitting and Underfitting

**Overfitting (High Variance)**
- Model memorizes training data
- Poor generalization to new data
- High training accuracy, low validation accuracy

**Underfitting (High Bias)**
- Model too simple to capture patterns
- Poor performance on both training and validation

**Detection:**
```python
# Compare training vs validation performance
train_score = model.score(X_train, y_train)
val_score = model.score(X_val, y_val)

if train_score - val_score > 0.1:
    print("Potential overfitting detected")
elif train_score < 0.7 and val_score < 0.7:
    print("Potential underfitting detected")
```

**Solutions for Overfitting:**
- More training data
- Regularization (L1/L2)
- Cross-validation
- Feature selection
- Early stopping
- Dropout (neural networks)

**Solutions for Underfitting:**
- More complex model
- Feature engineering
- Reduce regularization
- Increase training time

### Hyperparameter Tuning

**Grid Search**
```python
from sklearn.model_selection import GridSearchCV

param_grid = {
    'C': [0.1, 1, 10, 100],
    'gamma': [0.001, 0.01, 0.1, 1],
    'kernel': ['rbf', 'linear']
}

grid_search = GridSearchCV(
    SVM(), param_grid, cv=5,
    scoring='f1_weighted', n_jobs=-1
)

grid_search.fit(X_train, y_train)
print("Best parameters:", grid_search.best_params_)
print("Best score:", grid_search.best_score_)
```

**Random Search**
```python
from sklearn.model_selection import RandomizedSearchCV
from scipy.stats import uniform, randint

param_dist = {
    'n_estimators': randint(50, 500),
    'max_depth': randint(3, 20),
    'min_samples_split': randint(2, 20),
    'min_samples_leaf': randint(1, 10)
}

random_search = RandomizedSearchCV(
    RandomForestClassifier(), param_dist,
    n_iter=100, cv=5, random_state=42
)

random_search.fit(X_train, y_train)
```

**Bayesian Optimization**
```python
# Using scikit-optimize
from skopt import BayesSearchCV
from skopt.space import Real, Integer

search_spaces = {
    'learning_rate': Real(0.01, 1.0, 'log-uniform'),
    'max_depth': Integer(3, 10),
    'n_estimators': Integer(50, 500)
}

bayes_search = BayesSearchCV(
    XGBClassifier(), search_spaces, n_iter=50, cv=5
)

bayes_search.fit(X_train, y_train)
```

### Feature Engineering

**Techniques:**
- **Scaling**: StandardScaler, MinMaxScaler
- **Encoding**: One-hot encoding, label encoding
- **Feature Selection**: SelectKBest, RFE
- **Feature Creation**: Polynomial features, interaction terms

---

## Deep Learning

### Neural Network Fundamentals

**Perceptron**: Basic building block
```
y = activation(Σ(wi * xi) + bias)
```

**Multi-layer Perceptron (MLP)**
- Input layer, hidden layers, output layer
- Universal function approximator

**Backpropagation**
- Algorithm for training neural networks
- Computes gradients using chain rule

### Activation Functions

**ReLU (Rectified Linear Unit)**
```python
f(x) = max(0, x)
```
- Most popular activation function
- Solves vanishing gradient problem

**Sigmoid**
```python
f(x) = 1 / (1 + e^(-x))
```
- Output range: (0, 1)
- Used in output layer for binary classification

**Tanh**
```python
f(x) = (e^x - e^(-x)) / (e^x + e^(-x))
```
- Output range: (-1, 1)
- Zero-centered

**Softmax**
```python
f(xi) = e^xi / Σ(e^xj)
```
- Used in multi-class classification output layer

### Loss Functions

**Mean Squared Error (Regression)**
```python
loss = (1/n) * Σ(yi - ŷi)²
```

**Cross-Entropy (Classification)**
```python
loss = -Σ(yi * log(ŷi))
```

**Binary Cross-Entropy**
```python
loss = -(y * log(ŷ) + (1-y) * log(1-ŷ))
```

### Optimization Algorithms

**Gradient Descent**
```python
θ = θ - α * ∇J(θ)
```

**Adam**
- Adaptive learning rate
- Combines momentum and RMSprop
- Most popular optimizer

**SGD with Momentum**
- Accelerates convergence
- Reduces oscillations

### CNN (Convolutional Neural Networks)

**Components:**
- **Convolutional Layer**: Feature extraction using filters
- **Pooling Layer**: Downsampling (MaxPool, AvgPool)
- **Fully Connected Layer**: Classification

**Popular Architectures:**
- **LeNet**: Early CNN for digit recognition
- **AlexNet**: Breakthrough in image classification
- **VGG**: Very deep networks with small filters
- **ResNet**: Residual connections for very deep networks
- **EfficientNet**: Optimal scaling of depth, width, resolution

```python
import tensorflow as tf
model = tf.keras.Sequential([
    tf.keras.layers.Conv2D(32, (3, 3), activation='relu'),
    tf.keras.layers.MaxPooling2D((2, 2)),
    tf.keras.layers.Conv2D(64, (3, 3), activation='relu'),
    tf.keras.layers.Flatten(),
    tf.keras.layers.Dense(10, activation='softmax')
])
```

### RNN (Recurrent Neural Networks)
Recurrent networks for sequential data.

**Vanilla RNN**
- Processes sequential data
- Suffers from vanishing gradient problem

**LSTM (Long Short-Term Memory)**
- Solves vanishing gradient problem
- Gates: forget, input, output

**GRU (Gated Recurrent Unit)**
- Simplified version of LSTM
- Fewer parameters

**Applications:**
- Natural language processing
- Time series prediction
- Speech recognition

### Transformer Architecture

**Key Innovations:**
- **Self-Attention**: Parallel processing of sequences
- **Positional Encoding**: Maintains sequence order
- **Multi-Head Attention**: Multiple attention mechanisms

**Architecture:**
- Encoder-Decoder structure
- Skip connections
- Layer normalization

**Popular Models:**
- **BERT**: Bidirectional Encoder Representations
- **GPT**: Generative Pre-trained Transformer
- **T5**: Text-to-Text Transfer Transformer

### GANs (Generative Adversarial Networks)

**Components:**
- **Generator**: Creates fake data
- **Discriminator**: Distinguishes real from fake

**Training Process:**
```
min_G max_D V(D,G) = E[log D(x)] + E[log(1 - D(G(z)))]
```

**Variants:**
- **DCGAN**: Deep Convolutional GAN
- **StyleGAN**: High-quality image generation
- **CycleGAN**: Image-to-image translation

---

## Natural Language Processing

### Text Preprocessing

**Steps:**
1. **Tokenization**: Breaking text into words/tokens
2. **Lowercasing**: Converting to lowercase
3. **Stop Word Removal**: Removing common words
4. **Stemming/Lemmatization**: Reducing words to root form
5. **Vectorization**: Converting text to numbers

```python
import nltk
from sklearn.feature_extraction.text import TfidfVectorizer

# Tokenization
tokens = nltk.word_tokenize(text)

# TF-IDF Vectorization
vectorizer = TfidfVectorizer()
tfidf_matrix = vectorizer.fit_transform(documents)
```

### Language Models

**N-gram Models**
- Predicts next word based on previous n-1 words
- Limited context window

**Word Embeddings**
- **Word2Vec**: Skip-gram, CBOW
- **GloVe**: Global Vectors for Word Representation
- **FastText**: Subword information

**Contextualized Embeddings**
- **ELMo**: Embeddings from Language Models
- **BERT**: Bidirectional context
- **GPT**: Autoregressive language modeling

### Named Entity Recognition

**Task**: Identify and classify named entities in text
- **PERSON**: People names
- **ORGANIZATION**: Company, agency names
- **LOCATION**: Countries, cities, addresses
- **DATE**: Dates and times

```python
import spacy
nlp = spacy.load("en_core_web_sm")
doc = nlp("Apple Inc. was founded by Steve Jobs in Cupertino.")
for ent in doc.ents:
    print(ent.text, ent.label_)
```

### Sentiment Analysis

**Approaches:**
1. **Lexicon-based**: Using sentiment dictionaries
2. **Machine Learning**: Training classifiers
3. **Deep Learning**: Neural networks

**Example:**
```python
from textblob import TextBlob
blob = TextBlob("I love this product!")
sentiment = blob.sentiment.polarity  # -1 to 1
```

### Machine Translation

**Approaches:**
- **Statistical MT**: Phrase-based translation
- **Neural MT**: Encoder-decoder with attention
- **Transformer-based**: State-of-the-art approach

**Popular Services:**
- Google Translate
- Microsoft Translator
- DeepL

### Large Language Models

**Characteristics:**
- Billions of parameters
- Pre-trained on massive text corpora
- Fine-tuned for specific tasks

**Notable Models:**
- **GPT-3/4**: 175B+ parameters
- **PaLM**: 540B parameters
- **LaMDA**: Conversation-focused
- **Claude**: Constitutional AI approach

**Applications:**
- Text generation
- Question answering
- Code generation
- Creative writing

---

## Computer Vision

### Image Processing

**Basic Operations:**
- **Filtering**: Noise reduction, edge detection
- **Morphological Operations**: Erosion, dilation
- **Histogram Equalization**: Contrast enhancement
- **Color Space Conversion**: RGB, HSV, LAB

```python
import cv2
import numpy as np

# Load image
img = cv2.imread('image.jpg')

# Edge detection
edges = cv2.Canny(img, 100, 200)

# Gaussian blur
blurred = cv2.GaussianBlur(img, (15, 15), 0)
```

### Object Detection

**Approaches:**
1. **Traditional**: HOG + SVM, Haar Cascades
2. **Two-stage**: R-CNN, Fast R-CNN, Faster R-CNN
3. **Single-stage**: YOLO, SSD, RetinaNet

**YOLO (You Only Look Once)**
- Real-time object detection
- Single neural network
- Divides image into grid cells

**Evaluation Metrics:**
- **IoU (Intersection over Union)**: Overlap measure
- **mAP (mean Average Precision)**: Detection accuracy

### Face Recognition

**Steps:**
1. **Face Detection**: Locate faces in image
2. **Face Alignment**: Normalize face orientation
3. **Feature Extraction**: Create face embeddings
4. **Matching**: Compare embeddings

**Popular Libraries:**
- **OpenCV**: Traditional methods
- **dlib**: HOG + Linear SVM
- **FaceNet**: Deep learning approach

### Optical Character Recognition

**Process:**
1. **Image Preprocessing**: Noise removal, binarization
2. **Text Detection**: Locate text regions
3. **Character Segmentation**: Separate individual characters
4. **Character Recognition**: Classify characters

**Tools:**
- **Tesseract**: Open-source OCR engine
- **AWS Textract**: Cloud-based OCR
- **Google Cloud Vision**: Advanced OCR capabilities

### Medical Imaging

**Applications:**
- **X-ray Analysis**: Pneumonia detection, bone fractures
- **MRI/CT Scan**: Tumor detection, organ segmentation
- **Retinal Imaging**: Diabetic retinopathy detection
- **Pathology**: Cancer cell identification

**Challenges:**
- Limited training data
- High accuracy requirements
- Regulatory compliance
- Interpretability needs

---

## AI Ethics and Safety

### Bias and Fairness

**Types of Bias:**
- **Historical Bias**: Reflects past inequalities
- **Sampling Bias**: Unrepresentative training data
- **Algorithmic Bias**: Discriminatory model behavior

**Mitigation Strategies:**
- Diverse training data
- Bias testing and monitoring
- Fairness constraints in model training
- Regular audits

### Privacy Concerns

**Issues:**
- **Data Collection**: Consent and transparency
- **Re-identification**: Anonymized data risks
- **Inference Attacks**: Extracting sensitive information

**Solutions:**
- **Differential Privacy**: Mathematical privacy guarantee
- **Federated Learning**: Training without centralizing data
- **Homomorphic Encryption**: Computing on encrypted data

### Explainable AI

**Need for Explainability:**
- Regulatory compliance
- Trust and adoption
- Debugging and improvement
- Ethical decision making

**Techniques:**
- **LIME**: Local Interpretable Model-agnostic Explanations
- **SHAP**: SHapley Additive exPlanations
- **Attention Visualization**: For neural networks
- **Feature Importance**: For tree-based models

### AI Alignment

**Problem**: Ensuring AI systems pursue intended goals
**Challenges:**
- Goal specification
- Value learning
- Reward hacking
- Distributional shift

**Approaches:**
- Constitutional AI
- Human feedback training
- Value alignment research
- AI safety testing

### Adversarial Attacks

**Types:**
- **Evasion Attacks**: Fool model at test time
- **Poisoning Attacks**: Corrupt training data
- **Model Extraction**: Steal model parameters

**Defenses:**
- Adversarial training
- Input preprocessing
- Model ensemble
- Certified defenses

---

## AI Tools and Frameworks

### Python Libraries

**Machine Learning:**
- **scikit-learn**: General-purpose ML library
- **pandas**: Data manipulation and analysis
- **numpy**: Numerical computing
- **matplotlib/seaborn**: Data visualization

**Deep Learning:**
- **TensorFlow**: Google's ML platform
- **PyTorch**: Facebook's dynamic neural network library
- **Keras**: High-level neural network API
- **JAX**: NumPy-compatible ML library

**Natural Language Processing:**
- **NLTK**: Natural Language Toolkit
- **spaCy**: Industrial-strength NLP
- **transformers**: Pre-trained transformer models
- **gensim**: Topic modeling and document similarity

**Computer Vision:**
- **OpenCV**: Computer vision library
- **PIL/Pillow**: Image processing
- **albumentations**: Image augmentation
- **detectron2**: Object detection platform

### Cloud Platforms

**Amazon Web Services (AWS)**
- **SageMaker**: ML platform
- **EC2**: Compute instances
- **S3**: Data storage

**Google Cloud Platform (GCP)**
- **Vertex AI**: ML platform
- **Compute Engine**: Virtual machines
- **BigQuery**: Data warehouse

**Microsoft Azure**
- **Azure ML**: ML platform
- **Cognitive Services**: Pre-built AI APIs
- **Azure Databricks**: Analytics platform

### Development Environments

**Jupyter Notebook**
- Interactive computing
- Data exploration
- Prototyping

**Google Colab**
- Free GPU/TPU access
- Cloud-based notebooks
- Easy sharing

**VS Code**
- Python development
- Extensions for ML
- Debugging capabilities

### Model Deployment

**Containerization:**
- **Docker**: Container platform
- **Kubernetes**: Container orchestration

**Serving Platforms:**
- **TensorFlow Serving**: Model serving system
- **TorchServe**: PyTorch model serving
- **MLflow**: ML lifecycle management

**Edge Deployment:**
- **TensorFlow Lite**: Mobile/embedded deployment
- **ONNX**: Model interoperability
- **OpenVINO**: Intel's optimization toolkit

---

## Data Science

### Data Collection

**Sources:**
- **Databases**: SQL, NoSQL
- **APIs**: REST, GraphQL
- **Web Scraping**: BeautifulSoup, Scrapy
- **Files**: CSV, JSON, Parquet
- **Streaming**: Kafka, real-time data

**Considerations:**
- Data quality
- Legal and ethical issues
- Privacy compliance
- Cost and scalability

### Data Cleaning

**Common Issues:**
- Missing values
- Duplicate records
- Inconsistent formats
- Outliers

**Techniques:**
```python
import pandas as pd

# Handle missing values
df.fillna(method='forward')
df.dropna()

# Remove duplicates
df.drop_duplicates()

# Outlier detection
Q1 = df.quantile(0.25)
Q3 = df.quantile(0.75)
IQR = Q3 - Q1
outliers = df[((df < (Q1 - 1.5 * IQR)) | (df > (Q3 + 1.5 * IQR)))]
```

### Exploratory Data Analysis

**Objectives:**
- Understand data distribution
- Identify patterns and relationships
- Detect anomalies
- Generate hypotheses

**Techniques:**
- Summary statistics
- Data visualization
- Correlation analysis
- Hypothesis testing

```python
# Basic statistics
df.describe()

# Correlation matrix
import seaborn as sns
sns.heatmap(df.corr(), annot=True)

# Distribution plots
df.hist(bins=50, figsize=(20, 15))
```

### Statistical Methods

**Descriptive Statistics:**
- Mean, median, mode
- Standard deviation, variance
- Percentiles, quartiles

**Inferential Statistics:**
- Hypothesis testing
- Confidence intervals
- ANOVA
- Chi-square tests

**Probability Distributions:**
- Normal distribution
- Binomial distribution
- Poisson distribution
- Exponential distribution

---

## AI Applications

### Healthcare

**Applications:**
- **Medical Imaging**: X-ray, MRI, CT scan analysis
- **Drug Discovery**: Molecular property prediction
- **Clinical Decision Support**: Diagnosis assistance
- **Personalized Medicine**: Treatment recommendations
- **Epidemic Prediction**: Disease outbreak modeling

**Examples:**
- IBM Watson for Oncology
- Google's diabetic retinopathy detection
- DeepMind's protein folding (AlphaFold)

### Finance

**Applications:**
- **Algorithmic Trading**: Automated trading strategies
- **Credit Scoring**: Loan default prediction
- **Fraud Detection**: Suspicious transaction identification
- **Risk Management**: Portfolio optimization
- **Robo-advisors**: Automated investment advice

**Techniques:**
- Time series analysis
- Anomaly detection
- Natural language processing for news analysis
- Reinforcement learning for trading

### Autonomous Vehicles

**Components:**
- **Perception**: Object detection, lane detection
- **Localization**: GPS, SLAM
- **Planning**: Path planning, motion planning
- **Control**: Vehicle dynamics, actuator control

**Sensors:**
- LiDAR, cameras, radar
- GPS, IMU
- Ultrasonic sensors

**Challenges:**
- Safety and reliability
- Edge cases handling
- Regulatory approval
- Ethical decisions

### Recommendation Systems

**Types:**
1. **Content-Based**: Item features similarity
2. **Collaborative Filtering**: User behavior similarity
3. **Hybrid**: Combination of both approaches

**Algorithms:**
- Matrix factorization
- Deep learning embeddings
- Association rules
- Clustering

**Examples:**
- Netflix movie recommendations
- Amazon product suggestions
- Spotify music recommendations

### Chatbots and Virtual Assistants

**Components:**
- **Natural Language Understanding**: Intent recognition
- **Dialog Management**: Conversation flow
- **Natural Language Generation**: Response generation
- **Knowledge Base**: Information retrieval

**Platforms:**
- Dialogflow (Google)
- Rasa (Open source)
- Microsoft Bot Framework
- Amazon Lex

**Applications:**
- Customer service
- Personal assistants (Siri, Alexa)
- Educational tutors
- Mental health support

---

## Emerging Trends

### Quantum Machine Learning

**Concept**: Leveraging quantum computing for ML tasks

**Potential Advantages:**
- Exponential speedup for certain problems
- Quantum feature spaces
- Enhanced optimization

**Current Status:**
- Early research phase
- Limited quantum hardware
- Hybrid classical-quantum algorithms

**Applications:**
- Quantum neural networks
- Quantum support vector machines
- Optimization problems

### Federated Learning

**Concept**: Training ML models across decentralized data

**Benefits:**
- Privacy preservation
- Reduced data transfer
- Regulatory compliance
- Edge computing enablement

**Challenges:**
- Communication efficiency
- Non-IID data distribution
- System heterogeneity
- Security concerns

**Applications:**
- Mobile keyboard prediction
- Healthcare data analysis
- Financial services
- IoT devices

### AutoML

**Concept**: Automating machine learning pipeline

**Components:**
- **Neural Architecture Search (NAS)**: Automated network design
- **Hyperparameter Optimization**: Automated tuning
- **Feature Engineering**: Automated feature creation
- **Model Selection**: Automated algorithm choice

**Tools:**
- Google AutoML
- H2O.ai
- Auto-sklearn
- TPOT

### AI Hardware

**Specialized Chips:**
- **GPUs**: Graphics Processing Units
- **TPUs**: Tensor Processing Units (Google)
- **FPGAs**: Field-Programmable Gate Arrays
- **Neuromorphic Chips**: Brain-inspired computing

**Edge AI:**
- Mobile AI chips (Apple Neural Engine, Qualcomm AI Engine)
- IoT AI processors
- Autonomous vehicle chips
- Smart camera processors

**Quantum Processors:**
- IBM Quantum
- Google Sycamore
- IonQ
- Rigetti Computing