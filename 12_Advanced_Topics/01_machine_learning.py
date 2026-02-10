#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Machine Learning for Cybersecurity in Python
This script implements machine learning techniques for cybersecurity:
- Malware classification
- Network anomaly detection
- Phishing detection
- Intrusion detection systems
- Vulnerability prediction
Perfect for beginners!
"""

import os
import sys
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report,
    roc_auc_score, roc_curve
)
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from scipy.sparse import csr_matrix
from sklearn.pipeline import Pipeline
from sklearn.feature_selection import SelectFromModel
import joblib
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

class ThreatType(Enum):
    """Threat type enumeration"""
    BENIGN = 0
    MALWARE = 1
    PHISHING = 2
    INTRUSION = 3
    VULNERABILITY = 4

@dataclass
class FeatureImportance:
    """Feature importance structure"""
    feature_name: str
    importance: float

@dataclass
class ModelPerformance:
    """Model performance metrics"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    confusion_matrix: np.ndarray
    roc_auc: float
    class_report: str

class MachineLearningEngine:
    """Class for machine learning operations"""
    
    def __init__(self):
        """Initialize machine learning engine"""
        self.models = {
            'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'gradient_boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'svm': SVC(kernel='rbf', C=1.0, gamma='scale', probability=True, random_state=42),
            'knn': KNeighborsClassifier(n_neighbors=5),
            'naive_bayes': GaussianNB(),
            'logistic_regression': LogisticRegression(max_iter=1000, random_state=42),
            'neural_network': MLPClassifier(hidden_layer_sizes=(100,), max_iter=500, random_state=42),
            'kmeans': KMeans(n_clusters=2, random_state=42)
        }
        
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
    def load_dataset(self, file_path: str, features: List[str] = None,
                   target_column: str = None) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load dataset from CSV file
        
        Args:
            file_path: CSV file path
            features: List of feature columns
            target_column: Target column name
            
        Returns:
            Tuple of features and labels
        """
        try:
            data = pd.read_csv(file_path)
            
            if features is None:
                features = data.columns[data.columns != target_column]
                
            if target_column is None:
                raise ValueError("Target column must be specified")
                
            X = data[features].values
            y = data[target_column].values
            
            # Handle categorical features
            for i in range(X.shape[1]):
                if isinstance(X[:, i][0], str):
                    le = LabelEncoder()
                    X[:, i] = le.fit_transform(X[:, i])
                    
            # Handle missing values
            X = np.nan_to_num(X)
            
            return X, y
            
        except Exception as e:
            print(f"Error loading dataset: {e}")
            return None, None
            
    def prepare_data(self, X: np.ndarray, y: np.ndarray,
                   test_size: float = 0.2, random_state: int = 42) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Prepare data for training
        
        Args:
            X: Features array
            y: Labels array
            test_size: Test size split
            random_state: Random state for reproducibility
            
        Returns:
            Train and test split
        """
        try:
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            return X_train_scaled, X_test_scaled, y_train, y_test
            
        except Exception as e:
            print(f"Error preparing data: {e}")
            return None, None, None, None
            
    def train_model(self, model_name: str, X_train: np.ndarray,
                   y_train: np.ndarray) -> Any:
        """
        Train specified model
        
        Args:
            model_name: Model name from self.models dictionary
            X_train: Training features
            y_train: Training labels
            
        Returns:
            Trained model
        """
        if model_name not in self.models:
            print(f"Model '{model_name}' not supported")
            return None
            
        try:
            print(f"Training {model_name}...")
            model = self.models[model_name]
            
            if model_name == 'kmeans':
                model.fit(X_train)
            else:
                model.fit(X_train, y_train)
                
            return model
            
        except Exception as e:
            print(f"Error training model: {e}")
            return None
            
    def evaluate_model(self, model: Any, X_test: np.ndarray,
                     y_test: np.ndarray) -> ModelPerformance:
        """
        Evaluate model performance
        
        Args:
            model: Trained model
            X_test: Test features
            y_test: Test labels
            
        Returns:
            ModelPerformance object
        """
        try:
            # Predictions
            if hasattr(model, 'predict_proba'):
                y_pred = model.predict(X_test)
                y_proba = model.predict_proba(X_test)
            else:
                y_pred = model.predict(X_test)
                y_proba = None
                
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            conf_matrix = confusion_matrix(y_test, y_pred)
            class_report = classification_report(y_test, y_pred)
            
            # ROC-AUC if probabilities available
            if y_proba is not None:
                roc_auc = roc_auc_score(y_test, y_proba[:, 1])
            else:
                roc_auc = 0.0
                
            return ModelPerformance(
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_score=f1,
                confusion_matrix=conf_matrix,
                roc_auc=roc_auc,
                class_report=class_report
            )
            
        except Exception as e:
            print(f"Error evaluating model: {e}")
            return None
            
    def cross_validate_model(self, model_name: str, X: np.ndarray,
                           y: np.ndarray, cv: int = 5) -> Dict[str, float]:
        """
        Cross-validate model
        
        Args:
            model_name: Model name
            X: Features
            y: Labels
            cv: Number of folds
            
        Returns:
            Cross-validation results
        """
        if model_name not in self.models:
            return None
            
        try:
            scores = cross_val_score(
                self.models[model_name],
                X, y,
                cv=cv,
                scoring='f1'
            )
            
            return {
                'mean': scores.mean(),
                'std': scores.std(),
                'scores': scores
            }
            
        except Exception as e:
            print(f"Error cross-validating model: {e}")
            return None
            
    def feature_importance(self, model: Any, feature_names: List[str]) -> List[FeatureImportance]:
        """
        Get feature importance from tree-based models
        
        Args:
            model: Trained model
            feature_names: List of feature names
            
        Returns:
            List of FeatureImportance objects
        """
        if not hasattr(model, 'feature_importances_') and not hasattr(model, 'coef_'):
            return None
            
        try:
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
            else:
                importances = np.abs(model.coef_[0])
                
            features = []
            
            for name, importance in zip(feature_names, importances):
                features.append(FeatureImportance(feature_name=name, importance=importance))
                
            return sorted(features, key=lambda x: x.importance, reverse=True)
            
        except Exception as e:
            print(f"Error calculating feature importance: {e}")
            return None
            
    def plot_confusion_matrix(self, conf_matrix: np.ndarray, classes: List[str] = None):
        """
        Plot confusion matrix
        
        Args:
            conf_matrix: Confusion matrix
            classes: Class labels
        """
        if classes is None:
            classes = ['Benign', 'Malicious']
            
        plt.figure(figsize=(10, 8))
        sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
                   xticklabels=classes, yticklabels=classes)
        plt.title('Confusion Matrix')
        plt.xlabel('Predicted Label')
        plt.ylabel('True Label')
        
        plt.tight_layout()
        plt.savefig('confusion_matrix.png', dpi=300, bbox_inches='tight')
        plt.show()
        
    def plot_roc_curve(self, model: Any, X_test: np.ndarray, y_test: np.ndarray):
        """
        Plot ROC curve
        
        Args:
            model: Trained model
            X_test: Test features
            y_test: Test labels
        """
        if hasattr(model, 'predict_proba'):
            y_proba = model.predict_proba(X_test)[:, 1]
            fpr, tpr, _ = roc_curve(y_test, y_proba)
            roc_auc = roc_auc_score(y_test, y_proba)
            
            plt.figure(figsize=(10, 8))
            plt.plot(fpr, tpr, color='darkorange', lw=2,
                    label=f'ROC curve (area = {roc_auc:.2f})')
            plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title('Receiver Operating Characteristic (ROC) Curve')
            plt.legend(loc="lower right")
            
            plt.tight_layout()
            plt.savefig('roc_curve.png', dpi=300, bbox_inches='tight')
            plt.show()
            
    def save_model(self, model: Any, file_path: str):
        """
        Save trained model to file
        
        Args:
            model: Trained model
            file_path: Output file path
        """
        try:
            joblib.dump(model, file_path)
            print(f"Model saved to: {file_path}")
            
        except Exception as e:
            print(f"Error saving model: {e}")
            
    def load_model(self, file_path: str) -> Any:
        """
        Load trained model from file
        
        Args:
            file_path: Model file path
            
        Returns:
            Loaded model
        """
        try:
            model = joblib.load(file_path)
            print(f"Model loaded from: {file_path}")
            
            return model
            
        except Exception as e:
            print(f"Error loading model: {e}")
            return None
            
    def predict_malware(self, file_features: np.ndarray) -> Tuple[bool, float]:
        """
        Predict if file is malware
        
        Args:
            file_features: File features array
            
        Returns:
            Tuple of (is_malware, confidence)
        """
        try:
            # Load pre-trained model
            model = self.load_model('malware_classifier.joblib')
            
            if model is None:
                return False, 0.0
                
            # Scale features
            features_scaled = self.scaler.transform([file_features])
            
            # Predict
            prediction = model.predict(features_scaled)
            confidence = model.predict_proba(features_scaled)[0][prediction[0]]
            
            return bool(prediction[0]), confidence
            
        except Exception as e:
            print(f"Error predicting malware: {e}")
            return False, 0.0
            
    def detect_anomaly(self, network_features: np.ndarray) -> Tuple[bool, float]:
        """
        Detect network anomalies
        
        Args:
            network_features: Network features array
            
        Returns:
            Tuple of (is_anomaly, confidence)
        """
        try:
            # Load pre-trained model
            model = self.load_model('anomaly_detector.joblib')
            
            if model is None:
                return False, 0.0
                
            # Scale features
            features_scaled = self.scaler.transform([network_features])
            
            # Predict
            prediction = model.predict(features_scaled)
            confidence = model.predict_proba(features_scaled)[0][prediction[0]]
            
            return bool(prediction[0]), confidence
            
        except Exception as e:
            print(f"Error detecting anomaly: {e}")
            return False, 0.0

class MalwareClassifier:
    """Class for malware classification"""
    
    def __init__(self):
        """Initialize malware classifier"""
        self.mle = MachineLearningEngine()
        
    def extract_file_features(self, file_path: str) -> np.ndarray:
        """
        Extract features from executable file
        
        Args:
            file_path: File path to extract features from
            
        Returns:
            Feature array
        """
        features = []
        
        try:
            file_size = os.path.getsize(file_path)
            
            # Calculate entropy
            with open(file_path, 'rb') as f:
                data = f.read()
                
            byte_counts = [0] * 256
            
            for byte in data:
                byte_counts[byte] += 1
                
            file_size = len(data)
            entropy = 0.0
            
            for count in byte_counts:
                if count > 0:
                    probability = count / file_size
                    entropy -= probability * (probability.bit_length() if probability else 0)
                    
            features.extend([
                file_size,
                entropy
            ])
            
            # PE file features
            try:
                import pefile
                pe = pefile.PE(file_path)
                
                # Section count
                features.append(len(pe.sections))
                
                # Import count
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    imports = 0
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        imports += len(entry.imports)
                    features.append(imports)
                else:
                    features.append(0)
                    
                # Export count
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    features.append(len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
                else:
                    features.append(0)
                    
                # Section characteristics
                for section in pe.sections:
                    features.extend([
                        section.VirtualAddress,
                        section.Misc_VirtualSize,
                        section.SizeOfRawData
                    ])
                    
                pe.close()
                
            except Exception as e:
                print(f"PE file analysis error: {e}")
                features.extend([0, 0, 0])
                
            return np.array(features)
            
        except Exception as e:
            print(f"Feature extraction error: {e}")
            return np.array([])
            
    def train_classifier(self, dataset_path: str):
        """
        Train malware classifier
        
        Args:
            dataset_path: Path to malware dataset (CSV file)
        """
        try:
            # Load dataset
            features = ['file_size', 'entropy', 'section_count', 'import_count', 'export_count']
            X, y = self.mle.load_dataset(dataset_path, features, 'is_malware')
            
            # Prepare data
            X_train, X_test, y_train, y_test = self.mle.prepare_data(X, y)
            
            if X_train is not None:
                # Train model
                model = self.mle.train_model('random_forest', X_train, y_train)
                
                # Evaluate model
                performance = self.mle.evaluate_model(model, X_test, y_test)
                
                print(f"{'='*60}")
                print(f"  MODEL PERFORMANCE")
                print(f"{'='*60}")
                print(f"Accuracy: {performance.accuracy:.3f}")
                print(f"Precision: {performance.precision:.3f}")
                print(f"Recall: {performance.recall:.3f}")
                print(f"F1 Score: {performance.f1_score:.3f}")
                print(f"ROC-AUC: {performance.roc_auc:.3f}")
                
                # Plot results
                self.mle.plot_confusion_matrix(performance.confusion_matrix)
                self.mle.plot_roc_curve(model, X_test, y_test)
                
                # Save model
                self.mle.save_model(model, 'malware_classifier.joblib')
                
        except Exception as e:
            print(f"Training error: {e}")

class NetworkAnomalyDetector:
    """Class for network anomaly detection"""
    
    def __init__(self):
        """Initialize network anomaly detector"""
        self.mle = MachineLearningEngine()
        
    def train_detector(self, dataset_path: str):
        """
        Train network anomaly detector
        
        Args:
            dataset_path: Path to network traffic dataset (CSV file)
        """
        try:
            # Load dataset
            features = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes',
                      'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
                      'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
                      'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
                      'num_access_files', 'num_outbound_cmds', 'is_host_login',
                      'is_guest_login', 'count', 'srv_count', 'serror_rate',
                      'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
                      'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
                      'dst_host_srv_count', 'dst_host_same_srv_rate',
                      'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                      'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                      'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
                      'dst_host_srv_rerror_rate']
                      
            X, y = self.mle.load_dataset(dataset_path, features, 'class')
            
            # Prepare data
            X_train, X_test, y_train, y_test = self.mle.prepare_data(X, y)
            
            if X_train is not None:
                # Train model
                model = self.mle.train_model('gradient_boosting', X_train, y_train)
                
                # Evaluate model
                performance = self.mle.evaluate_model(model, X_test, y_test)
                
                print(f"{'='*60}")
                print(f"  MODEL PERFORMANCE")
                print(f"{'='*60}")
                print(f"Accuracy: {performance.accuracy:.3f}")
                print(f"Precision: {performance.precision:.3f}")
                print(f"Recall: {performance.recall:.3f}")
                print(f"F1 Score: {performance.f1_score:.3f}")
                print(f"ROC-AUC: {performance.roc_auc:.3f}")
                
                # Plot results
                self.mle.plot_confusion_matrix(performance.confusion_matrix)
                self.mle.plot_roc_curve(model, X_test, y_test)
                
                # Save model
                self.mle.save_model(model, 'anomaly_detector.joblib')
                
        except Exception as e:
            print(f"Training error: {e}")

def main():
    """Main function to demonstrate machine learning functionality"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Machine Learning for Cybersecurity - Malware classification and anomaly detection"
    )
    
    parser.add_argument(
        "-m", "--malware",
        help="File path to test for malware"
    )
    
    parser.add_argument(
        "-a", "--anomaly",
        help="Network traffic file to analyze for anomalies"
    )
    
    parser.add_argument(
        "-t", "--train-malware",
        help="Dataset for training malware classifier"
    )
    
    parser.add_argument(
        "-T", "--train-anomaly",
        help="Dataset for training anomaly detector"
    )
    
    parser.add_argument(
        "-l", "--list-models",
        action="store_true",
        help="List available machine learning models"
    )
    
    args = parser.parse_args()
    
    try:
        if args.list_models:
            print(f"{'='*60}")
            print(f"  AVAILABLE MODELS")
            print(f"{'='*60}")
            
            engine = MachineLearningEngine()
            for i, (name, model) in enumerate(engine.models.items(), 1):
                print(f"{i:2d}. {name} - {type(model).__name__}")
                
        elif args.malware:
            classifier = MalwareClassifier()
            
            # Extract features from file
            features = classifier.extract_file_features(args.malware)
            
            if len(features) > 0:
                is_malware, confidence = classifier.mle.predict_malware(features)
                
                print(f"{'='*60}")
                print(f"  MALWARE ANALYSIS")
                print(f"{'='*60}")
                print(f"File: {args.malware}")
                print(f"Size: {os.path.getsize(args.malware)} bytes")
                print(f"Is Malware: {is_malware}")
                print(f"Confidence: {confidence:.3f}")
                
                if is_malware:
                    print("Recommendation: Quarantine and further analysis recommended")
                else:
                    print("Recommendation: File appears to be clean")
                    
            else:
                print("Error: Could not extract features from file")
                
        elif args.anomaly:
            detector = NetworkAnomalyDetector()
            
            # Load network traffic data
            engine = MachineLearningEngine()
            
            try:
                import pandas as pd
                data = pd.read_csv(args.anomaly)
                
                features = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes',
                          'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
                          'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
                          'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
                          'num_access_files', 'num_outbound_cmds', 'is_host_login',
                          'is_guest_login', 'count', 'srv_count', 'serror_rate',
                          'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
                          'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
                          'dst_host_srv_count', 'dst_host_same_srv_rate',
                          'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                          'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                          'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
                          'dst_host_srv_rerror_rate']
                          
                X = data[features].values
                
                # Handle categorical features
                for i in range(X.shape[1]):
                    if isinstance(X[:, i][0], str):
                        le = LabelEncoder()
                        X[:, i] = le.fit_transform(X[:, i])
                        
                X_scaled = engine.scaler.fit_transform(X)
                
                model = engine.load_model('anomaly_detector.joblib')
                
                if model is not None:
                    predictions = model.predict(X_scaled)
                    
                    print(f"{'='*60}")
                    print(f"  ANOMALY DETECTION RESULTS")
                    print(f"{'='*60}")
                    print(f"Total packets analyzed: {len(predictions)}")
                    print(f"Anomalies detected: {sum(predictions)}")
                    print(f"Normal packets: {len(predictions) - sum(predictions)}")
                    
                    normal_ratio = (len(predictions) - sum(predictions)) / len(predictions) * 100
                    print(f"Normal packet ratio: {normal_ratio:.1f}%")
                    
                    if sum(predictions) > 0:
                        print("\nANOMALY DETAILS:")
                        
                        anomaly_indices = [i for i, pred in enumerate(predictions) if pred == 1]
                        
                        for i, idx in enumerate(anomaly_indices[:10]):
                            row = data.iloc[idx]
                            print(f"\n{row['protocol_type']} {row['service']} {row['flag']}")
                            print(f"  Source Bytes: {row['src_bytes']}")
                            print(f"  Destination Bytes: {row['dst_bytes']}")
                            print(f"  Duration: {row['duration']} seconds")
                            print(f"  Count: {row['count']}")
                    
            except Exception as e:
                print(f"Error analyzing network traffic: {e}")
                
        elif args.train_malware:
            classifier = MalwareClassifier()
            classifier.train_classifier(args.train_malware)
            
        elif args.train_anomaly:
            detector = NetworkAnomalyDetector()
            detector.train_detector(args.train_anomaly)
            
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
