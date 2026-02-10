#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Artificial Intelligence for Cybersecurity in Python
This script implements AI techniques for cybersecurity:
- Threat intelligence gathering
- Malware classification
- Intrusion detection
- Vulnerability assessment
- Security automation
- Anomaly detection
Perfect for beginners!
"""

import os
import sys
import time
import json
import requests
import re
import nltk
import spacy
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from scipy.sparse import csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.cluster import KMeans
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split
from collections import Counter
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
import joblib

class ThreatLevel(Enum):
    """Threat level enumeration"""
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

@dataclass
class ThreatIntelligence:
    """Threat intelligence structure"""
    source: str
    description: str
    threat_type: str
    severity: ThreatLevel
    indicators: Dict[str, List[str]]
    references: List[str]
    timestamp: float
    confidence: float

@dataclass
class MalwareFamily:
    """Malware family information"""
    name: str
    description: str
    variants: List[str]
    behavior: List[str]
    signatures: List[str]
    detection_rate: float

class ThreatIntelligenceSystem:
    """Threat intelligence gathering and analysis system"""
    
    def __init__(self):
        """Initialize threat intelligence system"""
        self.sources = [
            'virustotal',
            'alienvault',
            'shodan',
            'malwarebytes',
            'trendmicro',
            'mcafee',
            'symantec',
            'kaspersky'
        ]
        
        self.threats: List[ThreatIntelligence] = []
        self.malware_families: List[MalwareFamily] = []
        
        # Initialize NLP tools
        nltk.download('stopwords')
        nltk.download('punkt')
        nltk.download('wordnet')
        
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        
        # Try to load SpaCy model, use nltk as fallback if not available
        try:
            self.nlp = spacy.load('en_core_web_sm')
        except:
            self.nlp = None
            print("SpaCy model not available, using NLTK instead")
            
    def gather_intelligence(self, keywords: List[str], limit: int = 50) -> List[ThreatIntelligence]:
        """
        Gather threat intelligence from various sources
        
        Args:
            keywords: Keywords to search for
            limit: Maximum number of results to return
            
        Returns:
            List of ThreatIntelligence objects
        """
        threats = []
        
        # Simulated threat intelligence gathering (in real scenario, use actual APIs)
        for source in self.sources:
            for keyword in keywords:
                threat = ThreatIntelligence(
                    source=source,
                    description=f"Detected {keyword} threat targeting {source} systems",
                    threat_type=keyword,
                    severity=self._get_random_severity(),
                    indicators={
                        'ips': [f'{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'],
                        'domains': [f'{keyword}.malicious-domain.com'],
                        'hashes': [self._generate_random_hash() for _ in range(2)],
                        'urls': [f'http://{keyword}.malicious-domain.com/exploit']
                    },
                    references=[f'https://{source}.com/reports/{keyword}'],
                    timestamp=time.time(),
                    confidence=random.uniform(0.7, 0.95)
                )
                
                threats.append(threat)
                
        # Limit to specified number of results
        return random.sample(threats, min(limit, len(threats)))
        
    def _get_random_severity(self) -> ThreatLevel:
        """Get random threat severity"""
        return random.choice([ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL])
        
    def _generate_random_hash(self) -> str:
        """Generate random SHA-256 hash"""
        import hashlib
        return hashlib.sha256(str(time.time() + random.random()).encode()).hexdigest()
        
    def analyze_intelligence(self, intelligence: List[ThreatIntelligence]) -> Dict[str, Any]:
        """
        Analyze gathered intelligence
        
        Args:
            intelligence: List of ThreatIntelligence objects
            
        Returns:
            Analysis results
        """
        analysis = {
            'summary': {
                'total_threats': len(intelligence),
                'severity_distribution': Counter(),
                'type_distribution': Counter(),
                'source_distribution': Counter(),
                'average_confidence': 0.0
            },
            'malware_families': [],
            'top_indicators': {},
            'relationships': []
        }
        
        # Calculate basic statistics
        total_confidence = 0
        
        for threat in intelligence:
            analysis['summary']['severity_distribution'][threat.severity.name] += 1
            analysis['summary']['type_distribution'][threat.threat_type] += 1
            analysis['summary']['source_distribution'][threat.source] += 1
            total_confidence += threat.confidence
            
            # Collect indicators
            for indicator_type, indicators in threat.indicators.items():
                if indicator_type not in analysis['top_indicators']:
                    analysis['top_indicators'][indicator_type] = Counter()
                    
                for indicator in indicators:
                    analysis['top_indicators'][indicator_type][indicator] += 1
                    
        analysis['summary']['average_confidence'] = total_confidence / len(intelligence)
        
        return analysis
        
    def classify_threats(self, intelligence: List[ThreatIntelligence]) -> List[Tuple[ThreatIntelligence, str]]:
        """
        Classify threats using machine learning
        
        Args:
            intelligence: List of ThreatIntelligence objects
            
        Returns:
            List of (ThreatIntelligence, classification) tuples
        """
        classifications = []
        
        # Load or train classification model
        model = self._get_classification_model()
        
        for threat in intelligence:
            # Extract features from threat description
            features = self._extract_features(threat.description)
            
            # Predict classification
            classification = model.predict([features])[0]
            
            classifications.append((threat, classification))
            
        return classifications
        
    def _get_classification_model(self):
        """Load or train classification model"""
        model_file = 'threat_classifier.joblib'
        
        if os.path.exists(model_file):
            return joblib.load(model_file)
            
        # Train simple classification model (in real scenario, use labeled dataset)
        dummy_texts = [
            'Trojan malware detected',
            'Phishing attempt in email',
            'SQL injection vulnerability',
            'Ransomware encryption detected',
            'Denial of service attack',
            'Password brute force attempt',
            'Buffer overflow vulnerability',
            'Cross-site scripting attack'
        ]
        
        dummy_labels = [
            'malware', 'phishing', 'vulnerability', 'ransomware',
            'dos', 'brute-force', 'vulnerability', 'xss'
        ]
        
        vectorizer = TfidfVectorizer(stop_words='english')
        X = vectorizer.fit_transform(dummy_texts)
        
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, dummy_labels)
        
        joblib.dump(model, model_file)
        
        return model
        
    def _extract_features(self, text: str) -> str:
        """Extract features from text using NLP"""
        if self.nlp:
            doc = self.nlp(text)
            features = ' '.join([token.lemma_ for token in doc if token.is_alpha and not token.is_stop])
        else:
            # Fallback to NLTK
            words = word_tokenize(text)
            words = [word.lower() for word in words if word.isalpha()]
            words = [word for word in words if word not in self.stop_words]
            words = [self.lemmatizer.lemmatize(word) for word in words]
            features = ' '.join(words)
            
        return features
        
    def visualize_network(self, intelligence: List[ThreatIntelligence]):
        """Visualize threat network graph"""
        try:
            G = nx.DiGraph()
            
            for threat in intelligence:
                G.add_node(threat.threat_type, type='threat', severity=threat.severity.name)
                
                # Add indicator nodes
                for indicator_type, indicators in threat.indicators.items():
                    for indicator in indicators:
                        G.add_node(indicator, type=indicator_type)
                        G.add_edge(threat.threat_type, indicator)
                        
            # Visualize
            plt.figure(figsize=(12, 8))
            
            pos = nx.spring_layout(G, k=0.3)
            
            node_colors = []
            node_sizes = []
            
            for node in G.nodes():
                if G.nodes[node]['type'] == 'threat':
                    if G.nodes[node]['severity'] == 'CRITICAL':
                        node_colors.append('#FF4444')
                    elif G.nodes[node]['severity'] == 'HIGH':
                        node_colors.append('#FF8844')
                    elif G.nodes[node]['severity'] == 'MEDIUM':
                        node_colors.append('#FFCC44')
                    else:
                        node_colors.append('#44FF44')
                        
                    node_sizes.append(1000)
                else:
                    node_colors.append('#4444FF')
                    node_sizes.append(300)
                    
            nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes)
            nx.draw_networkx_edges(G, pos, edge_color='#888888', width=1)
            
            plt.title('Threat Network Graph')
            plt.axis('off')
            
            plt.savefig('threat_network.png', dpi=300, bbox_inches='tight')
            plt.show()
            
        except Exception as e:
            print(f"Graph visualization error: {e}")

class MalwareClassifier:
    """Malware classification system"""
    
    def __init__(self):
        """Initialize malware classifier"""
        self.classifier = None
        
    def train_classifier(self, dataset_path: str) -> float:
        """
        Train malware classifier
        
        Args:
            dataset_path: Path to malware dataset
            
        Returns:
            Training accuracy
        """
        try:
            data = pd.read_csv(dataset_path)
            
            X = data['description']
            y = data['malware_type']
            
            # Text vectorization
            vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
            X_vectorized = vectorizer.fit_transform(X)
            
            # Train-test split
            X_train, X_test, y_train, y_test = train_test_split(X_vectorized, y, test_size=0.2)
            
            # Train classifier
            self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
            self.classifier.fit(X_train, y_train)
            
            # Evaluate
            y_pred = self.classifier.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            return accuracy
            
        except Exception as e:
            print(f"Training error: {e}")
            return 0.0
            
    def classify_malware(self, description: str) -> str:
        """
        Classify malware from description
        
        Args:
            description: Malware description
            
        Returns:
            Malware type
        """
        if self.classifier is None:
            raise Exception("Classifier not trained")
            
        vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
        
        features = vectorizer.transform([description])
        
        return self.classifier.predict(features)[0]
        
    def analyze_file(self, file_path: str) -> Tuple[bool, str, float]:
        """
        Analyze file for malware
        
        Args:
            file_path: File path to analyze
            
        Returns:
            Tuple of (is_malware, classification, confidence)
        """
        try:
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'rb') as f:
                content = f.read(1024)
                
            # Extract features
            description = self._extract_file_features(file_path)
            
            # Classify
            classification = self.classify_malware(description)
            
            # Calculate confidence (simulated)
            confidence = random.uniform(0.7, 0.95)
            
            is_malware = classification != 'safe'
            
            return is_malware, classification, confidence
            
        except Exception as e:
            print(f"File analysis error: {e}")
            return False, 'error', 0.0
            
    def _extract_file_features(self, file_path: str) -> str:
        """Extract features from file content"""
        features = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
            features.append(f"File size: {len(content)} bytes")
            
            if b'MZ' in content[:2]:
                features.append("PE executable")
                
            if b'UPX' in content:
                features.append("UPX packed")
                
            entropy = self._calculate_entropy(content)
            features.append(f"Entropy: {entropy:.2f}")
            
            if entropy > 7.5:
                features.append("High entropy (compressed)")
                
            if b'http' in content:
                features.append("HTTP signatures")
                
            if b'https' in content:
                features.append("HTTPS signatures")
                
            if b'system32' in content.lower():
                features.append("System32 references")
                
            return ' '.join(features)
            
        except Exception as e:
            print(f"Feature extraction error: {e}")
            return ''
            
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate entropy of binary data"""
        byte_counts = Counter(data)
        total_bytes = len(data)
        entropy = 0
        
        for count in byte_counts.values():
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)
            
        return entropy

class IntrusionDetectionSystem:
    """Intrusion Detection System using AI"""
    
    def __init__(self):
        """Initialize IDS"""
        self.models = {
            'normal': self._train_normal_model(),
            'intrusion': self._train_intrusion_model()
        }
        
        self.anomaly_detector = None
        
    def _train_normal_model(self):
        """Train normal behavior model"""
        return RandomForestClassifier(n_estimators=50, random_state=42)
        
    def _train_intrusion_model(self):
        """Train intrusion detection model"""
        return SVC(kernel='rbf', C=1.0, gamma='scale', probability=True)
        
    def detect_intrusion(self, network_traffic: pd.DataFrame) -> Tuple[bool, str, float]:
        """
        Detect intrusion in network traffic
        
        Args:
            network_traffic: Network traffic data
            
        Returns:
            Tuple of (is_intrusion, intrusion_type, confidence)
        """
        try:
            # Extract features
            features = self._extract_traffic_features(network_traffic)
            
            # Use pre-trained anomaly detector
            if self.anomaly_detector is None:
                self.anomaly_detector = KMeans(n_clusters=2, random_state=42)
                self.anomaly_detector.fit(features)
                
            # Predict cluster
            cluster = self.anomaly_detector.predict(features)
            
            if np.mean(cluster) > 0.5:
                return True, 'anomaly', random.uniform(0.6, 0.9)
            else:
                return False, 'normal', random.uniform(0.7, 0.95)
                
        except Exception as e:
            print(f"Intrusion detection error: {e}")
            return False, 'error', 0.0
            
    def _extract_traffic_features(self, traffic: pd.DataFrame) -> np.ndarray:
        """Extract features from network traffic"""
        features = []
        
        # Calculate basic statistics
        features.append(traffic['duration'].mean())
        features.append(traffic['src_bytes'].sum())
        features.append(traffic['dst_bytes'].sum())
        features.append(len(traffic))
        features.append(traffic['protocol_type'].nunique())
        features.append(traffic['service'].nunique())
        
        return np.array(features).reshape(1, -1)

def main():
    """Main function to demonstrate AI for cybersecurity functionality"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="AI for Cybersecurity - Threat intelligence and malware analysis"
    )
    
    parser.add_argument(
        "-t", "--threat",
        help="Gather threat intelligence for specific keyword"
    )
    
    parser.add_argument(
        "-f", "--file",
        help="Analyze file for malware"
    )
    
    parser.add_argument(
        "-i", "--intrusion",
        help="Analyze network traffic for intrusions"
    )
    
    parser.add_argument(
        "-c", "--classify",
        help="Classify malware from description"
    )
    
    parser.add_argument(
        "-v", "--visualize",
        action="store_true",
        help="Visualize threat network graph"
    )
    
    parser.add_argument(
        "-l", "--list-sources",
        action="store_true",
        help="List available intelligence sources"
    )
    
    args = parser.parse_args()
    
    try:
        if args.list_sources:
            tis = ThreatIntelligenceSystem()
            print(f"{'='*60}")
            print(f"  THREAT INTELLIGENCE SOURCES")
            print(f"{'='*60}")
            
            for i, source in enumerate(tis.sources, 1):
                print(f"{i:2d}. {source.capitalize()}")
                
        elif args.threat:
            tis = ThreatIntelligenceSystem()
            
            print(f"{'='*60}")
            print(f"  GATHERING THREAT INTELLIGENCE")
            print(f"{'='*60}")
            
            threats = tis.gather_intelligence([args.threat], limit=20)
            
            for threat in threats:
                print(f"{'='*60}")
                print(f"Source: {threat.source}")
                print(f"Type: {threat.threat_type}")
                print(f"Severity: {threat.severity.name}")
                print(f"Description: {threat.description}")
                print(f"Confidence: {threat.confidence:.1%}")
                
                if threat.indicators:
                    print("Indicators:")
                    for indicator_type, indicators in threat.indicators.items():
                        print(f"  {indicator_type}:")
                        for indicator in indicators:
                            print(f"    - {indicator}")
                            
                if threat.references:
                    print("References:")
                    for ref in threat.references:
                        print(f"  - {ref}")
                        
        elif args.file:
            classifier = MalwareClassifier()
            
            try:
                classifier.train_classifier('malware_dataset.csv')
            except Exception as e:
                print(f"Training error: {e}")
                return
                
            is_malware, classification, confidence = classifier.analyze_file(args.file)
            
            print(f"{'='*60}")
            print(f"  FILE ANALYSIS")
            print(f"{'='*60}")
            print(f"File: {args.file}")
            print(f"Malware: {is_malware}")
            print(f"Classification: {classification}")
            print(f"Confidence: {confidence:.1%}")
            
        elif args.intrusion:
            ids = IntrusionDetectionSystem()
            
            try:
                traffic = pd.read_csv(args.intrusion)
                
                is_intrusion, intrusion_type, confidence = ids.detect_intrusion(traffic)
                
                print(f"{'='*60}")
                print(f"  INTRUSION DETECTION")
                print(f"{'='*60}")
                print(f"Intrusion Detected: {is_intrusion}")
                print(f"Intrusion Type: {intrusion_type}")
                print(f"Confidence: {confidence:.1%}")
                
            except Exception as e:
                print(f"Traffic analysis error: {e}")
                
        elif args.classify:
            classifier = MalwareClassifier()
            
            try:
                classifier.train_classifier('malware_dataset.csv')
                
                classification = classifier.classify_malware(args.classify)
                
                print(f"{'='*60}")
                print(f"  MALWARE CLASSIFICATION")
                print(f"{'='*60}")
                print(f"Description: {args.classify}")
                print(f"Classification: {classification}")
                
            except Exception as e:
                print(f"Classification error: {e}")
                
        elif args.visualize:
            tis = ThreatIntelligenceSystem()
            threats = tis.gather_intelligence(['malware', 'phishing', 'ransomware'], limit=30)
            tis.visualize_network(threats)
            
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
