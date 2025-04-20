# src/feature_extractor.py
import pandas as pd
import numpy as np
from typing import Dict, List, Any
import joblib
import os
import logging

class FeatureExtractor:
    def __init__(self, model_path: str = 'models/random_forest_model.pkl'):
        """
        Initialize the feature extractor with a path to the saved model
        
        Args:
            model_path: Path to the saved model file
        """
        # Load the model which should include the scaler and label encoder
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found at {model_path}")
        
        self.model_data = joblib.load(model_path)
        self.scaler = self.model_data.get('scaler')
        self.feature_names = self.model_data.get('feature_names')
        
        logging.info(f"Feature extractor initialized with model from {model_path}")
    
    def extract_features(self, flow_data: List[Dict]) -> pd.DataFrame:
        """
        Extract and preprocess features from flow data
        
        Args:
            flow_data: List of flow dictionaries with traffic statistics
            
        Returns:
            DataFrame with processed features ready for model input
        """
        if not flow_data:
            return pd.DataFrame()
        
        # Convert to DataFrame
        df = pd.DataFrame(flow_data)
        
        # Keep track of IP addresses but remove them from features
        ip_addresses = None
        if 'src_ip' in df.columns:
            ip_addresses = df[['src_ip', 'dst_ip']].copy()
            df = df.drop(['src_ip', 'dst_ip'], axis=1)
        
        # Ensure all needed features are present
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0
        
        # Keep only the features used by the model
        df = df[self.feature_names]
        
        # Fill NA values
        df = df.fillna(0)
        
        # Apply scaling
        if self.scaler:
            df_scaled = pd.DataFrame(
                self.scaler.transform(df),
                columns=df.columns
            )
        else:
            df_scaled = df
        
        # Add back IP addresses
        if ip_addresses is not None:
            df_scaled['src_ip'] = ip_addresses['src_ip'].values
            df_scaled['dst_ip'] = ip_addresses['dst_ip'].values
            
        return df_scaled