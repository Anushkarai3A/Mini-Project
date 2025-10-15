# specula_enhanced.py - Comprehensive IoT Device Vulnerability Mapper

import dash
from dash import dcc, html, Input, Output, State, dash_table
import dash_bootstrap_components as dbc
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
import networkx as nx
import plotly.graph_objs as go
import plotly.express as px
from datetime import datetime, timedelta
import json
import base64
import io
import threading
import time
from collections import deque

# Enhanced Mock Data and Helper Functions
class SpeculaEnhanced:
    def __init__(self):
        self.device_history = deque(maxlen=1000)
        self.anomaly_detector = IsolationForest(contamination=0.1)
        self.traffic_patterns = {}
        self.real_time_monitoring = False
        self.monitoring_thread = None
        
    def enhanced_device_discovery(self, user_input=None, network_scan=False):
        """Enhanced device discovery with network simulation"""
        base_devices = [
            {'ip': '192.168.1.1', 'type': 'Smart Light', 'manufacturer': 'Philips', 
             'os': 'Linux-based', 'firmware': '1.2.3', 'ports': '80,443', 'mac': '00:1B:44:11:3A:B7'},
            {'ip': '192.168.1.2', 'type': 'Smart Thermostat', 'manufacturer': 'Nest', 
             'os': 'Android-based', 'firmware': '2.1.0', 'ports': '8080', 'mac': '00:1B:44:11:3A:B8'},
            {'ip': '192.168.1.3', 'type': 'Security Camera', 'manufacturer': 'Honeywell', 
             'os': 'Embedded Linux', 'firmware': '1.0.5', 'ports': '21,23,80', 'mac': '00:1B:44:11:3A:B9'},
            {'ip': '192.168.1.4', 'type': 'Smart Speaker', 'manufacturer': 'Amazon', 
             'os': 'FireOS', 'firmware': '3.4.1', 'ports': '443', 'mac': '00:1B:44:11:3A:BA'},
            {'ip': '192.168.1.5', 'type': 'Smart Lock', 'manufacturer': 'August', 
             'os': 'RTOS', 'firmware': '1.7.2', 'ports': '22', 'mac': '00:1B:44:11:3A:BB'},
        ]
        
        if user_input:
            user_device = user_input.copy()
            user_device.update({
                'firmware': '1.0.0',
                'ports': '80,443',
                'mac': '00:1B:44:11:3A:BC'
            })
            base_devices.append(user_device)
            
        if network_scan:
            # Simulate finding additional devices
            additional_devices = [
                {'ip': '192.168.1.6', 'type': 'Smart TV', 'manufacturer': 'Samsung', 
                 'os': 'Tizen', 'firmware': '2.3.4', 'ports': '80,443,8000', 'mac': '00:1B:44:11:3A:BD'},
                {'ip': '192.168.1.7', 'type': 'Router', 'manufacturer': 'TP-Link', 
                 'os': 'OpenWRT', 'firmware': '1.5.6', 'ports': '22,80,443', 'mac': '00:1B:44:11:3A:BE'},
            ]
            base_devices.extend(additional_devices)
            
        return pd.DataFrame(base_devices)
    
    def comprehensive_vulnerability_assessment(self, devices):
        """Enhanced vulnerability assessment with CVSS scoring"""
        mock_cve_db = {
            'Philips': [
                {'cve_id': 'CVE-2023-1234', 'score': 8.2, 'severity': 'High', 
                 'description': 'Unpatched firmware vulnerability allows remote code execution'},
                {'cve_id': 'CVE-2023-5678', 'score': 5.5, 'severity': 'Medium',
                 'description': 'Weak authentication mechanism'}
            ],
            'Nest': [
                {'cve_id': 'CVE-2024-5678', 'score': 6.8, 'severity': 'Medium',
                 'description': 'Weak authentication allows unauthorized access'},
                {'cve_id': 'CVE-2024-9012', 'score': 7.5, 'severity': 'High',
                 'description': 'Buffer overflow in device communication'}
            ],
            'Honeywell': [
                {'cve_id': 'CVE-2023-9876', 'score': 4.3, 'severity': 'Low',
                 'description': 'Outdated OS with known security issues'}
            ],
            'Amazon': [
                {'cve_id': 'CVE-2024-3456', 'score': 9.1, 'severity': 'Critical',
                 'description': 'Remote code execution via voice commands'}
            ],
            'August': [
                {'cve_id': 'CVE-2024-7890', 'score': 7.8, 'severity': 'High',
                 'description': 'Bluetooth authentication bypass'}
            ],
            'Samsung': [
                {'cve_id': 'CVE-2024-2345', 'score': 6.5, 'severity': 'Medium',
                 'description': 'Privilege escalation vulnerability'}
            ],
            'TP-Link': [
                {'cve_id': 'CVE-2024-6789', 'score': 8.9, 'severity': 'High',
                 'description': 'Default credentials not enforced'}
            ]
        }
        
        vulnerabilities = []
        for index, device in devices.iterrows():
            manufacturer = device['manufacturer']
            if manufacturer in mock_cve_db:
                for vuln in mock_cve_db[manufacturer]:
                    vulnerabilities.append({
                        'ip': device['ip'],
                        'mac': device.get('mac', 'Unknown'),
                        'device_type': device['type'],
                        'manufacturer': manufacturer,
                        'cve_id': vuln['cve_id'],
                        'cvss_score': vuln['score'],
                        'severity': vuln['severity'],
                        'description': vuln['description'],
                        'ports': device.get('ports', 'Unknown'),
                        'firmware': device.get('firmware', 'Unknown')
                    })
                    
        return pd.DataFrame(vulnerabilities)
    
    def check_insecure_practices(self, devices):
        """Check for common insecure practices"""
        insecure_findings = []
        for index, device in devices.iterrows():
            findings = []
            
            # Check for default credentials
            if device['manufacturer'] in ['TP-Link', 'Honeywell']:
                findings.append('Default credentials detected')
                
            # Check for open ports
            ports = str(device.get('ports', ''))
            if '23' in ports:  # Telnet
                findings.append('Telnet port open')
            if '21' in ports:  # FTP
                findings.append('FTP port open')
            if '22' in ports and device['manufacturer'] != 'TP-Link':  # SSH on non-router
                findings.append('Unexpected SSH port open')
                
            # Check firmware age
            if device.get('firmware', '1.0.0') == '1.0.0':
                findings.append('Outdated firmware')
                
            if findings:
                insecure_findings.append({
                    'ip': device['ip'],
                    'device_type': device['type'],
                    'findings': '; '.join(findings),
                    'risk_level': 'High' if len(findings) > 2 else 'Medium'
                })
                
        return pd.DataFrame(insecure_findings)
    
    def train_enhanced_risk_model(self):
        """Train multiple ML models for risk prediction"""
        np.random.seed(42)
        
        # Simulate training data with more features
        n_samples = 1000
        X = np.random.rand(n_samples, 6)  # More features
        feature_names = ['patch_frequency', 'exploit_history', 'traffic_volume', 
                        'device_age', 'vendor_reputation', 'port_exposure']
        
        # More realistic target distribution
        y_probs = X[:, 0] * 0.3 + X[:, 1] * 0.4 + X[:, 2] * 0.2 + X[:, 3] * 0.1
        y = np.array(['Low'] * n_samples)
        y[y_probs > 0.4] = 'Medium'
        y[y_probs > 0.7] = 'High'
        y[y_probs > 0.9] = 'Critical'
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
        
        models = {
            'random_forest': RandomForestClassifier(n_estimators=100),
            'svm': SVC(probability=True),
            'neural_network': MLPClassifier(hidden_layer_sizes=(50, 25))
        }
        
        for name, model in models.items():
            model.fit(X_train, y_train)
            
        return models, feature_names
    
    def predict_comprehensive_risk(self, models, device_data, vulnerabilities):
        """Enhanced risk prediction considering multiple factors"""
        # Simulate feature extraction
        features = np.random.rand(1, 6)
        
        predictions = {}
        for name, model in models.items():
            pred = model.predict(features)[0]
            proba = model.predict_proba(features)[0]
            predictions[name] = {
                'prediction': pred,
                'confidence': max(proba)
            }
            
        # Aggregate predictions
        risk_counts = {}
        for pred in predictions.values():
            risk_counts[pred['prediction']] = risk_counts.get(pred['prediction'], 0) + 1
            
        final_risk = max(risk_counts, key=risk_counts.get)
        
        # Adjust based on vulnerabilities
        if not vulnerabilities.empty:
            max_vuln_score = vulnerabilities['cvss_score'].max()
            if max_vuln_score > 8.0 and final_risk != 'Critical':
                final_risk = 'High'
            elif max_vuln_score > 9.0:
                final_risk = 'Critical'
                
        return final_risk, predictions
    
    def simulate_advanced_attack_paths(self, devices, vulnerabilities):
        """Enhanced attack path simulation with multiple scenarios"""
        graph = nx.DiGraph()
        
        # Add nodes with enhanced attributes
        for _, device in devices.iterrows():
            graph.add_node(
                device['ip'],
                device_type=device['type'],
                manufacturer=device['manufacturer'],
                risk='Low'  # Initial risk
            )
            
        # Add vulnerability-based edges
        for _, vuln in vulnerabilities.iterrows():
            if vuln['severity'] in ['High', 'Critical']:
                # High-risk devices can attack others
                for _, target in devices.iterrows():
                    if target['ip'] != vuln['ip']:
                        # Simulate different attack probabilities
                        weight = vuln['cvss_score'] / 10.0
                        graph.add_edge(vuln['ip'], target['ip'], weight=weight, type='vulnerability')
                        
        # Add network-based connections
        for _, source in devices.iterrows():
            for _, target in devices.iterrows():
                if source['ip'] != target['ip']:
                    # Simulate network proximity
                    if source['ip'].split('.')[-1] == target['ip'].split('.')[-1]:
                        graph.add_edge(source['ip'], target['ip'], weight=0.3, type='network')
                        
        return graph
    
    def generate_mitigation_recommendations(self, vulnerabilities, insecure_practices):
        """Generate actionable mitigation recommendations"""
        recommendations = []
        
        # Vulnerability-based recommendations
        for _, vuln in vulnerabilities.iterrows():
            if vuln['severity'] in ['High', 'Critical']:
                recommendations.append({
                    'device_ip': vuln['ip'],
                    'issue_type': 'Vulnerability',
                    'issue': vuln['cve_id'],
                    'severity': vuln['severity'],
                    'recommendation': f"Apply firmware update to patch {vuln['cve_id']}",
                    'priority': 'Immediate' if vuln['severity'] == 'Critical' else 'High'
                })
                
        # Insecure practice recommendations
        for _, practice in insecure_practices.iterrows():
            recommendations.append({
                'device_ip': practice['ip'],
                'issue_type': 'Insecure Practice',
                'issue': practice['findings'],
                'severity': practice['risk_level'],
                'recommendation': f"Review and secure configuration: {practice['findings']}",
                'priority': 'High' if practice['risk_level'] == 'High' else 'Medium'
            })
            
        return pd.DataFrame(recommendations)
    
    def generate_security_report(self, devices, vulnerabilities, insecure_practices, recommendations):
        """Generate comprehensive security report"""
        report = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': {
                'total_devices': len(devices),
                'vulnerable_devices': len(vulnerabilities['ip'].unique()) if not vulnerabilities.empty else 0,
                'high_risk_devices': len(devices[devices['predicted_risk'].isin(['High', 'Critical'])]) if 'predicted_risk' in devices.columns else 0,
                'security_score': max(0, 100 - (len(vulnerabilities['ip'].unique()) / len(devices) * 100)) if len(devices) > 0 else 100
            },
            'critical_findings': [],
            'recommendations': recommendations.to_dict('records') if not recommendations.empty else []
        }
        
        # Add critical findings
        if not vulnerabilities.empty:
            critical_vulns = vulnerabilities[vulnerabilities['severity'].isin(['Critical', 'High'])]
            for _, vuln in critical_vulns.iterrows():
                report['critical_findings'].append({
                    'type': 'Vulnerability',
                    'device': vuln['ip'],
                    'issue': vuln['cve_id'],
                    'severity': vuln['severity'],
                    'description': vuln['description']
                })
                
        if not insecure_practices.empty:
            high_risk_practices = insecure_practices[insecure_practices['risk_level'] == 'High']
            for _, practice in high_risk_practices.iterrows():
                report['critical_findings'].append({
                    'type': 'Insecure Practice',
                    'device': practice['ip'],
                    'issue': practice['findings'],
                    'severity': 'High',
                    'description': practice['findings']
                })
                
        return report
    
    def simulate_network_traffic(self, devices):
        """Simulate network traffic patterns for anomaly detection"""
        traffic_data = []
        current_time = datetime.now()
        
        for _, device in devices.iterrows():
            # Simulate normal traffic patterns
            base_traffic = np.random.poisson(50)  # Normal traffic level
            
            # Add some anomalies
            if device['manufacturer'] == 'Philips':
                base_traffic *= np.random.choice([1, 3], p=[0.8, 0.2])  # 20% chance of high traffic
                
            traffic_data.append({
                'timestamp': current_time,
                'ip': device['ip'],
                'device_type': device['type'],
                'traffic_volume': max(0, base_traffic),
                'packet_count': np.random.poisson(1000),
                'is_anomaly': base_traffic > 100
            })
            
        return pd.DataFrame(traffic_data)

# Initialize enhanced system
specula_system = SpeculaEnhanced()
risk_models, feature_names = specula_system.train_enhanced_risk_model()

# Global variables to store data
global_devices = pd.DataFrame()
global_vulnerabilities = pd.DataFrame()
global_insecure_practices = pd.DataFrame()
global_recommendations = pd.DataFrame()
global_traffic_data = pd.DataFrame()
global_security_report = {}

# Create Dash app
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.CYBORG], suppress_callback_exceptions=True)
app.title = "Specula - Enhanced IoT Vulnerability Mapper"

# Custom CSS for better styling
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <style>
            .risk-critical { background: linear-gradient(135deg, #ff0000, #8b0000); color: white; font-weight: bold; padding: 8px; border-radius: 6px; text-align: center; }
            .risk-high { background: linear-gradient(135deg, #ff4444, #cc0000); color: white; font-weight: bold; padding: 8px; border-radius: 6px; text-align: center; }
            .risk-medium { background: linear-gradient(135deg, #ffa500, #ff8c00); color: white; font-weight: bold; padding: 8px; border-radius: 6px; text-align: center; }
            .risk-low { background: linear-gradient(135deg, #00cc00, #009900); color: white; font-weight: bold; padding: 8px; border-radius: 6px; text-align: center; }
            .specula-card { transition: all 0.3s ease; border: 1px solid #0f3460; }
            .specula-card:hover { transform: translateY(-5px); box-shadow: 0 8px 25px rgba(0,0,0,0.3); }
            .stat-card { background: linear-gradient(135deg, #1a1a2e, #16213e); border-left: 4px solid #e94560; }
            .monitoring-active { background: linear-gradient(135deg, #00cc00, #009900) !important; }
            .monitoring-inactive { background: linear-gradient(135deg, #ff4444, #cc0000) !important; }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''

app.layout = dbc.Container([
    # Header Section
    dbc.Row([
        dbc.Col([
            html.Div([
                html.Div([
                    html.H1("SPECULA", className="display-4", style={
                        'color': '#e94560', 
                        'fontWeight': 'bold', 
                        'textShadow': '2px 2px 4px rgba(0,0,0,0.5)',
                        'marginBottom': '0'
                    }),
                    html.P("Enhanced IoT Device Vulnerability Mapper", style={
                        'color': '#f0f0f0', 
                        'fontSize': '1.2rem',
                        'marginBottom': '0'
                    }),
                    html.P("Comprehensive Security Assessment & Risk Prediction", style={
                        'color': '#a0a0a0',
                        'fontSize': '1rem',
                        'fontStyle': 'italic'
                    })
                ], style={'textAlign': 'center'}),
            ], style={
                'background': 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
                'borderBottom': '3px solid #0f3460',
                'padding': '20px',
                'marginBottom': '20px',
                'borderRadius': '0 0 10px 10px',
                'boxShadow': '0 4px 12px rgba(0,0,0,0.3)'
            })
        ], width=12)
    ]),
    
    # Network Scan Control
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H4("Network Control Center", style={'color': '#e94560', 'margin': '0'})
                ], style={'background': 'linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%)', 'borderBottom': '2px solid #e94560'}),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            dbc.Button(
                                "🔍 Full Network Scan", 
                                id='network-scan-btn',
                                color="danger",
                                size="lg",
                                style={'width': '100%', 'marginBottom': '10px'}
                            ),
                        ], width=4),
                        dbc.Col([
                            dbc.Button(
                                "📊 Generate Security Report", 
                                id='report-btn',
                                color="info",
                                size="lg",
                                style={'width': '100%', 'marginBottom': '10px'}
                            ),
                        ], width=4),
                        dbc.Col([
                            dbc.Button(
                                "🔄 Real-time Monitoring", 
                                id='monitor-btn',
                                color="success",
                                size="lg",
                                className="monitoring-inactive",
                                style={'width': '100%', 'marginBottom': '10px'}
                            ),
                        ], width=4),
                    ]),
                    html.Div(id='network-status', style={'marginTop': '15px'}),
                    dcc.Download(id="download-report"),
                    dcc.Interval(
                        id='monitoring-interval',
                        interval=2000,  # Update every 2 seconds for real-time monitoring
                        n_intervals=0,
                        disabled=True
                    )
                ], style={'backgroundColor': '#1a1a2e'})
            ], className="specula-card mb-4")
        ], width=12)
    ]),
    
    # Statistics Dashboard
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("📈 Security Overview", className="card-title", style={'color': '#e94560'}),
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.H3("0", id="total-devices", style={'color': '#e94560', 'margin': '0'}),
                                html.P("Total Devices", style={'color': '#a0a0a0', 'margin': '0'})
                            ], className="stat-card p-3")
                        ], width=3),
                        dbc.Col([
                            html.Div([
                                html.H3("0", id="vulnerable-devices", style={'color': '#ff4444', 'margin': '0'}),
                                html.P("Vulnerable Devices", style={'color': '#a0a0a0', 'margin': '0'})
                            ], className="stat-card p-3")
                        ], width=3),
                        dbc.Col([
                            html.Div([
                                html.H3("0", id="high-risk-devices", style={'color': '#ffa500', 'margin': '0'}),
                                html.P("High Risk Devices", style={'color': '#a0a0a0', 'margin': '0'})
                            ], className="stat-card p-3")
                        ], width=3),
                        dbc.Col([
                            html.Div([
                                html.H3("0", id="security-score", style={'color': '#00cc00', 'margin': '0'}),
                                html.P("Security Score", style={'color': '#a0a0a0', 'margin': '0'})
                            ], className="stat-card p-3")
                        ], width=3),
                    ])
                ], style={'backgroundColor': '#1a1a2e'})
            ], className="specula-card mb-4")
        ], width=12)
    ]),
    
    # Input Form and Main Tabs
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.H4("IoT Device Scanner & Manual Entry", style={'color': '#e94560', 'margin': '0'})
                ], style={'background': 'linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%)', 'borderBottom': '2px solid #e94560'}),
                dbc.CardBody([
                    dbc.Form([
                        dbc.Row([
                            dbc.Col([
                                dbc.FormFloating([
                                    dbc.Input(
                                        type="text", 
                                        id='ip-input', 
                                        placeholder="192.168.1.1",
                                        style={
                                            'backgroundColor': '#1a1a2e',
                                            'border': '1px solid #0f3460',
                                            'color': 'white',
                                            'borderRadius': '5px'
                                        }
                                    ),
                                    dbc.Label("IP Address", style={'color': '#a0a0a0'})
                                ])
                            ], width=6),
                            dbc.Col([
                                dbc.FormFloating([
                                    dbc.Input(
                                        type="text", 
                                        id='type-input', 
                                        placeholder="Smart Light",
                                        style={
                                            'backgroundColor': '#1a1a2e',
                                            'border': '1px solid #0f3460',
                                            'color': 'white',
                                            'borderRadius': '5px'
                                        }
                                    ),
                                    dbc.Label("Device Type", style={'color': '#a0a0a0'})
                                ])
                            ], width=6),
                        ], className="mb-3"),
                        dbc.Row([
                            dbc.Col([
                                dbc.FormFloating([
                                    dbc.Input(
                                        type="text", 
                                        id='manufacturer-input', 
                                        placeholder="Philips",
                                        style={
                                            'backgroundColor': '#1a1a2e',
                                            'border': '1px solid #0f3460',
                                            'color': 'white',
                                            'borderRadius': '5px'
                                        }
                                    ),
                                    dbc.Label("Manufacturer", style={'color': '#a0a0a0'})
                                ])
                            ], width=6),
                            dbc.Col([
                                dbc.FormFloating([
                                    dbc.Input(
                                        type="text", 
                                        id='os-input', 
                                        placeholder="Linux-based",
                                        style={
                                            'backgroundColor': '#1a1a2e',
                                            'border': '1px solid #0f3460',
                                            'color': 'white',
                                            'borderRadius': '5px'
                                        }
                                    ),
                                    dbc.Label("Operating System", style={'color': '#a0a0a0'})
                                ])
                            ], width=6),
                        ], className="mb-4"),
                        dbc.Row([
                            dbc.Col([
                                dbc.Button(
                                    "🔍 Scan Device", 
                                    id='submit-button', 
                                    color="primary", 
                                    size="lg",
                                    style={
                                        'width': '100%',
                                        'background': 'linear-gradient(135deg, #e94560 0%, #c13550 100%)',
                                        'border': 'none',
                                        'borderRadius': '5px',
                                        'fontWeight': 'bold'
                                    }
                                )
                            ], width=12)
                        ]),
                    ]),
                    html.Div(
                        id='status-message', 
                        className="mt-3", 
                        style={
                            'padding': '10px',
                            'borderRadius': '5px',
                            'textAlign': 'center',
                            'fontWeight': 'bold'
                        }
                    ),
                ], style={'backgroundColor': '#1a1a2e'})
            ], className="specula-card mb-4")
        ], width=12)
    ]),
    
    # Enhanced Tabs Section
    dbc.Tabs([
        # Device Overview Tab
        dbc.Tab(
            label="📊 Device Overview",
            tab_id="tab-overview",
            children=[
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.H4("Discovered Devices", style={'color': '#e94560', 'margin': '0'})
                            ], style={'background': 'linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%)', 'borderBottom': '2px solid #e94560'}),
                            dbc.CardBody(
                                id='output-div',
                                style={'backgroundColor': '#1a1a2e'}
                            )
                        ], className="specula-card mb-4")
                    ], width=12)
                ]),
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.H4("Risk Assessment", style={'color': '#e94560', 'margin': '0'})
                            ], style={'background': 'linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%)', 'borderBottom': '2px solid #e94560'}),
                            dbc.CardBody([
                                dcc.Graph(id='risk-graph')
                            ], style={'backgroundColor': '#1a1a2e'})
                        ], className="specula-card")
                    ], width=6),
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.H4("Vulnerability Distribution", style={'color': '#e94560', 'margin': '0'})
                            ], style={'background': 'linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%)', 'borderBottom': '2px solid #e94560'}),
                            dbc.CardBody([
                                dcc.Graph(id='vulnerability-pie')
                            ], style={'backgroundColor': '#1a1a2e'})
                        ], className="specula-card")
                    ], width=6)
                ])
            ]
        ),
        
        # Vulnerabilities Tab
        dbc.Tab(
            label="⚠️ Vulnerabilities",
            tab_id="tab-vulnerabilities",
            children=[
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.H4("Detected Vulnerabilities", style={'color': '#e94560', 'margin': '0'})
                            ], style={'background': 'linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%)', 'borderBottom': '2px solid #e94560'}),
                            dbc.CardBody([
                                html.Div(id='vulnerabilities-table')
                            ], style={'backgroundColor': '#1a1a2e'})
                        ], className="specula-card mb-4")
                    ], width=12)
                ]),
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.H4("Insecure Practices", style={'color': '#e94560', 'margin': '0'})
                            ], style={'background': 'linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%)', 'borderBottom': '2px solid #e94560'}),
                            dbc.CardBody([
                                html.Div(id='insecure-practices-table')
                            ], style={'backgroundColor': '#1a1a2e'})
                        ], className="specula-card")
                    ], width=12)
                ])
            ]
        ),
        
        # Attack Paths Tab
        dbc.Tab(
            label="🕸️ Attack Paths",
            tab_id="tab-attack",
            children=[
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.H4("Attack Path Simulation", style={'color': '#e94560', 'margin': '0'})
                            ], style={'background': 'linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%)', 'borderBottom': '2px solid #e94560'}),
                            dbc.CardBody([
                                dcc.Graph(id='attack-graph')
                            ], style={'backgroundColor': '#1a1a2e'})
                        ], className="specula-card mb-4")
                    ], width=8),
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.H4("Attack Path Analysis", style={'color': '#e94560', 'margin': '0'})
                            ], style={'background': 'linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%)', 'borderBottom': '2px solid #e94560'}),
                            dbc.CardBody([
                                html.Div(id='attack-analysis')
                            ], style={'backgroundColor': '#1a1a2e'})
                        ], className="specula-card")
                    ], width=4)
                ])
            ]
        ),
        
        # Mitigation Tab
        dbc.Tab(
            label="🛡️ Mitigation",
            tab_id="tab-mitigation",
            children=[
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.H4("Security Recommendations", style={'color': '#e94560', 'margin': '0'})
                            ], style={'background': 'linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%)', 'borderBottom': '2px solid #e94560'}),
                            dbc.CardBody([
                                html.Div(id='mitigation-recommendations')
                            ], style={'backgroundColor': '#1a1a2e'})
                        ], className="specula-card")
                    ], width=12)
                ])
            ]
        ),
        
        # Network Traffic Tab
        dbc.Tab(
            label="📡 Network Traffic",
            tab_id="tab-traffic",
            children=[
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.H4("Real-time Traffic Monitoring", style={'color': '#e94560', 'margin': '0'})
                            ], style={'background': 'linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%)', 'borderBottom': '2px solid #e94560'}),
                            dbc.CardBody([
                                dcc.Graph(id='traffic-monitor'),
                                html.Div(id='anomaly-alerts', style={'marginTop': '20px'}),
                                dcc.Interval(
                                    id='traffic-interval',
                                    interval=2000,  # Update every 2 seconds
                                    n_intervals=0
                                )
                            ], style={'backgroundColor': '#1a1a2e'})
                        ], className="specula-card")
                    ], width=12)
                ])
            ]
        ),
        
        # Security Report Tab
        dbc.Tab(
            label="📋 Security Report",
            tab_id="tab-report",
            children=[
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.H4("Security Report", style={'color': '#e94560', 'margin': '0'})
                            ], style={'background': 'linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%)', 'borderBottom': '2px solid #e94560'}),
                            dbc.CardBody([
                                html.Div(id='security-report-content'),
                                dbc.Button(
                                    "📥 Download Report as JSON",
                                    id='download-report-btn',
                                    color="primary",
                                    className="mt-3"
                                )
                            ], style={'backgroundColor': '#1a1a2e'})
                        ], className="specula-card")
                    ], width=12)
                ])
            ]
        )
    ], 
    id="tabs", 
    active_tab="tab-overview",
    style={
        'backgroundColor': '#1a1a2e',
        'borderRadius': '10px',
        'overflow': 'hidden'
    })
], 
fluid=True, 
style={
    'background': 'linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%)',
    'minHeight': '100vh',
    'padding': '20px',
    'color': 'white'
})

def create_enhanced_table(df, table_type):
    """Create enhanced tables with custom styling"""
    if df.empty:
        return html.P("No data available.", style={'color': '#a0a0a0', 'textAlign': 'center'})
    
    # Define column configurations based on table type
    column_configs = {
        'devices': {
            'ip': 'IP Address',
            'type': 'Device Type',
            'manufacturer': 'Manufacturer',
            'os': 'OS',
            'firmware': 'Firmware',
            'predicted_risk': 'Risk Level'
        },
        'vulnerabilities': {
            'ip': 'IP Address',
            'device_type': 'Device Type',
            'cve_id': 'CVE ID',
            'cvss_score': 'CVSS Score',
            'severity': 'Severity',
            'description': 'Description'
        },
        'insecure': {
            'ip': 'IP Address',
            'device_type': 'Device Type',
            'findings': 'Security Issues',
            'risk_level': 'Risk Level'
        },
        'recommendations': {
            'device_ip': 'Device IP',
            'issue_type': 'Issue Type',
            'issue': 'Issue',
            'severity': 'Severity',
            'recommendation': 'Recommendation',
            'priority': 'Priority'
        }
    }
    
    columns = column_configs.get(table_type, {})
    visible_columns = [col for col in columns.keys() if col in df.columns]
    
    # Create data table
    table = dash_table.DataTable(
        columns=[{"name": columns[col], "id": col} for col in visible_columns],
        data=df[visible_columns].to_dict('records'),
        style_header={
            'backgroundColor': '#0f3460',
            'color': 'white',
            'fontWeight': 'bold',
            'border': '1px solid #1a1a2e'
        },
        style_cell={
            'backgroundColor': '#1a1a2e',
            'color': 'white',
            'border': '1px solid #0f3460',
            'textAlign': 'left',
            'overflow': 'hidden',
            'textOverflow': 'ellipsis',
            'maxWidth': 0,
        },
        style_data_conditional=[
            {
                'if': {
                    'filter_query': '{predicted_risk} = "Critical"',
                    'column_id': 'predicted_risk'
                },
                'backgroundColor': '#8b0000',
                'color': 'white'
            },
            {
                'if': {
                    'filter_query': '{predicted_risk} = "High"',
                    'column_id': 'predicted_risk'
                },
                'backgroundColor': '#ff4444',
                'color': 'white'
            },
            {
                'if': {
                    'filter_query': '{predicted_risk} = "Medium"',
                    'column_id': 'predicted_risk'
                },
                'backgroundColor': '#ffa500',
                'color': 'white'
            },
            {
                'if': {
                    'filter_query': '{predicted_risk} = "Low"',
                    'column_id': 'predicted_risk'
                },
                'backgroundColor': '#00cc00',
                'color': 'white'
            }
        ],
        page_size=10,
        sort_action='native',
        filter_action='native',
        style_table={'overflowX': 'auto'},
        tooltip_data=[
            {column: {'value': str(value), 'type': 'markdown'}
             for column, value in row.items()}
            for row in df.to_dict('records')
        ],
        tooltip_duration=None
    )
    
    return table

# Enhanced Callbacks
@app.callback(
    [Output('status-message', 'children'),
     Output('output-div', 'children'),
     Output('risk-graph', 'figure'),
     Output('vulnerability-pie', 'figure'),
     Output('vulnerabilities-table', 'children'),
     Output('insecure-practices-table', 'children'),
     Output('attack-graph', 'figure'),
     Output('attack-analysis', 'children'),
     Output('mitigation-recommendations', 'children'),
     Output('total-devices', 'children'),
     Output('vulnerable-devices', 'children'),
     Output('high-risk-devices', 'children'),
     Output('security-score', 'children')],
    [Input('submit-button', 'n_clicks'),
     Input('network-scan-btn', 'n_clicks')],
    [State('ip-input', 'value'),
     State('type-input', 'value'),
     State('manufacturer-input', 'value'),
     State('os-input', 'value'),
     State('tabs', 'active_tab')]
)
def update_comprehensive_dashboard(scan_clicks, network_clicks, ip, device_type, manufacturer, os, active_tab):
    ctx = dash.callback_context
    triggered_id = ctx.triggered[0]['prop_id'].split('.')[0] if ctx.triggered else None
    
    global global_devices, global_vulnerabilities, global_insecure_practices, global_recommendations
    
    if triggered_id == 'network-scan-btn' and network_clicks:
        # Perform full network scan
        global_devices = specula_system.enhanced_device_discovery(network_scan=True)
        status_msg = dbc.Alert("🔍 Full network scan completed! Multiple devices discovered.", color="success")
        
    elif triggered_id == 'submit-button' and scan_clicks and all([ip, device_type, manufacturer, os]):
        # Manual device entry
        user_input = {'ip': ip, 'type': device_type, 'manufacturer': manufacturer, 'os': os}
        global_devices = specula_system.enhanced_device_discovery(user_input)
        status_msg = dbc.Alert("✅ Device scanned successfully! Vulnerabilities analyzed.", color="success")
        
    else:
        if global_devices.empty:
            # Return empty figures for graphs and empty divs for tables
            empty_figure = go.Figure()
            empty_figure.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                xaxis=dict(visible=False),
                yaxis=dict(visible=False),
                annotations=[dict(
                    text="No data available",
                    x=0.5,
                    y=0.5,
                    xref="paper",
                    yref="paper",
                    showarrow=False,
                    font=dict(size=16, color='white')
                )]
            )
            return [
                dbc.Alert("ℹ️ Enter device details or perform network scan to begin.", color="info"),
                html.P("No data available. Scan your network or add devices manually.", style={'color': '#a0a0a0', 'textAlign': 'center'}),
                empty_figure,  # risk-graph
                empty_figure,  # vulnerability-pie
                html.P("No vulnerabilities detected.", style={'color': '#a0a0a0', 'textAlign': 'center'}),  # vulnerabilities-table
                html.P("No insecure practices found.", style={'color': '#a0a0a0', 'textAlign': 'center'}),  # insecure-practices-table
                empty_figure,  # attack-graph
                html.P("No attack paths to analyze.", style={'color': '#a0a0a0', 'textAlign': 'center'}),  # attack-analysis
                html.P("No recommendations available.", style={'color': '#a0a0a0', 'textAlign': 'center'}),  # mitigation-recommendations
                "0", "0", "0", "0"  # statistics
            ]
        else:
            status_msg = dbc.Alert("📊 Displaying current network security assessment.", color="info")
    
    if not global_devices.empty:
        # Perform comprehensive analysis
        global_vulnerabilities = specula_system.comprehensive_vulnerability_assessment(global_devices)
        global_insecure_practices = specula_system.check_insecure_practices(global_devices)
        
        # Generate risk predictions
        risk_predictions = []
        for _, device in global_devices.iterrows():
            device_vulns = global_vulnerabilities[global_vulnerabilities['ip'] == device['ip']]
            risk, _ = specula_system.predict_comprehensive_risk(risk_models, device.to_dict(), device_vulns)
            risk_predictions.append(risk)
        
        global_devices['predicted_risk'] = risk_predictions
        
        # Generate recommendations
        global_recommendations = specula_system.generate_mitigation_recommendations(
            global_vulnerabilities, global_insecure_practices
        )
        
        # Calculate statistics
        total_devices = len(global_devices)
        vulnerable_devices = len(global_vulnerabilities['ip'].unique())
        high_risk_devices = len(global_devices[global_devices['predicted_risk'].isin(['High', 'Critical'])])
        security_score = max(0, 100 - (vulnerable_devices / total_devices * 100)) if total_devices > 0 else 100
        
        # Enhanced Risk Graph
        risk_figure = go.Figure(data=[go.Scatter(
            x=global_devices['ip'],
            y=global_devices['predicted_risk'],
            mode='markers+text',
            marker=dict(
                size=20,
                color=global_devices['predicted_risk'].map({'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}),
                colorscale=[[0, '#00cc00'], [0.33, '#ffa500'], [0.66, '#ff4444'], [1, '#8b0000']],
                cmin=0,
                cmax=3,
                line=dict(width=2, color='white')
            ),
            text=global_devices['predicted_risk'],
            textposition="middle center",
            hovertext=global_devices['type'] + ' - ' + global_devices['manufacturer'],
            hoverinfo='text'
        )])
        risk_figure.update_layout(
            title=dict(text="Device Risk Levels", font=dict(color='white', size=18)),
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            xaxis=dict(title=dict(text='IP Address', font=dict(color='white'))),
            yaxis=dict(title=dict(text='Risk Level', font=dict(color='white')))
        )
        
        # Enhanced Pie Chart
        if not global_vulnerabilities.empty:
            severity_counts = global_vulnerabilities['severity'].value_counts()
            pie_figure = go.Figure(data=[go.Pie(
                labels=severity_counts.index,
                values=severity_counts.values,
                hole=0.5,
                marker=dict(colors=['#00cc00', '#ffa500', '#ff4444', '#8b0000']),
                textinfo='label+percent',
                hoverinfo='label+value+percent'
            )])
        else:
            pie_figure = go.Figure(data=[go.Pie(
                labels=['No Vulnerabilities'],
                values=[1],
                hole=0.5,
                marker=dict(colors=['#00cc00'])
            )])
        pie_figure.update_layout(
            title=dict(text="Vulnerability Severity Distribution", font=dict(color='white', size=18)),
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'), showlegend=True,
            legend=dict(font=dict(color='white'))
        )
        
        # Enhanced Attack Graph
        attack_graph = specula_system.simulate_advanced_attack_paths(global_devices, global_vulnerabilities)
        
        if attack_graph and len(attack_graph.nodes()) > 0:
            pos = nx.spring_layout(attack_graph, k=3, iterations=50)
            
            # Create edge traces
            edge_traces = []
            for edge_type in ['vulnerability', 'network']:
                edge_x, edge_y = [], []
                for edge in attack_graph.edges(data=True):
                    if edge[2].get('type') == edge_type:
                        x0, y0 = pos[edge[0]]
                        x1, y1 = pos[edge[1]]
                        edge_x.extend([x0, x1, None])
                        edge_y.extend([y0, y1, None])
                
                color = '#e94560' if edge_type == 'vulnerability' else '#3498db'
                width = 3 if edge_type == 'vulnerability' else 1
                
                edge_traces.append(go.Scatter(
                    x=edge_x, y=edge_y, line=dict(width=width, color=color), 
                    mode='lines', name=f'{edge_type.title()} Connection',
                    hoverinfo='none'
                ))
            
            # Create node trace
            node_x, node_y, node_text, node_color = [], [], [], []
            for node in attack_graph.nodes():
                x, y = pos[node]
                node_x.append(x)
                node_y.append(y)
                node_text.append(f"IP: {node}<br>Type: {attack_graph.nodes[node]['device_type']}")
                node_color.append(2 if attack_graph.nodes[node].get('risk') == 'High' else 0)
            
            node_trace = go.Scatter(
                x=node_x, y=node_y, mode='markers+text', text=[node for node in attack_graph.nodes()],
                textposition="middle center", hovertext=node_text, hoverinfo='text',
                marker=dict(size=25, color=node_color, colorscale='YlOrRd', cmin=0, cmax=2,
                          line=dict(width=2, color='white'))
            )
            
            attack_figure = go.Figure(data=edge_traces + [node_trace])
            attack_figure.update_layout(
                title=dict(text='Advanced Attack Path Simulation', font=dict(color='white', size=18)),
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='white'),
                showlegend=True, xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                legend=dict(font=dict(color='white'))
            )
            
            # Attack analysis
            attack_analysis = html.Div([
                html.H5("Attack Path Analysis", style={'color': '#e94560'}),
                html.P(f"Total Nodes: {len(attack_graph.nodes())}"),
                html.P(f"Total Edges: {len(attack_graph.edges())}"),
                html.P(f"High-Risk Propagation Paths: {len([e for e in attack_graph.edges(data=True) if e[2].get('type') == 'vulnerability'])}"),
                html.Hr(),
                html.H6("Critical Paths:", style={'color': '#ff4444'}),
                html.Ul([html.Li(f"{edge[0]} → {edge[1]} (Risk: High)") 
                        for edge in attack_graph.edges(data=True) 
                        if edge[2].get('type') == 'vulnerability'][:3])
            ])
        else:
            attack_figure = go.Figure()
            attack_figure.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                xaxis=dict(visible=False), yaxis=dict(visible=False),
                annotations=[dict(text="No attack paths detected", x=0.5, y=0.5,
                                xref="paper", yref="paper", showarrow=False,
                                font=dict(size=16, color='white'))]
            )
            attack_analysis = html.P("No significant attack paths identified.", style={'color': '#a0a0a0', 'textAlign': 'center'})
        
        # Create tables with enhanced styling
        devices_table = create_enhanced_table(global_devices, 'devices')
        vulnerabilities_table = create_enhanced_table(global_vulnerabilities, 'vulnerabilities')
        insecure_table = create_enhanced_table(global_insecure_practices, 'insecure')
        recommendations_table = create_enhanced_table(global_recommendations, 'recommendations')
        
        return [
            status_msg, devices_table, risk_figure, pie_figure, vulnerabilities_table,
            insecure_table, attack_figure, attack_analysis, recommendations_table,
            str(total_devices), str(vulnerable_devices), str(high_risk_devices), f"{security_score:.1f}"
        ]
    
    return [status_msg] + [html.P("No data available.")] + [go.Figure()] * 3 + [html.Div()] * 4 + ["0"] * 4

# Real-time Monitoring Callbacks
@app.callback(
    [Output('monitor-btn', 'children'),
     Output('monitoring-interval', 'disabled')],
    [Input('monitor-btn', 'n_clicks')],
    [State('monitoring-interval', 'disabled')]
)
def toggle_real_time_monitoring(n_clicks, is_disabled):
    if n_clicks:
        if is_disabled:
            # Start monitoring
            specula_system.real_time_monitoring = True
            return "🛑 Stop Monitoring", False
        else:
            # Stop monitoring
            specula_system.real_time_monitoring = False
            return "🔄 Real-time Monitoring", True
    return "🔄 Real-time Monitoring", True

@app.callback(
    [Output('traffic-monitor', 'figure'),
     Output('anomaly-alerts', 'children')],
    [Input('traffic-interval', 'n_intervals')]
)
def update_traffic_monitor(n):
    global global_devices, global_traffic_data
    
    # Initialize global_traffic_data if it doesn't exist or is empty
    if 'global_traffic_data' not in globals() or global_traffic_data.empty:
        global_traffic_data = pd.DataFrame()
    
    if global_devices.empty:
        empty_fig = go.Figure()
        empty_fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
            annotations=[dict(
                text="No traffic data available",
                x=0.5,
                y=0.5,
                xref="paper",
                yref="paper",
                showarrow=False,
                font=dict(size=16, color='white')
            )]
        )
        return empty_fig, html.Div()
    
    try:
        # Generate new traffic data
        new_traffic = specula_system.simulate_network_traffic(global_devices)
        
        # Ensure new_traffic has the required columns
        if new_traffic.empty:
            # Create empty figure if no traffic data
            empty_fig = go.Figure()
            empty_fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                xaxis=dict(visible=False),
                yaxis=dict(visible=False),
                annotations=[dict(
                    text="No traffic data generated",
                    x=0.5,
                    y=0.5,
                    xref="paper",
                    yref="paper",
                    showarrow=False,
                    font=dict(size=16, color='white')
                )]
            )
            return empty_fig, html.Div()
        
        # Update global traffic data
        if global_traffic_data.empty:
            global_traffic_data = new_traffic
        else:
            global_traffic_data = pd.concat([global_traffic_data, new_traffic], ignore_index=True).tail(50)
        
        # Create traffic monitor figure
        fig = px.line(
            global_traffic_data, 
            x='timestamp', 
            y='traffic_volume', 
            color='ip',
            title='Real-time Network Traffic Monitoring'
        )
        
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            xaxis=dict(color='white'),
            yaxis=dict(color='white'),
            legend=dict(font=dict(color='white'))
        )
        
        # Check for anomalies
        anomaly_alerts = []
        if not new_traffic.empty:
            anomalies = new_traffic[new_traffic['is_anomaly'] == True]
            for _, anomaly in anomalies.iterrows():
                anomaly_alerts.append(
                    dbc.Alert(
                        f"🚨 Anomaly detected: High traffic volume from {anomaly['ip']} ({anomaly['device_type']})",
                        color="danger",
                        style={'marginBottom': '10px'}
                    )
                )
        
        return fig, html.Div(anomaly_alerts)
    
    except Exception as e:
        # Return empty figure in case of any error
        print(f"Error in traffic monitor: {e}")
        empty_fig = go.Figure()
        empty_fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
            annotations=[dict(
                text="Error loading traffic data",
                x=0.5,
                y=0.5,
                xref="paper",
                yref="paper",
                showarrow=False,
                font=dict(size=16, color='white')
            )]
        )
        return empty_fig, html.Div()

# Security Report Callbacks
@app.callback(
    Output('security-report-content', 'children'),
    [Input('report-btn', 'n_clicks')]
)
def generate_security_report(n_clicks):
    global global_devices, global_vulnerabilities, global_insecure_practices, global_recommendations, global_security_report
    
    if n_clicks and not global_devices.empty:
        # Generate security report
        global_security_report = specula_system.generate_security_report(
            global_devices, global_vulnerabilities, global_insecure_practices, global_recommendations
        )
        
        # Create report content
        report_content = [
            html.H4(f"Security Report - {global_security_report['timestamp']}", style={'color': '#e94560'}),
            html.Hr(),
            
            html.H5("Executive Summary", style={'color': '#e94560'}),
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.H3(str(global_security_report['summary']['total_devices']), style={'color': '#e94560'}),
                        html.P("Total Devices")
                    ], className="stat-card p-3")
                ], width=3),
                dbc.Col([
                    html.Div([
                        html.H3(str(global_security_report['summary']['vulnerable_devices']), style={'color': '#ff4444'}),
                        html.P("Vulnerable Devices")
                    ], className="stat-card p-3")
                ], width=3),
                dbc.Col([
                    html.Div([
                        html.H3(str(global_security_report['summary']['high_risk_devices']), style={'color': '#ffa500'}),
                        html.P("High Risk Devices")
                    ], className="stat-card p-3")
                ], width=3),
                dbc.Col([
                    html.Div([
                        html.H3(f"{global_security_report['summary']['security_score']:.1f}", style={'color': '#00cc00'}),
                        html.P("Security Score")
                    ], className="stat-card p-3")
                ], width=3),
            ]),
            
            html.H5("Critical Findings", style={'color': '#e94560', 'marginTop': '20px'}),
        ]
        
        if global_security_report['critical_findings']:
            for finding in global_security_report['critical_findings']:
                report_content.append(
                    dbc.Alert([
                        html.Strong(f"{finding['type']} - {finding['device']}"),
                        html.Br(),
                        f"Issue: {finding['issue']}",
                        html.Br(),
                        f"Severity: {finding['severity']}",
                        html.Br(),
                        f"Description: {finding['description']}"
                    ], color="danger" if finding['severity'] in ['Critical', 'High'] else "warning")
                )
        else:
            report_content.append(
                dbc.Alert("No critical findings detected.", color="success")
            )
            
        report_content.extend([
            html.H5("Recommendations", style={'color': '#e94560', 'marginTop': '20px'}),
        ])
        
        if global_security_report['recommendations']:
            for rec in global_security_report['recommendations']:
                report_content.append(
                    dbc.Card([
                        dbc.CardBody([
                            html.H6(f"Device: {rec['device_ip']}", style={'color': '#e94560'}),
                            html.P(f"Issue: {rec['issue']}"),
                            html.P(f"Recommendation: {rec['recommendation']}"),
                            html.P(f"Priority: {rec['priority']}", 
                                  style={'color': '#ff4444' if rec['priority'] == 'Immediate' else '#ffa500' if rec['priority'] == 'High' else '#00cc00'})
                        ])
                    ], className="mb-2")
                )
        else:
            report_content.append(
                dbc.Alert("No recommendations available.", color="info")
            )
        
        return report_content
    
    return html.P("Click 'Generate Security Report' to create a comprehensive security assessment.", 
                 style={'color': '#a0a0a0', 'textAlign': 'center'})

@app.callback(
    Output("download-report", "data"),
    [Input("download-report-btn", "n_clicks")],
    prevent_initial_call=True,
)
def download_security_report(n_clicks):
    global global_security_report
    if global_security_report:
        report_json = json.dumps(global_security_report, indent=2)
        return dict(content=report_json, filename="specula_security_report.json")

@app.callback(
    Output('network-status', 'children'),
    [Input('network-scan-btn', 'n_clicks')]
)
def update_network_status(n_clicks):
    if n_clicks:
        return dbc.Alert("🔄 Network scanning in progress...", color="warning")
    return ""

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8050)
