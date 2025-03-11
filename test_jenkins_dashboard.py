import unittest
import json
import os
import sys
import tempfile
import shutil
from unittest.mock import patch, MagicMock
from flask import session

# Add parent directory to path to import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app

class TestJenkinsDashboard(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.secret_key = 'test-key'
        self.app = app.test_client()
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Sample settings for testing
        self.settings = {
            "ssl": {
                "default_cert_mode": "system",
                "default_ca_path": "/etc/pki/CA/certs",
                "allow_insecure_ssl": True,
                "verify_ssl_by_default": True
            },
            "general": {
                "max_upload_size": 16,
                "session_lifetime": 24,
                "enable_url_analysis": True,
                "enable_guest_access": False
            },
            "jenkins": {
                "base_url": "https://jenkins-test.example.com",
                "api_token": "test-token",
                "username": "test-user",
                "auto_fetch_logs": True,
                "ssl_verify": True,
                "poll_interval": 15,
                "import_builds": {
                    "limit": 50,
                    "days": 30,
                    "include_successful": True
                },
                "api_keys": ["jenkins-test-key", "jenkins-analyzer-test-key"]
            }
        }
        
        # Write settings to a temporary file
        self.settings_path = os.path.join(self.test_dir, 'settings.json')
        with open(self.settings_path, 'w') as f:
            json.dump(self.settings, f)
        
        # Create a logs directory in the test dir
        self.logs_dir = os.path.join(self.test_dir, 'logs')
        os.makedirs(self.logs_dir, exist_ok=True)
        
        # Sample log content
        self.sample_log = "Starting build #1234\nCloning repository\nCompiling code\nRunning tests\nTest failures found\nBuild failed"
        self.sample_log_path = os.path.join(self.test_dir, 'sample_log.txt')
        with open(self.sample_log_path, 'w') as f:
            f.write(self.sample_log)
        
    def tearDown(self):
        # Clean up temporary files
        shutil.rmtree(self.test_dir)
    
    @patch('app.open')
    @patch('app.os.path.join')
    def test_jenkins_dashboard_access_denied(self, mock_path_join, mock_open):
        # Test access to Jenkins dashboard without login
        with app.test_request_context():
            # Ensure no session data
            if 'username' in session:
                session.pop('username')
            
            response = self.app.get('/jenkins-dashboard')
            self.assertEqual(response.status_code, 302)  # Should redirect to login
            self.assertIn('/login', response.location)
    
    @patch('app.open')
    @patch('app.os.path.join')
    def test_jenkins_dashboard_access_allowed(self, mock_path_join, mock_open):
        # Mock the open call to return our settings
        mock_file = MagicMock()
        mock_file.__enter__.return_value = MagicMock()
        mock_file.__enter__.return_value.read.return_value = json.dumps(self.settings)
        mock_open.return_value = mock_file
        
        # Mock path.join to return our settings path
        mock_path_join.return_value = self.settings_path
        
        # Set up session for logged in user
        with self.app.session_transaction() as sess:
            sess['username'] = 'testuser'
            sess['role'] = 'user'
        
        # Test access to Jenkins dashboard with login
        response = self.app.get('/jenkins-dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Jenkins CI/CD Monitoring Dashboard', response.data)
        self.assertIn(b'Build Success Rate', response.data)
        self.assertIn(b'Pipeline Stage Analysis', response.data)
        self.assertIn(b'AI-Powered Insights', response.data)
    
    @patch('app.open')
    @patch('app.os.path.join')
    def test_export_jenkins_report(self, mock_path_join, mock_open):
        # Mock the open call to return our settings
        mock_file = MagicMock()
        mock_file.__enter__.return_value = MagicMock()
        mock_file.__enter__.return_value.read.return_value = json.dumps(self.settings)
        mock_open.return_value = mock_file
        
        # Mock path.join to return our settings path
        mock_path_join.return_value = self.settings_path
        
        # Set up session for logged in user
        with self.app.session_transaction() as sess:
            sess['username'] = 'testuser'
            sess['role'] = 'user'
        
        # Test export report
        response = self.app.get('/export_jenkins_report')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'application/json')
        
        # Parse the JSON response and validate
        report_data = json.loads(response.data)
        self.assertIn('metrics', report_data)
        self.assertIn('pipeline_stats', report_data)
        self.assertIn('insights', report_data)
        self.assertEqual(report_data['generated_by'], 'testuser')
    
    @patch('app.open')
    @patch('app.os.path.join')
    def test_analyze_url(self, mock_path_join, mock_open):
        # Mock the open calls
        def mock_open_func(file_path, mode='r'):
            if mode == 'r' and 'settings.json' in str(file_path):
                mock_file = MagicMock()
                mock_file.__enter__.return_value.read.return_value = json.dumps(self.settings)
                return mock_file
            elif mode == 'r' and 'sample_log.txt' in str(file_path):
                mock_file = MagicMock()
                mock_file.__enter__.return_value.read.return_value = self.sample_log
                return mock_file
            elif mode == 'w':
                # This is for writing the log file
                mock_file = MagicMock()
                return mock_file
            return MagicMock()
        
        mock_open.side_effect = mock_open_func
        
        # Mock path.join to create log path
        mock_path_join.return_value = os.path.join(self.logs_dir, 'jenkins_url_test.txt')
        
        # Set up session for logged in user
        with self.app.session_transaction() as sess:
            sess['username'] = 'testuser'
            sess['role'] = 'user'
        
        # Test analyze URL endpoint
        response = self.app.post('/analyze_url', data={
            'logurl': 'https://jenkins.example.com/job/test-project/123/console',
            'verify_ssl': 'on'
        }, follow_redirects=False)
        
        self.assertEqual(response.status_code, 302)  # Expect redirect

if __name__ == '__main__':
    unittest.main()