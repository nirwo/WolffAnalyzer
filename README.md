# Log Analyzer

A web application for analyzing system logs to identify errors, warnings, and critical issues.

## Features

- Upload log files or paste log content for analysis
- Extract errors, exceptions, and warnings in chronological order
- Identify critical issues versus minor warnings
- Trace error chains to find root causes
- Pattern recognition in component interactions
- Plain language explanations of errors
- Troubleshooting recommendations
- Save and view previous analyses

## Advanced Features (NEW)

### Adaptive Pattern Matching
- **Real-time Pattern Adjustment**: Fix patterns directly from error entries with the "Fix Pattern" button
- **Pattern Testing**: Test regex patterns against log content to ensure accuracy before saving
- **Pattern Effectiveness Tracking**: Monitors pattern effectiveness and false positive rates
- **False Positive Reporting**: Report false matches to continuously improve pattern recognition

### Smart Component Extraction
- **Enhanced Filtering**: Intelligently filters out false components like timestamps, paths, and common words
- **Path Detection**: Avoids misclassifying Windows and Unix paths as components
- **Unit Recognition**: Filters out numbers with units of measurement that are not actual components

### Intuitive User Interface
- **Interactive Pattern Management**: Edit patterns directly from error entries
- **Pattern Match Highlighting**: Clearly shows which pattern matched each log entry
- **Pattern Creation**: Generate new patterns directly from log entries with one click
- **Error Clustering**: Groups similar errors to reduce noise and improve analysis

## Installation

### Prerequisites

- Python 3.7+
- pip (Python package manager)

### Setup

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/log-analyzer.git
   cd log-analyzer
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   ```

3. Activate the virtual environment:
   - On Windows:
     ```
     venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```
     source venv/bin/activate
     ```

4. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Start the application:
   ```
   python app.py
   ```

2. Open a web browser and go to:
   ```
   http://localhost:5000
   ```

3. Use the web interface to:
   - Upload log files (supported formats: .log, .txt)
   - Paste log content directly for analysis
   - View analysis results including errors, timestamps, and recommendations
   - Browse previous analyses

## Log Format Support

The analyzer supports common log formats with:
- Various timestamp formats (ISO, common date formats)
- Standard error levels (ERROR, WARNING, INFO, DEBUG, etc.)
- Component identification from log structure
- Stack trace recognition

## Development

### Project Structure

```
log_analyzer/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── static/                # Static assets
│   ├── css/               # CSS stylesheets
│   │   └── style.css      # Custom styles
│   └── js/                # JavaScript files
│       └── script.js      # Custom scripts
├── templates/             # HTML templates
│   ├── index.html         # Home page
│   ├── analysis.html      # Analysis results page
│   └── logs.html          # Previous logs page
└── logs/                  # Uploaded logs storage
```

### Adding New Features

To extend the analyzer with new capabilities:

1. Enhance the log parsing in `parse_log()` function
2. Add new analysis algorithms in `analyze_log_entries()`
3. Extend recommendations in `generate_recommendations()`
4. Update the UI templates accordingly

### Pattern Management

Patterns are the core of the analysis engine. To manage patterns:

1. **View/edit existing patterns** in the Patterns page
2. **Add new patterns** manually or generate them from log entries
3. **Test patterns** against logs before saving
4. **Report false positives** to improve pattern accuracy over time

### Improving Component Detection

To enhance component extraction for better log analysis:

1. Update the `enhanced_extract_component()` function in `app.py`
2. Add new filters for known false positives
3. Implement domain-specific component recognition for your log types
4. Verify improvements with the test suite

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.