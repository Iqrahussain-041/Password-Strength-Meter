# 🔐 Professional Password Strength Analyzer

## Overview
This is a web application built with Streamlit that helps you analyze the strength of your passwords and generate strong, secure passwords. It provides real-time feedback on password strength and offers a password generator for creating robust passwords.

## Features
- **Password Strength Analysis**: Evaluates the strength of a password based on length and character diversity
- **Strength Levels**: Provides clear feedback on password strength
  - Very Weak
  - Weak
  - Moderate
  - Strong
  - Very Strong
- **Password History**: Temporary session-based password tracking
- **Strong Password Generator**: Creates random, secure passwords

## Installation

### Prerequisites
- Python 3.8+
- pip

### Setup
1. Clone the repository
```bash
git clone https://github.com/yourusername/password-strength-analyzer.git
cd password-strength-analyzer
```

2. Create a virtual environment (optional but recommended)
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

## Running the Application
```bash
streamlit run main.py
```

## Security Notes
- Password history is session-based and not persistent
- Passwords are not stored permanently
- Use this tool for educational and personal password management purposes

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
MIT License 
