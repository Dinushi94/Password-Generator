# Password Manager

A secure desktop application for generating and managing passwords with encryption.

## Features

- Create, store, and manage passwords securely
- Generate strong passwords with customizable settings
- Encrypt all passwords with a master password
- Copy passwords to clipboard with one click
- Simple and intuitive user interface

## How to Run Locally

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/password-manager.git
   cd password-manager
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python main.py
   ```

4. Upon first run, you'll be prompted to create a master password.

## Project Structure

- `main.py` - Application entry point
- `password_generator.py` - Password generation functionality
- `password_storage.py` - Secure storage with encryption
- `gui.py` - User interface built with tkinter
- `requirements.txt` - Required Python packages

## How to Deploy as a Standalone Application

### Using PyInstaller

1. Install PyInstaller:
   ```
   pip install pyinstaller
   ```

2. Create a standalone executable:
   ```
   pyinstaller --onefile --windowed --name PasswordManager main.py
   ```

3. Find the executable in the `dist` folder

### Distribution Options

#### Option 1: Direct Distribution
- Share the executable file directly with users
- Note that antivirus software might flag unknown executables

#### Option 2: Create an Installer
1. Use Inno Setup (Windows) to create an installer:
   - Download and install [Inno Setup](https://jrsoftware.org/isinfo.php)
   - Create a new script using the wizard
   - Add your executable and any additional files
   - Build the installer

#### Option 3: GitHub Releases
1. Create a GitHub release
2. Upload the executable or installer
3. Share the release URL with users

## Security Notes

- All passwords are encrypted using Fernet symmetric encryption
- The master password is never stored directly
- The encrypted password file cannot be decrypted without the master password
- For maximum security, don't store the password file in cloud-synced folders

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.