# https-security-checker




```markdown
# HTTPS Security Checker

The `https-security-checker` is a simple Python script designed to assess the security of a website using HTTPS. It checks whether a website is using HTTPS, analyzes the SSL certificate, and looks for security-related meta tags in the HTML.

## Features

- Checks if the website is using HTTPS.
- Verifies SSL certificate details.
- Analyzes HTML for security-related meta tags.
- Provides basic information about the security of the website.

## Usage

1. Install the required dependencies:
   ```bash
   pip install requests beautifulsoup4
   ```

2. Run the script:
   ```bash
   python https_security_checker.py
   ```

3. Enter the URL of the website when prompted.

## Example

```bash
Enter the website URL: https://example.com
```
if you have problems with pip install you need to do this



1. Install `virtualenv` using the system package manager:

   ```bash
   sudo apt-get update
   sudo apt-get install python3-virtualenv
   ```

2. Create a virtual environment:

   ```bash
   virtualenv venv
   ```

3. Activate the virtual environment:

   ```bash
   source venv/bin/activate
   ```

   If you are using a Windows system, the activation command is:

   ```bash
   .\venv\Scripts\activate
   ```

4. Now, you should see `(venv)` in your terminal prompt, indicating that you are in the virtual environment.

5. Install the required packages using `pip`:

   ```bash
   pip install requests beautifulsoup4
   ```

Now you have a virtual environment with the necessary packages installed. You can run your Python script within this virtual environment. When you're done, you can deactivate the virtual environment using the command `deactivate`.

```bash
deactivate
```

Remember to activate the virtual environment (`source venv/bin/activate`) each time you want to use it and install packages specific to your project within that environment.

## Disclaimer

This tool is intended for educational and informational purposes only. It does not guarantee a comprehensive security assessment, and additional tools and methods may be required for a thorough analysis.
```

