# 4L1-Check

A local Flask application for learning how common web security findings are discovered and investigated. The Arabic interface lets you choose a check, submit a lab URL, and review the pages tested and findings returned.

## What the prototype checks

- Reflected and stored cross-site scripting (XSS)
- SQL injection indicators
- Cross-site request forgery (CSRF) indicators

The application crawls a bounded set of pages, inspects HTML forms, and displays results as leads for manual review. Stored XSS checks submit form data and can change a target’s state. Use a lab you own or have explicit permission to test.

## Run locally

Create a virtual environment with Python 3, then install the pinned dependencies.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

On Windows PowerShell, activate the environment with `.venv\Scripts\Activate.ps1`. Open `http://127.0.0.1:8000` in your browser and enter a URL from your authorized lab.

## Implementation

- `app.py` provides the Flask routes, crawl logic, and checks.
- `templates/` and `static/` contain the Arabic interface.
- The local server binds to `127.0.0.1`. It uses the `FLASK_SECRET_KEY` environment variable when set, or generates a session key for the current run.
- Requests checks HTTPS certificates against the local trust configuration.

Keep this educational prototype on a local machine. Review potential findings in the lab before recording them as confirmed vulnerabilities.
