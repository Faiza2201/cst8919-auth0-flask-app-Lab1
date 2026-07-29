

**Student Name**: Faiza Boudehane
**Student ID**: 041273470
**Course**: CST8919-300 DevOps Security and Compliance
**Semester**: Spring 2026


## Demo Video

🎥 [Watch Demo Video](https://youtu.be/r5XKUafYeLs)

# CST8919 Assignment 1: Securing and Monitoring an Authenticated Flask App

A Flask web application secured with Auth0 (SSO), deployed to Azure App Service, with custom activity logging monitored through Azure Log Analytics and an automated alert for excessive access to the protected route.

## Live App

- **URL**: https://auth0-flask-boud0219-cba2dpeaarebh2h7.canadacentral-01.azurewebsites.net

---

## Setup Steps

### 1. Auth0 Configuration

1. Create a free account at [Auth0](https://auth0.com) and log into the [dashboard](https://manage.auth0.com).
2. Go to **Applications → Applications → + Create Application**.
3. Choose **Regular Web Applications**, give it a name, and click **Create**.
4. On the **Settings** tab, note the **Domain**, **Client ID**, and **Client Secret**.
5. Scroll to **Application URIs** and set:
   - **Allowed Callback URLs**:
     ```
     http://localhost:3000/callback,
     https://<your-azure-app>.azurewebsites.net/callback
     ```
   - **Allowed Logout URLs**:
     ```
     http://localhost:3000,
     https://<your-azure-app>.azurewebsites.net
     ```
   - **Allowed Web Origins**:
     ```
     http://localhost:3000,
     https://<your-azure-app>.azurewebsites.net
     ```
6. Save changes.
7. Go to **Connections** tab of the app and confirm **Username-Password-Authentication** is enabled for this application.

### 2. Local Environment Setup

Clone the repo and set up a virtual environment:

```bash
git clone https://github.com/Faiza2201/cst8919-auth0-flask-app-Lab1.git
cd cst8919-auth0-flask-app-Lab1
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in real values:

```bash
cp .env.example .env
```

`.env` contents:
```
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_DOMAIN=your-tenant.us.auth0.com
APP_SECRET_KEY=generate-a-random-string-here
PORT=3000
```

Generate a secure `APP_SECRET_KEY` (used by Flask to sign session cookies — unrelated to Auth0):
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Run the app locally:
```bash
python app.py
```
Visit `http://localhost:3000`.

### 3. Azure Deployment

1. Create a **Resource Group** (e.g., `cst8919-assignment-rg`).
2. Create an **App Service (Web App)**:
   - Runtime stack: Python 3.12
   - OS: Linux
   - Plan: Free F1
3. In **Deployment Center**, connect the App Service to this GitHub repo (branch `main`) using **GitHub Actions** with **Basic authentication** (a federated/OIDC identity approach was attempted first but failed with a credential-mismatch error; Basic authentication via publish profile worked reliably).
4. In **Configuration → General settings → Stack settings**, set the **Startup Command**:
   ```
   gunicorn --bind=0.0.0.0 --timeout 600 app:app
   ```
5. In **Environment variables → App settings**, add:
   - `AUTH0_CLIENT_ID`
   - `AUTH0_CLIENT_SECRET`
   - `AUTH0_DOMAIN`
   - `APP_SECRET_KEY`
6. Add the deployed Azure URL to Auth0's Allowed Callback/Logout/Web Origin URLs (see Step 1 above).

**Note on HTTPS behind Azure's proxy**: Azure terminates SSL at its load balancer and forwards requests to the app as plain HTTP internally. Flask's `url_for(..., _external=True)` therefore generated `http://` redirect URIs instead of `https://`, causing an Auth0 "Callback URL mismatch" error. This was fixed by adding Werkzeug's `ProxyFix` middleware in `app.py`:
```python
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
```
This reads the `X-Forwarded-Proto` header Azure sends and correctly reports the original request as HTTPS.

### 4. Azure Monitoring Setup

1. Create a **Log Analytics Workspace** (`cst8919-law`) in the same region as the Web App (Canada Central).
2. On the Web App, go to **Diagnostic settings → + Add diagnostic setting**:
   - Enable **AppServiceConsoleLogs** (captures `app.logger` output) and **AppServiceHTTPLogs**.
   - Send to Log Analytics workspace `cst8919-law`.
3. On the Web App, go to **App Service logs**, and set **Application Logging (Filesystem)** to **On** — this is required on Linux App Service to actually pipe the app's stdout/stderr (which includes the Python logger output) into the log stream that diagnostic settings then routes to Log Analytics.

---

## Logging & Detection Logic

The Flask app uses `app.logger.info()` and `app.logger.warning()` to emit structured log lines for three events:

| Event | Level | Log format |
|---|---|---|
| Successful login | INFO | `LOGIN_SUCCESS user_id=<sub> email=<email> timestamp=<iso8601>` |
| Access to `/protected` (authenticated) | INFO | `PROTECTED_ACCESS user_id=<sub> email=<email> timestamp=<iso8601>` |
| Access to `/protected` while unauthenticated | WARNING | `UNAUTHORIZED_ACCESS path=/protected ip=<ip> timestamp=<iso8601>` |

These log lines land in stdout, which Azure App Service on Linux forwards as `AppServiceConsoleLogs`, and the diagnostic setting streams that into the `cst8919-law` Log Analytics Workspace, where they can be queried with KQL.

**Detection logic**: the goal is to flag a specific authenticated user who accesses the sensitive `/protected` endpoint an unusually high number of times in a short window — a pattern that could indicate a compromised session, a scripted/automated abuse attempt, or a misbehaving client, rather than normal human browsing.

---

## KQL Query

```kql
AppServiceConsoleLogs
| where ResultDescription has "PROTECTED_ACCESS"
| extend UserId = extract(@"user_id=(\S+)", 1, ResultDescription)
| summarize AccessCount = count(), LastAccess = max(TimeGenerated) by UserId
| where AccessCount > 3
```

**Explanation, line by line:**
- `where ResultDescription has "PROTECTED_ACCESS"` — filters the raw console log stream down to only the log lines emitted when an authenticated user hits `/protected`, ignoring login and unauthorized-access lines.
- `extend UserId = extract(@"user_id=(\S+)", 1, ResultDescription)` — uses a regular expression to pull the `user_id` value (Auth0's `sub` claim) out of the log text, since the raw log is unstructured text rather than a structured JSON column.
- `summarize AccessCount = count(), LastAccess = max(TimeGenerated) by UserId` — groups all matching log lines by user and counts how many `/protected` accesses each user has, plus the timestamp of their most recent access.
- `where AccessCount > 3` — keeps only users who exceeded the threshold (adjusted to 3 for faster demo/testing purposes; see Alert Configuration below).

When run manually for exploration/testing, the aggregation window is bounded by an added `| where TimeGenerated > ago(2m)` line (or by adjusting the query's time range picker in the Logs UI); when used inside the Alert Rule, the window is instead controlled by the rule's **Aggregation granularity** setting, so no manual time filter is needed inside the query itself.

---

## Alert Configuration

| Setting | Value used | Assignment spec |
|---|---|---|
| Threshold | AccessCount > 3 | AccessCount > 10 |
| Aggregation granularity | 2 minutes | 15 minutes |
| Frequency of evaluation | 1 minute | 1 minute |
| Alert threshold (rows) | Greater than 0 | Greater than 0 |
| Severity | 3 (Azure labels this "Informational"; corresponds to the assignment's "Severity 3 – Low") | 3 (Low) |
| Action Group | `email-alert-group` → email notification | Email notification |

**Note**: the count/window (3 accesses in 2 minutes vs. the assignment's 10 in 15 minutes) was intentionally lowered to allow faster, more reliable testing and demonstration of the alert firing and the email notification arriving, without needing to sustain 11+ requests over a full 15-minute window. The detection *logic* (regex extraction, per-user grouping, threshold-based filtering, Table rows measurement, email Action Group, Severity 3) is otherwise identical to what the assignment specifies.

Steps to recreate the alert rule:
1. **Monitor → Alerts → + Create → Alert rule**
2. **Scope**: Log Analytics Workspace `cst8919-law`
3. **Condition**: Custom log search, using the KQL query above; Measure = Table rows; Aggregation granularity = 2 minutes; Frequency of evaluation = 1 minute; Threshold = Greater than 0
4. **Actions**: Action group `email-alert-group` (Email notification type)
5. **Details**: Name = `Excessive Protected Route Access` (rule shown in portal as `alertLogin`); Severity = 3

---

## Testing

A `test-app.http` file (compatible with the VS Code REST Client extension) is included in the repo root. It tests:
- The home page (unauthenticated)
- Repeated unauthorized attempts to access `/protected`
- The logout endpoint

**Limitation**: REST Client requests do not carry a browser-based session cookie, so `.http` requests cannot simulate an *authenticated* user repeatedly hitting `/protected` (which is what actually triggers the alert). That traffic was generated manually through the browser: logging in via Auth0, then repeatedly clicking through to the Protected Page.

---

## What I Learned / Challenges / Improvements

**What I learned**: how Auth0's Regular Web Application flow integrates with Flask via Authlib, how Azure App Service on Linux surfaces application logs through `AppServiceConsoleLogs`, and how to write KQL to parse unstructured text logs into structured, groupable fields using `extract()`.

**Challenges faced**:
- The Auth0 Application was initially created as **Native** instead of **Regular Web Application**, causing an "Unknown client" error that required creating/using a differently-typed application.
- Azure's auto-generated GitHub Actions deployment using a **federated (OIDC) identity** repeatedly failed with a "no matching federated identity record" error; switching the Deployment Center's authentication type to **Basic authentication** (publish profile) resolved it.
- Azure's reverse proxy caused Flask to generate `http://` redirect URIs instead of `https://`, breaking Auth0's callback URL matching, until Werkzeug's `ProxyFix` middleware was added.

**How I'd improve detection in a real-world scenario**:
- Use the assignment's actual thresholds (>10 accesses in 15 minutes) rather than the faster demo thresholds used here, to avoid false positives from normal user browsing.
- Emit structured JSON logs (rather than plain text) so KQL queries can reference fields directly instead of relying on regex extraction, which is more fragile.
- Add IP-based and device/user-agent-based correlation, not just `user_id`, to catch session-hijacking scenarios where the same account is used from an unexpected location.
- Layer in a secondary, longer-window alert (e.g., >50 accesses in 24 hours) to catch slower, low-and-slow abuse patterns that a short window would miss.
- Route alerts to a security team channel (e.g., Teams/Slack webhook) in addition to email, for faster triage.
