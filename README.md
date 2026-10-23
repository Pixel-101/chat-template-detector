# SentinelOne User & Role Export

Pulls every user from the SentinelOne Management API and flattens each
person's role/scope assignments into one row per user-per-role-per-scope —
the same shape as the console's manual "Users" CSV export, but scriptable
and repeatable.

This was built to support the CRDC SentinelOne authorization matrix: a
document showing who has what access, where, so it can be reviewed rather
than checked account-by-account in the console.

## What it does

- Calls `GET /web/api/v2.1/users`, paging through all results automatically
- For each user, unpacks their `scopeRoles` into separate rows (one account
  can hold different roles at different scopes — e.g. Admin account-wide,
  Viewer on a specific site)
- Cleans up names where possible: `firstname.lastname@bilfinger.com` becomes
  `Firstname Lastname`. Service/admin accounts identified only by an internal
  ID number (e.g. `adm.idm123456@...`) are left as-is — those still need a
  manual name lookup, there's no way to derive a real name from an ID alone
- Writes everything out to a CSV

## Before you run it, you need

1. **Python 3** installed (`python --version` to check)
2. The `requests` library: `pip install requests`
3. **Your own SentinelOne API token.** Generate one from your own account:
   SentinelOne console → Settings → Users → your account → Generate API
   Token. It's shown once only — copy it immediately.

## Running it

Set your token as an environment variable in your terminal before running —
do not paste a real token into the script itself:

**Command Prompt:**
```
set S1_API_TOKEN=your-token-here
```

**PowerShell:**
```
$env:S1_API_TOKEN = "your-token-here"
```

Then, in that same terminal window:
```
python S1_users.py
```

**Important:** the script currently falls back to the placeholder text
`"insert personal api token here"` if `S1_API_TOKEN` isn't set — it will
not stop and warn you. If you forget to set the environment variable
first, it'll run anyway and fail with a confusing authentication error
from the API instead of a clear message. If that happens, it almost
always means the environment variable wasn't set in that terminal session
— set it and run the script again in the same window.

It'll print progress per page as it pulls, then write the result to the
path set in `OUTPUT_PATH` near the top of the script (defaults to
`C:\Temp\s1_users_export.csv` — change this to wherever you want it, and
make sure that folder exists first).


## Output

A CSV with one row per user-per-role-per-scope, columns: Full name, Email,
Source, Verification Status, 2FA status, Allowed to generate API token,
Last connected, Created at, Role, Account, Site, Scope level.

This output file contains real names and email addresses — treat it as you
would any export of personal data. Don't commit output CSVs to this repo
(see `.gitignore`).

