export default {
  "title": "Activate administrator account",
  "introduction": "Set a password to verify your email address.",
  "password": "New password",
  "confirmation": "Confirm password",
  "minimum": "12 to 1024 UTF-8 bytes, no NUL character.",
  "strength": "Password diversity",
  "strengthHint": "A long passphrase with varied characters is recommended.",
  "submit": "Activate account",
  "busy": "Activating…",
  "done": "Your account is now active. You can sign in.",
  "login": "Go to sign in",
  "mismatch": "Passwords do not match.",
  "invalidPassword": "Choose a valid password with at least 12 characters.",
  "invalidToken": "Invitation link is missing or invalid.",
  "expired": "This link is invalid, expired or has already been used.",
  "failure": "Account activation is currently unavailable.",
  "strengthLevels": {
    "0": "Empty",
    "1": "Very low",
    "2": "Low",
    "3": "Moderate",
    "4": "Good"
  },
  "signIn": {
    "title": "Sign in",
    "intro": "Sign in to the administration panel.",
    "email": "Email address",
    "password": "Password",
    "busy": "Signing in…",
    "submit": "Sign in",
    "invalidCredentials": "Invalid credentials.",
    "failure": "Sign-in is currently unavailable."
  },
  "session": {
    "logout": "Log out",
    "checking": "Checking session…"
  }
} as const;
