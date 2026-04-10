# =============================================================================
# license_client.py — QuantTerminal Pro
# License verification on the client (embedded in the app)
# =============================================================================
import hashlib, hmac, json, os, platform, subprocess, uuid
from datetime import datetime, timedelta

import requests

# ── Config — change SERVER_URL to your deployed server ───────────────────────
SERVER_URL  = "https://your-server.railway.app"   # ← DEINE Server-URL hier
SECRET_KEY  = "CHANGE_THIS_IN_PRODUCTION_NOW"     # ← muss mit Server übereinstimmen
KEY_FILE    = os.path.join(os.path.dirname(__file__), ".license")
CACHE_FILE  = os.path.join(os.path.dirname(__file__), ".lic_cache")
GRACE_HOURS = 48   # Offline-Toleranz: 48h ohne Server-Check

# =============================================================================
# MACHINE ID — eindeutige Hardware-ID
# =============================================================================
def get_machine_id() -> str:
    """Generate a stable machine identifier from hardware info."""
    parts = []
    # Hostname
    parts.append(platform.node())
    # CPU / processor
    parts.append(platform.processor() or platform.machine())
    # Windows: use MachineGuid from registry
    if platform.system() == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography"
            )
            guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            parts.append(guid)
        except Exception:
            pass
    # macOS: use IOPlatformSerialNumber
    elif platform.system() == "Darwin":
        try:
            serial = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                timeout=3
            ).decode()
            for line in serial.split("\n"):
                if "IOPlatformSerialNumber" in line:
                    parts.append(line.split("=")[-1].strip().strip('"'))
                    break
        except Exception:
            pass
    # Linux: use /etc/machine-id
    else:
        try:
            with open("/etc/machine-id") as f:
                parts.append(f.read().strip())
        except Exception:
            pass

    combined = "|".join(parts) or str(uuid.getnode())
    return hashlib.sha256(combined.encode()).hexdigest()[:32]


# =============================================================================
# KEY FILE
# =============================================================================
def load_key() -> str:
    try:
        with open(KEY_FILE) as f:
            return f.read().strip()
    except Exception:
        return ""


def save_key(key: str):
    with open(KEY_FILE, "w") as f:
        f.write(key.strip())


# =============================================================================
# CACHE (for offline grace period)
# =============================================================================
def load_cache() -> dict:
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_cache(data: dict):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(data, f)
    except Exception:
        pass


def verify_signature(data: dict) -> bool:
    """Verify HMAC signature from server to prevent response tampering."""
    sig = data.pop("_sig", None)
    if not sig:
        return False
    payload = json.dumps(data, sort_keys=True)
    expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


# =============================================================================
# MAIN VERIFICATION
# =============================================================================
class LicenseStatus:
    def __init__(self, valid: bool, reason: str = "", email: str = "",
                 expires: str = "", offline: bool = False):
        self.valid   = valid
        self.reason  = reason
        self.email   = email
        self.expires = expires
        self.offline = offline

    def days_remaining(self) -> int:
        if not self.expires:
            return 0
        try:
            exp = datetime.fromisoformat(self.expires)
            delta = exp - datetime.utcnow()
            return max(0, delta.days)
        except Exception:
            return 0

    def __bool__(self):
        return self.valid


REASON_MESSAGES = {
    "invalid_key":      "Ungültiger Lizenzschlüssel.",
    "expired":          "Lizenz abgelaufen. Bitte Abo verlängern.",
    "suspended":        "Lizenz wurde gesperrt. Bitte Support kontaktieren.",
    "too_many_devices": "Zu viele Geräte. Max. 2 Geräte pro Lizenz.",
    "no_key":           "Kein Lizenzschlüssel eingegeben.",
    "offline":          "Server nicht erreichbar — Offline-Modus aktiv.",
    "cache_expired":    "Offline-Toleranz abgelaufen. Bitte Internet-Verbindung herstellen.",
}


def verify_license(key: str = None) -> LicenseStatus:
    """
    Verify license against server.
    Falls back to cache if server unreachable (grace period: 48h).
    """
    if not key:
        key = load_key()
    if not key:
        return LicenseStatus(False, "no_key")

    key = key.upper().strip()
    machine_id = get_machine_id()

    # ── Try online verification ───────────────────────────────────────────────
    try:
        resp = requests.post(
            f"{SERVER_URL}/v1/verify",
            json={"key": key, "machine_id": machine_id},
            timeout=6,
        )
        resp.raise_for_status()
        data = resp.json()

        sig_ok = verify_signature(data)
        # Note: verify_signature pops _sig, so data is now clean

        if not sig_ok:
            # Don't trust unsigned responses
            return LicenseStatus(False, "invalid_response")

        if data.get("valid"):
            status = LicenseStatus(
                valid   = True,
                email   = data.get("email",""),
                expires = data.get("expires",""),
            )
            # Update cache
            save_cache({
                "key":       key,
                "valid":     True,
                "email":     data.get("email",""),
                "expires":   data.get("expires",""),
                "cached_at": datetime.utcnow().isoformat(),
            })
            save_key(key)
            return status
        else:
            reason = data.get("reason","invalid_key")
            return LicenseStatus(False, reason)

    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.Timeout:
        pass
    except Exception:
        pass

    # ── Offline fallback ─────────────────────────────────────────────────────
    cache = load_cache()
    if not cache or cache.get("key") != key:
        return LicenseStatus(False, "offline")

    try:
        cached_at  = datetime.fromisoformat(cache["cached_at"])
        hours_gone = (datetime.utcnow() - cached_at).total_seconds() / 3600
        if hours_gone > GRACE_HOURS:
            return LicenseStatus(False, "cache_expired")
    except Exception:
        return LicenseStatus(False, "offline")

    # Check cached expiry
    try:
        exp = datetime.fromisoformat(cache.get("expires",""))
        if datetime.utcnow() > exp:
            return LicenseStatus(False, "expired", expires=cache["expires"])
    except Exception:
        pass

    return LicenseStatus(
        valid   = True,
        offline = True,
        email   = cache.get("email",""),
        expires = cache.get("expires",""),
    )


def get_reason_message(reason: str) -> str:
    return REASON_MESSAGES.get(reason, f"Fehler: {reason}")
