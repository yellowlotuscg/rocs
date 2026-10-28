"""Android over adb (USB debugging, no root): packages vs stalkerware IOCs,
device-admin apps, accessibility services, notification listeners."""
from __future__ import annotations

import re

from ..common import Report, Env
from ..iocs import IOCSet

KNOWN_STORES = {"com.android.vending", "com.amazon.venezia", "com.sec.android.app.samsungapps",
                "com.huawei.appmarket", "com.xiaomi.market", "com.google.android.packageinstaller"}


def _sh(env: Env, serial: str, *cmd: str) -> tuple[int, str]:
    rc, out, _ = env.run(["adb", "-s", serial, "shell", *cmd])
    return rc, out


def _pick_device(env: Env, rep: Report, serial: str | None) -> str | None:
    rc, out, err = env.run(["adb", "devices"])
    if rc != 0:
        rep.skip("Android device", f"adb not available or failed ({(err or '').strip()[:120]}). "
                 "Install Android platform-tools and enable USB debugging.")
        return None
    devs = [ln.split()[0] for ln in out.splitlines()[1:] if ln.strip().endswith("\tdevice") or ln.strip().endswith(" device")]
    unauth = [ln.split()[0] for ln in out.splitlines()[1:] if "unauthorized" in ln]
    if serial:
        if serial in devs:
            return serial
        rep.skip("Android device", f"device {serial} not connected/authorised")
        return None
    if len(devs) == 1:
        return devs[0]
    if not devs:
        why = "the phone shows an 'Allow USB debugging?' prompt that must be accepted" if unauth else \
              "no device connected over adb"
        rep.skip("Android device", why)
    else:
        rep.skip("Android device", f"{len(devs)} devices connected; pass --android-serial")
    return None


def _components(value: str) -> set[str]:
    value = (value or "").strip()
    if not value or value == "null":
        return set()
    return {c.split("/", 1)[0] for c in value.split(":") if c}


def collect(env: Env, iocs: IOCSet, serial: str | None = None, hash_apks: bool = False) -> Report:
    rep = Report("android")
    s = _pick_device(env, rep, serial)
    if not s:
        return rep
    _, model = _sh(env, s, "getprop", "ro.product.model")
    _, ver = _sh(env, s, "getprop", "ro.build.version.release")
    rep.ok("Device", None, f"{model.strip()} / Android {ver.strip()}")

    rc, out = _sh(env, s, "pm", "list", "packages", "-i")
    if rc != 0:
        rep.skip("Installed packages", "pm list packages failed")
        return rep
    pkgs: dict[str, str] = {}
    for ln in out.splitlines():
        m = re.match(r"package:(\S+)\s+installer=(\S+)", ln.strip())
        if m:
            pkgs[m.group(1)] = m.group(2)
    _, sysout = _sh(env, s, "pm", "list", "packages", "-s")
    system = {ln.split(":", 1)[1].strip() for ln in sysout.splitlines() if ln.startswith("package:")}

    bad = iocs.get("android_package")
    for p in sorted(pkgs):
        hit = bad.get(p)
        if hit:
            rep.add("high", "android-package", f"Installed app matches known stalkerware: {p}",
                    f"Package {p} is listed for {hit.malware}. Stalkerware usually means someone with "
                    "physical access installed it to monitor this phone.",
                    {"package": p, "installer": pkgs[p]},
                    {"kind": "android_package", "value": p, "malware": hit.malware, "source": hit.source},
                    "Before removing it, think about safety: removal can alert the person who installed "
                    "it. Talk to a domestic-violence advocate or stalkerware help line first (see README).")
    rep.ok("Installed packages vs stalkerware/spyware package IOCs", len(pkgs))

    def nonsys(names):
        return sorted(n for n in names if n not in system)

    _, dp = _sh(env, s, "dumpsys", "device_policy")
    admins = set(re.findall(r"ComponentInfo\{([^/}]+)/", dp))
    for a in nonsys(admins):
        if a in bad:
            continue
        rep.add("medium", "android-device-admin", f"Non-system app is a device administrator: {a}",
                "Device-admin rights can lock the phone, wipe it or block uninstalling. Work apps (MDM) "
                "use it legitimately; stalkerware uses it to stay installed.",
                {"package": a, "installer": pkgs.get(a, "?")}, None,
                "Settings > Security > Device admin apps: confirm you recognise it.")
    rep.ok("Device administrator apps", len(admins))

    _, acc = _sh(env, s, "settings", "get", "secure", "enabled_accessibility_services")
    accs = _components(acc)
    for a in nonsys(accs):
        if a in bad:
            continue
        rep.add("medium", "android-accessibility", f"Non-system app has accessibility access: {a}",
                "Accessibility access lets an app read the screen and act as you. Password managers and "
                "assistive apps use it legitimately; stalkerware relies on it.",
                {"package": a, "installer": pkgs.get(a, "?")}, None,
                "Settings > Accessibility: confirm you turned this on yourself.")
    rep.ok("Accessibility services", len(accs))

    _, nl = _sh(env, s, "settings", "get", "secure", "enabled_notification_listeners")
    nls = _components(nl)
    for a in nonsys(nls):
        if a in bad:
            continue
        rep.add("low", "android-notifications", f"App can read all notifications: {a}",
                "Notification access exposes message previews and 2FA codes.",
                {"package": a}, None, "Settings > Notifications > Device & app notifications: review.")
    rep.ok("Notification listeners", len(nls))

    side = sorted(p for p, inst in pkgs.items() if p not in system and inst not in KNOWN_STORES)
    if side:
        rep.add("info", "android-sideloaded", f"{len(side)} app(s) not installed from a known app store",
                "Sideloaded apps aren't necessarily bad, but stalkerware is almost always sideloaded.",
                {"packages": side[:100]}, None, "Review any you don't recognise.")

    if hash_apks and iocs.get("sha256"):
        _, paths = _sh(env, s, "pm", "list", "packages", "-f", "-3")
        n = 0
        for ln in paths.splitlines():
            m = re.match(r"package:(\S+\.apk)=(\S+)$", ln.strip())
            if not m:
                continue
            rc, h = _sh(env, s, "sha256sum", m.group(1))
            if rc != 0 or not h.split():
                continue
            n += 1
            digest = h.split()[0].lower()
            hit = iocs.get("sha256").get(digest)
            if hit:
                rep.add("high", "android-apk-hash", f"APK hash matches known stalkerware: {m.group(2)}",
                        f"{m.group(1)} SHA-256 {digest} is listed for {hit.malware}.",
                        {"package": m.group(2), "sha256": digest},
                        {"kind": "sha256", "value": digest, "malware": hit.malware, "source": hit.source},
                        "Same safety guidance as above before removing.")
        rep.ok("APK SHA-256 hashes (user apps)", n)
    else:
        rep.skip("APK file hashes", "off by default (slow); add --android-hash")
    rep.skip("APK signing certificates", "would require copying APKs off the phone; use AndroidQF + "
             "`mvt-android check-androidqf`, or a professional, for that")
    rep.skip("Apps hidden by a root-level implant, SMS/call logs, system partition",
             "needs root or forensic acquisition")
    return rep
