import io
import json
import socket
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from rocs import cli, update
from rocs.common import Env, CommandRefused, is_read_only, Report
from rocs.iocs import load_ioc_dir, parse_stix_bundle
from rocs.collectors import linux, macos, windows, android
from rocs import report as R
from tests import helpers as H


def sev(rep, s):
    return [f for f in rep.findings if f.severity == s]


class TestIOCs(unittest.TestCase):
    def test_parse_kinds_and_malware_names(self):
        with H.tmpdir() as t:
            s = load_ioc_dir(H.make_ioc_dir(Path(t)))
        self.assertEqual(s.problems, [])
        self.assertIn("evil-spy.example", s.get("domain"))
        self.assertIn("c2.bad-tracker.example", s.get("domain"))      # url on own host -> host
        self.assertIn("wild.example", s.get("domain"))                # wildcard stripped
        self.assertEqual(s.get("process")["fakespyd"].malware, "FakeSpy (TEST ONLY)")
        self.assertIn("com.fake.stalker", s.get("android_package"))
        self.assertIn("aabbcc", s.get("android_cert_sha1"))
        self.assertIn("x@evil-spy.example", s.get("email"))
        self.assertEqual(s.match_domain("a.b.wild.example").value, "wild.example")
        self.assertIsNone(s.match_domain("notevil-spy.example"))

    def test_checksum_mismatch_is_skipped_and_reported(self):
        with H.tmpdir() as t:
            d = H.make_ioc_dir(Path(t))
            (d / "fake.stix2").write_text('{"type":"bundle","objects":[]}')
            s = load_ioc_dir(d)
        self.assertTrue(any("Checksum mismatch" in p for p in s.problems))
        self.assertEqual(s.counts(), {})

    def test_missing_manifest(self):
        with H.tmpdir() as t:
            s = load_ioc_dir(Path(t))
        self.assertTrue(s.problems)


class TestUpdate(unittest.TestCase):
    def test_mvt_index_parser(self):
        e = update.parse_mvt_index((H.FIX / "mvt_index.yaml").read_text())
        self.assertEqual(len(e), 2)
        self.assertEqual(e[0]["url"], "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2")

    def test_fetch_refuses_non_allowlisted(self):
        for bad in ("http://raw.githubusercontent.com/x", "https://evil.example/x.stix2"):
            with self.assertRaises(ValueError):
                update._fetch(bad, ["raw.githubusercontent.com"])

    def test_update_records_url_and_checksum_without_network(self):
        bundle = (H.FIX / "fake_iocs.stix2").read_bytes()
        index = (H.FIX / "mvt_index.yaml").read_bytes()
        fetched = []

        def fake_fetch(url, hosts):
            fetched.append(url)
            return index if url.endswith(".yaml") else bundle
        with H.tmpdir() as t:
            t = Path(t)
            src = H.w(t / "sources.json", json.dumps({
                "indexes": [{"name": "idx", "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"}],
                "files": [{"name": "echap", "url": "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/stalkerware.stix2"}],
                "allowed_hosts": ["raw.githubusercontent.com"],
                "allowed_owners": ["AmnestyTech", "AssoEchap", "mvt-project"]}))
            with mock.patch.object(update, "_fetch", fake_fetch):
                rc = update.run_update(src, t / "iocs", log=lambda *a: None)
            m = json.loads((t / "iocs/manifest.json").read_text())
            self.assertEqual(rc, 0)
            self.assertEqual(len(m["files"]), 2)
            self.assertFalse(any("random-person" in u for u in fetched))   # owner allowlist
            for f in m["files"]:
                self.assertTrue(f["url"].startswith("https://raw.githubusercontent.com/"))
                self.assertEqual(len(f["sha256"]), 64)
            self.assertEqual(load_ioc_dir(t / "iocs").problems, [])


class TestReadOnlyGuards(unittest.TestCase):
    def test_allowlist(self):
        ok = [["ps", "-axo", "pid=,comm="], ["crontab", "-l"], ["adb", "devices"],
              ["adb", "-s", "X", "shell", "pm", "list", "packages", "-i"],
              ["adb", "-s", "X", "shell", "settings", "get", "secure", "enabled_accessibility_services"]]
        bad = [["rm", "-rf", "/"], ["crontab", "-r"], ["adb", "-s", "X", "shell", "pm", "uninstall", "a"],
               ["adb", "-s", "X", "shell", "settings", "put", "secure", "x", "1"],
               ["adb", "-s", "X", "shell", "pm", "list", "packages;", "reboot"],
               ["adb", "-s", "X", "install", "a.apk"], ["adb", "pull", "/sdcard"],
               ["schtasks", "/delete"], ["powershell", "-Command", "Remove-Item"], ["curl", "x"],
               ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-CimInstance Win32_Service; Remove-Item C:\\x"]]
        for a in ok:
            self.assertTrue(is_read_only(a), a)
        for a in bad:
            self.assertFalse(is_read_only(a), a)

    def test_env_run_refuses(self):
        with self.assertRaises(CommandRefused):
            Env(runner=lambda a: (0, "", "")).run(["rm", "x"])

    def test_no_network_during_scan(self):
        with cli.no_network():
            with self.assertRaises(cli.NetworkBlocked):
                socket.create_connection(("example.com", 443))
            with self.assertRaises(cli.NetworkBlocked):
                socket.getaddrinfo("example.com", 443)
        # restored afterwards
        self.assertFalse(getattr(socket.create_connection, "__name__", "") == "_blocked")


class TestLinux(unittest.TestCase):
    def setUp(self):
        self._t = H.tmpdir()
        self.t = Path(self._t.name)
        self.root = self.t / "root"
        H.linux_tree(self.root)
        self.iocs = load_ioc_dir(H.make_ioc_dir(self.t))
        self.env = Env(root=self.root, home=Path("/home/alice"),
                       runner=H.fake_runner({("crontab", "-l"): (0, "0 3 * * * /usr/bin/backup\n")}))

    def tearDown(self):
        self._t.cleanup()

    def test_findings(self):
        before = H.snapshot(self.root)
        rep = linux.collect(self.env, self.iocs)
        self.assertEqual(before, H.snapshot(self.root), "scan modified the fixture tree")
        titles = " | ".join(f.title for f in rep.findings)
        high = sev(rep, "high")
        self.assertTrue(any("fakespyd" in f.title and f.category == "process" for f in high), titles)
        self.assertTrue(any(f.indicator and f.indicator["kind"] == "sha256" for f in high), titles)
        self.assertTrue(any("evil-spy.example" in f.title and f.category == "systemd" for f in high), titles)
        self.assertTrue(any("c2.bad-tracker.example" in f.title and f.category == "cron" for f in high), titles)
        self.assertTrue(any(f.category == "autostart" for f in high), titles)
        self.assertTrue(any(f.category == "browser-history" and "evil-spy.example" in f.title for f in high))
        self.assertTrue(any(f.category == "browser-history" and "wild.example" in f.title for f in high))
        # system-path name collision is graded low, not high
        diag = [f for f in rep.findings if "diagnosticd" in f.title]
        self.assertEqual([f.severity for f in diag], ["low"])
        med = " | ".join(f.title for f in sev(rep, "medium"))
        self.assertIn("temporary, shared or hidden", med)
        self.assertIn("ld.so.preload", med)
        self.assertFalse(any("wikipedia" in f.title for f in rep.findings))
        self.assertTrue(rep.not_checked)

    def test_clean_tree_never_claims_clean(self):
        clean = self.t / "clean"
        H.w(clean / "proc/1/comm", "init\n")
        rep = linux.collect(Env(root=clean, home=Path("/home/bob"),
                                runner=H.fake_runner({})), self.iocs)
        d = R.build(rep, {"total": 9, "age_days": 1.0}, [])
        self.assertEqual(d["verdict"], "no_known_indicators")
        self.assertIn("NOT proof", d["verdict_text"])
        self.assertTrue(any("not proof" in m for m in d["must_tell_human"]))
        self.assertNotIn("is clean.", R.to_text(d))
        self.assertIn("WHAT I COULD NOT CHECK", R.to_text(d))


class TestMacOS(unittest.TestCase):
    def test_findings(self):
        with H.tmpdir() as t:
            t = Path(t)
            root, home = t / "root", "/Users/alice"
            iocs = load_ioc_dir(H.make_ioc_dir(t))
            H.w(root / "Users/alice/Library/LaunchAgents/com.x.plist",
                __import__("plistlib").dumps({"Label": "com.x", "ProgramArguments": ["/Users/Shared/.x/fakespyd", "-d"]},
                                             fmt=__import__("plistlib").FMT_BINARY))
            H.w(root / "Library/LaunchDaemons/com.ok.plist",
                __import__("plistlib").dumps({"Label": "com.ok", "Program": "/usr/local/bin/okd"}))
            H.w(root / "Library/LaunchAgents/broken.plist", b"not a plist")
            H.safari_history(root / "Users/alice/Library/Safari/History.db",
                             [("https://evil-spy.example/x", 4), ("https://apple.com/", 9)])
            runner = H.fake_runner({
                ("ps",): (0, "  1 /sbin/launchd\n 55 /usr/libexec/diagnosticd\n 77 /Applications/Foo.app/Contents/MacOS/fakespyd\n"),
                ("profiles", "list"): (0, "_computerlevel[1] attribute: profileIdentifier: com.corp.mdm\n"),
            })
            before = H.snapshot(root)
            rep = macos.collect(Env(root=root, home=Path(home), runner=runner), iocs)
            self.assertEqual(before, H.snapshot(root))
        cats_high = {f.category for f in sev(rep, "high")}
        self.assertTrue({"process", "launchd", "browser-history"} <= cats_high, cats_high)
        self.assertTrue(any(f.category == "launchd" for f in sev(rep, "medium")))
        self.assertTrue(any(f.category == "config-profile" for f in sev(rep, "low")))
        self.assertTrue(any("broken.plist" in n["area"] for n in rep.not_checked))
        self.assertTrue(any("macOS 13+" in n["area"] for n in rep.not_checked))
        self.assertEqual(runner.calls, [["ps", "-axo", "pid=,comm="], ["profiles", "list"]])


class TestWindows(unittest.TestCase):
    def test_findings(self):
        with H.tmpdir() as t:
            t = Path(t)
            iocs = load_ioc_dir(H.make_ioc_dir(t))
            root = t / "root"
            H.chrome_history(root / "Users/alice/AppData/Local/Google/Chrome/User Data/Default/History",
                             [("https://c2.bad-tracker.example/u", 1)])
            sched = ('"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run"\n'
                     '"PC","\\Updater","N/A","Ready","Interactive","N/A","0","me","C:\\Users\\Public\\upd.exe /s"\n')
            runner = H.fake_runner({
                ("tasklist",): (0, '"System","4","Services","0","1 K"\n"fakespyd.exe","999","Console","1","2 K"\n'),
                ("powershell",): (0, json.dumps([{"Name": "Good", "PathName": "C:\\Windows\\System32\\svchost.exe -k x", "State": "Running"},
                                                 {"Name": "Beacon", "PathName": "C:\\Tools\\b.exe --host evil-spy.example", "State": "Running"}])),
                ("schtasks", "/query"): (0, sched),
            })
            env = Env(root=root, home=Path("/Users/alice"), runner=runner,
                      run_keys=[{"key": "HKCU\\...\\Run", "name": "x",
                                 "value": "C:\\Users\\alice\\AppData\\Local\\Temp\\x.exe"}])
            rep = windows.collect(env, iocs)
        # fakespyd.exe: name 'fakespyd' IOC is without .exe; basename is fakespyd.exe -> no exact match
        self.assertTrue(any(f.category == "service" and "evil-spy.example" in f.title for f in sev(rep, "high")))
        self.assertTrue(any(f.category == "browser-history" for f in sev(rep, "high")))
        meds = {f.category for f in sev(rep, "medium")}
        self.assertTrue({"scheduled-task", "run-key"} <= meds, meds)


class TestAndroid(unittest.TestCase):
    def _runner(self, devices="List of devices attached\nSER123\tdevice\n"):
        sh = ("adb", "-s", "SER123", "shell")
        return H.fake_runner({
            ("adb", "devices"): (0, devices),
            sh + ("getprop", "ro.product.model"): (0, "Pixel Test\n"),
            sh + ("getprop", "ro.build.version.release"): (0, "15\n"),
            sh + ("pm", "list", "packages", "-i"): (0, "package:com.android.settings  installer=null\n"
                                                       "package:com.fake.stalker  installer=null\n"
                                                       "package:com.bank.app  installer=com.android.vending\n"
                                                       "package:com.unknown.helper  installer=null\n"),
            sh + ("pm", "list", "packages", "-s"): (0, "package:com.android.settings\n"),
            sh + ("pm", "list", "packages", "-f", "-3"): (0, "package:/data/app/~~a==/com.unknown.helper-1/base.apk=com.unknown.helper\n"),
            sh + ("sha256sum",): (0, H.FAKE_SHA + "  /data/app/x/base.apk\n"),
            sh + ("dumpsys", "device_policy"): (0, "  admin=ComponentInfo{com.unknown.helper/com.unknown.helper.Admin}\n"),
            sh + ("settings", "get", "secure", "enabled_accessibility_services"):
                (0, "com.unknown.helper/.Acc:com.fake.stalker/.Svc\n"),
            sh + ("settings", "get", "secure", "enabled_notification_listeners"): (0, "null\n"),
        })

    def test_findings(self):
        with H.tmpdir() as t:
            iocs = load_ioc_dir(H.make_ioc_dir(Path(t)))
        rep = android.collect(Env(runner=self._runner()), iocs, None, hash_apks=True)
        self.assertTrue(any(f.category == "android-package" and "com.fake.stalker" in f.title for f in sev(rep, "high")))
        self.assertTrue(any(f.category == "android-apk-hash" for f in sev(rep, "high")))
        meds = {f.category for f in sev(rep, "medium")}
        self.assertEqual(meds, {"android-device-admin", "android-accessibility"})
        side = [f for f in rep.findings if f.category == "android-sideloaded"][0]
        self.assertIn("com.unknown.helper", side.evidence["packages"])
        d = R.build(rep, {"total": 9, "age_days": 1}, [])
        self.assertTrue(any("Stalkerware safety" in m for m in d["must_tell_human"]))

    def test_unauthorised_device(self):
        rep = android.collect(Env(runner=self._runner("List of devices attached\nSER123\tunauthorized\n")),
                              load_ioc_dir(Path("/nonexistent")))
        self.assertIn("Allow USB debugging", rep.not_checked[0]["reason"])
        self.assertEqual(rep.findings, [])
        self.assertEqual(R.build(rep, {"total": 9, "age_days": 1}, [])["verdict"], "scan_incomplete")


class TestCLI(unittest.TestCase):
    def _args(self, **kw):
        base = dict(out="-", json=True, platform="linux", ioc_dir="/nonexistent", android_serial=None,
                    android_hash=False, force=False)
        base.update(kw)
        return SimpleNamespace(**base)

    def test_json_contract_fields_and_exit_code(self):
        with H.tmpdir() as t:
            t = Path(t)
            root = t / "root"
            H.linux_tree(root)
            ioc = H.make_ioc_dir(t)
            out = t / "r.json"
            env = Env(root=root, home=Path("/home/alice"), runner=H.fake_runner({}))
            with redirect_stderr(io.StringIO()):
                code, d = cli.run_scan(self._args(out=str(out), ioc_dir=str(ioc)), env)
            on_disk = json.loads(out.read_text())
            for k in ("verdict", "verdict_text", "must_tell_human", "findings", "checked", "not_checked",
                      "limitations", "indicators", "mode", "schema_version"):
                self.assertIn(k, on_disk)
            self.assertEqual(code, cli.EXIT_FOUND)
            self.assertFalse(on_disk["mode"]["samples_uploaded"])
            # refuses to overwrite
            with redirect_stderr(io.StringIO()):
                code2, _ = cli.run_scan(self._args(out=str(out), ioc_dir=str(ioc)), env)
            self.assertEqual(code2, cli.EXIT_ERROR)

    def test_no_iocs_means_incomplete(self):
        with H.tmpdir() as t:
            root = Path(t) / "r"
            H.w(root / "proc/1/comm", "init\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code, d = cli.run_scan(self._args(), Env(root=root, runner=H.fake_runner({})))
        self.assertEqual(d["verdict"], "scan_incomplete")
        self.assertEqual(code, cli.EXIT_ERROR)

    def test_ios_points_to_mvt(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code, _ = cli.run_scan(self._args(platform="ios"))
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("MVT", err.getvalue())

    def test_scan_code_has_no_network_imports(self):
        pkg = Path(cli.__file__).parent
        for f in list(pkg.glob("*.py")) + list((pkg / "collectors").glob("*.py")):
            if f.name == "update.py":
                continue
            src = f.read_text()
            for bad in ("urllib.request", "http.client", "requests", "urlopen", "ftplib", "smtplib"):
                self.assertNotIn(bad, src, f"{f.name} references {bad}")


class TestFalsePositiveGuards(unittest.TestCase):
    """Regressions from the first real macOS run: a URL indicator for one GitHub repo matched
    every github.com visit, and a hidden-folder argument flagged an ordinary program."""

    def _iocs(self):
        from rocs.iocs import IOCSet
        b = {"objects": [
            {"type": "indicator", "id": "indicator--1", "name": "RepoRAT",
             "pattern": "[url:value = 'https://github.com/someone/android-rat']"},
            {"type": "indicator", "id": "indicator--2", "name": "C2",
             "pattern": "[url:value = 'https://c2.bad.example/upload']"}]}
        s = IOCSet()
        for i in parse_stix_bundle(b, "TEST"):
            s.add(i)
        return s

    def test_url_on_shared_platform_matches_only_that_path(self):
        s = self._iocs()
        self.assertNotIn("github.com", s.get("domain"))
        self.assertIsNone(s.match_domain("github.com"))
        self.assertIsNone(s.match_url("https://github.com/"))
        self.assertIsNone(s.match_url("https://github.com/someone/android-rat-fork"))
        self.assertIsNotNone(s.match_url("https://github.com/someone/android-rat"))
        self.assertIsNotNone(s.match_url("https://www.github.com/someone/android-rat/releases?x=1"))

    def test_url_on_dedicated_host_still_matches_whole_host(self):
        self.assertIsNotNone(self._iocs().match_domain("c2.bad.example"))

    def test_hidden_folder_heuristic_checks_program_not_arguments(self):
        from rocs.common import check_command_line
        from rocs.iocs import IOCSet
        rep = Report("macos")
        check_command_line(rep, IOCSet(), "launchd", "tunnel",
                           "/opt/tool/bin/agent run --token-file /Users/a/.secret/token")
        check_command_line(rep, IOCSet(), "launchd", "venv-app",
                           "/Users/a/proj/.venv/bin/python /Users/a/proj/app.py")
        self.assertEqual(rep.findings, [])
        check_command_line(rep, IOCSet(), "launchd", "script",
                           "/usr/bin/python3 -I /Users/a/.hidden-thing/run.py")
        check_command_line(rep, IOCSet(), "launchd", "binary", "/Users/a/.cache2/x/agent")
        self.assertEqual(len(sev(rep, "medium")), 2)


if __name__ == "__main__":
    unittest.main()
