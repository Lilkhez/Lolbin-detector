# rules.py
# This file contains all LOLBIN detection rules.
# Each entry defines a binary, its MITRE ATT&CK mapping,
# and the suspicious command line patterns to look for.
# To add a new LOLBIN later, just add a new entry here.
# No other file needs to change.

LOLBIN_RULES = {
    "certutil.exe": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "severity": "High",
        "suspicious_patterns": [
            "-urlcache",
            "-decode",
            "-encode",
            "http://",
            "https://"
        ]
    },
    "mshta.exe": {
        "technique_id": "T1218.005",
        "technique_name": "Signed Binary Proxy Execution: Mshta",
        "severity": "High",
        "suspicious_patterns": [
            "http://",
            "https://",
            "javascript:",
            "vbscript:",
            ".hta"
        ]
    },
    "regsvr32.exe": {
        "technique_id": "T1218.010",
        "technique_name": "Signed Binary Proxy Execution: Regsvr32",
        "severity": "High",
        "suspicious_patterns": [
            "/s",
            "/u",
            "/i:",
            "scrobj.dll",
            "http://",
            "https://"
        ]
    },
    "rundll32.exe": {
        "technique_id": "T1218.011",
        "technique_name": "Signed Binary Proxy Execution: Rundll32",
        "severity": "Medium",
        "suspicious_patterns": [
            "javascript:",
            "http://",
            "shell32.dll,shellexec_rundll",
            "shell32.dll,openas_rundll",
            "url.dll",
            "advpack.dll",
            "shdocvw.dll",
            "FileProtocolHandler",
            "RegisterOCX"
        ]
    },
    "wscript.exe": {
        "technique_id": "T1059.005",
        "technique_name": "Command and Scripting Interpreter: VBScript",
        "severity": "Medium",
        "suspicious_patterns": [
            ".vbs",
            ".js",
            "http://",
            "https://",
            "//e:",
            "//b"
        ]
    },
    "bitsadmin.exe": {
        "technique_id": "T1197",
        "technique_name": "BITS Jobs",
        "severity": "Medium",
        "suspicious_patterns": [
            "/transfer",
            "/download",
            "/addfile",
            "http://",
            "https://"
        ]
    },
    "powershell.exe": {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "severity": "High",
        "suspicious_patterns": [
            "-encodedcommand",
            "-enc",
            "-nop",
            "-windowstyle hidden",
            "iex",
            "invoke-expression",
            "downloadstring",
            "downloadfile",
            "bypass",
            "invoke-webrequest",
            "system.net.webclient",
            "-command",
            "frombase64string"
        ]
    },
    "cscript.exe": {
        "technique_id": "T1059.005",
        "technique_name": "Command and Scripting Interpreter: VBScript",
        "severity": "Medium",
        "suspicious_patterns": [
            ".vbs",
            ".js",
            ".wsf",              # Windows Script File — often used to chain scripts
            "http://",
            "https://",
            "//e:",              # specifies script engine — used to run arbitrary code
            "//b"                # batch mode — suppresses errors and dialogs
        ]
    },
    "msiexec.exe": {
        "technique_id": "T1218.007",
        "technique_name": "Signed Binary Proxy Execution: Msiexec",
        "severity": "High",
        "suspicious_patterns": [
            "/q",                # quiet install — no user interface shown
            "http://",           # remote MSI package
            "https://",          # remote MSI package
            "/i",                # install flag used with remote URL
            "temp\\",            # installation from temp folder — suspicious location
            "appdata\\"          # installation from appdata — suspicious location
        ]
    },
    "wmic.exe": {
        "technique_id": "T1047",
        "technique_name": "Windows Management Instrumentation",
        "severity": "High",
        "suspicious_patterns": [
            "process call create",  # creates a new process — lateral movement technique
            "shadowcopy delete",    # deletes shadow copies — ransomware behaviour
            "os get",               # OS reconnaissance
            "/node:",               # remote execution on another machine
            "xsl",                  # XSL transformation — used for code execution
            "useraccount",          # user account enumeration
            "startup"               # startup item manipulation
        ]
    },
    "vssadmin.exe": {
        "technique_id": "T1490",
        "technique_name": "Inhibit System Recovery",
        "severity": "High",
        "suspicious_patterns": [
            "delete shadows",    # deletes ALL shadow copies — classic ransomware
            "resize shadowstorage", # shrinks shadow storage to prevent recovery
            "delete shadowstorage",  # removes shadow copy storage entirely
            "list shadows"       # enumerating shadow copies before deletion
        ]
    },
    "wevtutil.exe": {
        "technique_id": "T1070.001",
        "technique_name": "Indicator Removal: Clear Windows Event Logs",
        "severity": "High",
        "suspicious_patterns": [
            "cl",                # clear-log shorthand — wipes an event log
            "clear-log",         # full form of log clearing command
            "el",                # enumerate logs — reconnaissance before clearing
            "/e:false",          # disables a log channel
            "sl"                 # set-log — used to disable logging
        ]
    },
    "schtasks.exe": {
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task",
        "severity": "Medium",
        "suspicious_patterns": [
            "/create",           # creating a new scheduled task
            "/sc minute",        # runs every minute — common for persistence
            "/sc onlogon",       # runs on user login — persistence mechanism
            "/sc onstart",       # runs on system start — persistence mechanism
            "http://",           # task downloading remote content
            "https://",          # task downloading remote content
            "appdata\\",         # task running from suspicious location
            "temp\\"             # task running from temp folder
        ]
    },
    "reg.exe": {
        "technique_id": "T1112",
        "technique_name": "Modify Registry",
        "severity": "Medium",
        "suspicious_patterns": [
            "add",               # adding registry keys
            "currentversion\\run",  # run key — classic persistence location
            "currentversion\\runonce", # runonce key — executes once on startup
            "disableregistrytools",  # disabling regedit — defence evasion
            "http://",           # URL stored in registry — download cradle setup
            "powershell",        # PowerShell stored in registry for persistence
            "cmd.exe"            # cmd stored in registry for persistence
        ]
    },
    "sc.exe": {
        "technique_id": "T1543.003",
        "technique_name": "Create or Modify System Process: Windows Service",
        "severity": "High",
        "suspicious_patterns": [
            "create",            # creating a new service
            "binpath=",          # service binary path — can point to malicious exe
            "start= auto",       # service starts automatically — persistence
            "type= own",         # service type own process
            "http://",           # remote binary path
            "temp\\",            # service binary in temp folder
            "appdata\\"          # service binary in appdata
        ]
    },
    "installutil.exe": {
        "technique_id": "T1218.004",
        "technique_name": "Signed Binary Proxy Execution: InstallUtil",
        "severity": "High",
        "suspicious_patterns": [
            "/logfile=",         # suppress log output — stealth
            "/logtoconsole=false", # hide console output
            "/u",                # uninstall mode used to trigger code execution
            "appdata\\",         # executing assembly from suspicious location
            "temp\\"             # executing assembly from temp folder
        ]
    },
    "cmstp.exe": {
        "technique_id": "T1218.003",
        "technique_name": "Signed Binary Proxy Execution: CMSTP",
        "severity": "High",
        "suspicious_patterns": [
            "/s",                # silent install — no UI shown
            "/ns",               # no status — suppresses dialogs
            "http://",           # remote INF file
            "https://",          # remote INF file
            ".inf",              # INF file execution — can contain malicious commands
            "appdata\\",         # INF file in suspicious location
            "temp\\"             # INF file in temp folder
        ]
    },
    "esentutl.exe": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "severity": "Medium",
        "suspicious_patterns": [
            "/y",                # copy file — can copy across network
            "/vss",              # volume shadow copy access — bypass file locks
            "/d",                # defragment mode used for file operations
            "http://",           # remote file copy
            "\\\\"               # UNC path — copying from network share
        ]
    },
    "desktopimgdownldr.exe": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "severity": "High",
        "suspicious_patterns": [
            "/lockscreenurl:",   # downloads file via lock screen image feature
            "http://",           # remote file download
            "https://",          # remote file download
            "appdata\\",         # file saved to suspicious location
            "temp\\"             # file saved to temp folder
        ]
    },
    "regasm.exe": {
        "technique_id": "T1218.009",
        "technique_name": "Signed Binary Proxy Execution: Regsvcs/Regasm",
        "severity": "High",
        "suspicious_patterns": [
            "/u",                # unregister — triggers code execution
            "appdata\\",         # assembly in suspicious location
            "temp\\",            # assembly in temp folder
            ".dll",              # DLL assembly registration
            "/codebase"          # registers assembly without strong name — suspicious
        ]
    },
    "forfiles.exe": {
        "technique_id": "T1202",
        "technique_name": "Indirect Command Execution",
        "severity": "Medium",
        "suspicious_patterns": [
            "/p",                # path parameter
            "/m",                # search mask
            "/c",                # command to execute — can run arbitrary commands
            "cmd",               # executing cmd through forfiles
            "powershell",        # executing PowerShell through forfiles
            "http://",           # remote content
            "/s"                 # recursive search through subdirectories
        ]
    }
}

