class SystemObjectRegistry:
    """
    Curated registry of known legitimate operating-system processes, services, and objects.
    Used to prevent standard operating system entities from being misclassified as malware.
    
    Version: 1.0.0 (Auditable & Versioned Registry)
    """
    
    SYSTEM_OBJECTS_V1 = {
        "lsass", "lsass.exe",
        "svchost", "svchost.exe",
        "services", "services.exe",
        "explorer", "explorer.exe",
        "taskmgr", "taskmgr.exe",
        "cmd", "cmd.exe",
        "powershell", "powershell.exe",
        "schtasks", "schtasks.exe",
        "reg", "reg.exe",
        "rundll32", "rundll32.exe",
        "vssadmin", "vssadmin.exe",
        "systemd", "init", "bash", "sh", "sshd",
        "wininit.exe", "wininit",
        "winlogon.exe", "winlogon",
        "csrss.exe", "csrss",
        "smss.exe", "smss",
        "spoolsv.exe", "spoolsv"
    }

    def __init__(self, registry_version: str = "1.0.0"):
        self.version = registry_version
        self.objects = self.SYSTEM_OBJECTS_V1

    def is_system_object(self, value: str) -> bool:
        """
        Returns True if the stripped, lowercase value matches a known system object.
        """
        if not value:
            return False
        clean_value = value.strip().lower()
        return clean_value in self.objects
