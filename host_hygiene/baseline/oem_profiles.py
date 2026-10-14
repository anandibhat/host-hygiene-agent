"""Hardware / OEM Profiles for ThinkPad/Lenovo, Intel Core Ultra, and Developer Tools."""

from typing import Dict, Set, Optional

# Lenovo & ThinkPad OEM platform binaries
LENOVO_OEM_BINARIES: Set[str] = {
    "lenovovantageservice.exe",
    "lenovovantage-(lenovoservicebridgeaddin).exe",
    "lenovovantage-(generictelemetryaddin).exe",
    "lenovovantage-(ideanotebookaddin).exe",
    "lenovovantage-(vantagecoreaddin).exe",
    "litssvc.exe",
    "powermgr.exe",
    "powermgrinst.exe",
    "tphkload.exe",
    "tposd.exe",
    "lenovohotkeys.exe",
    "smartstandbyinst.exe",
    "softlandingtask.exe",
    "udcinfinstaller.exe",
    "bioiso.exe",
    "elabssspsystemdaemon.exe",
    "lenovoservicebridge.exe",
    "imcontrollerservice.exe",
}

# Intel Core Ultra and Intel Platform binaries
INTEL_OEM_BINARIES: Set[str] = {
    "ipfsvc.exe",
    "ipf_uf.exe",
    "igfxshaderdistributionservice.exe",
    "igfxcuiservice.exe",
    "igfxem.exe",
    "igfxhk.exe",
    "intelaudioservice.exe",
    "oneapp.igcc.winservice.exe",
    "esrv_svc.exe",
    "surrun.exe",
}

# Developer Tools
DEVELOPER_BINARIES: Set[str] = {
    "vmware.exe",
    "vmware-vmx.exe",
    "vmware-tray.exe",
    "mkssandbox.exe",
    "git-bash.exe",
    "mintty.exe",
    "bash.exe",
    "python.exe",
    "pythonw.exe",
    "py.exe",
    "code.exe",
    "docker.exe",
    "dockerd.exe",
    "containerd.exe",
    "podman.exe",
    "node.exe",
    "git.exe",
}


def classify_hardware_or_oem(clean_name: str) -> Optional[str]:
    """Classify binary according to OEM / Platform / Dev profile.

    Returns:
        "OEM:Lenovo", "OEM:Intel", "DevTools", or None
    """
    clean_with_ext = f"{clean_name}.exe" if not clean_name.endswith(".exe") else clean_name
    target = clean_with_ext.lower()

    if target in LENOVO_OEM_BINARIES or clean_name in LENOVO_OEM_BINARIES:
        return "OEM:Lenovo"
    if target in INTEL_OEM_BINARIES or clean_name in INTEL_OEM_BINARIES:
        return "OEM:Intel"
    if target in DEVELOPER_BINARIES or clean_name in DEVELOPER_BINARIES:
        return "DevTools"

    # Prefix checks for Lenovo Vantage Addins
    if clean_name.startswith("lenovovantage"):
        return "OEM:Lenovo"

    return None
