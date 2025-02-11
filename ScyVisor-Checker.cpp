#include "hv.h"

#pragma comment(lib, "ntdll.lib")

#define SystemCodeIntegrityInformation 0x67
#define SystemHypervisorInformation 0x5A
#define IA32_FEATURE_CONTROL_MSR 0x3A

extern "C" NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

std::string GetCPUVendor() {
    int cpuInfo[4] = { -1 };
    char vendorID[13];
    __cpuid(cpuInfo, 0);
    *(int*)vendorID = cpuInfo[1];
    *(int*)(vendorID + 4) = cpuInfo[3];
    *(int*)(vendorID + 8) = cpuInfo[2];
    vendorID[12] = '\0';
    return std::string(vendorID);
}

void WriteWindowsVersion(std::ofstream& outFile) {
    OSVERSIONINFOEX osvi = { sizeof(OSVERSIONINFOEX) };
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (hMod) {
        RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
        if (RtlGetVersion) {
            RtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);
            outFile << "Windows Version: " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion << " (Build " << osvi.dwBuildNumber << ")" << std::endl;
        }
    }
}

void VirtualizationStatus(std::ofstream& outFile) {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);
    char vendor[13];
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[3], 4);
    memcpy(vendor + 8, &cpuInfo[2], 4);
    vendor[12] = '\0';

    outFile << "CPU Vendor: " << vendor << std::endl;

    bool isIntel = strcmp(vendor, "GenuineIntel") == 0;
    bool isAMD = strcmp(vendor, "AuthenticAMD") == 0;

    if (isIntel) {
        __cpuid(cpuInfo, 1);
        bool vmx_supported = (cpuInfo[2] & (1 << 5)) != 0;
        outFile << "VT-x Supported: " << (vmx_supported ? "Yes" : "No") << std::endl;

        if (vmx_supported) {
            unsigned long long feature_control = __readmsr(0x3A);
            bool locked = (feature_control & 1) != 0;
            bool enabled_outside_smx = (feature_control & (1 << 2)) != 0;
            outFile << "VT-x Locked: " << (locked ? "Yes" : "No") << std::endl;
            outFile << "VT-x Enabled Outside SMX: " << (enabled_outside_smx ? "Yes" : "No") << std::endl;

            // Check if VMX is actually enabled
            unsigned long long vmx_basic_msr = __readmsr(0x480);
            bool vmx_enabled = (vmx_basic_msr & (1ULL << 55)) != 0;
            outFile << "VT-x Enabled: " << (vmx_enabled ? "Yes" : "No") << std::endl;
        }
    }
    else if (isAMD) {
        __cpuid(cpuInfo, 0x80000001);
        bool svm_supported = (cpuInfo[2] & (1 << 2)) != 0;
        outFile << "AMD-V Supported: " << (svm_supported ? "Yes" : "No") << std::endl;

        if (svm_supported) {
            unsigned long long vm_cr = __readmsr(0xC0010114);
            bool svme_disabled = (vm_cr & (1 << 4)) != 0;
            outFile << "AMD-V Disabled: " << (svme_disabled ? "Yes" : "No") << std::endl;
            outFile << "AMD-V Enabled: " << (!svme_disabled ? "Yes" : "No") << std::endl;
        }
    }
    else {
        outFile << "Unknown CPU vendor. Virtualization status cannot be determined." << std::endl;
    }
}

bool IsHVCIEnabled() {
    SYSTEM_CODEINTEGRITY_INFORMATION sci = { sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) };
    ULONG returnLength = 0;
    if (NT_SUCCESS(NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemCodeIntegrityInformation), &sci, sizeof(sci), &returnLength))) {
        return (sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0;
    }
    return false;
}

bool IsSecureBootEnabled() {
    UINT32 attributes = 0;
    DWORD size = sizeof(attributes);
    if (GetFirmwareEnvironmentVariableA("SecureBoot", "{8be4df61-93ca-11d2-aa0d-00e098032b8c}", &attributes, size) != 0) {
        return attributes != 0;
    }
    return false;
}

bool IsUEFIMode() {
    FIRMWARE_TYPE firmwareType;
    return (GetFirmwareType(&firmwareType) && firmwareType == FirmwareTypeUefi);
}

void CheckExtendedCPUFeatures(std::ofstream& outFile) {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    outFile << "SSE3 Support: " << ((cpuInfo[2] & (1 << 0)) ? "Yes" : "No") << std::endl;
    outFile << "SSSE3 Support: " << ((cpuInfo[2] & (1 << 9)) ? "Yes" : "No") << std::endl;
    outFile << "SSE4.1 Support: " << ((cpuInfo[2] & (1 << 19)) ? "Yes" : "No") << std::endl;
    outFile << "SSE4.2 Support: " << ((cpuInfo[2] & (1 << 20)) ? "Yes" : "No") << std::endl;
    outFile << "AES-NI Support: " << ((cpuInfo[2] & (1 << 25)) ? "Yes" : "No") << std::endl;
    outFile << "AVX Support: " << ((cpuInfo[2] & (1 << 28)) ? "Yes" : "No") << std::endl;
}

bool IsVBSEnabled() {
    HKEY hKey;
    DWORD dwValue = 0;
    DWORD dwSize = sizeof(DWORD);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueEx(hKey, L"EnableVirtualizationBasedSecurity", NULL, NULL, (LPBYTE)&dwValue, &dwSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return dwValue != 0;
        }
        RegCloseKey(hKey);
    }
    return false;
}



int main() {
    std::ofstream outFile("system_info.txt");

    if (!outFile.is_open()) {
        std::cerr << "Failed to open output file." << std::endl;
        return 1;
    }

    outFile << "============= ScyVisor - System Information Checker =============" << std::endl << std::endl;

    outFile << "----------- Windows Features -----------" << std::endl;
    WriteWindowsVersion(outFile);
    outFile << "HVCI Enabled: " << (IsHVCIEnabled() ? "Yes" : "No") << std::endl;
    outFile << "Secure Boot Enabled: " << (IsSecureBootEnabled() ? "Yes" : "No") << std::endl;
    outFile << "UEFI Mode: " << (IsUEFIMode() ? "Yes" : "No") << std::endl;
    outFile << "VBS (Virtualization Based Security) Enabled: " << (IsVBSEnabled() ? "Yes" : "No") << std::endl;
    outFile << std::endl;

    outFile << "----------- CPU Information -----------" << std::endl;
    VirtualizationStatus(outFile);
    outFile << std::endl;

    outFile << "----------- Extended CPU Features -----------" << std::endl;
    CheckExtendedCPUFeatures(outFile);
    outFile << std::endl;

    outFile << "----------- Additional CPU Security Features -----------" << std::endl;
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    outFile << "NX (Execute Disable) Bit Supported: " << ((cpuInfo[3] & (1 << 20)) ? "Yes" : "No") << std::endl;

    __cpuid(cpuInfo, 7);
    outFile << "SMAP Supported: " << ((cpuInfo[1] & (1 << 20)) ? "Yes" : "No") << std::endl;
    outFile << "SMEP Supported: " << ((cpuInfo[1] & (1 << 7)) ? "Yes" : "No") << std::endl;

    outFile << "----------- Hypervisor Information -----------" << std::endl;
    outFile << "Hyper-V Enabled in Windows Features: " << (IsHyperVEnabled() ? "Yes" : "No") << std::endl;
    outFile << "Hypervisor Running: " << (IsHypervisorRunning() ? "Yes" : "No") << std::endl;
    outFile << "Hyper-V Running: " << (IsHyperVRunning() ? "Yes" : "No") << std::endl;
    outFile << std::endl;

    outFile.close();
    std::cout << "System information has been written to system_info.txt" << std::endl;

    return 0;
}