#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <intrin.h>
#include <winternl.h>
#include <wbemidl.h>
#include <comdef.h>
#include <winsvc.h>


#define _WIN32_DCOM
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

#include <intrin.h>

bool IsHyperVEnabled() {
   
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    bool hypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;

    if (hypervisorPresent) {
        __cpuid(cpuInfo, 0x40000000);
        char hypervisorVendor[13];
        memcpy(hypervisorVendor, &cpuInfo[1], 4);
        memcpy(hypervisorVendor + 4, &cpuInfo[2], 4);
        memcpy(hypervisorVendor + 8, &cpuInfo[3], 4);
        hypervisorVendor[12] = '\0';
        if (strcmp(hypervisorVendor, "Microsoft Hv") == 0) {
            return true;
        }
    }

   
    HKEY hKey;
    DWORD dwValue = 0;
    DWORD dwSize = sizeof(DWORD);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueEx(hKey, L"HypervisorPresent", NULL, NULL, (LPBYTE)&dwValue, &dwSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            if (dwValue != 0) {
                return true;
            }
        }
        RegCloseKey(hKey);
    }

    
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (schSCManager) {
        SC_HANDLE schService = OpenService(schSCManager, L"vmms", SERVICE_QUERY_STATUS);
        if (schService) {
            SERVICE_STATUS_PROCESS ssStatus;
            DWORD dwBytesNeeded;
            if (QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
                if (ssStatus.dwCurrentState == SERVICE_RUNNING) {
                    CloseServiceHandle(schService);
                    CloseServiceHandle(schSCManager);
                    return true;
                }
            }
            CloseServiceHandle(schService);
        }
        CloseServiceHandle(schSCManager);
    }

    return false;
}

bool IsHypervisorRunning() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31)) != 0;
}

bool IsHyperVRunning() {
    HRESULT hres;

    
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return false;
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }
    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_ComputerSystem"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    bool isHyperVRunning = false;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) break;

        VARIANT vtProp;
        hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            if (wcscmp(vtProp.bstrVal, L"Microsoft Corporation") == 0) {
                isHyperVRunning = true;
            }
            VariantClear(&vtProp);
        }
        pclsObj->Release();
    }

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();

    return isHyperVRunning;
}