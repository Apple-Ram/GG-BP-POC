#include "pch.h"
#include <Windows.h>
#include <metahost.h>
#include <string>
#include <iostream>

#pragma comment(lib, "mscoree.lib")

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

DWORD WINAPI Main(LPVOID lpParam)
{
    AllocConsole();
    FILE* pFile;
    freopen_s(&pFile, "CONOUT$", "w", stdout);
    freopen_s(&pFile, "CONIN$", "r", stdin);

    ICLRMetaHost* metaHost = NULL;
    ICLRRuntimeInfo* runtimeInfo = NULL;
    ICLRRuntimeHost* runtimeHost = NULL;

    WCHAR dllPath[MAX_PATH];
    GetModuleFileNameW((HINSTANCE)&__ImageBase, dllPath, MAX_PATH);
    std::wstring path(dllPath);

    size_t pos = path.find_last_of(L"\\");
    if (pos != std::wstring::npos)
    {
        path = path.substr(0, pos + 1);
    }

    std::wstring targetDll = path + L"AppUI.dll";

    if (CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&metaHost) == S_OK)
    {
        if (metaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&runtimeInfo) == S_OK)
        {
            if (runtimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (LPVOID*)&runtimeHost) == S_OK)
            {
                runtimeHost->Start();
                DWORD pReturnValue;
                runtimeHost->ExecuteInDefaultAppDomain(
                    targetDll.c_str(),
                    L"Pomme.IClass",
                    L"IMain",
                    L"Go",
                    &pReturnValue
                );
                runtimeHost->Release();
            }
            runtimeInfo->Release();
        }
        metaHost->Release();
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Main, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
