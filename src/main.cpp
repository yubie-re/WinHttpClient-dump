#include "inc.hpp"
#include "scan.hpp"
#include <winhttp.h>

class WinHttpClient
{
public:
    HINTERNET m_sessionHandle;
    bool m_requireValidSsl;
    std::wstring m_requestURL;
    std::wstring m_requestHost;
    std::wstring m_responseHeader;
    std::wstring m_responseContent;
    std::wstring m_responseCharset;
    BYTE *m_pResponse;
    unsigned int m_responseByteCountReceived;
    void* m_pfProcessProc;
    unsigned int m_responseByteCount;
    std::wstring m_responseCookies;
    std::wstring m_additionalRequestCookies;
    BYTE *m_pDataToSend;
    unsigned int m_dataToSendSize;
    std::wstring m_additionalRequestHeaders;
    std::wstring m_proxy;
    DWORD m_dwLastError;
    std::wstring m_statusCode;
    std::wstring m_userAgent;
    bool m_bForceCharset;
    std::wstring m_proxyUsername;
    std::wstring m_proxyPassword;
    std::wstring m_location;
    unsigned int m_resolveTimeout;
    unsigned int m_connectTimeout;
    unsigned int m_sendTimeout;
    unsigned int m_receiveTimeout;
};

bool g_hooked_write = false;
void *g_winhttpclient_ctor = nullptr;
void *g_winhttpclient_send = nullptr;

void hook_func(void **orig, void *address, void *hook)
{
    auto res = MH_CreateHook(address, hook, orig);
    if (res != MH_OK)
    {
        printf("CreateHook failed: %s\n", MH_StatusToString(res));
    }
    res = MH_EnableHook(address);
    if (res != MH_OK)
    {
        printf("EnableHook failed: %s\n", MH_StatusToString(res));
    }
}

void unhook_func(void *address)
{
    auto res = MH_DisableHook(address);
    if (res != MH_OK)
    {
        printf("DisableHook failed: %s\n", MH_StatusToString(res));
    }
}

void(__fastcall *o_winhttpclient_ctor)(WinHttpClient *this_, const std::wstring *url, bool(__fastcall *progress_proc)(long double));

void __fastcall winhttpclient_ctor(WinHttpClient *this_, const std::wstring *url, bool(__fastcall *progress_proc)(long double))
{
    wprintf(L"WinHttpClient::WinHttpClient -> %s (%p)\n", url->c_str(), this_);
    return o_winhttpclient_ctor(this_, url, progress_proc);
}

bool(__fastcall *o_winhttpclient_send)(WinHttpClient *this_, const std::wstring *http_verb, bool disable_auto_redirect);

bool __fastcall winhttpclient_send(WinHttpClient *this_, const std::wstring *http_verb, bool disable_auto_redirect)
{
    wprintf(L"WinHttpClient::SendHttpRequest -> %s\nRequest URL: %s\nUser Agent: %s\nAdditional Headers: %s\n", http_verb->c_str(), this_->m_requestURL.c_str(), this_->m_userAgent.c_str(), this_->m_additionalRequestHeaders.c_str(), this_);
    auto res = o_winhttpclient_send(this_, http_verb, disable_auto_redirect);
    wprintf(L"WinHttpClient::SendHttpRequest -> Status: %s\nResponse Content: %s\nResponse Header: %s\n", this_->m_statusCode.c_str(), this_->m_responseContent.c_str(), this_->m_responseHeader.c_str());
    return res;
}

void hook()
{
    MH_Initialize();

#if _WIN64
    g_winhttpclient_ctor = scanner::scan("48 89 5C 24 ? 48 89 4C 24 ? 57 48 83 EC 20 48 8B D9 33 FF 48 89 39 40 88 79 08 48 83 C1 10 E8 ? ? ? ? 90", "WinHttpClient::WinHttpClient", GetModuleHandleA(nullptr));
    g_winhttpclient_send = scanner::scan("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 0F 29", "WinHttpClient::SendHttpRequest", GetModuleHandleA(nullptr));
#else
    // TODO
#endif

    //g_winhttpclient_ctor = (void*)((uintptr_t)GetModuleHandleA(nullptr) + 0xFFFFFF); // Replace offset if you want to hardcode it
    //g_winhttpclient_send = (void*)((uintptr_t)GetModuleHandleA(nullptr) + 0xFFFFFF); // Replace offset if you want to hardcode it

    if (g_winhttpclient_ctor)
        hook_func((void **)&o_winhttpclient_ctor, g_winhttpclient_ctor, winhttpclient_ctor);
    if (g_winhttpclient_send)
        hook_func((void **)&o_winhttpclient_send, g_winhttpclient_send, winhttpclient_send);
}

void unhook()
{
    if (g_winhttpclient_ctor)
        unhook_func(g_winhttpclient_ctor);
    if (g_winhttpclient_send)
        unhook_func(g_winhttpclient_send);
}

bool g_dealloc_console = false;

DWORD WINAPI main_thread(PVOID module)
{
    if (!GetConsoleWindow())
    {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        g_dealloc_console = true;
    }
    hook();
    while (!GetAsyncKeyState(VK_DELETE))
    {
        std::this_thread::yield();
    }
    unhook();
    if (g_dealloc_console)
    {
        fclose(stdout);
        FreeConsole();
    }
    FreeLibraryAndExitThread((HMODULE)module, 0);
    return 1;
}

// Entrypoint
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        CreateThread(nullptr, 0, &main_thread, (void *)module, 0, nullptr);
    }
    return TRUE;
}