/*
 * Lab-authored inert DLL for the bounded AdaptixC2 sideloading simulation.
 *
 * This is not an AdaptixC2 component and contains no networking, persistence,
 * process injection, command execution, or payload-loading behavior. Its only
 * observable action is creating a fixed marker when a signed laboratory copy
 * of WerFault.exe loads faultrep.dll from its application directory.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static const char marker_path[] =
    "C:\\lab\\adaptix\\sideload-flow\\sideload-marker.txt";
static const char marker_text[] = "ADAPTIX_SIDELOAD_INERT_MARKER\r\n";

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    HANDLE marker;
    DWORD written = 0;

    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    DisableThreadLibraryCalls(instance);
    marker = CreateFileA(marker_path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (marker == INVALID_HANDLE_VALUE) {
        return TRUE;
    }
    WriteFile(marker, marker_text, (DWORD)(sizeof(marker_text) - 1), &written,
              NULL);
    CloseHandle(marker);
    return TRUE;
}

/* WerFault imports this symbol. Returning an error keeps the simulation inert. */
HRESULT WINAPI WerpInitiateCrashReporting(LPVOID context)
{
    (void)context;
    return E_NOTIMPL;
}
