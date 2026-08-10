#include <windows.h>

int main(void) {
    static const char marker[] = "certutil download-execute lab marker\r\n";
    HANDLE file = CreateFileA(
        "C:\\lab\\download-execute-marker.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (file == INVALID_HANDLE_VALUE) {
        return 1;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(file, marker, (DWORD)(sizeof(marker) - 1), &written, NULL);
    CloseHandle(file);
    return ok && written == sizeof(marker) - 1 ? 0 : 2;
}
