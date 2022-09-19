#include <Windows.h>

BOOL was_dllmain_caled = FALSE;
DWORD dll_param;

extern "C" __declspec(dllexport) int FunEntry()
{
	char dll_path[MAX_PATH];
	DWORD ret = GetModuleFileNameA((HINSTANCE)dll_param, dll_path, MAX_PATH);
	char test[1024];
	wsprintfA(test, "%s", dll_path);
	MessageBoxA(0, test, "", 0);
	// inject dll inside remote process

}


BOOL APIENTRY DllMain(HMODULE Base, DWORD Callback, LPVOID Param)
{

	dll_param = (DWORD)Base;
	was_dllmain_caled = TRUE;

	switch (Callback)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}



extern "C" __declspec(dllexport) void MainEntry()
{
	if (was_dllmain_caled)
	{
		while (TRUE)
		{
			char exe[MAX_PATH + 1];
			GetModuleFileNameA(0, exe, sizeof(exe));
			MessageBoxA(0, exe, "FunDll.dll, I am inside: ", 0);

		}
	}
	else
	{
		MessageBoxA(0, "DllMain was not called.", NULL, 0);
	}

	
}


