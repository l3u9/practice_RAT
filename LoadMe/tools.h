#pragma once

#define RtlOffsetToPointer(Module, Pointer) PBYTE(PBYTE(Module) + DWORD(Pointer))

namespace Tools
{
	PVOID GetImageBase();
	PBYTE ExtractDllFile(PBYTE module_base, PDWORD module_size);

}

