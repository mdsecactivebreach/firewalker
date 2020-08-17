#pragma once

#define FIREWALK(call)	\
	[&](){ \
	HANDLE veh = AddVectoredExceptionHandler(1, TrapFilter); \
	Trap(); \
	auto r = call; \
	Untrap(); \
	RemoveVectoredExceptionHandler(veh); \
	return r; \
	}()

DECLSPEC_NOINLINE void Untrap();

//#define IF_DEBUG(x)	x;
#define IF_DEBUG(x) ;

DWORD FindThunkJump(DWORD RangeStart, DWORD RangeEnd)
{
	DWORD Address = 1;
	MEMORY_BASIC_INFORMATION mbi;

	while (Address < 0x7fffff00)
	{
		SIZE_T result = VirtualQuery((PVOID)Address, &mbi, sizeof(mbi));
		if (!result)
		{
			break;
		}

		Address = (DWORD)mbi.BaseAddress;

		if (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
		{
			for (DWORD i = 0; i < (mbi.RegionSize - 6); i++)
			{
				__try
				{
					if (*(PBYTE)Address == 0xe9)
					{
						// jmp rel
						DWORD Target = Address + *(DWORD*)(Address + 1) + 5;

						if (Target >= RangeStart && Target <= RangeEnd)
						{
							return Address;
						}
					}
					else if (*(PBYTE)Address == 0xff && *(PBYTE)(Address + 1) == 0x25)
					{
						// jmp indirect
						DWORD Target = *(DWORD*)(Address + *(DWORD*)(Address + 2) + 6);

						if (Target >= RangeStart && Target <= RangeEnd)
						{
							return Address;
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{

				}

				Address++;
			}
		}

		Address = (DWORD)mbi.BaseAddress + mbi.RegionSize;
	}

	return 0;
}

LONG __stdcall TrapFilter(PEXCEPTION_POINTERS pexinf)
{
	IF_DEBUG(printf("[0x%p] pexinf->ExceptionRecord->ExceptionAddress = 0x%p, pexinf->ExceptionRecord->ExceptionCode = 0x%x (%u)\n",
		pexinf->ContextRecord->Eip,
		pexinf->ExceptionRecord->ExceptionAddress,
		pexinf->ExceptionRecord->ExceptionCode,
		pexinf->ExceptionRecord->ExceptionCode));

	if (pexinf->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
		((DWORD)pexinf->ExceptionRecord->ExceptionAddress & 0x80000000) != 0)
	{
		pexinf->ContextRecord->Eip = pexinf->ContextRecord->Eip ^ 0x80000000;
		IF_DEBUG(printf("Setting EIP back to 0x%p\n", pexinf->ContextRecord->Eip));
	}
	else if (pexinf->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}

	//UINT length = length_disasm((PBYTE)pexinf->ContextRecord->Eip);
	//IF_DEBUG(printf("[0x%p] %S", pexinf->ContextRecord->Eip, HexDump((PBYTE)pexinf->ContextRecord->Eip, length).c_str()));

	// https://c9x.me/x86/html/file_module_x86_id_26.html

	DWORD CallTarget = 0;
	DWORD CallInstrLength = 2;

	switch (*(PBYTE)pexinf->ContextRecord->Eip)
	{
	case 0xff:
		// FF /2	CALL r/m32	Call near, absolute indirect, address given in r/m32

		switch (*(PBYTE)(pexinf->ContextRecord->Eip + 1))
		{
		case 0x10:
			CallTarget = *(DWORD*)pexinf->ContextRecord->Eax;
			break;
		case 0x11:
			CallTarget = *(DWORD*)pexinf->ContextRecord->Ecx;
			break;
		case 0x12:
			CallTarget = *(DWORD*)pexinf->ContextRecord->Edx;
			break;
		case 0x13:
			CallTarget = *(DWORD*)pexinf->ContextRecord->Ebx;
			break;
		case 0x15:
			CallTarget = *(DWORD*)(*(DWORD*)(pexinf->ContextRecord->Eip + 2));
			CallInstrLength = 6;
			break;
		case 0x16:
			CallTarget = *(DWORD*)pexinf->ContextRecord->Esi;
			break;
		case 0x17:
			CallTarget = *(DWORD*)pexinf->ContextRecord->Edi;
			break;
		case 0xd0:
			CallTarget = pexinf->ContextRecord->Eax;
			break;
		case 0xd1:
			CallTarget = pexinf->ContextRecord->Ecx;
			break;
		case 0xd2:
			CallTarget = pexinf->ContextRecord->Edx;
			break;
		case 0xd3:
			CallTarget = pexinf->ContextRecord->Ebx;
			break;
		case 0xd6:
			CallTarget = pexinf->ContextRecord->Esi;
			break;
		case 0xd7:
			CallTarget = pexinf->ContextRecord->Edi;
			break;
		}

		break;
	case 0xe8:
		// E8 cd	CALL rel32	Call near, relative, displacement relative to next instruction

		CallTarget = pexinf->ContextRecord->Eip + *(DWORD*)(pexinf->ContextRecord->Eip + 1) + 5;
		CallInstrLength = 5;

		break;
	}

	if (CallTarget != 0)
	{
		IF_DEBUG(printf("Call to 0x%p\n", CallTarget));

		if (*(PBYTE)CallTarget == 0xe9)
		{
			IF_DEBUG(printf("Call to 0x%p leads to jmp\n", CallTarget));

			DWORD ThunkAddress = FindThunkJump((DWORD)CallTarget, CallTarget + 16);
			DWORD ThunkLength = ThunkAddress + *(DWORD*)(ThunkAddress + 1) + 5 - CallTarget;

			if (CallTarget != ThunkAddress)
			{
				IF_DEBUG(printf("Thunk address 0x%p length 0x%x\n", ThunkAddress, ThunkLength));
				IF_DEBUG(printf("Thunk [0x%p] %S", ThunkAddress, HexDump((PVOID)(ThunkAddress - ThunkLength), ThunkLength + 5).c_str()));

				// emulate the call
				pexinf->ContextRecord->Esp -= 4;
				*(DWORD*)pexinf->ContextRecord->Esp = pexinf->ContextRecord->Eip + CallInstrLength;

				pexinf->ContextRecord->Eip = ThunkAddress - ThunkLength;
			}
		}
	}

	if (*(PBYTE)pexinf->ContextRecord->Eip != 0xea || *(PWORD)(pexinf->ContextRecord->Eip + 5) != 0x33)
	{
		if (pexinf->ContextRecord->Eip == (DWORD)Untrap)
		{
			IF_DEBUG(printf("Removing trap\n"));
			pexinf->ContextRecord->Eip += 1; // skip int3
		}
		else
		{
			IF_DEBUG(printf("Restoring trap\n"));
			pexinf->ContextRecord->EFlags |= 0x100; // restore trap
		}
	}
	else
	{
		// heaven's gate - trap the return
		IF_DEBUG(printf("Entering heaven's gate\n"));
		*(DWORD*)pexinf->ContextRecord->Esp |= 0x80000000; // set the high bit
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}

__forceinline void Trap()
{
	__asm
	{
		pushfd
		or dword ptr[esp], 0x100
		popfd
	}
}

DECLSPEC_NOINLINE void Untrap()
{
	__asm { int 3 }
	return;
}