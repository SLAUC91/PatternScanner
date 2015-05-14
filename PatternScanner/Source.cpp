#include "PScanner.h"
#include <Windows.h>
#include <iostream>
#include <assert.h>

#define CountOf(x) (std::extent< decltype(x) >::value - 1);

//Func Protos
void PrintMemoryRegion(PBYTE zRegion, DWORD dwSize);

//Test Patterns

const char seqPatternA[] = "\x95\x90\x90\x90\x35\x9f\xda\x00\x45\x68\x21";
const size_t seqPatternALen = CountOf(seqPatternA);
const char seqSig1[] = "xxxx????xxx";

const char seqPatternB[] = "\x90\x20\xaf\xaf\x90\x80\x90";
const size_t seqPatternBLen = CountOf(seqPatternB);
const char seqSig2[] = "x????xx";

//End Test Patterns

//Print a Memory Region 
void PrintMemoryRegion(PBYTE zRegion, DWORD dwSize){
	DWORD i;
	for (i = 0; i < dwSize; i++){
		printf("\\x%x", *(zRegion + i));
	}
	return;
}

int main(){
	PScanner pScanner;
	int nPages = 1;

	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);

	std::cout << "Page dwSize: " << systemInfo.dwPageSize << ", NumOfPages:  " << nPages << std::endl;

	DWORD dwSize = systemInfo.dwPageSize * nPages;
	PBYTE zMemoryRegion = (PBYTE) VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	memset(zMemoryRegion, 0, dwSize);

	PBYTE LocA = zMemoryRegion + 5;	//Random Location of PatternA
	PBYTE LocB = zMemoryRegion + 1005;	//Random Location of PatternB

	//Allocate the bytes at a specific location
	memcpy(LocA, seqPatternA, seqPatternALen); //PatternA
	memcpy(LocB, seqPatternB, seqPatternBLen); //PatternB

	DWORD dwOldAccess = 0;
	
	//Read Only Access To Page
	VirtualProtect(zMemoryRegion, systemInfo.dwPageSize - 1, PAGE_READONLY, &dwOldAccess);

	//PrintMemoryRegion(zMemoryRegion, dwSize);

	//Find the Pattern Start Location
	PBYTE BaseAddrA = pScanner.FindPattern(zMemoryRegion, dwSize, (PBYTE)seqPatternA, (PCHAR)seqSig1);
	PBYTE BaseAddrB = pScanner.FindPattern(zMemoryRegion, dwSize, (PBYTE)seqPatternB, (PCHAR)seqSig2);

	//Test 1
	printf("Location: %d\n", LocA);
	printf("Location: %d\n", BaseAddrA);
	assert(LocA == BaseAddrA);

	//Test 2
	printf("Location: %d\n", LocB);
	printf("Location: %d\n", BaseAddrB);
	assert(LocB == BaseAddrB);

	//Restore The Original Access
	VirtualProtect(zMemoryRegion, systemInfo.dwPageSize - 1, dwOldAccess, &dwOldAccess);

	VirtualFree(zMemoryRegion, NULL, MEM_RELEASE);

	system("Pause");

	return 0;
}