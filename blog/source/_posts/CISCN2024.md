---
title: CISCN2024之RE
date: 2024-05-20 23:14:11
tags:
  - wp
  - re	
  - CISCN
categories:
  - Reverse
  - Write Up
description: 只出了两道，关于so的没出来，电脑上面环境刷机后一塌糊涂……
cover: ../img/zizi.png
---

# Reverse

## asm_re

![image-20240519162041849](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/image-20240519162041849.png)

分析arm汇编发现是三个循环，一个加密flag,一个加密input,一个结果判断，前两个相同

```cpp
#include"stdio.h"
int main() {

	int arr[] = { 0x1fd7,0x21b7,0x1e47,0x2027,0x26e7,0x10d7,0x1127,0x2007,0x11c7,0x1e47,0x1017,0x1017,0x11f7,0x2007,0x1037,0x1107,0x1f17,0x10d7,
	0x1017,0x1017,0x1f67,0x1017,0x11c7,0x11c7,0x1017,0x1fd7,0x1f17,0x1107,0xf47,0x1127,0x1037,0x1e47,0x1037,0x1fd7,0x1107,0x1fd7,0x1107,0x2787 };
	int temp = 0;
	int flag[40] = { 0 };
	for (int i = 0; i < sizeof(arr)/4; i++)
	{
		flag[i] = (((arr[i] - 0x1e) ^ 0x4d) - 0x14) / 0x50;
		//flag[i] = (((flag[i] - 0x1e) ^ 0x4d) - 0x14) / 0x50;
	}
	for (int k = 0; k < sizeof(arr)/4; k++) {
		putchar(flag[k] & 0xff);
		//putchar((flag[k] >> 8) & 0xff);
	}
	return 0;
}
```

## gdb_debug

![image-20240519162340166](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/202405241619072.png)

主要是随机数，虽然是时间作为种子，但是伪随机，被&掉了，然后就是产生密钥盒子等运算

```cpp
#include"stdio.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <malloc.h>
int main() {
	int a =time(0);
	srand(a);
	unsigned int keys[] =
	{
	  0x12, 0x0E, 0x1B, 0x1E, 0x11, 0x05, 0x07, 0x01, 0x10, 0x22,
	  0x06, 0x17, 0x16, 0x08, 0x19, 0x13, 0x04, 0x0F, 0x02, 0x0D,
	  0x25, 0x0C, 0x03, 0x15, 0x1C, 0x14, 0x0B, 0x1A, 0x18, 0x09,
	  0x1D, 0x23, 0x1F, 0x20, 0x24, 0x0A, 0x00, 0x21, 0x00
	};
	unsigned int end[] =
	{
	  191, 215,  46, 218, 238, 168,  26,  16, 131, 115,
	  172, 241,   6, 190, 173, 136,   4, 215,  18, 254,
	  181, 226,  97, 183,  61,   7,  74, 232, 150, 162,
	  157,  77, 188, 129, 140, 233, 136, 120,   0,   0
	};
	char str[] = "congratulationstoyoucongratulationstoy";
	int flag[39] = { 0 };
	int temp[] = { 0xd9,0xf,0x18,0xbd,0xc7,0x16,0x81,0xbe,0xf8,0x4a,0x65,0xf2,0x5d,0xab,0x2b,
		0x33,0xd4,0xa5,0x67,0x98,0x9f,0x7e,0x2b,0x5d,0xc2,0xaf,0x8e,0x3a,0x4c,0xa5,0x75,0x25,0xb4,0x8d,0xe3,0x7b,0xa3,0x64,0x39,0x9c,0xae,0x9e,0x8e,0xb,0x4a,0xb9,0x3f,0x1e,0x5e,0xa6,0xb6,0xfd,0x25,0xe1,0x5a,0xe7,0x91,0xe8,0x21,0xdd,0x8d,0x96,0x2,0x41,0x23,0xe5,0xbc,0xc7,0x49,0xf5,0x63,0xf7,0x94,0xf1,0x3,0xde,0xaa,0x42,0xfc,0x9,0xe8,0xb2,0x6,0xd,0x93,0x61,0xf4,0x24,0x49,0x15,0x1,0xd7,0xab,0x4,0x18,0xcf,0xe9,0xd5,0x96,0x33,0xca,0xf9,
		0x2a,0x5e,0xea,0x2d,0x3c,0x94,0x6f,0x38,0x9d,0x58,0xea,0xa4,0x65,0x7e,0x5,0x5a,0xa2,0x4e,0x6f,0xa4,0x25,0x1b,0xa8,0x3e,0xea,0x91 };
	//srand(0);
	//for (int s1=0;s1<38*2 ; ++s1)
	//{
	//	                           // d9,f	
	//	 temp[s1] = rand()&0xff;
	//}
	int wow[38];
	for (int i = 0; i < 39; i++) {
		flag[i] = str[i]^end[i];
		flag[i] ^= temp[38*2-2 +i];
		wow[keys[i]] = flag[i];
		flag[i] = (wow[i] ^temp[i])&0xff;
		putchar(wow[i]);
	}
	
	/*for (int i = 0; i < 38; i++) {
		for (int j = 0; j < 128; j++) {
			flag[i] = j ^ temp[i];
			flag[i] += keys[i];
			flag[i] ^= temp[38 * 2  + i];
			
			flag[i] ^= end[i];
			if (flag[i] == str[i]) {
				printf("%#x,", temp[38 * 2 - 2 + i]);
				putchar(j);
				break;
			}
		}
	}*/
	return 0;
}

```

## androidso_re

> 这道题就是个简单的des加密，只要知道key和iv即可,至少我知道的方法中动调或者直接frida附加都可以获得运行时的参数，或者直接使用java调用库函数，动调不知道什么原因总是跑一半就断掉了，frida的环境之前给删掉了，至于函数库由于whereislib这道题用python调死调不出来，所以犹豫没有试过，什么时候自己的想法才可以完全用代码完全实现啊😟

### 分析

![image-20240520232831841](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/202405241619677.png)

发现加密函数在inspect里面

![image-20240520233005944](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/202405241624891.png)

发现函数在so函数库里面

### 解题方法

#### frida

frida显示apk文件的值方法也很多可以主动调用或者等待app主动调用，利用函数覆盖和重载可以实现，本打算直接使用主动调用但一直报错，可以知道那两个函数是静态函数，但提示输入值不符合有0xbb，可能是主动调用时侯环境并没有完全被初始化完全

![image-20240523013147683](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/202405241620287.png)

此时需要满足输入flag{***}长度为38才会调用inspect验证函数

![image-20240523013241272](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/202405241621303.png)

![image-20240523195749822](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/202405241621965.png)

#### 动调

ida倒是可以跑动但太乱了不好定位主要函数位置

使用jeb试试，提示java版本有点问题,jeb动调到调用so函数时会弹出，或许两个结合一下就可以了吧，先到这吧，以后有机会再试试

## WhereTheLib

> 两种方法，一种是直接爆破，一种分析so文件

### 爆破

#### 分析

文件为linux文件给定python文件需要在liunx下使用python3.10运行

发现给定python文件调用了两个函数

![image-20240524132844590](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/202405241621914.png)



内部函数调用流程，但在脚本中whereistheflag只是返回了输入的字节串，主要加密在trytry,看so文件内部知道主要加密就是随机数和base64,三个输入对应四个结果字符输出

#### wp



```
import whereThel1b
encry = [108, 117, 72, 80, 64, 49, 99, 19, 69, 115, 94, 93, 94, 115, 71, 95, 84, 89, 56, 101, 70, 2, 84, 75, 127, 68, 103, 85, 105, 113, 80, 103, 95, 67, 81, 7, 113, 70, 47, 73, 92, 124, 93, 120, 104, 108, 106, 17, 80, 102, 101, 75, 93, 68, 121, 26]
#cry =bytes(encry)
table =b"abcdefghijklmnopqrstuvwxyz0123456789{}-"
flag =b""
for n in range(0,len(encry),4):
    temp =0
    for i in table:
        for j in table:
            for k in table:
                if(temp ==1):
                    break
                else:
                    str =bytes([i,j,k])
                    tmp =flag +str
                    tmp =tmp.ljust(42,b"1")
                    #print(tmp)
                    a =whereThel1b.trytry(tmp)[n:n+4]
                    b =encry[n:n+4]
                    if( a==b):
                        flag +=str
                        print(flag)
                        temp =1
#b'flag{7f9a2d3c-07de-11ef-be5e-cf1e88674c0b}'
```



### so

> 谷歌一下可以知道这是一个被Cpython编译了的pyd文件（linux上为so）

#### 分析

利用help函数和dir函数我们可以很快的直到函数主要逻辑

![image-20240524140213978](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/202405241622910.png)

![image-20240524140510874](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/202405241622728.png)

![image-20240524140203285](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/202405241622299.png)

可以发现so文件中所有自定义函数和对象有这些

**主要函数：**

_pyx_pymod_exec_whereThel1b：初始化各模块

_Pyx_CreateStringTabAndInitStrings： 是 Cython 在其编译过程中生成的一个内部函数，用于初始化和管理 Cython 模块中使用的字符串字面量。

![image-20240524143351245](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/202405241622259.png)

check_flag:验证flag是否非空

trytry:发现设置了seed

![image-20240524144733782](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/202405241622284.png)

当时没以为下面if判断的值为0是seed,因为感觉是类型更像是一些系统跳转什么的,而且下面有一个一样的·

whereistheflag:发现调用了randint

![image-20240524145036545](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/202405241623082.png)

当时看到有xor运算

![image-20240524145443560](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/202405241623165.png)

这倒很容易猜出来

但即使是现在面向结果解题感觉还是很难想象出来是这么个解题思路



#### wp

```python
import base64
import random

random.seed(0)
encry = [108, 117, 72, 80, 64, 49, 99, 19, 69, 115, 94, 93, 94, 115, 71, 95, 84, 89, 56, 101, 70, 2, 84, 75, 127, 68, 103, 85, 105, 113, 80, 103, 95, 67, 81, 7, 113, 70, 47, 73, 92, 124, 93, 120, 104, 108, 106, 17, 80, 102, 101, 75, 93, 68, 121, 26]
#cry =bytes(encry)
arr =[]
flag =""
for i in range(len(encry)):
    arr.append(random.randint(0,len(encry)))
    flag +=chr(encry[i]^arr[i])
    print(flag)
a =base64.b64decode(flag)
print(a)

#b'flag{7f9a2d3c-07de-11ef-be5e-cf1e88674c0b}'
```

