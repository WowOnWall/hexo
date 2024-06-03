---
title: ASPack脱壳
date: 2024-03-28 13:37:43
tags: 
  - 壳
  - ASPack
categories: 
  - Reverse
  - 脱壳
description: 对于aspack的加壳，脱壳，和IAT重定位
cover: https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/115668966_p0_master1200.jpg
---

# Aspack脱壳

> 对这里一直有点模糊，稀里糊涂的解决了，全部推到来一次吧

## 前期准备

+ PE Tools

+ demo.exe

+ ida8.2
+ ImportREC
+ Aspack
+ 010editor

*源代码：*

```
#include"stdio.h"
int main(){
        printf("hello world!");
        return 0;
}
```



## 分析加密变化

![image-20240327221625795](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/image-20240327221625795.png)

在文件可选头可以发现主要是EP和SizeOfImage发生了修改

![image-20240327222112344](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/image-20240327222112344.png)

除此外文件新加了两个节区（这个用010editor模版直接看还看不出来，可能软件设置问题）

## 脱壳

### 算法流程

|                源程序                 |    加壳程序     |
| :-----------------------------------: | :-------------: |
|       断点在EP(_mainCRTStartup)       | 断点在EP(start) |
|             进入main函数              |                 |
| main函数执行完退出回到_mainCRTStartup |                 |
|        _mainCRTStartup执行结束        |                 |

- _mainCRTStartup由编译器提供的函数，根据编译器的不同也可能是start函数，作用是初始化运行时库，用户的主函数区为main



<center>
    <img style="border-radius: 0.3125em;
    box-shadow: 0 2px 4px 0 rgba(34,36,38,.12),0 2px 10px 0 rgba(34,36,38,.08);" 
    src="C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20240327225349868.png" width = "65%" alt=""/>
    <br>
    <div style="color:orange; border-bottom: 1px solid #d9d9d9;
    display: inline-block;
    color: #999;
    padding: 2px;">
      _mainCRTStartup
  	</div>
</center>

### ESP定律

> 利用堆栈平衡，当popad压入的寄存器数据时，对这些数据进行硬件访问断点，至于为什么不是内存断点，我试过停不下来，可能是因为内存断点每次标记的是一个页，对于这个页上所有的内容程序遇到后就会暂停，然后又会去判断是不是要求的，然后就卡死在里面了吧，然后栈的所在页比较特殊，就。。只是一种猜测

 <center>
    <img style="border-radius: 0.3125em;
    box-shadow: 0 2px 4px 0 rgba(34,36,38,.12),0 2px 10px 0 rgba(34,36,38,.08);" 
    src="C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20240327231636440.png" width = "30%" alt=""/>
    <img style="border-radius: 0.3125em;
    box-shadow: 0 2px 4px 0 rgba(34,36,38,.12),0 2px 10px 0 rgba(34,36,38,.08);" 
    src="C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20240328002322841.png" width = "30%" alt=""/>
    <br>
    <div style="color:orange; border-bottom: 1px solid #d9d9d9;
    display: inline-block;
    color: #999;
    padding: 2px;">
      oep
  	</div>
</center>

当pushad执行后对堆栈的数据下硬件访问断点，可以看到此时已完成解密，恢复基本数据，往oep出发

ret后发现回到了原始OEP

![image-20240328003351050](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/image-20240328003351050.png)

### dump

主要修改入口点，其他可以暂时不管，这样可以直接将内存解密好的文件重新装回新的exe

![image-20240328004953895](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/image-20240328004953895.png)

### IAT表修复

+ 先使用ImportREC修改OEP,然后自动寻找IAT
+ 将找到的IAT放入刚dump文件

![image-20240328010514184](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/image-20240328010514184.png)

修补前后修补后的运行如图

![image-20240328010639220](https://raw.githubusercontent.com/WowOnWall/Drawing-bed/main/image-20240328010639220.png)

## 总结

很好，以后别想再难住我了，对硬件断点和内存断点理解的也更深了✌️

