- BUUCTF Reverse 刷题
# easyre | 入门级
- 方法一：WinHex 打开 easyre.exe，浏览一下字符串，发现有flag
- 方法二：IDA Pro 打开 easyre.exe，能直接看到flag，或者 F5 反汇编看到逻辑是输入两个相同的整数就输出 flag，或者 shift+F12 打开字符串常量窗口，比 WinHex 方便一点浏览字符串。

# reverse_1 | 入门级
函数列表找不到名称带有 main 的函数。看字符串也看不到 flag，但没关系，能看到 wrong flag 和 this is right flag 的提示信息，进入对应函数，F5 反汇编。

- strncmp(Str1, Str2, v3): 比较 Str1 和 Str2 的前 v3 个字节(char)。
- Str1 是 {hello_world}，下面的逻辑是把 Str1 的 o 替换为 0，即得到 flag。

![](https://img-blog.csdnimg.cn/2d8c58433aea4047a897e231ddca37a1.png)

# reverse_2 | 入门级
看起来不是 PE 格式的程序，那就只能静态分析了（毕竟本地没装linux）。IDA Pro 加载，能找到 main 函数，F5 反汇编。
![](https://img-blog.csdnimg.cn/73f633b086664c2695678a3ae0a9cdc7.png)
![](https://img-blog.csdnimg.cn/7058190d1b834f56a00f6b6c47061b40.png)

- 0x7B 是 '{'，因为 0x7B 后面没有结束符，所以上面的循环会遍历到`hacking_for_fun}`结尾处的0x00（字符串`\0`结束标记）。合起来这里的字符串实际上是`{hacking_for_fun}`。
- 把字符串的i和r替换为1即可。

# 内涵的软件 | 入门级

IDA 打开，能找到main函数，不过是32位程序，用32位的ida才能反汇编。看了下面的逻辑都是定时和cmd交互。所以flag只可能是与v5相关了。把DBAPP换成flag提交成功。
![](https://img-blog.csdnimg.cn/d3e131d6e6c340d9acbbb6a49a9cc290.png)

# 新年快乐 | 入门级
IDA 打开，发现是32位加 upx 壳的程序。用 Exeinfo PE 或者 PEiD 查壳确认一下。因此下一步需要脱壳。UPX 是压缩壳，并不防逆向，因此很容易脱。参考资料：
- [ESP 定律 | 堆栈平衡定律 | 合天网安](https://baijiahao.baidu.com/s?id=1662196196423030806&wfr=spider&for=pc)
- [x64dbg 手工脱 upx 壳教程 | 看雪](https://bbs.kanxue.com/thread-268159.htm)

> 壳实质上是一个子程序，在程序运行时首先取得控制权并对程序进行压缩，同时隐藏程序真正的OEP(入口点)。脱壳的目的就是找到真正的OEP。ESP 定律是用于脱壳的方法，本质上是堆栈平衡原理。程序自解密或者自解压过程中，多数壳会先将当前寄存器状态压栈，如pushad，在解压后将之前的寄存器值出栈, 如popad。如果只有ESP寄存器变化，那么该程序大概率可用该方式脱壳。然后再popad后单步找到OEP后再dump即可。
> 加一段个人理解：为什么要下硬件断点是因为这里的stack push 进去的 address 处的数据或指令在解压过程中会被覆盖导致软断点失效。

![](https://img-blog.csdnimg.cn/b0ebaaa7f1c34f939d9a7f4f41ea1a2c.png)

用 x64dbg 调试程序，两次 F9 发现程序在 pushad 处暂停。该指令将所有寄存器的值压栈，而在UPX的执行流程里，这一步之后会加载UPX的解压代码用于将原始程序解压，在这里对ESP指向的栈内存中的地址下一个硬件断点然后再F9执行，会看到下图所示的代码段。popad后还有一些清理程序然后才是入口点，F7进入口点。
![](https://img-blog.csdnimg.cn/eecb94a418a940208e53736f991cd1e4.png)
![](https://img-blog.csdnimg.cn/755283836b8d4999b32ba04956e39c82.png)
用x64dbg自带的Scylla（如果是ollydbg需要用ollydump插件）把此时的程序dump下来。
正常流程：
1.调试器运行相应程序到oep
2.插件 -> Scylla, 打开这个插件
3.右下角 Dump -> Dump, 使用Scylla dump进程
4.左下角 IAT Info 中，依次点击 IAT Autosearch, Get Imports 找到并获取导入表
5.右下角 Dump -> Fix Dump, 选择第3步dump出的文件，即可修复导入表
![](https://img-blog.csdnimg.cn/73aecd1a6b8c45c390404a36610c8a94.png)
![](https://img-blog.csdnimg.cn/96c18e478317417eb6303763b13a94ab.png)

