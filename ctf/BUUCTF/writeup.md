- BUUCTF Reverse 刷题
# easyre | 入门级
- 方法一：WinHex 打开 easyre.exe，浏览一下字符串，发现有flag
- 方法二：IDA Pro 打开 easyre.exe，能直接看到flag，或者 F5 反汇编看到逻辑是输入两个相同的整数就输出 flag，或者 shift+F12 打开字符串常量窗口，比 WinHex 方便一点浏览字符串。

# reverse_1 | 入门级
函数列表找不到名称带有 main 的函数。看字符串也看不到 flag，但没关系，能看到 wrong flag 和 this is right flag 的提示信息，进入对应函数，F5 反汇编。

- strncmp(Str1, Str2, v3): 比较 Str1 和 Str2 的前 v3 个字节(char)。
- Str1 是 {hello_world}，下面的逻辑是把 Str1 的 o 替换为 0，即得到 flag。

![](2023-01-27-19-31-35.png)

# reverse_2 | 入门级
看起来不是 PE 格式的程序，那就只能静态分析了（毕竟本地没装linux）。IDA Pro 加载，能找到 main 函数，F5 反汇编。
![](https://img-blog.csdnimg.cn/73f633b086664c2695678a3ae0a9cdc7.png)
![](https://img-blog.csdnimg.cn/7058190d1b834f56a00f6b6c47061b40.png)

- 0x7B 是 '{'，因为 0x7B 后面没有结束符，所以上面的循环会遍历到`hacking_for_fun}`结尾处的0x00（字符串`\0`结束标记）。合起来这里的字符串实际上是`{hacking_for_fun}`。
- 把字符串的i和r替换为1即可。
