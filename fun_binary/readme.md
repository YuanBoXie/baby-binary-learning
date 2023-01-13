- 冯诺依曼结构的核心：处理器按照顺序执行指令和操作数据。无论是指令还是数据，本质都是二进制构成的序列。逆向工程通过分析二进制(反汇编后的汇编代码)来分析程序行为。

------------
- 静态分析：在不运行目标程序的情况下进行分析
- 动态分析：在运行目标程序的情况下进行分析

# Ch1 hello,world
## sample_mal.exe - hello,world
待分析样本：ch1_sample_mal.exe (运行前请 copy 备份一份,即 ch1_sample_mal.exe.backup，该程序会自我删除，无恶意行为)

程序行为：
- 1）将自己复制到启动文件夹以便在系统重启时运行：在启动文件夹创建 0.exe、在我的文档创建 1.exe
- 2）修改注册表以便在系统重启时运行：在注册表创建 Software\\Microsoft\\Windows\\CurrentVersion\\Run\sample_mal

完整源码参考原始 repo，上述行为代码如下:
```cpp
	case WM_DESTROY:
		// file
		GetModuleFileName(NULL, szMe, sizeof(szMe));
		SHGetSpecialFolderPath(NULL, szPath, CSIDL_STARTUP, FALSE); // CSIDL_STARTUP 启动文件夹
		lstrcat(szPath, "\\0.exe");
		CopyFile(szMe, szPath, FALSE);
		// reg
		SHGetSpecialFolderPath(NULL, szPath, CSIDL_PERSONAL, FALSE); // CSIDL_PERSONAL 我的文档
		lstrcat(szPath, "\\1.exe");
		CopyFile(szMe, szPath, FALSE);
		SetRegValue(HKEY_LOCAL_MACHINE,                             // 注册表自启动项
			"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
			"sample_mal", szPath, strlen(szPath));
		SelfDelete();                                               // 自我删除(因此进行该实验前请先备份文件)
		PostQuitMessage(0);
		break;
```
实验流程：1. 双击运行该文件，然后关闭窗口（触发相关行为）；2. 观察相关位置是否被修改（分别从文件系统、注册表和Process Monitor观察）；3. 还原：删除对应位置的文件和注册表即可。

Win11 启动文件夹位置：C:\Users\（用户名）\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
## wasample01a.exe - 静态分析 hello,world
待分析样本：ch1_wasample01a.exe 用 WinHex 打开可以看到一些字符串，用 IDA 打开在 Hex View 也类似，IDA 打开文件时选 PE 格式，shift+F4 打开 Names Window，双击 wWinMian 函数跳转到对应的 View-A 反汇编代码页面的对应函数汇编代码位置。
分别执行：
```bash
./ch1_wasample01a.exe
./ch1_wasample01a.exe 2012
```
发现窗口中文案有变化，阅读汇编代码可以看到程序执行了lstrcmpW()函数，并根据结果分别进入了两个分支。以下是该程序的源码：
```cpp
#include <Windows.h>
#include <tchar.h>

int APIENTRY _tWinMain(
	HINSTANCE hInstance, 
	HINSTANCE hPrevInstance, 
	LPTSTR    lpCmdLine, 
	int       nCmdShow)
{
	if(lstrcmp(lpCmdLine, _T("2012")) == 0){
		MessageBox(GetActiveWindow(), 
			_T("Hello! 2012"), _T("MESSAGE"), MB_OK);
	}else{
		MessageBox(GetActiveWindow(), 
			_T("Hello! Windows"), _T("MESSAGE"), MB_OK);
	}	
	return 0;
}
```
在IDA Pro View-A 按 F5 可以查看C语言伪码（这里需要用32bit的IDA），可以看到伪码跟上述源码差不多。
## wasample01b.exe - 动态分析 hello,world
待分析样本：ch1_wsample01b.exe 用 Process Monitor 监控，设置过滤规则只看该程序的文件操作，可以看到与 sample_mal.exe 有同样的行为：在启动文件夹释放了程序副本。要进一步跟踪程序逻辑，需要用到调试器。调试器具有断点；单步跳入、跳出；查看寄存器和内存数据等功能。此处使用 x32dbg 进行动态调试。

- 反汇编窗口 Ctrl+G => 00401000 (注意这是x32的地址) 跳转到该地址的程序逻辑，看到程序依次执行了四个函数，并且结合 ProcessMonitor 的监控结果知道程序会向启动文件夹复制文件，因此猜测第四个函数 CopyFileW 即实现该功能。如果要调试到该处的代码，需要在00401000处下好断点然后F9(会一直执行到断点)即可。然后按 F8 单步调试（不进入函数内部），直到 00401062 即 call dword ptr ds:[<&CopyFileW>]，此时启动文件夹下还没有程序。此时继续按下 F8，启动文件夹下出现该程序。因此可以判断该行指令调用的函数即实现启动文件夹副本释放的功能。

在软件分析时，一般先用 WinHex 和 IDA 先看一下软件整体情况，然后再用调试器单步运行看一些关键点。

## 汇编基础
- 寄存器：EAX、ECX、EDX、EBX、ESP、EBP、ESI、EDI、EIP；
- 标志寄存器：ZF、PF、AF、OF、SF、DF、CF、TF、IF；
- 只有 WinDbg 才能对 Windows 系统内核程序进行调试，分析 Rootkit 这类运行在 Windows 内核中的恶意程序时需要该调试器；
- 一般子程序的返回值写在 EAX 寄存器中；
- 大多数情况下 test 指令后都跟两个相同的寄存器名称，test 是判断寄存器的值是否为0，若为0设置 ZF=1；

Windows 汇编器：[nasm](nasm.us) 连接器: ALINK 汇编程序样本：ch1_hello32.asm

# Ch2 在射击游戏中防止玩家作弊
在分析本书样本之前，可以先用 CheatEngine 分析一下自带教程，在 Help 里，会打开一个新的窗口，然后在CE里直接挂载这个进程。

## ch2_shooting
![](2023-01-13-12-52-42.png)
打开 shooting.exe 先玩一下，然后通过 CheatEngine 搜索 Score。这个时候可能有多个返回结果，我们继续玩游戏，CE里修改数值，再 NextScan 一次。如果还是定位到该变量，尝试修改数值，观察游戏中的数值是否发生改变。注意：Memory Scan Options 里别选 shooting.exe。

## ch2_guitest
内存转储(memory dump)：把内存数据转储成文件；
随着程序的运行，内存中的数据会随着时间不断变化，如果想要保存某个时间点的快照，就用内存转储。

Windows任务管理器->选中进程右键->创建转储文件
由于目前的Windows已经默认不带有 Dr.Watson 内存转储工具（win xp以后的高版本windows可以手动设置实时调试器，如 OllyDbg），此处已经给出了分析结果。
```
*----> 线程 Id 0x4d8 的状态转储  <----*

eax=00000001 ebx=00000000 ecx=00000000 edx=00000041 esi=00401290 edi=0012f958
eip=004012bf esp=0012f8f0 ebp=0012f8f0 iopl=0         nv up ei pl zr na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246

*** ERROR: Module load completed but symbols could not be loaded for C:\Temp\guitest.exe
函数: guitest
        004012a4 106683           adc     [esi-0x7d],ah
        004012a7 f8               clc
        004012a8 01740c66         add     [esp+ecx+0x66],esi
        004012ac 83f802           cmp     eax,0x2
        004012af 7406             jz      guitest+0x12b7 (004012b7)
        004012b1 33c0             xor     eax,eax
        004012b3 5d               pop     ebp
        004012b4 c21000           ret     0x10
        004012b7 0fb7c0           movzx   eax,ax
        004012ba ba41000000       mov     edx,0x41
错误 ->004012bf 668911           mov     [ecx],dx              ds:0023:00000000=????
        004012c2 8b4d08           mov     ecx,[ebp+0x8]
        004012c5 50               push    eax
```
可以看到此时 ecx 的地址是 0，NULL ptr 导致程序崩溃。

对于转储的 .dmp 文件，可以用 WinDbg 分析：File -> Open Crash Dumps，这里分析方式参考书（因为我的实验环境装不上WinDbg..)

游戏机的调试分析网站：devkitPro

## 反调试
