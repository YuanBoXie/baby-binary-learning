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
待分析样本：ch1_wsample01b.exe 用 Process Monitor 监控，设置过滤规则只看该程序的文件操作，可以看到与 sample_mal.exe 有同样的行为：在启动文件夹释放了程序副本。要进一步跟踪程序逻辑，需要用到调试器。调试器具有断点；单步跳入、跳出；查看寄存器和内存数据等功能。此处使用 OllyDbg 进行动态调试。

