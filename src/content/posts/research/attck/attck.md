---
title: ATT&CK介绍
published: 2024-09-01
description: "ATT&CK介绍"
tags: ["技战法"]
category: research
draft: false
---

#### **一、ATT&CK介绍**

ATT&CK，全称为Adversarial Tactics, Techniques, and Common Knowledge(对抗性战术、技术和通用知识)，是一个由MITRE创建并维护的框架。这个知识库旨在汇总和分类现实世界中观察到的网络攻击行为，为网络安全专业人员提供了一套全面的工具，以便更好地理解、预防、检测和响应这些威胁。

官方站点：https://attack.mitre.org/

中文版：https://seccmd.github.io/Attack_CN/

ATT&CK框架的核心组成部分包括：

- **战术(Tactics)**：代表攻击者追求的短期目标，如初始访问、执行、持久化、特权提升等，这些战术构成了攻击的各个阶段。
- **技术(Techniques)**：描述了攻击者为达到战术目标而采用的具体方法或动作。
- **子技术(Sub-techniques)**：进一步细分技术，提供了更细致的层次，说明了在更具体的情境下如何实施这些技术。

该框架不仅被用于分析和逆向工程恶意活动，还帮助组织评估自己的防御措施、规划安全控制、进行威胁狩猎和提升事件响应能力。由于它是基于实际案例研究的，因此具有高度的相关性和实用性，能够不断进化以适应新的威胁 landscape。此外，ATT&CK框架也常用于红队(攻击模拟团队)和蓝队(防御团队)的训练与演练中，以增强组织的整体安全态势。

:::warning
ATT&CK框架中的技术列表会随时间更新以反映最新的威胁情报。因此，建议定期访问MITRE的官方网站以获取最新版本。
:::

#### **二、战术**

MITRE ATT&CK框架为网络攻击行为定义了14个核心战术(Tactics)，这些战术代表了攻击者为了达成其最终目标所采取的一系列阶段性目标。以下是这14个战术及其简要说明：

1. **初始访问 (Initial Access)**：攻击者首次进入目标网络或系统的方式，例如通过钓鱼邮件、利用公开的远程访问或供应链妥协。
2. **执行 (Execution)**：攻击者在目标系统上启动恶意代码的过程，包括通过文档宏、命令行界面或脚本执行。
3. **持久化 (Persistence)**：确保恶意软件或访问权限能在系统重启后仍然存在，例如通过注册表修改、计划任务或服务安装。
4. **权限提升 (Privilege Escalation)**：增加攻击者在系统或网络中的权限级别，如通过漏洞利用或盗取凭证。
5. **防御规避 (Defense Evasion)**：绕过或禁用安全控制和防御机制，以避免被检测或移除，如清除日志、隐藏文件或进程。
6. **凭据访问 (Credential Access)**：窃取、破解或利用账户凭证，以进一步访问目标系统或数据。
7. **发现 (Discovery)**：收集关于目标网络、系统和用户的信息，为后续攻击做准备，如枚举网络资源、查询系统信息。
8. **横向移动 (Lateral Movement)**：在目标网络内部扩展控制范围，通过已受感染系统访问其他系统。
9. **收集 (Collection)**：识别并获取目标信息，包括敏感文件和数据，为数据外传做准备。
10. **命令与控制 (Command and Control, C2)**：建立与受控系统的隐蔽通信渠道，发送指令和接收数据。
11. **数据外传 (Exfiltration)**：将窃取的数据传输出目标网络，可能使用加密或其他隐蔽方式。
12. **影响力 (Impact)**：破坏、篡改或阻止对目标系统的正常访问，以造成损害或混乱，例如数据加密(勒索软件)或删除数据。
13. **账户操纵 (Account Manipulation)**：操纵或利用账户，可能涉及创建、修改或删除账户，以支持攻击活动。
14. **业务流程妥协 (Business Process Compromise)**：通过操纵业务流程或交易，以非法获利或造成经济损失。

每个战术之下都包含了多种具体的技术(Techniques)和子技术(Sub-techniques)。

#### **三、技术**

由于每个ATT&CK**战术**下**包含**众多具体**技术**，并且技术列表会随时间更新以反映最新的威胁情报，因此下面只列举每个战术类别下通常涵盖的一些关键技术类型：

1. **初始访问 (Initial Access)**
   - Phishing：钓鱼攻击
   - Exploit Public-Facing Application：利用面向公众的应用程序漏洞
   - Drive-by Compromise：路过式攻击
   - Supply Chain Compromise：供应链攻击
2. **执行 (Execution)**
   - Scripting：脚本执行
   - Command Line Interface：命令行接口利用
   - PowerShell：利用PowerShell执行恶意代码
   - User Execution：诱导用户执行恶意代码
3. **持久化 (Persistence)**
   - Registry Run Keys / Startup Folder：注册表运行键和启动文件夹
   - Modify Existing Service：修改现有服务
   - Create or Modify System Process：创建或修改系统进程
4. **权限提升 (Privilege Escalation)**
   - Exploitation of Vulnerability：利用漏洞
   - Exploitation of Unquoted Service Path：利用未引号服务路径漏洞
   - Valid Accounts：使用合法账户
5. **防御规避 (Defense Evasion)**
   - Masquerading：伪装恶意软件为合法软件
   - Indicator Removal on Host：主机上的指标清除
   - Obfuscated Files or Information：文件或信息混淆
6. **凭据访问 (Credential Access)**
   - Brute Force：暴力破解
   - Credential Dumping：凭证转储
   - Password Spraying：密码喷洒
7. **发现 (Discovery)**
   - System Information Discovery：系统信息发现
   - Network Service Scanning：网络服务扫描
   - File and Directory Discovery：文件和目录发现
8. **横向移动 (Lateral Movement)**
   - Pass the Hash：传递哈希认证
   - Remote File Copy：远程文件复制
   - Remote Services：利用远程服务
9. **收集 (Collection)**
   - Data from Local System：从本地系统收集数据
   - Screen Capture：屏幕截图
   - Clipboard Data：剪贴板数据收集
10. **命令与控制 (Command and Control, C2)**
    - Standard Application Layer Protocol：标准应用层协议利用
    - Custom Command and Control Protocol：自定义C2协议
    - Web Service：基于Web的服务作为C2通道
11. **数据外传 (Exfiltration)**
    - Exfiltration Over Command and Control Channel：通过C2通道外传
    - Exfiltration Over Alternative Protocol：通过替代协议外传
    - Data Staged：数据暂存以待外传
12. **影响 (Impact)**
    - Disk Wipe：磁盘擦除
    - Service Stop：停止服务
    - Ransomware：勒索软件
13. **账户操纵 (Account Manipulation)**
    - Account Creation：账户创建
    - Account Modification：账户修改
    - Account Disablement：账户禁用
14. **业务流程妥协 (Business Process Compromise)**
    - Invoice Fraud：发票欺诈
    - Payment Request Fraud：支付请求欺诈

#### **四、子技术**

子技术(Sub-techniques)是在ATT&CK框架中对技术(Techniques)更细致的划分，它们提供了针对每项技术更为具体和详细的实施方法。子技术有助于安全专业人员更精确地识别和应对威胁。由于子技术数量庞大并且随着框架的更新而变化，下面概述几个例子来说明其性质：

- **T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking**：劫持执行流的一种子技术，通过利用DLL搜索顺序的特性加载恶意DLL。
- **T1059.001 - Command and Scripting Interpreter: PowerShell**：命令与脚本解释器技术下的子技术，专门指利用PowerShell执行恶意命令和脚本。
- **T1003.001 - OS Credential Dumping: LSASS Memory**：凭据转储技术的一个子技术，特别关注从LSASS内存中提取凭证。

每个子技术都附有其独特的描述、示例、缓解措施和检测方法，旨在帮助分析师深入了解攻击者行为并采取相应的防御措施。要查看所有最新的子技术及其详细信息，最佳做法是直接访问MITRE ATT&CK官方网站的[企业版技术页面](https://attack.mitre.org/techniques/enterprise/)，其提供了一个可搜索的数据库，允许用户根据战术、技术或子技术名称进行查询。