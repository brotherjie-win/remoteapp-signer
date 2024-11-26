# RemoteApp签名工具 (Python)
## 说明文档
[English](https://github.com/brotherjie-win/steam-icon-fix/blob/main/README.md) | 简体中文 | [繁體中文](https://github.com/brotherjie-win/steam-icon-fix/blob/main/README_TC.md)
## 功能
对RemoteAppTool生成的RDP文件进行签名，连接时显示发布者名称，避免未知发布者的提示。
### ✅ 已签名：
![已签名](https://raw.githubusercontent.com/brotherjie-win/remoteapp-signer/refs/heads/image/img/rdp_signed.png)
### ❌ 未签名:
![未签名](https://raw.githubusercontent.com/brotherjie-win/remoteapp-signer/refs/heads/image/img/rdp_unsigned.png)
### ❓签名篡改：
![签名篡改](https://raw.githubusercontent.com/brotherjie-win/remoteapp-signer/refs/heads/image/img/rdp_tampered.png)
## 使用方法
### ⚠ 警告: （1）RemoteApp签名工具目前只能用于为RemoteApp程序的RDP文件签名，普通的远程桌面连接的RDP文件签名后会无法正常打开。
### （2）该工具只能使RDP文件打开时不显示安全警告，如果要实现连接时也不显示安全警告，需要按照3. 远程连接安全性中的方法导入证书，修改RDP文件后重新签名。
### 1. 直接使用打包后的程序文件（普通用户推荐）
1. **Windows系统注意：** 签名工具依赖于OpenSSL，若未安装则首先必须[安装](https://slproweb.com/products/Win32OpenSSL.html)并将openssl.exe所在的目录加入环境变量中；
2. 首先从[Releases](https://github.com/brotherjie-win/steam-icon-fix/releases/latest)下载打包好的程序文件，解压到适当的文件夹下；
3. 进入程序目录后打开config.yml文件（推荐使用VSCode等编辑器），修改output-folder为签名后的RDP文件的输出文件夹，分别修改sign-certificate/key为SSL证书文件和密钥文件的路径（需要PEM格式）。
#### 1.1 列表批量签名模式（当前仅支持UTF-8编码的RDP文件）
4. 打开signlist.yml，在file中按照格式新增待签名的单个RDP文件的路径，在folder中按照格式新增待签名的包含待签名RDP文件的目录的路径，如果没有文件或文件夹需要签名，请将；
5. 运行"RemoteAppSigner.exe"等待程序自动扫描signlist.yml并提取所有的待签名文件的路径列表；
6. 程序会自动对所有的RDP文件进行签名并显示结果，如果中途出现问题，签名会失败并显示原因，此时列表中剩余的文件不会被继续签名。签名完成后按任意键退出。
#### <cmdsingle>1.2 命令行单个签名模式（支持UTF-8和UTF-16-LE编码的RDP文件）
4. 打开命令行（如CMD），输入cd /d RemoteAppSigner.exe所在的目录，切换工作目录到RemoteApp签名工具的路径下；
5. 按照以下格式输入命令：RemoteAppSigner.exe -i 待签名的单个RDP文件的路径 -s -c config.yml -e 待签名的RDP文件的编码。编码选项（-e）支持utf-8和utf-16，其中utf-8有无BOM均支持，utf-16仅支持UTF-16-LE（小端字节序）；
6. 程序会自动对该RDP文件进行签名并显示结果，如果中途出现问题，签名会失败并显示原因。签名完成后按任意键退出。
#### <cmdmulti>1.3 命令行批量签名模式（支持UTF-8和UTF-16-LE编码的RDP文件）
4. 打开命令行（如CMD），输入cd /d RemoteAppSigner.exe所在的目录，切换工作目录到RemoteApp签名工具的路径下；
5. 按照以下格式输入命令：RemoteAppSigner.exe -i 含待签名的RDP文件的文件夹的路径 -m -c config.yml -e 待签名的RDP文件的编码。编码选项（-e）支持utf-8和utf-16，其中utf-8有无BOM均支持，utf-16仅支持UTF-16-LE（小端字节序）；
6. 程序会自动提取该文件夹内的所有RDP文件，然后进行签名并显示结果，如果中途出现问题，签名会失败并显示原因，此时列表中剩余的文件不会被继续签名。签名完成后按任意键退出。
### 2. 开发者
1. 确保在本地搭建好Python开发环境, 目前用于开发和测试该程序使用的是Python 3.8.10版本。
2. 切换到代码目录下, 使用Conda, Virtualenv等工具创建开发用的虚拟环境。
3. 激活上面创建的虚拟环境, 在代码目录下运行"pip install -r requirements.txt"安装程序所需的依赖项。
4. 根据需要修改代码，完成后填写命令行参数的方法和[1.2](#cmdsingle)及[1.3](#cmdmulti)相同，区别是将exe文件名称更换为python signer.py 参数。
### 3. 远程连接安全性
1. 直接下载用于IIS服务器的SSL证书，或者使用openssl将PEM格式的证书和私钥合成P12证书：  
openssl pkcs12 -export -clcerts -in 证书文件路径 -inkey 私钥文件路径 -out 输出P12证书文件的路径；
2. 在键盘上按下Win+R打开运行，输入certlm.msc进入计算机证书管理，然后用右键单击“个人”，选择所有任务-导入，选择对应的证书，输入私钥密码完成证书导入；
3. 在计算机证书管理中打开导入的证书，切换到“详细信息”选项卡，找到“指纹”，获取其中的值；
4. 在键盘上按下Win+R打开运行，输入regedit进入注册表编辑器，进入HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp，
右键单击空白处选择新建-二进制值，值名称为SSLCertificateSHA1Hash，然后用键盘输入上一步获取的指纹的值，完成后单击确定；
5. 将证书对应的域名解析到需要提供远程桌面服务的服务器对应的IP地址，并将未签名的RDP文件中的连接地址替换为证书对应的域名，然后重新签名；
6. 重启计算机，确保设置已经生效。
## 原理
RDP文件签名的函数是从[rdpsign](https://github.com/nfedera/rdpsign)中获取的，是通过对Windows提供的rdpsign.exe的逆向工程后实现的。  
1. 程序首先检查指定的配置文件（可以通过-c选项指定）是否存在，并读取其中的配置信息。
2. 然后程序判断输入的待签名文件的格式，如果是.yml文件则进入列表批量签名模式，否则进入命令行签名模式。  
3. 如果使用命令行签名模式，程序会调用一系列检查函数，检查待签名文件和配置文件的有效性，验证通过后根据签名模式，对单个RDP文件或文件夹内的RDP文件签名。  
4. 如果使用列表批量签名模式，则首先提取出yml文件中所有待签名文件的路径，然后通过调用命令行单个文件签名的函数对RDP文件逐个签名。  
## 特别注意
1. 打包好的RemoteAppSigner.exe目前经过测试支持Windows 10 2004/Windows 11 22H2/23H2 x64系统，与Windows 7 x64 SP1系统不兼容。
2. 签名后的RDP文件目前在Windows10和11系统上测试连接正常，macOS、iOS、Android等终端暂未测试，如需全平台使用建议使用[RAWeb](https://github.com/kimmknight/raweb)部署基于网页的RemoteApp资源库。
3. 目前该工具暂时不适用于对远程桌面的RDP文件签名，如果你了解原因或知道修复方法欢迎提交Pull请求和Issue。  
