# RemoteApp簽名工具 (Python)
## 說明文檔
[English](https://github.com/brotherjie-win/steam-icon-fix/blob/main/README.md) | 简体中文 | [繁體中文](https://github.com/brotherjie-win/steam-icon-fix/blob/main/README_TC.md)
## 功能
對RemoteAppTool生成的RDP文件進行簽名，連接時顯示發布者名稱，避免未知發布者的提示。
### ✅ 已簽名：
![已簽名](https://raw.githubusercontent.com/brotherjie-win/remoteapp-signer/refs/heads/image/img/rdp_signed.png)
### ❌ 未簽名:
![未簽名](https://raw.githubusercontent.com/brotherjie-win/remoteapp-signer/refs/heads/image/img/rdp_unsigned.png)
### ❓簽名篡改：
![簽名篡改](https://raw.githubusercontent.com/brotherjie-win/remoteapp-signer/refs/heads/image/img/rdp_tampered.png)
## 使用方法
### ⚠ 警告: （1）RemoteApp簽名工具目前只能用於為RemoteApp程序的RDP文件簽名，普通的遠程桌面連接的RDP文件簽名後會無法正常打開。
### （2）該工具只能使RDP文件打開時不顯示安全警告，如果要實現連接時也不顯示安全警告，需要按照3. 遠程連接安全性中的方法導入證書，修改RDP文件後重新簽名。
### 1. 直接使用打包後的程序文件（普通用戶推薦）
1. **Windows系統註意：** 簽名工具依賴於OpenSSL，若未安裝則首先必須[安裝](https://slproweb.com/products/Win32OpenSSL.html)並將openssl.exe所在的目錄加入環境變量中；
2. 首先從[Releases](https://github.com/brotherjie-win/steam-icon-fix/releases/latest)下載打包好的程序文件，解壓到適當的文件夾下；
3. 進入程序目錄後打開config.yml文件（推薦使用VSCode等編輯器），修改output-folder為簽名後的RDP文件的輸出文件夾，分別修改sign-certificate/key為SSL證書文件和密鑰文件的路徑（需要PEM格式）。
#### 1.1 列表批量簽名模式（當前僅支持UTF-8編碼的RDP文件）
4. 打開signlist.yml，在file中按照格式新增待簽名的單個RDP文件的路徑，在folder中按照格式新增待簽名的包含待簽名RDP文件的目錄的路徑，如果沒有文件或文件夾需要簽名，請將；
5. 運行"RemoteAppSigner.exe"等待程序自動掃描signlist.yml並提取所有的待簽名文件的路徑列表；
6. 程序會自動對所有的RDP文件進行簽名並顯示結果，如果中途出現問題，簽名會失敗並顯示原因，此時列表中剩余的文件不會被繼續簽名。簽名完成後按任意鍵退出。
#### <cmdsingle>1.2 命令行單個簽名模式（支持UTF-8和UTF-16-LE編碼的RDP文件）
4. 打開命令行（如CMD），輸入cd /d RemoteAppSigner.exe所在的目錄，切換工作目錄到RemoteApp簽名工具的路徑下；
5. 按照以下格式輸入命令：RemoteAppSigner.exe -i 待簽名的單個RDP文件的路徑 -s -c config.yml -e 待簽名的RDP文件的編碼。編碼選項（-e）支持utf-8和utf-16，其中utf-8有無BOM均支持，utf-16僅支持UTF-16-LE（小端字節序）；
6. 程序會自動對該RDP文件進行簽名並顯示結果，如果中途出現問題，簽名會失敗並顯示原因。簽名完成後按任意鍵退出。
#### <cmdmulti>1.3 命令行批量簽名模式（支持UTF-8和UTF-16-LE編碼的RDP文件）
4. 打開命令行（如CMD），輸入cd /d RemoteAppSigner.exe所在的目錄，切換工作目錄到RemoteApp簽名工具的路徑下；
5. 按照以下格式輸入命令：RemoteAppSigner.exe -i 含待簽名的RDP文件的文件夾的路徑 -m -c config.yml -e 待簽名的RDP文件的編碼。編碼選項（-e）支持utf-8和utf-16，其中utf-8有無BOM均支持，utf-16僅支持UTF-16-LE（小端字節序）；
6. 程序會自動提取該文件夾內的所有RDP文件，然後進行簽名並顯示結果，如果中途出現問題，簽名會失敗並顯示原因，此時列表中剩余的文件不會被繼續簽名。簽名完成後按任意鍵退出。
### 2. 開發者
1. 確保在本地搭建好Python開發環境, 目前用於開發和測試該程序使用的是Python 3.8.10版本。
2. 切換到代碼目錄下, 使用Conda, Virtualenv等工具創建開發用的虛擬環境。
3. 激活上面創建的虛擬環境, 在代碼目錄下運行"pip install -r requirements.txt"安裝程序所需的依賴項。
4. 根據需要修改代碼，完成後填寫命令行參數的方法和[1.2](#cmdsingle)及[1.3](#cmdmulti)相同，區別是將exe文件名稱更換為python signer.py 參數。
### 3. 遠程連接安全性
1. 直接下載用於IIS服務器的SSL證書，或者使用openssl將PEM格式的證書和私鑰合成P12證書：  
openssl pkcs12 -export -clcerts -in 證書文件路徑 -inkey 私鑰文件路徑 -out 輸出P12證書文件的路徑；
2. 在鍵盤上按下Win+R打開運行，輸入certlm.msc進入計算機證書管理，然後用右鍵單擊「個人」，選擇所有任務-導入，選擇對應的證書，輸入私鑰密碼完成證書導入；
3. 在計算機證書管理中打開導入的證書，切換到「詳細信息」選項卡，找到「指紋」，獲取其中的值；
4. 在鍵盤上按下Win+R打開運行，輸入regedit進入註冊表編輯器，進入HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp，
右鍵單擊空白處選擇新建-二進製值，值名稱為SSLCertificateSHA1Hash，然後用鍵盤輸入上一步獲取的指紋的值，完成後單擊確定；
5. 將證書對應的域名解析到需要提供遠程桌面服務的服務器對應的IP地址，並將未簽名的RDP文件中的連接地址替換為證書對應的域名，然後重新簽名；
6. 重啟計算機，確保設置已經生效。
## 原理
RDP文件簽名的函數是從[rdpsign](https://github.com/nfedera/rdpsign)中獲取的，是通過對Windows提供的rdpsign.exe的逆向工程後實現的。  
1. 程序首先檢查指定的配置文件（可以通過-c選項指定）是否存在，並讀取其中的配置信息。
2. 然後程序判斷輸入的待簽名文件的格式，如果是.yml文件則進入列表批量簽名模式，否則進入命令行簽名模式。  
3. 如果使用命令行簽名模式，程序會調用一系列檢查函數，檢查待簽名文件和配置文件的有效性，驗證通過後根據簽名模式，對單個RDP文件或文件夾內的RDP文件簽名。  
4. 如果使用列表批量簽名模式，則首先提取出yml文件中所有待簽名文件的路徑，然後通過調用命令行單個文件簽名的函數對RDP文件逐個簽名。  
## 特別註意
1. 打包好的RemoteAppSigner.exe目前經過測試支持Windows 10 2004/Windows 11 22H2/23H2 x64系統，與Windows 7 x64 SP1系統不兼容。
2. 簽名後的RDP文件目前在Windows10和11系統上測試連接正常，macOS、iOS、Android等終端暫未測試，如需全平臺使用建議使用[RAWeb](https://github.com/kimmknight/raweb)部署基於網頁的RemoteApp資源庫。
3. 目前該工具暫時不適用於對遠程桌面的RDP文件簽名，如果你了解原因或知道修復方法歡迎提交Pull請求和Issue。  
