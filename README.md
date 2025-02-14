# sensitiveInfScan
对指定目录下进行敏感信息检索

# Why create
由于工作中常会遇到apk反编译/代码审计等情况，而对反编译后的结果或代码进行敏感信息搜索，常见的apk静态扫描工具实际上可拓展性不高，并且比较死板，如果apk加壳了，往往直接反编译其实效果非常差，故此可以将敏感信息搜索这部分功能单独分出来非常有必要，故此写了这个小工具。

# Demonstrate
指定目录进行扫描：
```bash
python3 scan.py -f /Users/xxx/Downloads/xxxx/sources
```
![image](https://github.com/user-attachments/assets/8ba831f1-33b1-4232-ac59-837723abc963)

输出结果会进行去重，如果想看重复的“敏感信息”在多文件中出现的具体位置，可通过“-data”的方式进行单独搜索（前提搜索结果是在上述目录扫描结果中存在的“敏感信息”）：
```bash
python3 scan.py -data "http://localhost/"
```
![image](https://github.com/user-attachments/assets/9bda51bf-fd08-4623-a497-b30dc664fc0a)


# Install
安装方式：
```bash
git clone https://github.com/z1sec/sensitiveInfScan
cd sensitiveInfScan
python3 -m pip install sqlite3 tqdm prettytable -i https://mirrors.aliyun.com/pypi/simple/
```

# 支持扫描的敏感信息
共支持68种敏感信息的搜集：
```
("信用卡号", re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b")),
("电子邮件", re.compile(r"\b[\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,6}\b")),
("URL地址", re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .?&%=_-]*")),
("IPv4地址", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
("社会安全号", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
("IPv6地址", re.compile(r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}")),
("电话号码", re.compile(r"\b[2-9]\d{2}-\d{3}-\d{4}\b")),
("MAC地址", re.compile(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")),
("Google密钥", re.compile(r'"private_key_id":\s*"(\w{40})"')),
("AWS密钥", re.compile(r"\b(?:aws_?access_?key_?id|aws_?secret_?access_?key)\s*=\s*[\w/+]{20,40}\b")),
("比特币钱包", re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")),
("文件路径", re.compile(r"\b[\w/-]+\.(?:txt|pdf|docx?|xlsx?|sql|db|bak|gpg|pgp)\b")),
("哈希值", re.compile(r"\b[0-9a-fA-F]{32,512}\b")),
("JWT令牌", re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+\b")),
("AWS访问密钥ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
("私钥文件", re.compile(r"-{5}BEGIN [A-Z ]+ PRIVATE KEY-{5}[\s\S]+?-{5}END [A-Z ]+ PRIVATE KEY-{5}")),
("密码字段1", re.compile(r"password\s*=\s*['\"]?[\w!@#$%^&*()+]{6,}")),
("密码字段2", re.compile(r"pass\s*=\s*['\"]?[\w!@#$%^&*()+]{6,}")),
("算法私钥", re.compile(r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", re.DOTALL)),
("SSH密钥", re.compile(r"ssh-(rsa|dss) [A-Za-z0-9+/]+[=]{0,3}")),
("身份证号码", re.compile(r"\b\d{17}[\dXx]\b")),
("手机号码", re.compile(r"\b1[3-9]\d{9}\b")),
("以太坊地址", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
("IMEI号码", re.compile(r"\b\d{15}\b")),
("银行卡号", re.compile(r"\b\d{16,19}\b")),
("EIN号码", re.compile(r"\b\d{2}-\d{7}\b")),
("Slack Webhook URL", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+")),
("谷歌API密钥", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
("OAuth令牌", re.compile(r"ya29\.[0-9A-Za-z\-_]+")),
("弱口令_admin123", re.compile(r"\badmin123\b")),
("弱口令_123456", re.compile(r"\b123456\b")),
("弱口令_1qaz@WSX", re.compile(r"\b1qaz@WSX\b")),
("弱口令_password", re.compile(r"\bpassword\b")),
("弱口令_qwerty", re.compile(r"\bqwerty\b")),
("弱口令_abc123", re.compile(r"\babc123\b")),
("弱口令_welcome", re.compile(r"\bwelcome\b")),
("弱口令_111111", re.compile(r"\b111111\b")),
("弱口令_666666", re.compile(r"\b666666\b")),
("弱口令_888888", re.compile(r"\b888888\b")),
("弱口令_123123", re.compile(r"\b123123\b")),
("弱口令_monkey", re.compile(r"\bmonkey\b")),
("弱口令_dragon", re.compile(r"\bdragon\b")),
("弱口令_ruoyi", re.compile(r"\bruoyi\b")),
("弱口令_iloveyou", re.compile(r"\biloveyou\b")),
("弱口令_admin", re.compile(r"\badmin\b")),
# ("弱口令_root", re.compile(r"\broot\b")), # 误报太多
("弱口令_password", re.compile(r"\bpassword\b")),
("AWS AK", re.compile(r'^AKIA[A-Za-z0-9]{16}$')),
("GoogleCloudPlatform", re.compile(r'^GOOG[\w\W]{10,30}$')),
("Microsoft Azure", re.compile(r'^AZ[A-Za-z0-9]{34,40}$')),
("IBM云", re.compile(r'^IBM[A-Za-z0-9]{10,40}$')),
("Oracle Cloud", re.compile(r'^OCID[A-Za-z0-9]{10,40}$')),
("阿里云", re.compile(r'^LTAI[A-Za-z0-9]{12,20}$')),
("腾讯云", re.compile(r'^AKID[A-Za-z0-9]{13,20}$')),
# ("华为云", re.compile(r'[A-Z0-9]{20}')), # 误报太多
("百度云", re.compile(r'^AK[A-Za-z0-9]{10,40}$')),
("京东云", re.compile(r'^JDC_[A-Z0-9]{28,32}$')),
("UCloud", re.compile(r'^UC[A-Za-z0-9]{10,40}$')),
("青云", re.compile(r'^QY[A-Za-z0-9]{10,40}$')),
("金山云", re.compile(r'^AKLT[a-zA-Z0-9-_]{16,28}$')),
("联通云", re.compile(r'^LTC[A-Za-z0-9]{10,60}$')),
("移动云", re.compile(r'^YD[A-Za-z0-9]{10,60}$')),
("电信云", re.compile(r'^CTC[A-Za-z0-9]{10,60}$')),
("一云通", re.compile(r'^YYT[A-Za-z0-9]{10,60}$')),
("用友云", re.compile(r'^YY[A-Za-z0-9]{10,40}$')),
("南大通用云", re.compile(r'^CI[A-Za-z0-9]{10,40}$')),
("G-Core Labs", re.compile(r'^gcore[A-Za-z0-9]{10,30}$')),
```
