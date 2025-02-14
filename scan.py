#!/usr/bin/env python3
import argparse
import os
import re
import sqlite3
from tqdm import tqdm
from prettytable import PrettyTable

# 配置正则表达式模式
PATTERNS = [
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
    # 补充额外的正则
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
    ("弱口令_root", re.compile(r"\broot\b")),
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
]

# 创建或连接 SQLite 数据库，并创建数据表
def create_db():
    conn = sqlite3.connect("sensitive_info.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sensitive_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT,
            line_number INTEGER,
            sensitive_type TEXT,
            match_content TEXT
        )
    ''')
    conn.commit()
    return conn

# 插入匹配记录到数据库
def insert_db(conn, record):
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO sensitive_matches (file_path, line_number, sensitive_type, match_content)
        VALUES (?, ?, ?, ?)
    ''', (record["path"], record["line"], record["type"], record["content"]))
    conn.commit()

# 扫描单个文件，返回匹配信息列表
def scan_file(file_path):
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                for name, pattern in PATTERNS:
                    for match in pattern.finditer(line):
                        findings.append({
                            "path": file_path,
                            "line": line_num,
                            "type": name,
                            "content": match.group()[:100]  # 截断前100个字符
                        })
    except Exception as e:
        # 忽略无法打开的文件
        pass
    return findings

# 扫描目录下所有文件（使用 tqdm 显示进度），同时进行匹配结果去重并保存到 DB
def scan_directory(root_dir):
    # 先收集所有文件，过滤掉 sensitive_info.db 文件
    file_list = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file == "sensitive_info.db":
                continue
            file_list.append(os.path.join(root, file))
    
    aggregated = {}  # key: (file, type, content), value: {"lines": set(), "count": int}
    conn = create_db()
    
    for file_path in tqdm(file_list, desc="扫描文件", unit="file"):
        findings = scan_file(file_path)
        for record in findings:
            key = (record["path"], record["type"], record["content"])
            if key not in aggregated:
                aggregated[key] = {"lines": set(), "count": 0}
            aggregated[key]["lines"].add(record["line"])
            aggregated[key]["count"] += 1
            # 保存每次匹配到的记录到数据库
            insert_db(conn, record)
    
    conn.close()
    return aggregated

# 输出扫描结果（去重后的统计信息）
def display_results(aggregated):
    table = PrettyTable()
    table.field_names = ["文件路径", "行号", "敏感类型", "匹配内容", "重复次数"]
    table.align = "l"
    table.max_width["文件路径"] = 60
    table.max_width["匹配内容"] = 50

    total = 0
    for (path, sensitive_type, content), data in aggregated.items():
        lines = ", ".join(map(str, sorted(data["lines"])))
        count = data["count"]
        total += count
        table.add_row([path, lines, sensitive_type, content, count])
    print("\n扫描结果：")
    print(table)
    print(f"\n扫描完成，共发现 {total} 处敏感信息（去重后 {len(aggregated)} 条记录）。")

# 查询数据库中的敏感信息记录
def query_db(query_str):
    conn = sqlite3.connect("sensitive_info.db")
    cursor = conn.cursor()
    like_pattern = f"%{query_str}%"
    cursor.execute('''
        SELECT file_path, line_number, sensitive_type, match_content 
        FROM sensitive_matches 
        WHERE match_content LIKE ?
    ''', (like_pattern,))
    rows = cursor.fetchall()
    conn.close()
    
    table = PrettyTable()
    table.field_names = ["文件路径", "行号", "敏感类型", "匹配内容"]
    table.align = "l"
    table.max_width["文件路径"] = 60
    table.max_width["匹配内容"] = 50
    for row in rows:
        table.add_row(row)
    print("\n查询结果：")
    print(table)

def main():
    parser = argparse.ArgumentParser(description="敏感信息扫描与查询工具")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="需要扫描的目录路径")
    group.add_argument("-data", "--data", help="查询敏感信息内容（通过数据库查询）")
    args = parser.parse_args()
    
    if args.file:
        if not os.path.isdir(args.file):
            print("错误：需要提供有效的目录路径")
            return
        print(f"正在扫描目录: {args.file} ...")
        aggregated = scan_directory(args.file)
        display_results(aggregated)
    elif args.data:
        print(f"正在查询包含 '{args.data}' 的敏感信息记录 ...")
        query_db(args.data)

if __name__ == "__main__":
    main()
