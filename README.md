# 一键式自动化渗透测试项目实现文档

## 一、项目概述

本项目以 “用户输入任意 URL” 为触发点，摒弃数据库依赖，通过**工具集成自动化、****JSON** **文件全程存储、轻量化报告生成**，实现 “信息收集→漏洞检测→漏洞渗透→报告导出” 的全流程闭环。所有测试数据（任务信息、工具输出、漏洞详情、渗透结果）均以 JSON 格式存储在本地文件，适配各类 Web 靶场 / 测试目标，部署简单、数据可追溯，适合快速验证与学习使用。

![流程图](data:image/png;base64,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avDoKAP/0v38ooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACsvWrnUrPSbq60a0F9fRRloYGfyxI46KXwdufXFXriQwwSSgZKKW/IZrzrWfiBb+Ho4H1eWOH7QWCARSOWKjceFJ6D1relh5TTaBsypvEfxHupI4G8Kxny2WRk+1r0yAuTj/eb6qB3r2CvB7T4saH/AGldXf8Aae9bjy41ha0lURmLhiCFDHcZFzkkDt3rvdG8X/25b21/YsktrcOEDeW6H7+w8MQRg56itPqUxcyO7wB071xvjG78SWsFmfDmkrqkjS5kJmEJhCqSrDIO7J+Uj0Jrb1qaaC0VoXMbF1GR1xXlWqeMvEGnaq9jFp1xc2yCMm5FzAi5cHI2OQ2RjHvnjvRSwjnHmTG2dR4d8Q+OdS1GGHWPD8VlYuH3TpchyMKCvy4BOWyPbFeiV89ad4u1TS4LfT7XSLq3gPmP893C+3Mn95nYsDuLdcDG30FevaPc3Ml60UszSL5ZOGx1BFVPBSjFyvsK509FFFcQwooooAoar/yC7z/rjJ/6CavDoKo6r/yC7z/rjJ/6CavDoKAP/9P9/KKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigBksayxvE3RwVOPQ8Vh/8ACP22MedIf++f/ia36K0hWlH4WFjA/wCEftv+e0n/AI7/APE0+PQbaORJBLIdjBgPlxlTkdFrcorR4qp3FYztUs5L22EUTBWDBvm6cfSuF1H4c6Vq7TPqdlaXLXBQyM6ElvL+5k9fl7V6XWff6jFYoM/PK33UHU+59B71VCvUXuQGzzNfhp4f1JYrufTLR3jDopcMxA3ZIz7kZrvtM0u4s7lp5nRgUKgLnuQe/wBKoeHLn7HbJpd3O8zhnKSyEEvvYttJAAyM4HqAO9dbV161VXhISsFFFFcQwooooAoar/yC7z/rjJ/6CavDoKo6r/yC7z/rjJ/6CavDoKAP/9T9/KKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAM/Ur1rG2MyJvJIA/urnu3tXj1x4rvxfXMb6FqE7o7KZgibJApAypLD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)

## 二、核心流程实现

### （一）URL 输入与预处理环节

**1.****功能目标**

◦   接收用户输入的 URL（如http://192.168.1.100/test），验证格式合法性与目标可达性；

◦   提取 URL 核心信息（IP / 域名、端口、路径），生成唯一任务 ID，初始化任务 JSON 文件。

**2.****技术实现**

◦   **格式验证**：使用正则表达式/^https?:\/\/.+/校验 URL，前端（Vue.js+Element UI）实时提示格式错误（如 “请输入 http:// 或 https:// 开头的有效 URL”）。

◦   **URL** **解析**：通过 Pythonurllib.parse库拆解 URL

◦   **可达性检测**：通过requests库发送 HEAD 请求，超时时间设为 5 秒，返回 200/301/302 则判定可达。

◦   **JSON** **初始化**：生成唯一任务 ID（如task_20251101_123456），创建任务根 JSON 文件（task_20251101_123456.json），存储基础信息：

 

  {   "task_id":  "task_20251101_123456",   "target_url":  "http://192.168.1.100:8080/test",   "target_ip":  "192.168.1.100",   "target_port": 8080,   "target_path": "/test",   "test_mode": "全面测试",   "task_status": "初始化完成",   "create_time": "2025-11-01  12:34:56",   "info_collection": {},   "vulnerability_detection": {},   "exploitation": {},   "report_path": ""  }  

**3.****输出结果**

◦   前端展示任务初始化成功日志；

◦   本地生成任务根 JSON 文件

### （二）自动化信息收集环节

**1.****功能目标**

◦   调用端口扫描、目录枚举等工具，收集目标开放端口、服务版本、Web 敏感目录等信息；

◦   将工具输出与解析结果存入任务 JSON 的info_collection字段，同时保存工具原始日志文件。

**2.****工具集成与逻辑**

 

| 工具      | 功能                     | 调用命令示例                                            | 结果解析方式                             | JSON 存储格式                                                |
| --------- | ------------------------ | ------------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------ |
| Nmap      | 端口 + 服务版本扫描      | nmap -sV -p 1-10000  {target_ip} -oN nmap.log           | 正则提取(\d+/tcp)\s+open\s+(\w+)\s+(\w+) | "ports":  [{"port": 80, "service": "http",  "version": "Apache/2.4.49", "is_high_risk": 0}] |
| Dirsearch | Web 目录 / 文件扫描      | dirsearch -u {target_url} -e  php,html -o dirsearch.log | 筛选状态码 200/302 的路径                | "web_dirs":  [{"path": "/admin", "status_code": 200,  "description": "敏感管理目录"}] |
| Sublist3r | 子域名枚举（域名 URL）   | sublist3r -d {target_domain}  -o sublist3r.log          | 去重后提取子域名                         | "subdomains":  ["blog.test.com", "api.test.com"]             |
| Whois     | 域名信息查询（域名 URL） | whois {target_domain} >  whois.log                      | 提取注册商、过期时间等关键字段           | "whois_info":  {"registrar": "XXX", "expiration_date":  "2026-11-01"} |

**3.****技术实现细节**

◦   工具调度：通过 Pythonsubprocess库调用系统命令，捕获输出日志。

◦   日志存储：工具原始日志（如nmap.log、dirsearch.log）保存在./tasks/{task_id}/logs/目录，JSON 中记录日志文件相对路径。

**4.****输出结果**

◦   任务 JSON 的info_collection字段填充完整信息；

◦   前端实时展示收集进度（如 “Nmap 扫描完成，发现开放端口 3 个”）。

### （三）自动化漏洞检测环节

**1.****功能目标**

◦   基于信息收集结果，自动选择扫描工具（Web 漏洞→Burp Suite；系统漏洞→OpenVAS）；

◦   检测目标漏洞（SQL 注入、XSS、文件上传等），按预定义规则排序，存入 JSON 的vulnerability_detection字段。

**2.****工具调度逻辑**

◦   **Web** **漏洞扫描（Burp Suite** **社区版）**：

▪   触发条件：信息收集发现 80/443 / 自定义 Web 端口开放，且存在有效 Web 路径；

▪   调用命令（静默扫描模式）：

 

  burpsuite  -silent -target {target_url} -scan-type active -report burp.xml  -report-format xml  

▪   结果解析：解析 XML 报告，提取漏洞名称、位置、CVSS 评分，示例：

 

  "web_vulnerabilities":  [   {    "vuln_name": "SQL注入",    "vuln_type": "Web",    "cvss_score": 8.5,    "vuln_location":  "{target_url}/list?id=1",    "description": "URL参数id存在SQL注入漏洞，可执行任意SQL语句",    "priority": 1 # 1=高危，2=中危，3=低危   }  ]  

◦   **系统 /** **中间件漏洞扫描（OpenVAS****）**：

▪   触发条件：信息收集发现非 Web 端口（如 22 SSH、3306 MySQL）或 Web 服务版本存在已知漏洞；

▪   调用命令：

 

  openvas-cli  scan --target {target_ip} --policy Full\ and\ fast --output openvas.log  

▪   结果解析：提取漏洞名称、影响版本、修复建议，存入 JSON 的system_vulnerabilities字段。

**3.****漏洞排序规则**

◦   优先级 1（高危）：CVSS≥7.0，可直接获取权限（如 SQL 注入、文件上传、远程代码执行）；

◦   优先级 2（中危）：4.0≤CVSS<7.0，影响数据安全（如 XSS、路径遍历）；

◦   优先级 3（低危）：CVSS<4.0，无直接危害（如敏感信息泄露、弱口令提示）。

**4.****输出结果**

◦   任务 JSON 的vulnerability_detection字段填充漏洞列表与工具日志；

◦   前端展示漏洞检测结果（如 “发现高危漏洞 2 个，中危漏洞 1 个”）。

### （四）自动化漏洞渗透环节

**1.****功能目标**

◦   按漏洞优先级（高危→中危→低危）调用渗透工具，尝试利用漏洞；

◦   记录渗透过程（成功 / 失败原因）、获取的权限，存入 JSON 的exploitation字段。

**2.****技术实现细节**

◦   渗透日志记录：工具输出日志（如 MSF 会话信息、sqlmap 结果）保存到./tasks/{task_id}/exploit_logs/目录，JSON 中记录日志路径；

◦   状态更新：渗透完成后，更新任务 JSON 的task_status为 “渗透环节完成”。

### （五）自动化报告生成环节

**1.****功能目标**

◦   读取任务 JSON 中的全流程数据，按标准化模板生成多格式报告（Markdown/PDF/Word）；

◦   报告保存到./tasks/{task_id}/report/目录，JSON 中记录报告路径，支持前端下载。

**2.****技术实现**

◦   **数据提取**：读取任务 JSON 的所有字段，格式化数据（如端口信息转为表格、日志按时间排序），示例：

 

  import  json  with  open(task_json_path, "r") as f:    task_data = json.load(f)  # 提取漏洞列表  vulnerabilities  =  task_data["vulnerability_detection"]["web_vulnerabilities"]  +  task_data["vulnerability_detection"]["system_vulnerabilities"]  

◦   **模板渲染**：使用 Jinja2 模板引擎，设计标准化报告模板（核心章节：执行摘要→测试过程→漏洞详情→渗透结果→安全建议→附录），示例模板片段：

 

  # 渗透测试报告  ## 1. 执行摘要  - 测试目标URL：{{ task_data.target_url }}  - 测试时间：{{ task_data.create_time }}  - 测试模式：{{ task_data.test_mode }}  - 漏洞总数：{{ len(vulnerabilities) }}  - 渗透成功数：{{ sum(1 for exp in  task_data.exploitation.exploitation_results if exp.result == '成功') }}  ## 2. 信息收集结果  ### 2.1 开放端口  | 端口 | 服务 | 版本 | 是否高危 |  {% for  port in task_data.info_collection.ports %}  | {{  port.port }} | {{ port.service }} | {{ port.version }} | {{ '是' if port.is_high_risk == 1 else  '否' }} |  {% endfor  %}  

◦   **多格式导出**：

▪   Markdown：直接渲染 Jinja2 模板，保存为report.md；

▪   PDF：通过Python-Markdown将 Markdown 转为 HTML，再用WeasyPrint转为 PDF；

▪   Word：通过python-docx库逐章节写入数据，插入表格与日志片段。

◦   **JSON** **更新**：报告生成后，在任务 JSON 中记录报告路径：

 

  "report_path":  {   "markdown":  "./tasks/task_20251101_123456/report/report.md",   "pdf":  "./tasks/task_20251101_123456/report/report.pdf",   "word":  "./tasks/task_20251101_123456/report/report.docx"  }  

1. **输出结果**

◦   本地生成多格式报告文件；

◦   前端展示 “报告生成完成”，提供下载链接（映射到本地报告路径）。

## 三、环境配置与部署

### （一）开发环境依赖（Windows/Linux 通用）

 

| 工具 / 程序       | 安装方式（示例）                                             | 验证命令                |
| ----------------- | ------------------------------------------------------------ | ----------------------- |
| Python 3.8+       | 官网下载安装（添加环境变量）                                 | python3 --version       |
| Flask + 依赖      | pip3 install flask requests  urllib3 json5                   | flask --version         |
| 前端框架          | npm install vue@2 element-ui                                 | 启动前端无报错          |
| Nmap              | 官网下载安装（Linux：sudo apt install nmap）                 | nmap --version          |
| Dirsearch         | git clone  https://github.com/maurosoria/dirsearch.git && pip3 install -r  requirements.txt | python3 dirsearch.py -h |
| Burp Suite 社区版 | 官网下载解压运行                                             | 启动后可调用命令行接口  |
| Metasploit        | Linux：sudo apt install  metasploit-framework；Windows：官网下载 | msfconsole -v           |
| sqlmap            | git clone  https://github.com/sqlmapproject/sqlmap.git       | python3 sqlmap.py -h    |
| 报告生成依赖      | pip3 install jinja2  weasyprint python-docx python-markdown  | 导入模块无报错          |

### （二）部署步骤

1. 克隆项目代码到本地，安装上述所有依赖工具；
2. 启动前端服务：进入前端目录，执行npm run dev，访问http://localhost:8080；
3. 启动后端服务：进入后端目录