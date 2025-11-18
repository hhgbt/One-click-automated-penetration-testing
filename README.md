# One-click-automated-penetration-testing
# 一键式自动化渗透测试

## 一、项目概述

本项目以 “用户输入任意 URL” 为触发点，摒弃数据库依赖，通过**工具集成自动化、JSON 文件全程存储、轻量化报告生成**，实现 “信息收集→漏洞检测→漏洞渗透→报告导出” 的全流程闭环。所有测试数据（任务信息、工具输出、漏洞详情、渗透结果）均以 JSON 格式存储在本地文件，适配各类 Web 靶场 / 测试目标，部署简单、数据可追溯，适合快速验证与学习使用。



<img src="C:\Users\29028\Desktop\微信图片_20251112163236_182_379.png" style="zoom:200%;" />



## 二、核心流程实现

### （一）URL 输入与预处理环节

**1. 功能目标**

- 接收用户输入的 URL（如 **http://192.168.1.100/test**），验证格式合法性与目标可达性

- 提取 URL 核心信息（IP / 域名、端口、路径），生成唯一任务 ID，初始化任务 JSON 文件

**2. 技术实现**

- **格式验证**：使用正则表达式 **/^https?:\/\/.+/** 校验 URL，前端（Vue.js+Element UI）实时提示格式错误（如 “请输入 http:// 或 https:// 开头的有效 URL”）
- **URL** **解析**：通过  **Pythonurllib.parse** 库拆解 URL
- **可达性检测**：通过 **requests** 库发送 HEAD 请求，超时时间设为 5 秒，返回 200/301/302 则判定可达
-  **JSON** **初始化**：生成唯一任务 ID（如 **task_20251101_123456**），创建任务根 JSON 文件（**task_20251101_123456.json**），存储基础信息：

  `{`  

​     `"task_id":  "task_20251101_123456",` 

​     `"target_url":  "http://192.168.1.100:8080/test",` 

​     `"target_ip":  "192.168.1.100",`  

​     `"target_port": 8080,` 

​     `"target_path": "/test",`

​     `"test_mode": "全面测试",`  

​     `"task_status": "初始化完成",`  

​     `"create_time": "2025-11-01  12:34:56",` 

​     `"info_collection": {},`   

​     `"vulnerability_detection": {},`

​     `"exploitation": {},`

​     `"report_path": ""` 

 `}`  

**3. 输出结果**

- 前端展示任务初始化成功日志
- 本地生成任务根 JSON 文件

### （二）自动化信息收集环节

**1. 功能目标**

- 调用端口扫描、目录枚举等工具，收集目标开放端口、服务版本、Web 敏感目录等信息
- 将工具输出与解析结果存入任务 JSON 的 **info_collection** 字段，同时保存工具原始日志文件

**2. 工具集成与逻辑**

| 工具      | 功能                    | 调用命令示例                                           | 结果解析方式                             | JSON 存储格式                                                |
| --------- | ----------------------- | ------------------------------------------------------ | ---------------------------------------- | ------------------------------------------------------------ |
| Nmap      | 端口 + 服务版本扫描     | nmap -sV -p 1-10000 {target_ip} -oN nmap.log           | 正则提取(\d+/tcp)\s+open\s+(\w+)\s+(\w+) | "ports": [{"port": 80, "service":  "http", "version": "Apache/2.4.49",  "is_high_risk": 0}] |
| Dirsearch | Web 目录 / 文件扫描     | dirsearch -u {target_url} -e php,html -o dirsearch.log | 筛选状态码 200/302 的路径                | "web_dirs": [{"path": "/admin",  "status_code": 200, "description": "敏感管理目录"}] |
| Sublist3r | 子域名枚举（域名 URL）  | sublist3r -d {target_domain} -o sublist3r.log          | 去重后提取子域名                         | "subdomains": ["blog.test.com",  "api.test.com"]             |
| Whois     | 域名信息查询（域名URL） | whois {target_domain} > whois.log                      | 提取注册商、过期时间等关键字段           | "whois_info": {"registrar": "XXX",  "expiration_date": "2026-11-01"} |

**3. 技术实现细节**

- 工具调度：通过 **Pythonsubprocess** 库调用系统命令，捕获输出日志
- 日志存储：工具原始日志（如 **nmap.log**、**dirsearch.log**）保存在 **./tasks/{task_id}/logs/** 目录，JSON 中记录日志文件相对路径

**4. 输出结果**

- 任务 JSON 的 **info_collection** 字段填充完整信息
- 前端实时展示收集进度（如 “Nmap 扫描完成，发现开放端口 3 个”）

### （三）自动化漏洞检测环节

**1. 功能目标**

- 基于信息收集结果，自动选择扫描工具（Web 漏洞→Burp Suite；系统漏洞→OpenVAS）
- 检测目标漏洞（SQL 注入、XSS、文件上传等），按预定义规则排序，存入 JSON 的**vulnerability_detection** 字段

**2. 工具调度逻辑**

- **Web** **漏洞扫描（Burp Suite** **社区版）**：
  - 触发条件：信息收集发现 80/443 / 自定义 Web 端口开放，且存在有效 Web 路径；
  - 调用命令（静默扫描模式）：`burpsuite  -silent -target {target_url} -scan-type active -report burp.xml  -report-format xml` 
  - 结果解析：解析 XML 报告，提取漏洞名称、位置、CVSS 评分，示例：

`"web_vulnerabilities":  [`   

  `{`    

​     `"vuln_name": "SQL注入",`    

​     `"vuln_type": "Web",` 

​     `"cvss_score": 8.5,`  

​     `"vuln_location":  "{target_url}/list?id=1",`    

​     `"description": "URL参数id存在SQL注入漏洞，可执行任意SQL语句",`    

​     `"priority": 1 # 1=高危，2=中危，3=低危`   

  `}` 

 `]`  

- **系统 /** **中间件漏洞扫描（OpenVAS**）：
  - 触发条件：信息收集发现非 Web 端口（如 22 SSH、3306 MySQL）或 Web 服务版本存在已知漏洞
  - 调用命令： `openvas-cli  scan --target {target_ip} --policy Full\ and\ fast --output openvas.log`  
  -  结果解析：提取漏洞名称、影响版本、修复建议，存入 JSON 的 **system_vulnerabilities** 字段

**3. 漏洞排序规则**

- 优先级 1（高危）：CVSS ≥ 7.0，可直接获取权限（如 SQL 注入、文件上传、远程代码执行）
- 优先级 2（中危）：4.0 ≤ CVSS < 7.0，影响数据安全（如 XSS、路径遍历）
- 优先级 3（低危）：CVSS < 4.0，无直接危害（如敏感信息泄露、弱口令提示）

**4. 输出结果**

- 任务 JSON 的 **vulnerability_detection** 字段填充漏洞列表与工具日志
- 前端展示漏洞检测结果（如 “发现高危漏洞 2 个，中危漏洞 1 个”）

### （四）自动化漏洞渗透环节

**1. 功能目标**

- 按漏洞优先级（高危→中危→低危）调用渗透工具，尝试利用漏洞
- 记录渗透过程（成功 / 失败原因）、获取的权限，存入 JSON 的 **exploitation** 字段

**2. 技术实现细节**

- 渗透日志记录：工具输出日志（如 MSF 会话信息、sqlmap 结果）保存到 **./tasks/{task_id}/exploit_logs/** 目录，JSON 中记录日志路径
- 状态更新：渗透完成后，更新任务 JSON 的 **task_status** 为 “渗透环节完成”

### （五）自动化报告生成环节

**1. 功能目标**

- 读取任务 JSON 中的全流程数据，按标准化模板生成多格式报告（Markdown/PDF/Word）
- 报告保存到 **./tasks/{task_id}/report/** 目录，JSON 中记录报告路径，支持前端下载

**2. 技术实现**

- **数据提取**：读取任务 JSON 的所有字段，格式化数据（如端口信息转为表格、日志按时间排序），示例：

`import  json`  

`with  open(task_json_path, "r") as f:`    

​     `task_data = json.load(f)`  

`# 提取漏洞列表`  

`vulnerabilities  =  task_data["vulnerability_detection"]["web_vulnerabilities"] + task_data["vulnerability_detection"]["system_vulnerabilities"]`  

- **模板渲染**：使用 Jinja2 模板引擎，设计标准化报告模板（核心章节：执行摘要→测试过程→漏洞详情→渗透结果→安全建议→附录），示例模板片段：

`# 渗透测试报告  `

`## 1.执行摘要  `

`- 测试目标URL：{{ task_data.target_url }}  `

`- 测试时间：{{ task_data.create_time }}  `

`- 测试模式：{{ task_data.test_mode }}  `

`- 漏洞总数：{{ len(vulnerabilities) }}  `

`- 渗透成功数：{{ sum(1 for exp in  task_data.exploitation.exploitation_results if exp.result == '成功') }}  ## `

`## 2.信息收集结果`

`### 2.1 开放端口`

`| 端口 | 服务 | 版本 | 是否高危 | `

`{% for port in task_data.info_collection.ports %} | {{ port.port }} | {{ port.service }} | {{ port.version }} | {{ '是' if port.is_high_risk == 1 else  '否' }} | `

`{%  endfor %}`  

- **多格式导出：**
  - Markdown：直接渲染 Jinja2 模板，保存为 **report.md**
  - PDF：通过 **Python-Markdown** 将 Markdown 转为 HTML，再用 **WeasyPrint** 转为 PDF
  - Word：通过 **python-docx** 库逐章节写入数据，插入表格与日志片段

- **JSON更新：**报告生成后，在任务 JSON 中记录报告路径：

`"report_path":{`

`   "markdown": "./tasks/task_20251101_123456/report/report.md",` 

`   "pdf": "./tasks/task_20251101_123456/report/report.pdf",` 

`   "word": "./tasks/task_20251101_123456/report/report.docx"  ` 

`}`  

**3. 输出结果**

- 本地生成多格式报告文件
- 前端展示 “报告生成完成”，提供下载链接（映射到本地报告路径）



## 三、环境配置与部署

### （一）开发环境依赖（Windows/Linux 通用）

| 工具 / 程序       | 安装方式（示例）                                             | 验证命令                |
| ----------------- | ------------------------------------------------------------ | ----------------------- |
| Python 3.8+       | 官网下载安装（添加环境变量）                                 | python3 --version       |
| Flask + 依赖      | pip3 install flask requests urllib3 json5                    | flask --version         |
| 前端框架          | npm install vue@2 element-ui                                 | 启动前端无报错          |
| Nmap              | 官网下载安装（Linux：sudo apt install nmap）                 | nmap --version          |
| Dirsearch         | git clone https://github.com/maurosoria/dirsearch.git && pip3  install -r requirements.txt | python3 dirsearch.py -h |
| Burp Suite 社区版 | 官网下载解压运行                                             | 启动后可调用命令行接口  |
| Metasploit        | Linux：sudo apt install  metasploit-framework；Windows：官网下载 | msfconsole -v           |
| sqlmap            | git clone https://github.com/sqlmapproject/sqlmap.git        | python3 sqlmap.py -h    |
| 报告生成依赖      | pip3 install jinja2 weasyprint python-docx python-markdown   | 导入模块无报错          |

### （二）部署步骤

1.  克隆项目代码到本地，安装上述所有依赖工具
2.  启动前端服务：进入前端目录，执行 **npm run dev**，访问 **http://localhost:8080**
3.  启动后端服务：进入后端目录
