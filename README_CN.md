# JS Collector - 现代前端 JavaScript 深度资产挖掘与接口还原扩展

<p align="center">
  <a href="https://github.com/0xLatentThreat/burp-js-collector/releases"><img src="https://img.shields.io/badge/Release-v0.1.0-blue.svg" alt="Release"></a>
  <a href="https://portswigger.net/burp/extender/api"><img src="https://img.shields.io/badge/Burp%20API-Montoya%202025.10-orange.svg" alt="Montoya API"></a>
  <a href="https://openjdk.org/projects/jdk/17/"><img src="https://img.shields.io/badge/Java-17%2B-green.svg" alt="Java 17+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-lightgrey.svg" alt="License"></a>
  <a href="README.md"><img src="https://img.shields.io/badge/English-Documentation-blue.svg" alt="English Documentation"></a>
</p>

---

## 🎬 核心威力实战演示 (Demonstration)

> ⚡ **动图演示**：无需复杂配置，加载插件后直接在浏览器中访问目标系统。浏览器仅请求了基础主页，插件在后台**自动递归穿透拉取所有隐藏分包**，还原完整**接口参数树与默认值**，并在主动探测时**实时捕获后端 SQL 语法报错**与硬编码凭证！

<p align="center">
  <img src="docs/images/demo.gif" alt="Burp JS Collector 实战动图演示" width="100%">
</p>

---

## 💡 为什么需要 JS Collector？

在现代 Web 渗透测试、红蓝对抗与 Bug Bounty 实战中，前端 JavaScript 资产是挖出未授权接口、越权漏洞（IDOR）和特权边界的兵家必争之地。

然而，目前现存的传统工具（如 JSFinder、LinkFinder、JS-Miner 等）在面对现代前端时存在两大致命硬伤：
1. **只能提取“裸 URL”**：仅凭粗暴正则表达式抽取静态路径，面对提取出来的接口（如 `/api/v1/user/update`），安全人员完全不知道参数名是什么、有哪些可选字段、默认值是什么，必须耗费大量精力逐行人工阅读压缩混淆代码。
2. **现代 SPA 分包导致漏报率高达 60%+**：Webpack 4/5、Vite 等现代打包工具对前端代码进行了深度碎片化拆分。正常浏览时，浏览器往往只加载了登录页或首页分包，**后台管理、支付结算、内部审批等核心敏感模块的分包浏览器根本不会向服务器请求**，导致海量核心业务接口沦为“隐形盲区”。

**JS Collector 专为打破这些盲区而生**：
它基于 Burp Suite 最新的 **Montoya API**，在被动监听流量的同时，**自动解析 Webpack 4/5 运行时映射表（Runtime Chunk Map），全自动拉取浏览器从未请求过的懒加载 Chunk**；并通过深入 AST 与跨文件调用点静态分析，**完整还原 API 接口的请求参数名、字面默认值、Vuex/Pinia 调度链及源码调用证据**！

---

## ⚡ 核心能力横向对比

| 功能特性 | JS Collector | JS Miner | JS Link Finder | HaE | Burp 官方 Scanner (Pro) |
|---|:---:|:---:|:---:|:---:|:---:|
| **原生 Montoya API 驱动** | ✅ | ❌ (老版 Extender) | ❌ (老版 Extender) | ❌ | 内置原生 |
| **Webpack 4/5 懒加载分包自动挖掘** | ✅ (递归穿透拉取) | ❌ | ❌ | ❌ | ❌ |
| **接口参数名与字面默认值深度还原** | ✅ (形参/解构/默认值) | ❌ (仅裸 URL) | ❌ (仅裸 URL) | ❌ | 部分识别 |
| **Vuex / Pinia Action 调度链映射** | ✅ (多跳 dispatch) | ❌ | ❌ | ❌ | ❌ |
| **全协议栈捕获 (WS/SSE/Beacon/Upload)** | ✅ (全协议识别) | ❌ | ❌ | ❌ | ❌ |
| **精准 Target Scope 作用域控制** | ✅ (支持开箱免配/一键隔离) | ❌ | ❌ | ❌ | 内置支持 |
| **自适应极客暗黑主题 (Dark Theme)** | ✅ (像素级适配) | 部分异常 | ❌ | 部分异常 | 内置支持 |
| **纯被动风险审计与实时 SQL 报错捕获** | ✅ (SQL报错/Token/反序列化) | ✅ (仅硬编码) | ❌ | ✅ | 部分规则 |

---

## 🌟 核心功能亮点

### 1. 自动穿透发现未加载分包（Unrequested Chunks）
现代前端普遍采用 `import('./admin.vue')` 路由懒加载。JS Collector 能够动态解密 Webpack 4/5 运行时映射函数（`__webpack_require__.u` / `jsonpScriptSrc`）以及 HTML 中的 `<link rel="modulepreload">`，自动补全并下载那些普通访客无法触达的敏感功能分包。

### 2. 真实参数树与字面默认值精准还原（True Parameter Recovery）
拒绝冰冷的空路径！JS Collector 深入静态调用链，自动还原出：
- 结构化参数对象：`{ page: 1, pageSize: 50, role: "ROLE_ADMIN", sortField: "id" }`
- RESTful 动态模版路径变量：`/api/v2/crm/lead/{leadId}/timeline`
- 常用 HTTP 封装别名匹配：`request.post()`, `client.get()`, `http.delete()`, `api.put()`
- 字面默认值提取：`taxRate: 0.13`, `amount: 99.50`

### 3. 主动存活探测与实时 SQL 注入报错捕获（Probe Alive & SQL Error）
在 **Endpoints** 标签页中选中任意接口，右键选择 **Probe alive** 进行连通性探测。如果后端数据库因缺少必要参数抛出未捕获异常（如 MySQL `SQL syntax`、`SQLException`、Oracle `ORA-`、PostgreSQL `syntax error` 等），插件将立即在 **Findings** 选项卡中触发 **HIGH 级 SQL_ERROR 警报**，并附带精确的高亮代码证据，助您在合法合规的前提下快人一步发现注入线索！

### 4. 纯被动敏感凭据与反序列化风险嗅探（Passive Risk Audit）
在分析捕获的 JS 文件与响应体时，插件内置高精正则引擎：
- **云厂商与平台密钥**：AWS AK/SK (`AKIA...`)、GitHub 个人访问令牌 (`ghp_...`)、Slack Webhook 凭据；
- **认证私钥与连接串**：RSA/EC 私钥声明、内网 JDBC 数据库连接串（`jdbc:mysql://...`）；
- **反序列化特征标记**：Java 反序列化魔数 (`ac ed 00 05`)、PHP 序列化特征 (`O:8:"UserAuth"...`)；
- **越权风险字段提示**：自动标记包含 `userId`、`orderNo`、`accountId` 等 ID 属性的敏感接口，提示潜在 IDOR 越权风险。

---

## 🚀 快速安装体验

### 环境依赖
- **Burp Suite**：Professional 专业版 / Community 社区版（推荐 2024.1+ 或 2025.10+ 最新版）。
- **Java 运行环境**：Java 17 或更高版本（Burp Suite 自带 JRE 即可直接运行）。

### 1 分钟开箱安装
1. 从本项目 [Releases](https://github.com) 页面下载最新构建好的 **`BurpJsCollector-0.1.0.jar`**；
2. 打开 Burp Suite，点击顶部导航栏 **Extensions**（扩展）→ **Installed** → **Add**；
3. 扩展类型选择 **Java**，点击 **Select file** 选择下载的 `BurpJsCollector-0.1.0.jar`，点击 **Next** 完成载入；
4. 顶部导航栏将出现 **JS Collector** 独立标签页；
5. **无需繁琐配置**：直接打开 Burp 内置浏览器访问目标网站，JS 文件、接口与参数便会全自动实时涌现！如需严格限定范围，只需在顶部勾选 **Only in-scope**。

---

## 🛡️ 工业级稳定性与性能加固

为了达到进驻 PortSwigger BApp Store 官方商店的最高安全与稳定性标准，本插件在架构层面实现了：
- **安全的作用域策略（Target Scope Enforcement）**：默认以被动模式全量监听流经代理的 JS 流量，同时提供 **Only in-scope** 开关；自动抓取懒加载 Chunk 时**严格限定同源同主机（Same Origin）**，绝不外发扫描第三方外链。
- **5MB 防 OOM 熔断保护**：对单文件超过 5MB 的超大型打包文件进行流式保护，防止极端畸形文件引发 Burp 界面假死或内存溢出。
- **抗 ReDoS 极限性能优化**：针对全量提取正则构建了 50,000+ 字符极端未闭合引号对抗样本，确保正则匹配均在 200ms 内跳出；多线程高并发解析 800 次仅耗时 52ms。
- **像素级主题自适应**：原生适配 Burp Suite 的深色（Dark）与浅色（Light）主题，表格高亮渲染器自适应对比度，告别刺眼白底与黑底黑字。

---

## 🛠️ 从源码编译与构建 (Building From Source)

JS Collector 秉持“极致轻量、零外部臃肿”的设计哲学，核心逻辑完全由原生 Java 编写，除官方标准 Montoya API 外**不引入任何第三方依赖包**，编译速度极快（秒级完成）。

### 编译环境要求 (Build Requirements)
- **JDK 版本**：JDK 17 或更高版本（支持 Oracle JDK、OpenJDK、Eclipse Temurin、Amazon Corretto 17 / 21 / 24）。请确保终端使用的是 JDK 17+ 的编译器（Java 17+ 原生支持 `--release 17` 参数）。
- **外部依赖**：**零第三方外部依赖**。编译所需的 Montoya API 库已内置在 `java/libs/montoya-api-2025.10.jar`。
- **操作系统**：跨平台支持（Windows / macOS / Linux 均可一键编译）。

### 编译与打包方式

#### 方式 1：标准命令行原生编译（推荐，跨平台秒级完成）

- **Linux / macOS (Bash)**:
  ```bash
  # 1. 创建输出目录
  mkdir -p build/classes

  # 2. 编译 core 引擎与 burp 插件代码
  javac --release 17 -encoding UTF-8 -cp "java/libs/montoya-api-2025.10.jar:core" -d build/classes $(find core java/src/main/java -name "*.java")

  # 3. 打包生成轻量 JAR 包
  jar cf BurpJsCollector-0.1.0.jar -C build/classes .
  ```

- **Windows (PowerShell)**:
  ```powershell
  # 1. 创建输出目录
  New-Item -ItemType Directory -Force build/classes

  # 2. 编译 core 引擎与 burp 插件代码
  javac --release 17 -encoding UTF-8 -cp "java/libs/montoya-api-2025.10.jar;core" -d build/classes (Get-ChildItem -Recurse core/*.java, java/src/main/java/*.java | ForEach-Object { $_.FullName })

  # 3. 打包生成轻量 JAR 包
  jar cf BurpJsCollector-0.1.0.jar -C build/classes .
  ```

#### 方式 2：使用 Gradle 构建

如果本地已配置 Gradle 环境，也可以直接执行项目内置任务：
```bash
# 执行打包任务
gradle fatJar
# 构建产物将自动生成在 build/libs/BurpJsCollector-0.1.0.jar
```

#### 方式 3：IntelliJ IDEA 导入开发与调试
1. 打开 IntelliJ IDEA，选择 **Open** 打开本项目根目录；
2. 进入 **File** ➔ **Project Structure** ➔ **Project**，设置 **SDK** 为 `Java 17` 或更高；
3. 进入 **Modules**，将 `core` 和 `java/src/main/java` 文件夹右键标记为 **Sources Root**；
4. 进入 **Libraries**，点击 `+` 将 `java/libs/montoya-api-2025.10.jar` 添加为全局库；
5. 进入 **Artifacts**，添加 JAR ➔ `From modules with dependencies`，构建后即可一键导出插件。

---

## 🧪 自动化测试套件

本项目内置了覆盖边界场景与极端压力的完备测试集：

```bash
# 编译核心引擎
javac --release 17 -encoding UTF-8 -d core/out core/jscollect/core/*.java

# 1. 运行 56 个边界场景测试（涵盖 IIFE、跨 JS 调度、ESM、REST 模版、特殊协议等）
java -Dfile.encoding=UTF-8 -cp core/out jscollect.core.ScenarioRunner test/scenarios

# 2. 运行真实项目架构还原回归测试（77 项严格断言）
java -Dfile.encoding=UTF-8 -cp core/out jscollect.core.ScenarioTest test/fixtures

# 3. 运行极限压力与抗 ReDoS 基准测试
java -Dfile.encoding=UTF-8 -cp core/out jscollect.core.StressTest
```

---

## 🤝 贡献与样本共建

> [!IMPORTANT]
> **📢 漏报反馈与精准度持续提升**：
> 如果使用过程中发现有遗漏项，请提交目标地址以及具体内容，作者将尽快更新以增加精准率！
> 现代前端框架与打包混淆技术日新月异，如果您在实战渗透中遇到了 JS Collector 未能正确解析的特殊打包格式或接口，非常欢迎通过 [GitHub Issues](https://github.com/your-username/burp-js-collector/issues) 提交反馈，或使用 [Unparsed JS Sample Submission](.github/ISSUE_TEMPLATE/chunk_sample.md) 提交脱敏样本。我们会在第一时间将其录入自动化测试集并迭代规则库！

---

## 📄 开源协议

本项目基于宽松友好的 [MIT License](LICENSE) 协议开源，欢迎自由使用、提交 PR 与商业安全评估。
