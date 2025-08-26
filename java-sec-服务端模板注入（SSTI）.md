# Java应用中的服务端模板注入（SSTI）


Java作为企业级应用的主流开发语言，广泛使用各类模板引擎（如Freemarker、Velocity、Thymeleaf等）实现动态页面渲染。若开发者对模板引擎的使用不当，可能导致服务端模板注入（SSTI）漏洞，攻击者可借此执行恶意代码、窃取敏感数据甚至控制服务器。本文将聚焦Java应用的SSTI特性，并详细介绍代码审计方法。


## 一、Java SSTI的核心特点与常见模板引擎

Java生态中的模板引擎通常通过**表达式语言（EL）** 实现动态数据填充，其语法和执行逻辑与Python的Jinja2等有显著差异，但SSTI的本质仍是“用户输入被当作模板语法解析执行”。


### 1. 主流模板引擎及SSTI特征
Java常用模板引擎的语法规则和SSTI风险点如下：

| 模板引擎       | 表达式语法（变量/逻辑）       | 执行能力（默认配置）          | 典型SSTI风险场景                          |
|----------------|------------------------------|-------------------------------|-------------------------------------------|
| Freemarker     | `${变量}`、`#{变量}`（旧版）<br>`<#if 条件>`（逻辑） | 可调用Java类方法（默认无沙箱） | 注入`${java.lang.Runtime.getRuntime().exec("cmd")}` |
| Velocity       | `$变量`、`$!{变量}`<br>`#if`、`#foreach`（逻辑） | 可调用Java方法（默认限制较少） | 注入`$!{Runtime.getRuntime().exec("ls")}` |
| Thymeleaf      | `${变量}`、`*{变量}`<br>`th:if`、`th:each`（逻辑） | 默认仅支持OGNL表达式子集       | 注入`${T(java.lang.Runtime).getRuntime().exec("whoami")}` |
| JSP（JSTL）    | `${变量}`（EL表达式）<br>`<% 脚本 %>`（Java代码） | 脚本标签可直接执行Java代码    | 注入`<% out.println(new File("/etc/passwd").exists()); %>` |


### 2. Java SSTI的核心原理
Java模板引擎的渲染流程通常为：  
`模板文件（含表达式） + 数据模型（变量值） → 模板引擎解析 → 生成最终HTML`  

当开发者**将用户可控输入直接作为模板内容（而非数据模型中的变量值）传递给引擎**时，引擎会将输入解析为模板语法。由于Java表达式可直接调用类方法（如`Runtime.exec()`），攻击者可构造恶意表达式执行系统命令或操作敏感资源。

**示例（Freemarker漏洞代码）**：  
```java
// 危险用法：用户输入直接作为模板内容
String userInput = request.getParameter("name");
Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
Template template = new Template("test", new StringReader("Hello " + userInput), cfg);
StringWriter out = new StringWriter();
template.process(new HashMap<>(), out); // 渲染时解析用户输入中的Freemarker语法
response.getWriter().write(out.toString());
```

若攻击者输入`${"".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("whoami")}`，模板引擎会解析并执行该表达式，返回服务器当前用户身份。


## 二、Java SSTI的典型漏洞场景与危害

### 1. 常见漏洞场景
- **动态模板拼接**：开发者为实现“灵活渲染”，将用户输入直接拼接进模板字符串（如`"Hello " + userInput`），再交给引擎解析。
- **模板文件动态加载**：从用户可控路径加载模板文件（如`templatePath = "templates/" + userInput + ".ftl"`），攻击者可构造路径注入恶意模板内容。
- **错误的表达式评估**：使用模板引擎的API直接评估用户输入的表达式（如Thymeleaf的`StandardExpressionParser`解析用户输入的`${...}`）。
- **JSP脚本滥用**：在JSP中使用`<%= userInput %>`（输出变量）本身无风险，但若使用`<% userInput %>`（执行脚本）且`userInput`可控，则直接导致代码执行。


### 2. 危害表现
Java SSTI的危害与模板引擎权限、JVM配置密切相关，主要包括：  
- **远程代码执行（RCE）**：通过调用`Runtime.exec()`、`ProcessBuilder`等执行系统命令（如`ls`、`rm`、反弹shell）。  
- **敏感文件读写**：调用`java.io.File`、`FileReader`等类读取服务器文件（如`/etc/passwd`、数据库配置）或写入后门。  
- **内存数据泄露**：访问JVM内存中的敏感对象（如`System.getenv()`获取环境变量、`Thread.currentThread().getContextClassLoader()`遍历类信息）。  
- **拒绝服务（DoS）**：注入无限循环（如Freemarker的`<#list 1.. as i><#assign x = i></#list>`）或高资源消耗代码，耗尽服务器CPU/内存。  


## 三、Java SSTI的代码审计方法

代码审计的核心目标是识别“用户可控输入被不当传入模板引擎解析流程”的场景。以下是针对不同模板引擎的审计要点和实践方法。


### 1. 通用审计思路
无论使用哪种模板引擎，需重点检查以下风险模式：  
- **用户输入是否直接进入模板内容**：搜索代码中模板引擎的核心API（如`Template.process()`、`VelocityEngine.evaluate()`），查看其输入的“模板字符串”是否包含用户可控参数（如`request.getParameter()`、`@RequestParam`参数）。  
- **模板路径是否可控**：检查模板文件加载路径（如`cfg.setTemplateLoader(new FileTemplateLoader(new File(userInput)))`）是否包含用户输入，可能导致加载恶意模板文件。  
- **表达式解析是否开放**：检查是否存在直接解析用户输入为表达式的代码（如Thymeleaf的`expressionParser.parseExpression(userInput)`）。  


### 2. 分引擎审计要点

#### （1）Freemarker审计
Freemarker的核心风险点在于`Template`类的实例化和`process()`方法的调用。  
**审计关键词**：`Configuration`、`Template`、`StringReader`、`process()`  

**危险代码特征**：  
- 将用户输入直接作为模板内容传递给`Template`构造函数：  
  ```java
  // 危险：userInput可控，直接作为模板内容
  String userInput = request.getParameter("tpl");
  Template template = new Template("dynamic", new StringReader(userInput), cfg); 
  template.process(dataModel, writer);
  ```  

- 模板字符串中拼接用户输入：  
  ```java
  // 危险：userInput被拼接进模板，可能注入Freemarker语法
  String templateContent = "Welcome, " + userInput + "!"; 
  Template template = new Template("demo", new StringReader(templateContent), cfg);
  ```  

**安全配置检查**：  
Freemarker可通过`Configuration`限制危险类调用，需检查是否配置了安全的`ObjectWrapper`：  
```java
// 安全配置：使用DefaultObjectWrapper并禁用危险类
DefaultObjectWrapper wrapper = new DefaultObjectWrapper(Configuration.VERSION_2_3_32);
wrapper.setExposureLevel(DefaultObjectWrapper.EXPOSURE_HIDDEN); // 限制类暴露
cfg.setObjectWrapper(wrapper);
```  
若未配置，则默认允许调用所有可见类，风险极高。


#### （2）Velocity审计
Velocity的风险主要来自`VelocityEngine.evaluate()`方法（直接评估字符串为模板）。  
**审计关键词**：`VelocityEngine`、`evaluate()`、`Template.merge()`  

**危险代码特征**：  
- 使用`evaluate()`方法解析包含用户输入的字符串：  
  ```java
  // 危险：userInput可控，被当作Velocity模板解析
  String userInput = request.getParameter("content");
  VelocityContext context = new VelocityContext();
  StringWriter writer = new StringWriter();
  velocityEngine.evaluate(context, writer, "test", "Hello " + userInput); // 拼接用户输入
  ```  

- 动态加载用户指定的模板文件：  
  ```java
  // 危险：templateName可控，可能指向恶意模板
  String templateName = request.getParameter("tpl");
  Template template = velocityEngine.getTemplate(templateName); 
  template.merge(context, writer);
  ```  

**安全配置检查**：  
Velocity可通过`velocity.properties`限制类访问，需检查是否配置：  
```properties
# 安全配置：禁止调用特定类
velocimacro.library.autoreload=false
runtime.references.strict=true
```  


#### （3）Thymeleaf审计
Thymeleaf默认使用OGNL表达式，风险点在于动态构建模板或直接解析表达式。  
**审计关键词**：`TemplateEngine`、`process()`、`StandardExpressionParser`  

**危险代码特征**：  
- 模板内容包含用户输入且未正确转义：  
  ```java
  // 危险：userInput被直接嵌入模板，可能注入Thymeleaf表达式
  String userInput = request.getParameter("name");
  String template = "<p>Hello " + userInput + "</p>"; 
  Context context = new Context();
  String result = templateEngine.process(template, context); // 解析模板
  ```  

- 直接解析用户输入为OGNL表达式：  
  ```java
  // 危险：解析用户输入为表达式并执行
  String expr = request.getParameter("expr");
  StandardExpressionParser parser = new StandardExpressionParser();
  Expression expression = parser.parseExpression(expr);
  Object result = expression.execute(context); // 执行表达式
  ```  

**安全配置检查**：  
Thymeleaf可通过`SpringEL`替代OGNL，并限制表达式权限：  
```java
// 安全配置：使用SpringEL并禁用危险方法
TemplateEngine engine = new TemplateEngine();
engine.setExpressionParser(new SpringStandardExpressionParser());
```  


#### （4）JSP审计
JSP的风险主要来自`<% ... %>`脚本标签和EL表达式的滥用。  
**审计关键词**：`<%`、`%>`、`${`、`request.getParameter`  

**危险代码特征**：  
- JSP中直接嵌入用户输入的脚本代码：  
  ```jsp
  <% 
    // 危险：userInput可控，直接作为Java代码执行
    String userInput = request.getParameter("code");
    out.println(eval(userInput)); // 假设存在eval方法执行字符串
  %>
  ```  

- EL表达式中包含用户可控参数（虽默认仅支持简单变量，但配置不当可执行方法）：  
  ```jsp
  <!-- 危险：param.name可控，可能注入EL表达式 -->
  <p>Hello ${param.name}</p>
  ```  

### 3. 实战案例：

- **CVE-2018-11784：Apache Struts2 S2-057 漏洞**  
Struts2 的某些标签（如url标签）在处理参数时，会将用户输入作为 OGNL 表达式解析，导致 SSTI。攻击者可注入 OGNL 代码执行命令，影响大量使用 Struts2 的企业系统。

- **CVE-2019-3396**  
[Confluence 未授权 RCE (CVE-2019-3396) 漏洞分析](https://paper.seebug.org/884/)  
[Atlassian Confluence 路径穿越导致远程代码执行漏洞（CVE-2019-3396）](https://github.com/vulhub/vulhub/blob/master/confluence/CVE-2019-3396/README.zh-cn.md)

### 3. 审计工具与辅助手段
- **静态分析工具**：使用SonarQube、FindSecBugs等扫描代码，规则集中关注“用户输入与模板引擎API的交互”。  
- **动态调试**：在本地搭建环境，跟踪用户输入是否进入模板解析流程（如在`Template.process()`处打断点，观察参数来源）。  
- **Payload测试**：对可疑输入点尝试注入Java表达式（如`${T(java.lang.Runtime).getRuntime().exec("whoami")}`），验证是否执行。  


## 四、Java SSTI的防御措施（审计参考标准）

代码审计时，需验证是否实施了以下防御措施，以确认漏洞修复有效性：  

1. **严格区分“数据”与“模板”**  
   禁止用户输入直接作为模板内容，仅允许作为数据模型中的变量传递。例如：  
   ```java
   // 安全用法：用户输入作为变量，模板固定
   String userInput = request.getParameter("name");
   Map<String, Object> data = new HashMap<>();
   data.put("name", userInput); // 用户输入仅作为变量值
   template.process(data, writer); // 模板内容固定，不包含用户输入
   ```  

2. **启用模板引擎安全配置**  
   - Freemarker：配置`DefaultObjectWrapper`限制类暴露，禁用`new`、`eval`等危险指令。  
   - Velocity：设置`runtime.references.strict=true`，禁止调用未定义变量的方法。  
   - Thymeleaf：使用`SpringEL`替代OGNL，限制表达式可调用的类和方法。  

3. **输入验证与转义**  
   对用户输入进行严格过滤，移除模板引擎的特殊字符（如`${`、`}`、`#`、`<#`等），或使用引擎提供的转义工具（如Freemarker的`?esc`）。  

4. **限制模板引擎权限**  
   运行JVM的进程使用低权限账号（如`appuser`），禁止访问敏感目录（如`/root`、`/etc`），降低漏洞被利用后的危害。  

5. **避免动态模板加载**  
   模板文件路径应固定在预定义目录（如`/templates/`），禁止用户输入参与路径拼接，防止加载恶意模板。  


## 五、总结

Java应用的SSTI漏洞根源在于“用户输入与模板语法的边界混淆”，其利用方式与模板引擎的表达式语法紧密相关。代码审计时，需重点追踪用户输入是否进入模板解析流程，检查模板引擎的配置是否安全，并结合具体引擎的语法特征识别风险点。通过严格区分数据与模板、启用安全配置、限制权限等措施，可有效防御此类漏洞。
