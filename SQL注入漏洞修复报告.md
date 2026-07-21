# SQL 注入漏洞修复报告

> **项目**：用户管理系统 (Flask)  
> **审查日期**：2026-07-20  
> **修复版本**：`dcf07ff`

---

## 漏洞总览

| # | 漏洞名称 | 位置 | 状态 |
|---|----------|------|------|
| 1 | 字符串拼接 SQL 查询 | `app.py` 搜索逻辑 + register 路由 | ✅ 已修复 |
| 2 | 无任何输入过滤 | `app.py` 搜索逻辑 + register 路由 | ✅ 已修复 |
| 3 | 搜索结果有回显 | `templates/index.html` | ✅ 已修复 |

---

## 漏洞 1：字符串拼接 SQL 查询

### 问题描述

注册和搜索功能中，用户输入直接拼接到 SQL 语句中：

```python
# 注册 - 字符串拼接
query = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"

# 搜索 - 字符串拼接
query = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
```

**危害**：用户输入中的特殊字符（如单引号 `'`）会改变 SQL 语句的结构，导致任意 SQL 命令执行。

### 攻击示例

**搜索 OR 万能注入**：
```
输入：/?keyword=' OR '1'='1

生成的 SQL：
SELECT * FROM users WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
                                       ^^^^^^^^^^^^^^^^
                                       WHERE 条件被改写为永真，返回全部用户
```

**注册闭合注入**：
```
输入：username = hacker', 'pass', 'h@x.com', '123')--

生成的 SQL：
INSERT INTO users (...) VALUES ('hacker', 'pass', 'h@x.com', '123')--', 'irrelevant', '', '')
                                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                注入者控制了 INSERT 全部字段
```

### 修复方案

使用 SQLite 参数化查询（`?` 占位符），将 SQL 语句结构与用户数据分离。数据库引擎预先编译 SQL 模板，用户输入仅作为参数填充，其中的特殊字符不会改变 SQL 解析结构。

### 修复后代码

```python
# 搜索 - 参数化查询
sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
pattern = f"%{keyword}%"
c.execute(sql, (pattern, pattern))

# 注册 - 参数化查询
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
c.execute(sql, (username, password, email, phone))
```

---

## 漏洞 2：无任何输入过滤

### 问题描述

所有用户输入直接传入 SQL 语句，没有做任何转义或过滤。攻击者输入的任何特殊字符（`'`、`"`、`--`、`;`、`UNION` 等）都会原封不动地进入 SQL 语法解析层。

### 原始代码

```python
# ❌ 用户输入 raw 传入，无过滤
keyword = request.args.get("keyword")       # 搜索
username = request.form.get("username")     # 注册
# 直接拼入 SQL
sql = f"... VALUES ('{username}', ...)"
sql = f"... LIKE '%{keyword}%'"
```

### 修复方案

参数化查询本身就是最彻底的"过滤"——它从架构层面将数据与代码分离。用户输入无需过滤即可安全传入，因为数据库引擎永远不会将参数值解析为 SQL 语法。

### 修复后代码

```python
# ✅ 用户输入作为参数传入，无需过滤
keyword = request.args.get("keyword")
pattern = f"%{keyword}%"
c.execute("SELECT ... WHERE username LIKE ? OR email LIKE ?", (pattern, pattern))
```

> **关键区别**：
> - 黑名单过滤：需要穷举 `' -- ; UNION SELECT DROP` 等，总有遗漏（如编码绕过、注释绕过）
> - 参数化查询：**不需要任何过滤**，特殊字符不会进入 SQL 编译阶段，不存在注入可能

---

## 漏洞 3：搜索结果有回显

### 问题描述

搜索结果直接以表格形式展示在页面上，攻击者可以通过 UNION 注入获取任意数据：

```html
<tbody>
    {% for r in search_results %}
    <tr>
        <td>{{ r.id }}</td>
        <td>{{ r.username }}</td>
        <td>{{ r.email }}</td>
        <td>{{ r.phone }}</td>
    </tr>
    {% endfor %}
</tbody>
```

回显本身不是漏洞，但**当搜索功能存在字符串拼接时**，回显位置就成为数据窃取的出口。攻击者通过 UNION 注入将自定义查询结果填充到表格中，从而提取数据库中的敏感数据。

### 攻击示例

```bash
# UNION 注入 — 通过回显窃取数据
/?keyword=' UNION SELECT 1,username,password,email FROM users--

# 生成的 SQL：
SELECT * FROM users WHERE username LIKE '%' 
UNION SELECT 1,username,password,email FROM users--%' ...

# 原始的 LIKE 查询无结果（%' 匹配不到任何行）
# UNION 查询返回了 users 表中的用户名和密码
# 这些数据被渲染到搜索结果表格中，攻击者直接看到所有人的密码
```

### 修复方案

通过参数化查询阻断注入源头后，回显不再构成可被利用的风险——攻击者无法注入 UNION 查询，回显表格只会展示正常的 LIKE 匹配结果。

### 修复后效果

```bash
# 同样的 payload 已失效
/?keyword=' UNION SELECT 1,username,password,email FROM users--

# 实际执行的 SQL：
SELECT ... WHERE username LIKE ? OR email LIKE ?
# params: ("%' UNION SELECT 1,username,password,email FROM users--%")

# → 数据库中不存在包含该字符串的用户，返回空结果
# → 回显表格显示"无搜索结果"
```

---

## 修复前后对比

| 攻击方式 | 漏洞 1 拼接 | 漏洞 2 过滤 | 漏洞 3 回显 | 修复前 | 修复后 |
|----------|------------|------------|------------|--------|--------|
| `keyword=' OR '1'='1` | ✅ 修改 WHERE | ❌ 未过滤 | ✅ 回显全部 | 泄露全部用户 | 无结果 |
| `keyword=' UNION SELECT 1,password,...` | ✅ 注入 UNION | ❌ 未过滤 | ✅ 回显数据 | 窃取密码 | 无结果 |
| 注册含 `'--` | ✅ 改写 INSERT | ❌ 未过滤 | — | 插入恶意数据 | 用户名原样入库 |
| `keyword=admin` | — | — | ✅ 正常回显 | 搜索正常 | ✅ 搜索正常 |

---

## 修复后 SQL 日志对比

```
修复前：
[SQL] SELECT * FROM users WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
      注入了永真条件，返回全部用户

修复后：
[SQL] SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?
      params: ("%' OR '1'='1%")
      整个输入被当作普通文本去 LIKE 匹配，无注入效果
```

---

*报告生成时间：2026-07-20 · 使用 Claude Code*
