# CAS登录暴力破解测试工具 v2.0



先说明一点：

**网络安全是数字时代的基石，但学习过程中必须严守法律红线**。‌
根据《中华人民共和国网络安全法》《数据安全法》等法律法规，**任何未经授权的网络测试、数据访问或攻击行为均属违法**。本文所有技术讨论与实例均基于‌合法授权的靶场环境‌（如Metasploitable、DVWA、Hack The Box等），**严禁将文中方法应用于真实系统或非授权场景**。
**网络安全学习应以提升防御能力为目标，而非成为攻击工具。**



本项目旨在解决网站登录验证码使用session的的情况，即两次 HTTP 请求未命中同一会话（Session）‌或‌资源加载时序不同步‌，导致前后端校验的“码值”并非同一份数据。

再次重申：**任何未经授权的网络测试、数据访问或攻击行为均属违法！**

## 文件说明：

### **generate_captcha_url.py** ：

​	如果captcha_url是异步生成的，那么就在这里逆向并生成。目的是模拟网站前段生成验证码链接的参数

- **url = "https://www.example.com/lyuapServer/kaptcha“** 是captcha_url的主要链接，不携带参数，或携带固定参数
- **JS_CODE = """... ..."""**：逆向中提取的前段页面相关代码，为保证运行稳定性，不要用python语言去模拟

### **baopo_main.py** ：

​	此文件为执行的主文件，**generate_captcha_url.py** 生成的 **captcha_url** ；**baopo_main.py** 生成用户名和密码后一并发送请求，每次验证码识别错误或者登录失败都会重新刷新session 。

​	保证每次请求的session是同步的，而且在验证码识别正确前，不会进行用户名和密码的验证步骤。

- 相关配置（可根据情况更改）：

  ```python
  # 请求配置
  REQUEST_TIMEOUT = 15
  VERIFY_SSL = False
  
  # 延迟配置（秒）
  DELAY_BASE = 3
  DELAY_JITTER = 2
  
  # OCR配置
  CAPTCHA_MIN_LENGTH = 3
  CAPTCHA_MAX_LENGTH = 5
  
  # OCR重试配置
  OCR_MAX_RETRIES = 2
  
  # 用户数据格式：(用户名, 密码模板)
  # 密码模板中的 {} 会被替换为日期（01-31）
  USERS_DATA = [
      ("12345678", "{}1235@ie"),
      ("12345678", "{}99999@zie"),
  ]
  ```

- 密码生成：（此处以日期为例）

  ```python
  # 此段代码需要根据情况进行更改
  # 遍历日期（01-31）
  for day in range(day_start, 32):
  	day_str = f"{day:02d}"
  	password = pwd_template.format(day_str)
  
       attempt_num = state_mgr.increment_attempts()
  ```

- 请求头：

  ```python
  # 添加Referer等请求头
  headers = {
      'Referer': Config.LOGIN_URL,
      'Origin': 'https://www.example.com',
      'Content-Type': 'application/x-www-form-urlencoded',
  }
  # 'Origin': 'https://www.example.com' 一般是要添加的
  ```

- 其它：

  其它的详细说明，代码里边都有。所以想怎么改，悉听尊便

## 运行效果

每次验证码失败，都会重新获取session后进行密码验证，所以可以忽略这个信息。有兴趣的师傅可以自行更改

<img src="./微信图片_20260625150038_636_1538.png" style="zoom:67%;" />