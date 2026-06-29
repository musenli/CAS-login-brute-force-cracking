import execjs
import time

# 1. 定义 JavaScript 代码（完全复制您提供的函数）
JS_CODE = """
function uuidGenerator() {
    var originStr = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
        originChar = '0123456789abcdef',
        len = originChar.length;
    return originStr.replace(/x/g, function(match) {
        return originChar.charAt(Math.floor(Math.random() * len))
    }) + (new Date().getTime())
}
"""

url = "https://www.example.com/lyuapServer/kaptcha"

def generate_captcha_url(base_url= url):
    """
    使用 pyexecjs 调用 JS 的 uuidGenerator 生成 captchaKey，
    并构造完整的验证码请求 URL。
    返回 (url, captcha_key)
    """
    # 编译 JS 代码
    ctx = execjs.compile(JS_CODE)
    # 调用 JS 函数生成 captchaKey
    captcha_key = ctx.call('uuidGenerator')
    # v 参数：当前毫秒时间戳，防止缓存
    v = int(time.time() * 1000)
    # 注意：参数分隔符必须使用 '&'，不能是 '&amp;'
    url = f"{base_url}?captchaKey={captcha_key}&v={v}"
    return url, captcha_key

if __name__ == "__main__":
    # 生成链接
    url, key = generate_captcha_url()
    print("生成的 captchaKey:", key)
    print("完整请求 URL:", url)