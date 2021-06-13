import urllib.request
import cookiejar

# cookiejar从HTTP请求提取cookie，并在HTTP响应中返回
cookie = cookiejar.CookieJar()
# 利用urllib库的HTTPCookieProcessor对象来创建cookie处理器
cookie_handler = urllib.request.HTTPCookieProcessor(cookie)
# 构建一个自定义的opener
opener = urllib.request.build_opener(cookie_handler)
opener.addhandlers = [("User-Agent", "Opera/9.80 (Windows NT 6.1; U; zh-cn) Presto/2.9.168 Version/11.50")]
opener.open(r'http://cc.scu.edu.cn/G2S/Showsystem/Index.aspx')
for item in cookie:
    print('Name ='+item.name)
    print('Value ='+item.value)
    print('Domain ='+item.domain)
    print('path ='+item.path)


# 保存cookie的文件
filename = 'cookie.txt'
# 声明一个MozillaCookieJar对象实例来保存cookie，后面写入文件
cookie_save = cookiejar.MozillaCookieJar(filename)
handler = urllib.request.HTTPCookieProcessor(cookie_save)
opener = urllib.request.build_opener(handler)
opener.open('http://cc.scu.edu.cn/G2S/Showsystem/Index.aspx')
# 保存
cookie_save.save(ignore_discard=True, ignore_expires=True)


# 读取cookie的文件
cookie_load = cookiejar.MozillaCookieJar()
# 从文件中读取内容到cookie变量中
cookie_load.load('cookie.txt', ignore_discard=True, ignore_expires=True)
handler = urllib.request.HTTPCookieProcessor(cookie_load)
opener = urllib.request.build_opener(handler)
opener.addhandlers = [("User-Agent", "Opera/9.80 (Windows NT 6.1; U; zh-cn) Presto/2.9.168 Version/11.50")]
print(opener.open('http://cc.scu.edu.cn/G2S/Showsystem/Index.aspx').read().decode('utf-8'))


