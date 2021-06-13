from http_client import HTTPConnection
import gzip
from lxml import etree
import re
import os
import threading

defaultCookie = "FSSBBIl1UgzbN7N80S=6T.kwYbMRbTvCHXRIN8ypHVkrzslMazTjD2F0HzlBKoiYbbKNSemBFRxSExGDhQd; safedog-flow-item=;JSESSIONID=348263ABA5E9829EADC562F8BAF1B7E0; FSSBBIl1UgzbN7N80T=4zLcIJW.5bE3wajMexDxLOSaxQq_zj1MnJfatNHv7jLHo5n.3wbU2QkTJrN7RIcC0ooPtScqdYXhjslnzQ0ZL3gGJv8hwqvDnF3YifUzmkU8qRkkiwHDSJkLygvnC_Lk2TMUorYPvOGf6foDCLkec9OiSJFomixqepoSvFN8.uRK4FE0T3StGx7edps7P1Jey0cIJiFDFsGWq0BvjixXoBHm6VJZw_dOAlaXSXAfQj6I3SuHMIvZ.bqK7ifQTFJMPfi2xA39jgXcZU.culzAH2BG1Il50J.SypvJomIABRkM5EoV1hDrcES1QLXAJipp7Q1pfIngPezeiOUrpr_rT60I7v3fdShMkJYwiy2JRKCuPH9Z5f.qZXcxQ.n9A_96S0N7"

defaultUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36"

suffix = ('.js', '.css', '.jpg', '.png', '.bmp', '.gif')
img_suffix = ('.jpg', '.png', '.bmp', '.gif')

PATH = os.path.dirname(os.getcwd())


class connect:
    """根据域名跟服务器维持连接"""
    def __init__(self, severname):
        self.connection_name = severname
        self.conn = None
        self.conn_flag = 0
        self.urls = {}  # 用于存放资源的url包括主页，值为是否已经在本地缓存
        self.extern_path=""#edit by dys 2020 6 17

        self.index_path = None  #  用于指示主页的目录，因为许多文件是通过相对主页的路径调用的 
        self.index_url = None  # 从http://cc.scu.edu.cn/G2S/Showsystem/Index.aspx去除最后/之后的部分获取根目录
    
        self.header = {
           "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/jpg,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
           "Accept-Encoding": "gzip,deflate",
           "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
           "Connection": "keep-alive"}
        self.response_num = 0  # 已发送的请求但仍未处理的其响应的数量
    
    def setup(self):
        self.conn = HTTPConnection(self.connection_name)
        self.conn.connect()
        self.conn_flag = 1

    def close(self):
        self.conn.close()
        self.conn_flag = 0

    def setHeader(self, Cookie=defaultCookie, UA=defaultUA):
        self.header['Cookie'] = Cookie
        self.header['User-Agent'] = UA
    
    def requestOne_get(self, method, url):
        """用于请求完整Index页面"""
        if(self.conn_flag):
            if(method in ['GET', 'POST']):
                self.conn.request(method, url, self.header, encode_chunked=False)
                self.index_url = re.sub(r'[^/]+(?!.*/)', '', url)  
                self.response_num += 1

                res = self.conn.getresponse()
                if(self.isPage(url)):
                    prefix_url = "http://" + self.connection_name
                    url_path = url.replace(prefix_url, "")
                    self.urls[url_path] = 1
                    self.mkdirs()

                    data = res.read()
                    if(res.status != 404):
                       
                        self.extern_path=url_path
                        self.save(data, url_path)
                        self.response_num -= 1

                        self.getlinks(data)  # 若为主页面则获取其中的所有资源存入self.url里
                        for _ in range(2):
                            # 进行两轮，第一轮用于主页面中的所有资源的请求包括js，css，图片等文件
                            # 第二轮检索所有由第一轮获取的css中插入的文件
                            print(self.urls)
                            self.mkdirs()
                            self.requestMulti_get()
                       
                    else:
                        print("请求的主页不存在！")
                else:
                    print("请输入请求的主页！")
            else:
                print("请输入正确的HTTP方法！")
        else:
            print("目前没有连接已经建立！")
        

    class requestThread (threading.Thread):   # 继承父类threading.Thread
        def __init__(self, method, url, connObj):
            threading.Thread.__init__(self)
            self.method = method
            self.url = url

            self.connect = connObj

            self.connection_name = connObj.connection_name

        def run(self):                   # 把要执行的代码写入run函数里面 
            print("Starting " + self.url)
            conn = HTTPConnection(self.connection_name)
            conn.connect()

            # 判断url是否补全
            if self.connect.isAbsolute(self.url) is False:
                full_url = self.connect.index_url + self.url
            else:
                full_url = self.url

            conn.request(self.method, full_url, self.connect.header)
            res = conn.getresponse()

            if(res.status != 404):
                data = res.read()

                # 如果获取的是css文件，需要检索css文件中有无需要获取的资源
                if self.url.endswith(('.css')):
                    self.connect.getlinks(data)

                self.connect.save(data, self.url)
                self.connect.urls[self.url] = 1        
                print("Exiting " + self.name)

    def requestMulti_get(self, method='GET'):
        """采用多线程的方式发送多个请求，
        请求的当前self.urls中所有没有被置为1的请求，即还没有获取的请求"""
        threads = []
        if(self.conn_flag):
            if(method in ['GET', 'POST']):
                for url in self.urls.keys():
                    if self.urls[url] == 0:
                        requestThread = self.requestThread(method, url, self)
                        requestThread.start()
                        threads.append(requestThread)
                for t in threads:
                    t.join(10)
            else:
                print("请输入正确的HTTP方法！")
        else:
            print("目前没有连接已经建立！")     

    def getlinks(self, data):
        """获取data中的所有链接，以用于请求资源.(data可以是html文件，也可以是aspx文件或者css文件)
        设置资源的self.urls列表, 注意这里返回的url并没有进行补全,是相对路径格式的"""

        try:
            unzip_data = gzip.decompress(data).decode()
        except(OSError):
            try:
                unzip_data = data.decode('UTF-8')
            except(UnicodeDecodeError):
                unzip_data = data.decode('ISO-8859-1')

        tree = etree.HTML(unzip_data)
        if tree.xpath('//div'):
            # 以下是资源链接可能存在的地方包括：src或者href的属性中 \ 嵌入标签的style属性中 \ style标签的内容中
            # 如果有另外放置链接的地方需要继续补充
            for link in tree.xpath('//@src'):
                if self.isAbsolute(link) is False:
                    link = self.check_url(link)
                    self.urls[link] = 0

            for link in tree.xpath('//link/@href'):
                if self.isAbsolute(link) is False:
                    link = self.check_url(link)
                    self.urls[link] = 0

            for style in tree.xpath('//@style'):
                link = re.search(r'(?<=url\()[^()]+(?=\))', style)
                if link and self.isAbsolute(link.group(0)) is False:
                    link = self.check_url(link.group(0))
                    self.urls[link] = 0

            for style in tree.xpath('//style/text()'):
                pattern = re.compile(r'(?<=url\()[^()]+(?=\))')
                links = pattern.findall(style)
                if links:
                    for link in links:
                        if self.isAbsolute(link) is False:
                            link = self.check_url(link)
                            self.urls[link] = 0
        else:
            # 针对与.css文件
            pattern = re.compile(r'(?<=url\()[^()]+(?=\))')
            links = pattern.findall(unzip_data)
            if links:
                for link in links:
                    if self.isAbsolute(link) is False:
                        link = self.check_url(link)
                        self.urls[link] = 0

    def check_url(self, url):
        """去除url中的不规范的地方如 \" , \.\. """
        if url.startswith(("\"")):
            url = eval(url)
        if url.startswith(("\'")):
            url = eval(url)
        if url.startswith(('../')):
            url = url.replace('../', "")
        return url

    def mkdirs(self):
        """根据当前资源列表self.urls中的相对路径构建目录"""
        # 如果还没有构建主页的目录即index_path
        if self.index_path is None:
            url = sorted(self.urls.keys())[0]
            url_dir = re.sub(r'[^/]+(?!.*/)', '', url)
            abs_dir = 'data/cc_scu' + url_dir
            if not os.path.exists(abs_dir):
                os.makedirs(abs_dir)
                print("成功创建目录: " + abs_dir + "\n")
            self.index_path = abs_dir
        else:
            for url in self.urls.keys():
                # 如果该资源还没有被存入
                if self.urls[url] == 0:
                    url_dir = re.sub(r'[^/]+(?!.*/)', '', url)  # 去尾，仅保留目录部分
                    # 如果该文件从顶级目录开始，这里顶级目录就是data/cc_scu
                    if(url_dir.startswith('/')):
                        abs_dir = 'data/cc_scu' + url_dir
                        if not os.path.exists(abs_dir):
                            os.makedirs(abs_dir)
                            print("成功创建目录: " + abs_dir + "\n")
                    else:
                        abs_dir = self.index_path + url_dir
                        if not os.path.exists(abs_dir):
                            os.makedirs(abs_dir)
                            print("成功创建目录: " + abs_dir + "\n")
        return abs_dir
                    
    def isAbsolute(self, link):
        """判断link是否为绝对路径
           这里的判断方法为 判断link是否为‘http://’开头"""
        if(re.match(r'(http):\/\/', link)):
            return True
        else:
            return False

    def isPage(self, url):
        """判断请求的url是否为页面
           这里的判断方法为 判断url是否以.***结尾"""
        if(url.endswith(suffix)):
            return False
        else:
            return True

    def save(self, data, url):
        """获取资源的相对目录
           然后将获取到的资源解码写入"""
        if url.startswith('/'):
            path = 'data/cc_scu' + url
        else:
            path = self.index_path + url

        try:
            unzip_data = gzip.decompress(data).decode()
            with open(path, "w") as f:
                f.write(unzip_data)
                print("成功写入：" + path + "\n")
            f.close()
        except(OSError):
            # 说明该页面并没有被压缩
            if url.endswith(img_suffix):
                with open(path, 'wb') as f:
                    f.write(data)
                    print("成功写入：" + path + "\n")
                f.close
            else:
                with open(path, 'w', errors='ignore') as f:
                    if url.endswith(('.css')):
                        try:
                            f.write(data.decode('utf-8-sig'))
                            print("成功写入：" + path + "\n")
                        except(UnicodeDecodeError):
                            f.write(data.decode("ISO-8859-1"))
                            print("成功写入：" + path + "\n")
                    elif url.endswith(('.aspx', '.html')):
                        try:
                            f.write(data.decode('utf-8'))
                            print("成功写入：" + path + "\n")
                         
                        except():
                            f.wirte(data.decode('utf-8-sig'))
                            print("成功写入：" + path + "\n")
                         
                    else:
                        f.write(data.decode("ISO-8859-1"))
                        print("成功写入：" + path + "\n")
                f.close
              


if __name__ == "__main__":
    conn = connect("cc.scu.edu.cn")
    conn.setup()
    conn.requestOne_get('GET', "http://cc.scu.edu.cn/G2S/Showsystem/Index.aspx")
    conn.close


