import os
import copy
import datetime
import re
import time
import urllib.parse, urllib.request
import threading as _threading
import http.client
from calendar import timegm
import io, warnings, traceback


class Cookie:  # HTTP Cookie 属性
    def __init__(self, version, name, value,  # 初始化
                 port, port_specified,
                 domain, domain_specified, domain_initial_dot,
                 path, path_specified,
                 secure,
                 expires,
                 discard,
                 ):

        if version is not None: version = int(version)  # 格式转换
        if expires is not None: expires = int(float(expires))
        if port is None and port_specified is True:
            raise ValueError("if port is None, port_specified must be false")

        self.version = version
        self.name = name
        self.value = value
        self.port = port
        self.port_specified = port_specified
        self.domain = domain.lower()
        self.domain_specified = domain_specified
        self.domain_initial_dot = domain_initial_dot
        self.path = path
        self.path_specified = path_specified
        self.secure = secure
        self.expires = expires
        self.discard = discard

    def is_expired(self, now=None):  # 是否已经过期
        if now is None:
            now = time.time()
        if (self.expires is not None) and (self.expires <= now):
            return True
        return False


class Absent: pass


class CookieJar:
    non_word_re = re.compile(r"\W")
    quote_re = re.compile(r"([\"\\])")
    strict_domain_re = re.compile(r"\.?[^.]*")
    domain_re = re.compile(r"[^.]*")
    dots_re = re.compile(r"^\.+")
    magic_re = re.compile(r"^\#LWP-Cookies-(\d+\.\d+)", re.ASCII)

    def __init__(self, policy=None):
        if policy is None:
            policy = DefaultCookiePolicy()
        self._policy = policy

        self._cookies_lock = _threading.RLock()
        self._cookies = {}

    def set_policy(self, policy):
        self._policy = policy

    def _cookies_for_domain(self, domain, request):
        cookies = []
        if not self._policy.domain_return_ok(domain, request):
            return []
        # print("Checking %s for cookies to return", domain)
        cookies_by_path = self._cookies[domain]
        for path in cookies_by_path.keys():
            if not self._policy.path_return_ok(path, request):
                continue
            cookies_by_name = cookies_by_path[path]
            for cookie in cookies_by_name.values():
                if not self._policy.return_ok(cookie, request):
                    print("   not returning cookie")
                    continue
                print("   it's a match")
                cookies.append(cookie)
        return cookies  # 返回Cookie对象

    def add_cookie_header(self, request):  # 增加cookie到请求信息的头部
        # print("add_cookie_header")
        self._cookies_lock.acquire()
        try:
            self._policy._now = self._now = int(time.time())
            cookies = self._cookies_for_request(request)  # 获取cookie
            attrs = self._cookie_attrs(cookies)  # 获取属性
            if attrs:
                if not request.has_header("Cookie"):
                    request.add_unredirected_header("Cookie", "; ".join(attrs))
            if self._policy.rfc2965 and not self._policy.hide_cookie2 and not request.has_header("Cookie2"):
                for cookie in cookies:
                    if cookie.version != 1:
                        request.add_unredirected_header("Cookie2", '$Version="1"')
                        break
        finally:
            self._cookies_lock.release()
        self.clear_expired_cookies()

    def _cookies_for_request(self, request):  # 返回给服务器的cookie列表
        cookies = []
        for domain in self._cookies.keys():
            cookies.extend(self._cookies_for_domain(domain, request))
        return cookies  # 返回Cookie对象

    def _cookie_attrs(self, cookies):  # 返回给服务器的cookie属性，格式为键值对
        cookies.sort(key=lambda a: len(a.path), reverse=True)
        version_set = False
        attrs = []
        for cookie in cookies:
            version = cookie.version
            if not version_set:
                version_set = True
                if version > 0:
                    attrs.append("$Version=%s" % version)
            if ((cookie.value is not None) and
                    self.non_word_re.search(cookie.value) and version > 0):
                value = self.quote_re.sub(r"\\\1", cookie.value)
            else:
                value = cookie.value
            if cookie.value is None:
                attrs.append(cookie.name)
            else:
                attrs.append("%s=%s" % (cookie.name, value))
            if version > 0:
                if cookie.path_specified:
                    attrs.append('$Path="%s"' % cookie.path)
                if cookie.domain.startswith("."):
                    domain = cookie.domain
                    if (not cookie.domain_initial_dot and
                            domain.startswith(".")):
                        domain = domain[1:]
                    attrs.append('$Domain="%s"' % domain)
                if cookie.port is not None:
                    p = "$Port"
                    if cookie.port_specified:
                        p = p + ('="%s"' % cookie.port)
                    attrs.append(p)
        return attrs

    def _normalized_cookie_tuples(self, attrs_set):  # 返回包含规范化cookie信息的元组列表
        cookie_tuples = []
        boolean_attrs = "discard", "secure"
        value_attrs = ("version",
                       "expires", "max-age",
                       "domain", "path", "port",
                       "comment", "commenturl")
        for cookie_attrs in attrs_set:  # attrs_set是从set Cookie或set-Cookie2头中提取的键值对列表
            name, value = cookie_attrs[0]
            max_age_set = False  # 布尔类型
            bad_cookie = False
            standard = {}  # standard是字典，存放基本的属性
            rest = {}  # rest是字典，存放其他的属性
            for k, v in cookie_attrs[1:]:
                lc = k.lower()
                if lc in value_attrs or lc in boolean_attrs:
                    k = lc
                if k in boolean_attrs and v is None:
                    v = True
                if k in standard:
                    continue
                if k == "domain":
                    if v is None:
                        print("   missing value for domain attribute")
                        bad_cookie = True
                        break
                    v = v.lower()
                if k == "expires":
                    if max_age_set:
                        continue
                    if v is None:
                        # print("   missing or invalid value for expires "
                              # "attribute: treating as session cookie")
                        continue
                if k == "max-age":
                    max_age_set = True
                    try:
                        v = int(v)
                    except ValueError:
                        print("   missing or invalid (non-numeric) value for "
                              "max-age attribute")
                        bad_cookie = True
                        break
                    k = "expires"
                    v = self._now + v
                if (k in value_attrs) or (k in boolean_attrs):
                    if v is None and k not in ("port", "comment", "commenturl"):
                        print("   missing value for %s attribute" % k)
                        bad_cookie = True
                        break
                    standard[k] = v
                else:
                    rest[k] = v
            if bad_cookie:
                continue
            cookie_tuples.append((name, value, standard, rest))
        return cookie_tuples

    def _cookie_from_cookie_tuple(self, tup, request):  # 从元组中提取
        name, value, standard, rest = tup
        domain = standard.get("domain", Absent)
        path = standard.get("path", Absent)
        port = standard.get("port", Absent)
        expires = standard.get("expires", Absent)
        version = standard.get("version", None)
        if version is not None:
            try:
                version = int(version)
            except ValueError:
                return None
        secure = standard.get("secure", False)
        discard = standard.get("discard", False)
        if path is not Absent and path != "":  # 默认路径
            path_specified = True
            path = escape_path(path)
        else:
            path_specified = False
            path = request_path(request)
            i = path.rfind("/")
            if i != -1:
                if version == 0:
                    path = path[:i]
                else:
                    path = path[:i + 1]
            if len(path) == 0: path = "/"
        domain_specified = domain is not Absent  # 默认域
        domain_initial_dot = False
        if domain_specified:
            domain_initial_dot = bool(domain.startswith("."))
        if domain is Absent:
            req_host, erhn = eff_request_host(request)
            domain = erhn
        elif not domain.startswith("."):
            domain = "." + domain
        port_specified = False  # 默认端口
        if port is not Absent:
            if port is None:
                port = request_port(request)
            else:
                port_specified = True
                port = re.sub(r"\s+", "", port)
        else:
            port = None
        if expires is Absent:  # 默认expires和discard
            expires = None
            discard = True
        elif expires <= self._now:
            try:
                self.clear(domain, path, name)
            except KeyError:
                pass
            print("Expiring cookie, domain='%s', path='%s', name='%s'",
                  domain, path, name)
            return None
        return Cookie(version,  # 从元组中获取到的cookie
                      name, value,
                      port, port_specified,
                      domain, domain_specified, domain_initial_dot,
                      path, path_specified,
                      secure,
                      expires,
                      discard,
                      )

    def _cookies_from_attrs_set(self, attrs_set, request):
        cookie_tuples = self._normalized_cookie_tuples(attrs_set)
        cookies = []
        for tup in cookie_tuples:
            cookie = self._cookie_from_cookie_tuple(tup, request)
            if cookie: cookies.append(cookie)
        return cookies

    def _process_rfc2109_cookies(self, cookies):
        rfc2109_as_ns = getattr(self._policy, 'rfc2109_as_netscape', None)
        if rfc2109_as_ns is None:
            rfc2109_as_ns = not self._policy.rfc2965
        for cookie in cookies:
            if cookie.version == 1:
                cookie.rfc2109 = True
                if rfc2109_as_ns:
                    cookie.version = 0

    def make_cookies(self, response, request):  # 返回从响应消息中提取的cookie序列
        headers = response.info()
        rfc2965_hdrs = headers.get_all("Set-Cookie2", [])
        ns_hdrs = headers.get_all("Set-Cookie", [])
        self._policy._now = self._now = int(time.time())
        rfc2965 = self._policy.rfc2965
        netscape = self._policy.netscape
        if ((not rfc2965_hdrs and not ns_hdrs) or
                (not ns_hdrs and not rfc2965) or
                (not rfc2965_hdrs and not netscape) or
                (not netscape and not rfc2965)):
            return []

        try:
            cookies = self._cookies_from_attrs_set(
                split_header_words(rfc2965_hdrs), request)
        except Exception:
            _warn_unhandled_exception()
            cookies = []

        if ns_hdrs and netscape:
            try:
                ns_cookies = self._cookies_from_attrs_set(
                    parse_ns_headers(ns_hdrs), request)
            except Exception:
                _warn_unhandled_exception()
                ns_cookies = []
            self._process_rfc2109_cookies(ns_cookies)

            if rfc2965:
                lookup = {}
                for cookie in cookies:
                    lookup[(cookie.domain, cookie.path, cookie.name)] = None

                def no_matching_rfc2965(ns_cookie, lookup=lookup):
                    key = ns_cookie.domain, ns_cookie.path, ns_cookie.name
                    return key not in lookup

                ns_cookies = filter(no_matching_rfc2965, ns_cookies)

            if ns_cookies:
                cookies.extend(ns_cookies)
        return cookies

    def set_cookie_if_ok(self, cookie, request):
        self._cookies_lock.acquire()
        try:
            self._policy._now = self._now = int(time.time())

            if self._policy.set_ok(cookie, request):
                self.set_cookie(cookie)

        finally:
            self._cookies_lock.release()

    def set_cookie(self, cookie):
        c = self._cookies
        self._cookies_lock.acquire()
        try:
            if cookie.domain not in c: c[cookie.domain] = {}
            c2 = c[cookie.domain]
            if cookie.path not in c2: c2[cookie.path] = {}
            c3 = c2[cookie.path]
            c3[cookie.name] = cookie
        finally:
            self._cookies_lock.release()

    # 从响应中提取cookies，并在允许的情况下调用set_cookie给出请求。
    def extract_cookies(self, response, request):
        print("extract_cookies: %s", response.info())
        self._cookies_lock.acquire()
        try:
            for cookie in self.make_cookies(response, request):
                if self._policy.set_ok(cookie, request):  # 可以接受从响应中提取的cookie
                    print(" setting cookie: %s", cookie)
                    self.set_cookie(cookie)
        finally:
            self._cookies_lock.release()

    def clear(self, domain=None, path=None, name=None):  # 清除一些指定的cookie
        if name is not None:
            if (domain is None) or (path is None):
                raise ValueError(
                    "domain and path must be given to remove a cookie by name")
            del self._cookies[domain][path][name]
        elif path is not None:
            if domain is None:
                raise ValueError(
                    "domain must be given to remove cookies by path")
            del self._cookies[domain][path]
        elif domain is not None:
            del self._cookies[domain]
        else:
            self._cookies = {}

    def clear_session_cookies(self):
        self._cookies_lock.acquire()
        try:
            for cookie in self:
                if cookie.discard:
                    self.clear(cookie.domain, cookie.path, cookie.name)
        finally:
            self._cookies_lock.release()

    def clear_expired_cookies(self):
        self._cookies_lock.acquire()
        try:
            now = time.time()
            for cookie in self:
                if cookie.is_expired(now):
                    self.clear(cookie.domain, cookie.path, cookie.name)
        finally:
            self._cookies_lock.release()

    def __iter__(self):
        return deepvalues(self._cookies)

    def __len__(self):  # 现有cookie的数目
        i = 0
        for cookie in self: i = i + 1
        return i

    def __repr__(self):
        r = []
        for cookie in self: r.append(repr(cookie))
        return "<%s[%s]>" % (self.__class__.__name__, ", ".join(r))

    def __str__(self):
        r = []
        for cookie in self: r.append(str(cookie))
        return "<%s[%s]>" % (self.__class__.__name__, ", ".join(r))


class LoadError(OSError): pass


class FileCookieJar(CookieJar):
    def __init__(self, filename=None, delayload=False, policy=None):
        CookieJar.__init__(self, policy)
        if filename is not None:
            filename = os.fspath(filename)
        self.filename = filename
        self.delayload = bool(delayload)

    def save(self, filename=None, ignore_discard=False, ignore_expires=False):  # 保存
        raise NotImplementedError()

    def load(self, filename=None, ignore_discard=False, ignore_expires=False):  # 加载
        if filename is None:
            if self.filename is not None:
                filename = self.filename
            else:
                raise ValueError("no filename")

        with open(filename) as f:
            self._really_load(f, filename, ignore_discard, ignore_expires)

    def revert(self, filename=None,
               ignore_discard=False, ignore_expires=False):
        if filename is None:
            if self.filename is not None:
                filename = self.filename
            else:
                raise ValueError("no filename")

        self._cookies_lock.acquire()
        try:

            old_state = copy.deepcopy(self._cookies)
            self._cookies = {}
            try:
                self.load(filename, ignore_discard, ignore_expires)
            except OSError:
                self._cookies = old_state
                raise
        finally:
            self._cookies_lock.release()

    def _really_load(self, f, filename, ignore_discard, ignore_expires):
        pass


class MozillaCookieJar(FileCookieJar):  # 使用Mozilla/Netscape的cookies.txt文件格式
    magic_re = re.compile("#( Netscape)? HTTP Cookie File")
    header = """\
# Netscape HTTP Cookie File
# http://curl.haxx.se/rfc/cookie_spec.html
# This is a generated file!  Do not edit.
"""

    def _really_load(self, f, filename, ignore_discard, ignore_expires):  # 重写load
        now = time.time()
        magic = f.readline()
        if not self.magic_re.search(magic):
            raise LoadError("%r does not look like a Netscape format cookies file" % filename)
        try:
            while 1:
                line = f.readline()
                if line == "":
                    break
                if line.endswith("\n"):
                    line = line[:-1]
                if line.strip().startswith(("#", "$")) or line.strip() == "":
                    continue
                domain, domain_specified, path, secure, expires, name, value = line.split("\t")
                secure = (secure == "TRUE")
                domain_specified = (domain_specified == "TRUE")
                if name == "":
                    name = value
                    value = None  # 无值
                initial_dot = domain.startswith(".")
                assert domain_specified == initial_dot
                discard = False
                if expires == "":
                    expires = None
                    discard = True
                c = Cookie(0, name, value,
                           None, False,
                           domain, domain_specified, initial_dot,
                           path, False,
                           secure,
                           expires,
                           discard,
                           )
                if not ignore_discard and c.discard:
                    continue
                if not ignore_expires and c.is_expired(now):
                    continue
                self.set_cookie(c)
        except OSError:
            raise
        except Exception:
            _warn_unhandled_exception()
            raise LoadError("invalid Netscape format cookies file %r: %r" %
                            (filename, line))

    def save(self, filename=None, ignore_discard=False, ignore_expires=False):  # 重写save
        if filename is None:
            if self.filename is not None:
                filename = self.filename
            else:
                raise ValueError("no filename")

        with open(filename, "w") as f:
            f.write(self.header)
            now = time.time()
            for cookie in self:
                if not ignore_discard and cookie.discard:
                    continue
                if not ignore_expires and cookie.is_expired(now):
                    continue
                if cookie.secure:
                    secure = "TRUE"
                else:
                    secure = "FALSE"
                if cookie.domain.startswith("."):
                    initial_dot = "TRUE"
                else:
                    initial_dot = "FALSE"
                if cookie.expires is not None:
                    expires = str(cookie.expires)
                else:
                    expires = ""
                if cookie.value is None:
                    name = ""
                    value = cookie.name
                else:
                    name = cookie.name
                    value = cookie.value
                # tur = {'name': name, 'value': value, 'domain': cookie.domain, 'domain_specified': initial_dot,
                #        'path': cookie.path, 'secure': secure, 'expires': expires}
                # f.write(str(tur))
                f.write("\t".join([cookie.domain, initial_dot, cookie.path, secure, expires, name, value]) + "\n")


class DefaultCookiePolicy:
    DomainStrictNoDots = 1
    DomainStrictNonDomain = 2
    DomainRFC2965Match = 4

    DomainLiberal = 0
    DomainStrict = DomainStrictNoDots | DomainStrictNonDomain

    def __init__(self,
                 blocked_domains=None, allowed_domains=None,
                 netscape=True, rfc2965=False,
                 rfc2109_as_netscape=None,
                 hide_cookie2=False,
                 strict_domain=False,
                 strict_rfc2965_unverifiable=True,
                 strict_ns_unverifiable=False,
                 strict_ns_domain=DomainLiberal,
                 strict_ns_set_initial_dollar=False,
                 strict_ns_set_path=False,
                 secure_protocols=("https", "wss")
                 ):

        self.netscape = netscape
        self.rfc2965 = rfc2965
        self.rfc2109_as_netscape = rfc2109_as_netscape
        self.hide_cookie2 = hide_cookie2
        self.strict_domain = strict_domain
        self.strict_rfc2965_unverifiable = strict_rfc2965_unverifiable
        self.strict_ns_unverifiable = strict_ns_unverifiable
        self.strict_ns_domain = strict_ns_domain
        self.strict_ns_set_initial_dollar = strict_ns_set_initial_dollar
        self.strict_ns_set_path = strict_ns_set_path
        self.secure_protocols = secure_protocols

        if blocked_domains is not None:
            self._blocked_domains = tuple(blocked_domains)
        else:
            self._blocked_domains = ()

        if allowed_domains is not None:
            allowed_domains = tuple(allowed_domains)
        self._allowed_domains = allowed_domains

    def blocked_domains(self):
        return self._blocked_domains

    def set_blocked_domains(self, blocked_domains):  # 黑名单
        self._blocked_domains = tuple(blocked_domains)

    def is_blocked(self, domain):  # 判断
        for blocked_domain in self._blocked_domains:
            if user_domain_match(domain, blocked_domain):
                return True
        return False

    def allowed_domains(self):
        return self._allowed_domains

    def set_allowed_domains(self, allowed_domains):  # 白名单
        if allowed_domains is not None:
            allowed_domains = tuple(allowed_domains)
        self._allowed_domains = allowed_domains

    def is_not_allowed(self, domain):  # 判断
        if self._allowed_domains is None:
            return False
        for allowed_domain in self._allowed_domains:
            if user_domain_match(domain, allowed_domain):
                return False
        return True

    def set_ok(self, cookie, request):  # 是否可以接受，依次设定"version", "verifiability", "name", "path", "domain", "port"
        assert cookie.name is not None
        for n in "version", "verifiability", "name", "path", "domain", "port":
            fn_name = "set_ok_" + n
            fn = getattr(self, fn_name)
            if not fn(cookie, request):
                return False
        return True

    def set_ok_version(self, cookie, request):
        if cookie.version is None:
            print("   Set-Cookie2 without version attribute (%s=%s)", cookie.name, cookie.value)
            return False
        if cookie.version > 0 and not self.rfc2965:
            print("   RFC 2965 cookies are switched off")
            return False
        elif cookie.version == 0 and not self.netscape:
            print("   Netscape cookies are switched off")
            return False
        return True

    def set_ok_verifiability(self, cookie, request):
        if request.unverifiable:
            if cookie.version > 0 and self.strict_rfc2965_unverifiable:
                print("   third-party RFC 2965 cookie during ""unverifiable transaction")
                return False
            elif cookie.version == 0 and self.strict_ns_unverifiable:
                print("   third-party Netscape cookie during " "unverifiable transaction")
                return False
        return True

    def set_ok_name(self, cookie, request):
        if cookie.version == 0 and self.strict_ns_set_initial_dollar and cookie.name.startswith("$"):
            # print("   illegal name (starts with '$'): '%s'", cookie.name)
            return False
        return True

    def set_ok_path(self, cookie, request):
        if cookie.path_specified:
            req_path = request_path(request)
            if ((cookie.version > 0 or
                 (cookie.version == 0 and self.strict_ns_set_path)) and
                    not self.path_return_ok(cookie.path, request)):
                print("   path attribute %s is not a prefix of request " "path %s", cookie.path, req_path)
                return False
        return True

    def set_ok_domain(self, cookie, request):
        if self.is_blocked(cookie.domain):
            print("   domain %s is in user block-list", cookie.domain)
            return False
        if self.is_not_allowed(cookie.domain):
            print("   domain %s is not in user allow-list", cookie.domain)
            return False
        if cookie.domain_specified:
            req_host, erhn = eff_request_host(request)
            domain = cookie.domain
            if self.strict_domain and (domain.count(".") >= 2):
                i = domain.rfind(".")
                j = domain.rfind(".", 0, i)
                if j == 0:  # domain like .foo.bar
                    tld = domain[i + 1:]
                    sld = domain[j + 1:i]
                    if sld.lower() in ("co", "ac", "com", "edu", "org", "net",  # 在范围内可以
                                       "gov", "mil", "int", "aero", "biz", "cat", "coop",
                                       "info", "jobs", "mobi", "museum", "name", "pro",
                                       "travel", "eu") and len(tld) == 2:
                        # domain like .co.uk
                        print("   country-code second level domain %s", domain)
                        return False
            if domain.startswith("."):
                undotted_domain = domain[1:]
            else:
                undotted_domain = domain
            embedded_dots = (undotted_domain.find(".") >= 0)
            if not embedded_dots and domain != ".local":
                print("   non-local domain %s contains no embedded dot", domain)
                return False
        return True

    def set_ok_port(self, cookie, request):
        if cookie.port_specified:
            req_port = request_port(request)
            if req_port is None:  # 没有端口号默认是80
                req_port = "80"
            else:
                req_port = str(req_port)
            for p in cookie.port.split(","):
                try:
                    int(p)
                except ValueError:
                    print("   bad port %s (not numeric)", p)
                    return False
                if p == req_port:
                    break
            else:
                print("   request port (%s) not found in %s",
                      req_port, cookie.port)
                return False
        return True

    def return_ok(self, cookie, request):  # 是否可以发出
        # print(" - checking cookie %s=%s", cookie.name, cookie.value)
        for n in "version", "verifiability", "secure", "expires", "port", "domain":
            fn_name = "return_ok_" + n
            fn = getattr(self, fn_name)
            if not fn(cookie, request):
                return False
        return True

    def return_ok_version(self, cookie, request):  # 只允许rfc2965 和 netscape
        if cookie.version > 0 and not self.rfc2965:
            print("   RFC 2965 cookies are switched off")
            return False
        elif cookie.version == 0 and not self.netscape:
            print("   Netscape cookies are switched off")
            return False
        return True

    def return_ok_verifiability(self, cookie, request):
        if request.unverifiable:
            if cookie.version > 0 and self.strict_rfc2965_unverifiable:
                print("   third-party RFC 2965 cookie during unverifiable "
                      "transaction")
                return False
            elif cookie.version == 0 and self.strict_ns_unverifiable:
                print("   third-party Netscape cookie during unverifiable "
                      "transaction")
                return False
        return True

    def return_ok_secure(self, cookie, request):
        if cookie.secure and request.type not in self.secure_protocols:
            print("   secure cookie with non-secure request")
            return False
        return True

    def return_ok_expires(self, cookie, request):
        if cookie.is_expired(self._now):
            print("   cookie expired")
            return False
        return True

    def return_ok_port(self, cookie, request):
        if cookie.port:
            req_port = request_port(request)
            if req_port is None:
                req_port = "80"
            for p in cookie.port.split(","):
                if p == req_port:
                    break
            else:
                print("   request port %s does not match cookie port %s",
                      req_port, cookie.port)
                return False
        return True

    def return_ok_domain(self, cookie, request):
        req_host, erhn = eff_request_host(request)
        domain = cookie.domain
        if domain and not domain.startswith("."):
            dotdomain = "." + domain
        else:
            dotdomain = domain

        if (cookie.version == 0 and
                (self.strict_ns_domain & self.DomainStrictNonDomain) and
                not cookie.domain_specified and domain != erhn):
            print("   cookie with unspecified domain does not string-compare "
                  "equal to request domain")
            return False

        if cookie.version > 0:
            print("   effective request-host name %s does not domain-match "
                  "RFC 2965 cookie domain %s", erhn, domain)
            return False
        if cookie.version == 0 and not ("." + erhn).endswith(dotdomain):
            print("   request-host %s does not match Netscape cookie domain "
                  "%s", req_host, domain)
            return False
        return True

    def domain_return_ok(self, domain, request):
        req_host, erhn = eff_request_host(request)
        if not req_host.startswith("."):
            req_host = "." + req_host
        if not erhn.startswith("."):
            erhn = "." + erhn
        if domain and not domain.startswith("."):
            dotdomain = "." + domain
        else:
            dotdomain = domain
        if not (req_host.endswith(dotdomain) or erhn.endswith(dotdomain)):
            return False
        if self.is_blocked(domain):
            print("   domain %s is in user block-list", domain)
            return False
        if self.is_not_allowed(domain):
            print("   domain %s is not in user allow-list", domain)
            return False

        return True

    def path_return_ok(self, path, request):
        print("- checking cookie path=%s", path)
        req_path = request_path(request)
        pathlen = len(path)
        if req_path == path:
            return True
        elif (req_path.startswith(path) and
              (path.endswith("/") or req_path[pathlen:pathlen + 1] == "/")):
            return True

        print("  %s does not path-match %s", req_path, path)
        return False


def _warn_unhandled_exception():  # 发现未处理异常,发出警告。
    f = io.StringIO()
    traceback.print_exc(None, f)
    msg = f.getvalue()
    warnings.warn("http.cookiejar bug!\n%s" % msg, stacklevel=2)


def vals_sorted_by_key(adict):  # 按键排序
    keys = sorted(adict.keys())
    return map(adict.get, keys)


def deepvalues(mapping):  # 在嵌套映射上迭代，深度优先，按键排序
    values = vals_sorted_by_key(mapping)
    for obj in values:
        mapping = False
        try:
            obj.items
        except AttributeError:
            pass
        else:
            mapping = True
            yield from deepvalues(obj)
        if not mapping:
            yield obj


# 时间格式转换部分！
def _timegm(tt):  # 时间格式合理化
    year, month, mday, hour, min, sec = tt[:6]
    if ((year >= 1970) and (1 <= month <= 12) and (1 <= mday <= 31) and
            (0 <= hour <= 24) and (0 <= min <= 59) and (0 <= sec <= 61)):
        return timegm(tt)
    else:
        return None


DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
MONTHS_LOWER = []
for month in MONTHS: MONTHS_LOWER.append(month.lower())  # 小写
UTC_ZONES = {"GMT": None, "UTC": None, "UT": None, "Z": None}
TIMEZONE_RE = re.compile(r"^([-+])?(\d\d?):?(\d\d)?$", re.ASCII)


def offset_from_tz_string(tz):  # 计算相对时间
    offset = None
    if tz in UTC_ZONES:
        offset = 0
    else:
        m = TIMEZONE_RE.search(tz)
        if m:
            offset = 3600 * int(m.group(2))
            if m.group(3):
                offset = offset + 60 * int(m.group(3))
            if m.group(1) == '-':
                offset = -offset
    return offset


def _str2time(day, mon, yr, hr, min, sec, tz):
    yr = int(yr)
    if yr > datetime.MAXYEAR:
        return None
    try:
        mon = MONTHS_LOWER.index(mon.lower()) + 1
    except ValueError:
        try:
            imon = int(mon)
        except ValueError:
            return None
        if 1 <= imon <= 12:
            mon = imon
        else:
            return None

    # make sure clock elements are defined
    if hr is None: hr = 0
    if min is None: min = 0
    if sec is None: sec = 0

    day = int(day)
    hr = int(hr)
    min = int(min)
    sec = int(sec)

    if yr < 1000:
        cur_yr = time.localtime(time.time())[0]
        m = cur_yr % 100
        tmp = yr
        yr = yr + cur_yr - m
        m = m - tmp
        if abs(m) > 50:
            if m > 0:
                yr = yr + 100
            else:
                yr = yr - 100

    t = _timegm((yr, mon, day, hr, min, sec, tz))

    if t is not None:
        if tz is None:
            tz = "UTC"
        tz = tz.upper()
        offset = offset_from_tz_string(tz)
        if offset is None:
            return None
        t = t - offset
    return t


STRICT_DATE_RE = re.compile(r"^[SMTWF][a-z][a-z], (\d\d) ([JFMASOND][a-z][a-z]) "
                            r"(\d\d\d\d) (\d\d):(\d\d):(\d\d) GMT$", re.ASCII)
WEEKDAY_RE = re.compile(r"^(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat)[a-z]*,?\s*", re.I | re.ASCII)
LOOSE_HTTP_DATE_RE = re.compile(r"""^(\d\d?)(?:\s+|[-\/])(\w+)(?:\s+|[-\/])
    (\d+)             
    (?:
          (?:\s+|:)   
       (\d\d?):(\d\d)  
       (?::(\d\d))?    
    )?                 
       \s*
    (?:
       ([-+]?\d{2,4}|(?![APap][Mm]\b)[A-Za-z]+)
       \s*
    )?
    (?:
       \(\w+\)       
       \s*
    )?$""", re.X | re.ASCII)


def http2time(text):
    m = STRICT_DATE_RE.search(text)
    if m:
        g = m.groups()
        mon = MONTHS_LOWER.index(g[1].lower()) + 1
        tt = (int(g[2]), mon, int(g[0]),
              int(g[3]), int(g[4]), float(g[5]))
        return _timegm(tt)

    text = text.lstrip()
    text = WEEKDAY_RE.sub("", text, 1)

    day, mon, yr, hr, min, sec, tz = [None] * 7

    m = LOOSE_HTTP_DATE_RE.search(text)  # 松散regexp解析
    if m is not None:
        day, mon, yr, hr, min, sec, tz = m.groups()
    else:
        return None
    return _str2time(day, mon, yr, hr, min, sec, tz)


# 头部处理部分！
def unmatched(match):
    start, end = match.span(0)
    return match.string[:start] + match.string[end:]


HEADER_TOKEN_RE = re.compile(r"^\s*([^=\s;,]+)")
HEADER_QUOTED_VALUE_RE = re.compile(r"^\s*=\s*\"([^\"\\]*(?:\\.[^\"\\]*)*)\"")
HEADER_VALUE_RE = re.compile(r"^\s*=\s*([^\s;,]*)")
HEADER_ESCAPE_RE = re.compile(r"\\(.)")


def split_header_words(header_values):  # 将头部解析为包含键和值对的列表列表。
    assert not isinstance(header_values, str)
    result = []
    for text in header_values:
        orig_text = text
        pairs = []
        while text:
            m = HEADER_TOKEN_RE.search(text)
            if m:
                text = unmatched(m)
                name = m.group(1)
                m = HEADER_QUOTED_VALUE_RE.search(text)
                if m:  # quoted value
                    text = unmatched(m)
                    value = m.group(1)
                    value = HEADER_ESCAPE_RE.sub(r"\1", value)
                else:
                    m = HEADER_VALUE_RE.search(text)
                    if m:  # unquoted value
                        text = unmatched(m)
                        value = m.group(1)
                        value = value.rstrip()
                    else:
                        value = None
                pairs.append((name, value))
            elif text.lstrip().startswith(","):
                text = text.lstrip()[1:]
                if pairs: result.append(pairs)
                pairs = []
            else:
                non_junk, nr_junk_chars = re.subn(r"^[=\s;]*", "", text)
                assert nr_junk_chars > 0, (
                        "split_header_words bug: '%s', '%s', %s" %
                        (orig_text, text, pairs))
                text = non_junk
        if pairs: result.append(pairs)
    return result


HEADER_JOIN_ESCAPE_RE = re.compile(r"([\"\\])")


def join_header_words(lists):  # 获取键值对的列表，并生成头部。
    headers = []
    for pairs in lists:
        attr = []
        for k, v in pairs:
            if v is not None:
                if not re.search(r"^\w+$", v):
                    v = HEADER_JOIN_ESCAPE_RE.sub(r"\\\1", v)  # escape " and \
                    v = '"%s"' % v
                k = "%s=%s" % (k, v)
            attr.append(k)
        if attr: headers.append("; ".join(attr))
    return ", ".join(headers)


def strip_quotes(text):
    if text.startswith('"'):
        text = text[1:]
    if text.endswith('"'):
        text = text[:-1]
    return text


def parse_ns_headers(ns_headers):
    known_attrs = ("expires", "domain", "path", "secure",
                   # RFC 2109 attrs (may turn up in Netscape cookies, too)
                   "version", "port", "max-age")

    result = []
    for ns_header in ns_headers:
        pairs = []
        version_set = False
        for ii, param in enumerate(ns_header.split(';')):
            param = param.strip()

            key, sep, val = param.partition('=')
            key = key.strip()

            if not key:
                if ii == 0:
                    break
                else:
                    continue

            val = val.strip() if sep else None

            if ii != 0:
                lc = key.lower()
                if lc in known_attrs:
                    key = lc

                if key == "version":
                    if val is not None:
                        val = strip_quotes(val)
                    version_set = True
                elif key == "expires":
                    if val is not None:
                        val = http2time(strip_quotes(val))  # None if invalid
            pairs.append((key, val))

        if pairs:
            if not version_set:
                pairs.append(("version", "0"))
            result.append(pairs)

    return result


IPV4_RE = re.compile(r"\.\d+$", re.ASCII)


def is_HDN(text):
    if IPV4_RE.search(text):
        return False
    if text == "":
        return False
    if text[0] == "." or text[-1] == ".":
        return False
    return True


def domain_match(A, B):  # 有相同的域名或IP
    A = A.lower()
    B = B.lower()
    if A == B:
        return True
    if not is_HDN(A):
        return False
    i = A.rfind(B)
    if i == -1 or i == 0:
        # A does not have form NB, or N is the empty string
        return False
    if not B.startswith("."):
        return False
    if not is_HDN(B[1:]):
        return False
    return True


def liberal_is_HDN(text):
    if IPV4_RE.search(text):
        return False
    return True


def user_domain_match(A, B):  # 有相同的域名或IP
    A = A.lower()
    B = B.lower()
    if not (liberal_is_HDN(A) and liberal_is_HDN(B)):
        if A == B:
            # equal IP addresses
            return True
        return False
    initial_dot = B.startswith(".")
    if initial_dot and A.endswith(B):
        return True
    if not initial_dot and A == B:
        return True
    return False


cut_port_re = re.compile(r":\d+$", re.ASCII)


def request_host(request):  # 返回请求的主机
    url = request.get_full_url()
    host = urllib.parse.urlparse(url)[1]
    if host == "":
        host = request.get_header("Host", "")

    # remove port, if present
    host = cut_port_re.sub("", host, 1)
    return host.lower()


def eff_request_host(request):  # 返回请求主机和有效主机名
    erhn = req_host = request_host(request)
    if req_host.find(".") == -1 and not IPV4_RE.search(req_host):
        erhn = req_host + ".local"
    return req_host, erhn


def request_path(request):  # 返回请求的路径
    url = request.get_full_url()
    parts = urllib.parse.urlsplit(url)
    path = escape_path(parts.path)
    if not path.startswith("/"):
        path = "/" + path
    return path


def request_port(request):  # 返回请求的端口
    host = request.host
    i = host.find(':')
    if i >= 0:
        port = host[i + 1:]
        try:
            int(port)
        except ValueError:
            print("error port: '%s'", port)
            return None
    else:
        port = str(http.client.HTTP_PORT)
    return port


def uppercase_escaped_char(match):
    return "%%%s" % match.group(1).upper()


def escape_path(path):
    path = urllib.parse.quote(path, "%/;:@&=+$,!~*'()")  # HTTP path
    path = re.compile(r"%([0-9a-fA-F][0-9a-fA-F])").sub(uppercase_escaped_char, path)
    return path
