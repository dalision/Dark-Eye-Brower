import email.parser
import email.message
import http
import io
import re
import socket
import collections.abc
from urllib.parse import urlsplit

__all__ = ["HTTPResponse", "HTTPConnection",
           "HTTPException", "NotConnected", "UnknownProtocol",
           "UnknownTransferEncoding", "UnimplementedFileMode",
           "IncompleteRead", "InvalidURL", "ImproperConnectionState",
           "CannotSendRequest", "CannotSendHeader", "ResponseNotReady",
           "BadStatusLine", "LineTooLong", "RemoteDisconnected", "error",
           "responses"]

HTTP_PORT = 80
HTTPS_PORT = 443

_UNKNOWN = 'UNKNOWN'

_CS_IDLE = 'Idle'
_CS_REQ_STARTED = 'Request-started'
_CS_REQ_SENT = 'Request-sent'
_MAXLINE = 65536
_MAXHEADERS = 100

CONTINUE = 100

# 这里负责状态码的转换
responses = {v: v.phrase for v in http.HTTPStatus.__members__.values()}

_is_legal_header_name = re.compile(rb'[^:\s][^:\r\n]*').fullmatch
_is_illegal_header_value = re.compile(rb'\n(?![ \t])|\r(?![ \t\n])').search
_contains_disallowed_url_pchar_re = re.compile('[\x00-\x20\x7f]')

_METHODS_EXPECTING_BODY = {'POST', 'PUT'}


class HTTPResponse(io.BufferedIOBase):
    """
    接收的是文本流的基类,用于处理字节表示的基类
    httpResponse是从服务器端返回的response实例
    """
    def __init__(self, sock, debuglevel=0, method=None, url=None):
        self.fp = sock.makefile("rb")  # 返回的是二进制只读的文件对象
        self.debuglevel = debuglevel
        self._method = method

        self.headers = self.msg = None

        # 通过响应的状态栏得到的
        self.version = _UNKNOWN  # HTTP版本
        self.status = _UNKNOWN  # 状态吗
        self.reason = _UNKNOWN

        self.chunked = _UNKNOWN         # 是否使用块编码
        self.chunk_left = _UNKNOWN      # bytes left to read in current chunk
        self.length = _UNKNOWN          # 响应中剩余的字节数
        self.will_close = _UNKNOWN      # 是否获取后关闭链接

    def _read_status(self):
        line = str(self.fp.readline(_MAXLINE + 1), "iso-8859-1")
        if len(line) > _MAXLINE:
            raise LineTooLong("status line")
        if self.debuglevel > 0:
            print("reply:", repr(line))
        if not line:
            raise RemoteDisconnected("Remote end closed connection without"
                                     " response")
        try:
            version, status, reason = line.split(None, 2)
        except ValueError:
            try:
                version, status = line.split(None, 1)
                reason = ""
            except ValueError:
                # empty version will cause next test to fail.
                version = ""
        if not version.startswith("HTTP/"):
            self._close_conn()
            raise BadStatusLine(line)

        # The status code is a three-digit number
        try:
            status = int(status)
            if status < 100 or status > 999:
                raise BadStatusLine(line)
        except ValueError:
            raise BadStatusLine(line)
        return version, status, reason

    def begin(self):
        """获取响应中提供的基本信息：状态行以及首部
        """
        if self.headers is not None:
            return
        # 直到遇到一个非100的状态码，状态码为100意味着服务器收到了请求的初始部分并请客户端继续发送，收到完整内容后进行响应
        # 事实上，只有当客户端想要往服务器端发送一个大文件时，才会首先向服务器发送一条expect 100的请求语句询问服务器是否可以处理，此时若服务器返回100 continue则客户端继续发送文件内容。
        while True:
            version, status, reason = self._read_status()
            if status != CONTINUE:
                break
            # 如果status为100，则跳过对头部的阅读
            while True:
                skip = self.fp.readline(_MAXLINE + 1)
                if len(skip) > _MAXLINE:
                    raise LineTooLong("header line")
                skip = skip.strip()
                if not skip:
                    break
                if self.debuglevel > 0:
                    print("header:", skip)

        self.code = self.status = status
        self.reason = reason.strip()
        if version in ("HTTP/1.0", "HTTP/0.9"):
            self.version = 10
        elif version.startswith("HTTP/1."):
            self.version = 11   # use HTTP/1.1 code for HTTP/1.x where x>=1
        else:
            raise UnknownProtocol(version)

        self.headers = self.msg = parse_headers(self.fp)

        if self.debuglevel > 0:
            for hdr, val in self.headers.items():
                print("header:", hdr + ":", val)
        # 查看transfer encoding是否为chunked
        tr_enc = self.headers.get("transfer-encoding")
        if tr_enc and tr_enc.lower() == "chunked":
            self.chunked = True
            self.chunk_left = None
        else:
            self.chunked = False

        # 查看响应结束后是否关闭连接
        self.will_close = self._check_close()

        self.length = None
        length = self.headers.get("content-length")

        # 如果没有用块编码的话就要确定内容的大小
        tr_enc = self.headers.get("transfer-encoding")
        if length and not self.chunked:
            try:
                self.length = int(length)
            except ValueError:
                self.length = None
            else:
                if self.length < 0:  # ignore nonsensical negative lengths
                    self.length = None
        else:
            self.length = None

        # 如果will_close、chunked以及length均为否定则认为连接要关闭
        if (not self.will_close and not self.chunked and self.length is None):
            self.will_close = True

    def _check_close(self):
        conn = self.headers.get("connection")
        if self.version == 11:
            if conn and "close" in conn.lower():
                return True
            return False

        # 对于老的http协议，Keep-Alive意味着持续链接
        if self.headers.get("keep-alive"):
            return False

        if conn and "keep-alive" in conn.lower():
            return False

        return True

    def _close_conn(self):
        """关闭套接字"""
        fp = self.fp
        self.fp = None
        fp.close()

    def close(self):
        try:
            super().close()  # set "closed" flag
        finally:
            if self.fp:
                self._close_conn()

    def isclosed(self):
        """True if the connection is closed."""
        return self.fp is None

    def read(self, amt=None):
        """读取响应中的内容，并以字节的形式返回"""
        if self.fp is None:
            return b""

        if self._method == "HEAD":
            self._close_conn()
            return b""

        if amt is not None:
            # 指定需要阅读的字节数则使用readinto方法
            b = bytearray(amt)  # 返回一个amt大小的字节数组，b可以看作为一个缓冲区
            n = self.readinto(b)  # 将amt大小的字节放入字节数组中，并返回实际读取的字节数
            # memoryview内置函数会返回一个内存视图的对象，类似于指针，可以不用将内容复制出来而直接访问（修改）
            return memoryview(b)[:n].tobytes()
        else:
            # 并没有给定需要阅读的字节数
            if self.chunked:
                return self._readall_chunked()

            if self.length is None:
                s = self.fp.read()
            else:
                try:
                    s = self._safe_read(self.length)
                except IncompleteRead:
                    self._close_conn()
                    raise
                self.length = 0
            self._close_conn()        # 这里默认读取了响应主体的全部内容
            return s

    def _read_next_chunk_size(self):
        line = self.fp.readline(_MAXLINE + 1)
        if len(line) > _MAXLINE:
            raise LineTooLong("chunk size")
        i = line.find(b";")
        if i >= 0:
            line = line[:i] # strip chunk-extensions
        try:
            return int(line, 16)
        except ValueError:
            self._close_conn()
            raise

    def _read_and_discard_trailer(self):
        while True:
            line = self.fp.readline(_MAXLINE + 1)
            if len(line) > _MAXLINE:
                raise LineTooLong("trailer line")
            if not line:
                # a vanishingly small number of sites EOF without
                # sending the trailer
                break
            if line in (b'\r\n', b'\n', b''):
                break

    def _get_chunk_left(self):
        chunk_left = self.chunk_left
        if not chunk_left: # Can be 0 or None
            if chunk_left is not None:
                # We are at the end of chunk, discard chunk end
                self._safe_read(2)  # toss the CRLF at the end of the chunk
            try:
                chunk_left = self._read_next_chunk_size()
            except ValueError:
                raise IncompleteRead(b'')
            if chunk_left == 0:
                # last chunk: 1*("0") [ chunk-extension ] CRLF
                self._read_and_discard_trailer()
                # we read everything; close the "file"
                self._close_conn()
                chunk_left = None
            self.chunk_left = chunk_left
        return chunk_left

    def _readall_chunked(self):
        assert self.chunked != _UNKNOWN
        value = []
        try:
            while True:
                chunk_left = self._get_chunk_left()
                if chunk_left is None:
                    break
                value.append(self._safe_read(chunk_left))
                self.chunk_left = 0
            return b''.join(value)
        except IncompleteRead:
            raise IncompleteRead(b''.join(value))

    def _safe_read(self, amt):
        """阅读指定数量的内容"""
        data = self.fp.read(amt)
        if len(data) < amt:
            raise IncompleteRead(data, amt-len(data))
        return data

    def getheader(self, name, default=None):
        '''获取指定头部的key所对应的value
        '''
        if self.headers is None:
            raise ResponseNotReady()
        headers = self.headers.get_all(name) or default
        if isinstance(headers, str) or not hasattr(headers, '__iter__'):
            return headers
        else:
            return ', '.join(headers)

    def getheaders(self):
        """以远组形式获得响应头"""
        if self.headers is None:
            raise ResponseNotReady()
        return list(self.headers.items())


class HTTPConnection:
    # 实现http1.1协议的内容
    _http_vsn = 11
    _http_vsn_str = 'HTTP/1.1'

    response_class = HTTPResponse
    default_port = HTTP_PORT
    auto_open = 1
    debuglevel = 0  # 用于判断是否出现了错误

    @staticmethod
    def _is_textIO(stream):
        """判断文件是否为text对象或者二进制流的形式
        """
        return isinstance(stream, io.TextIOBase)

    @staticmethod
    def _get_content_length(body, method):
        if body is None:
            if method.upper() in _METHODS_EXPECTING_BODY:
                return 0
            else:
                return None
        if hasattr(body, 'read'):
            # 是否是一个文件类型，拥有read方法
            return None
        try:
            mv = memoryview(body)
            return mv.nbytes
        except TypeError:
            pass
        if isinstance(body, str):
            return len(body)
        return None

    def __init__(self, host, port=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 source_address=None, blocksize=8192):
        """host为服务器端的ip地址,port为服务器监听的端口
           source_address为客户端的地址
           timeout为响应超时时间
           blocksize为消息体的最大字节数
           __response存储的是上一个返回的响应
        """
        self.timeout = timeout
        self.source_address = source_address
        self.blocksize = blocksize
        self.sock = None
        self._buffer = []
        self.__response = None
        self.__state = _CS_IDLE
        self._method = None
        self._tunnel_host = None
        self._tunnel_port = None
        self._tunnel_headers = {}

        (self.host, self.port) = self._get_hostport(host, port)

        self._create_connection = socket.create_connection

    def set_tunnel(self, host, port=None, headers=None):
        """与服务器之间建立通信通道"""
        if self.sock:
            raise RuntimeError("Can't set up tunnel for established connection")

        self._tunnel_host, self._tunnel_port = self._get_hostport(host, port)
        if headers:
            self._tunnel_headers = headers
        else:
            self._tunnel_headers.clear()

    def _get_hostport(self, host, port):
        if port is None:
            i = host.rfind(':')
            j = host.rfind(']')         # ipv6 addresses have [...]
            if i > j:
                try:
                    port = int(host[i+1:])
                except ValueError:
                    if host[i+1:] == "":  # http://foo.com:/ == http://foo.com/
                        port = self.default_port
                    else:
                        raise InvalidURL("nonnumeric port: '%s'" % host[i+1:])
                host = host[:i]
            else:
                port = self.default_port
            if host and host[0] == '[' and host[-1] == ']':
                host = host[1:-1]

        return (host, port)

    def set_debuglevel(self, level):
        self.debuglevel = level

    def _tunnel(self):
        connect_str = "CONNECT %s:%d HTTP/1.0\r\n" % (self._tunnel_host, self._tunnel_port)
        connect_bytes = connect_str.encode("ascii")
        self.send(connect_bytes)
        for header, value in self._tunnel_headers.items():
            header_str = "%s: %s\r\n" % (header, value)
            header_bytes = header_str.encode("latin-1")
            self.send(header_bytes)
        self.send(b'\r\n')

        response = self.response_class(self.sock, method=self._method)
        (version, code, message) = response._read_status()

        if code != http.HTTPStatus.OK:
            self.close()
            raise OSError("Tunnel connection failed: %d %s" % (code,
                                                               message.strip()))
        while True:
            line = response.fp.readline(_MAXLINE + 1)
            if len(line) > _MAXLINE:
                raise LineTooLong("header line")
            if not line:
                # for sites which EOF without sending a trailer
                break
            if line in (b'\r\n', b'\n', b''):
                break

            if self.debuglevel > 0:
                print('header:', line.decode())

    def connect(self):
        """建立一个TCP socket的连接
           create_connection(addr)返回一个套接字对象，用于连接到一个监听地址addr的TCP服务。"""
        self.sock = self._create_connection(
            (self.host, self.port), self.timeout, self.source_address)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        if self._tunnel_host:
            self._tunnel()

    def close(self):
        """关闭与服务器端的连接"""
        self.__state = _CS_IDLE
        try:
            sock = self.sock
            if sock:
                self.sock = None
                sock.close()
        finally:
            response = self.__response
            if response:
                self.__response = None
                response.close()

    def send(self, data):
        """发送报文内容到服务器
           发送的内容（data）可以是字符串、字节对象、数组、文件对象或者可迭代的对象
        """

        if self.sock is None:
            if self.auto_open:
                self.connect()
            else:
                raise NotConnected()

        if self.debuglevel > 0:
            print("send:", repr(data))
        if hasattr(data, "read"):  # hasattr（object，name）用于判断对象是否有该属性
            if self.debuglevel > 0:
                print("sendIng a read()able")
            encode = self._is_textIO(data)
            if encode and self.debuglevel > 0:
                print("encoding file using iso-8859-1")
            while 1:
                datablock = data.read(self.blocksize)
                if not datablock:
                    break
                if encode:
                    datablock = datablock.encode("iso-8859-1")
                self.sock.sendall(datablock)
            return
        try:
            self.sock.sendall(data)
        except TypeError:
            if isinstance(data, collections.abc.Iterable):
                # 判断data是否为可迭代对象
                for d in data:
                    self.sock.sendall(d)
            else:
                raise TypeError("data should be a bytes-like object "
                                "or an iterable, got %r" % type(data))

    def _output(self, s):
        """向请求缓冲区中添加内容
        """
        self._buffer.append(s)

    def _read_readable(self, readable):
        if self.debuglevel > 0:
            print("sendIng a read()able")
        encode = self._is_textIO(readable)
        if encode and self.debuglevel > 0:
            print("encoding file using iso-8859-1")
        while True:
            datablock = readable.read(self.blocksize)
            if not datablock:
                break
            if encode:
                datablock = datablock.encode("iso-8859-1")
            yield datablock

    def _send_output(self, message_body=None, encode_chunked=False):
        """发送当前缓存中请求并清空缓存.在报文结尾加上额外的\r\n(回车)
        """
        self._buffer.extend((b"", b""))
        msg = b"\r\n".join(self._buffer)
        del self._buffer[:]
        self.send(msg)

        if message_body is not None:
            if hasattr(message_body, 'read'):
                # 对于文件类型，使用_read_readable()
                chunks = self._read_readable(message_body)
            else:
                try:
                    memoryview(message_body)
                except TypeError:
                    try:
                        chunks = iter(message_body)
                    except TypeError:
                        raise TypeError("message_body should be a bytes-like "
                                        "object or an iterable, got %r"
                                        % type(message_body))
                else:
                    chunks = (message_body,)

            for chunk in chunks:
                if not chunk:
                    if self.debuglevel > 0:
                        print('Zero length chunk ignored')
                    continue

                if encode_chunked and self._http_vsn == 11:
                    # chunked encoding
                    chunk = f'{len(chunk):X}\r\n'.encode('ascii') + bytes(chunk, encoding='ascii') + b'\r\n'
                self.send(chunk)

            if encode_chunked and self._http_vsn == 11:
                # end chunked transfer
                self.send(b'0\r\n\r\n')

    def putrequest(self, method, url, skip_host=False,
                   skip_accept_encoding=False):
        """首先向sever发送method，url和http version
        """
        # 首先如果上一次的响应已经完成则跳出等待响应的状态
        if self.__response and self.__response.isclosed():
            self.__response = None
        # 此时如果客户端处于空闲状态则进入发送请求的状态，如果客户端未空闲则无法发送新的请求
        if self.__state == _CS_IDLE:
            self.__state = _CS_REQ_STARTED
        else:
            raise CannotSendRequest(self.__state)

        self._method = method

        url = url or '/' # 若url为空则置为/
        # self._validate_path(url) 判断url是否合法
        self._validate_path(url)

        request = '%s %s %s' % (method, url, self._http_vsn_str)

        self._output(self._encode_request(request))

        if self._http_vsn == 11:
            # 如果服务器支持http1.1则数据会通过chunked的形式传输
            if not skip_host:
                netloc = ''
                if url.startswith('http'):
                    nil, netloc, nil, nil, nil = urlsplit(url)

                if netloc:
                    try:
                        netloc_enc = netloc.encode("ascii")
                    except UnicodeEncodeError:
                        netloc_enc = netloc.encode("idna")
                    self.putheader('Host', netloc_enc)
                else:
                    if self._tunnel_host:
                        host = self._tunnel_host
                        port = self._tunnel_port
                    else:
                        host = self.host
                        port = self.port

                    try:
                        host_enc = host.encode("ascii")
                    except UnicodeEncodeError:
                        host_enc = host.encode("idna")

                    if host.find(':') >= 0:
                        host_enc = b'[' + host_enc + b']'

                    if port == self.default_port:
                        self.putheader('Host', host_enc)
                    else:
                        host_enc = host_enc.decode("ascii")
                        self.putheader('Host', "%s:%s" % (host_enc, port))

            if not skip_accept_encoding:
                self.putheader('Accept-Encoding', 'identity')
        else:
            pass

    def _encode_request(self, request):
        # ASCII编码请求
        return request.encode('ascii')

    def _validate_path(self, url):
        """判断url是否合法"""
        match = _contains_disallowed_url_pchar_re.search(url)
        if match:
            raise InvalidURL(f"URL can't contain control characters. {url!r} "
                             f"(found at least {match.group()!r})")

    def putheader(self, header, *values):
        """将一个报文头传递给服务器，*values用于接收所对应的头部的信息，可以是多个值
         例如 h.putheader('Accept', 'text/html')
        """
        if self.__state != _CS_REQ_STARTED:
            raise CannotSendHeader()

        if hasattr(header, 'encode'):
            header = header.encode('ascii')

        if not _is_legal_header_name(header):
            raise ValueError('Invalid header name %r' % (header,))

        values = list(values)
        for i, one_value in enumerate(values):
            if hasattr(one_value, 'encode'):
                values[i] = one_value.encode('latin-1')
            elif isinstance(one_value, int):
                values[i] = str(one_value).encode('ascii')

            if _is_illegal_header_value(values[i]):
                raise ValueError('Invalid header value %r' % (values[i],))

        value = b'\r\n\t'.join(values)  # 在值的结尾加上转义字符：回到本行行首再换行（等同于回车）然后横向制表符tab
        header = header + b': ' + value
        self._output(header)

    def endheaders(self, message_body=None, *, encode_chunked=False):
        """发送一个空行表示头部的结束
        """
        if self.__state == _CS_REQ_STARTED:
            self.__state = _CS_REQ_SENT
        else:
            raise CannotSendHeader()
        self._send_output(message_body, encode_chunked=encode_chunked)

    def request(self, method, url, body=None, headers={}, *,
                encode_chunked=False):
        """发送请求到服务器"""
        self._send_request(method, url, body, headers, encode_chunked)

    def _send_request(self, method, url, body, headers, encode_chunked):
        # 根据请求中的目的地址以及头部中的Accept-Encoding发送请求
        header_names = frozenset(k.lower() for k in headers)
        skips = {}
        if 'host' in header_names:
            skips['skip_host'] = 1
        if 'accept-encoding' in header_names:
            skips['skip_accept_encoding'] = 1

        self.putrequest(method, url, **skips)
        # 这里需要注意：
        # http1.1中支持块通信，如果请求汇总指明使用块通信或者下列三个条件之一满足的都会使用块通信：
        # 没有明确发送内容的大小; 传输的内容是文件形式或者可迭代类型; transfer-encoding传输过程中的编码没有明确

        if 'content-length' not in header_names:
            if 'transfer-encoding' not in header_names:
                encode_chunked = False
                content_length = self._get_content_length(body, method)
                if content_length is None:
                    if body is not None:
                        if self.debuglevel > 0:
                            print('Unable to determine size of %r' % body)
                        encode_chunked = True
                        self.putheader('Transfer-Encoding', 'chunked')
                else:
                    self.putheader('Content-Length', str(content_length))
        else:
            encode_chunked = False

        for hdr, value in headers.items():
            self.putheader(hdr, value)
        if isinstance(body, str):
            body = _encode(body, 'body')
        self.endheaders(body, encode_chunked=encode_chunked)

    def getresponse(self):
        """获取httpresponse
           注意只有读取响应之后才可以再次发送请求给sever
        """
        if self.__response and self.__response.isclosed():
            self.__response = None

        if self.__state != _CS_REQ_SENT or self.__response:
            raise ResponseNotReady(self.__state)

        if self.debuglevel > 0:
            response = self.response_class(self.sock, self.debuglevel,
                                           method=self._method)
        else:
            response = self.response_class(self.sock, method=self._method)

        try:
            try:
                response.begin()
            except ConnectionError:
                self.close()
                raise
            assert response.will_close != _UNKNOWN
            self.__state = _CS_IDLE

            if response.will_close:
                self.close()
            else:
                self.__response = response

            return response
        except():
            response.close()
            raise


def _encode(data, name='data'):
    """Call data.encode("latin-1") but show a better error message."""
    try:
        return data.encode("latin-1")
    except UnicodeEncodeError as err:
        raise UnicodeEncodeError(
            err.encoding,
            err.object,
            err.start,
            err.end,
            "%s (%.20r) is not valid Latin-1. Use %s.encode('utf-8') "
            "if you want to send it encoded in UTF-8." %
            (name.title(), data[err.start:err.end], name)) from None


class HTTPMessage(email.message.Message):
    def getallmatchingheaders(self, name):
        name = name.lower() + ':'
        n = len(name)
        lst = []
        hit = 0
        for line in self.keys():
            if line[:n].lower() == name:
                hit = 1
            elif not line[:1].isspace():
                hit = 0
            if hit:
                lst.append(line)
        return lst


def parse_headers(fp, _class=HTTPMessage):
    headers = []
    while True:
        line = fp.readline(_MAXLINE + 1)
        if len(line) > _MAXLINE:
            raise LineTooLong("header line")
        headers.append(line)
        if len(headers) > _MAXHEADERS:
            raise HTTPException("got more than %d headers" % _MAXHEADERS)
        if line in (b'\r\n', b'\n', b''):
            break
    hstring = b''.join(headers).decode('iso-8859-1')
    return email.parser.Parser(_class=_class).parsestr(hstring)

    
class HTTPException(Exception):
    # Subclasses that define an __init__ must call Exception.__init__
    # or define self.args.  Otherwise, str() will fail.
    pass


class NotConnected(HTTPException):
    pass


class InvalidURL(HTTPException):
    pass


class UnknownProtocol(HTTPException):
    def __init__(self, version):
        self.args = version,
        self.version = version


class UnknownTransferEncoding(HTTPException):
    pass


class UnimplementedFileMode(HTTPException):
    pass


class IncompleteRead(HTTPException):
    def __init__(self, partial, expected=None):
        self.args = partial,
        self.partial = partial
        self.expected = expected

    def __repr__(self):
        if self.expected is not None:
            e = ', %i more expected' % self.expected
        else:
            e = ''
        return '%s(%i bytes read%s)' % (self.__class__.__name__,
                                        len(self.partial), e)
    __str__ = object.__str__


class ImproperConnectionState(HTTPException):
    pass


class CannotSendRequest(ImproperConnectionState):
    pass


class CannotSendHeader(ImproperConnectionState):
    pass


class ResponseNotReady(ImproperConnectionState):
    pass


class BadStatusLine(HTTPException):
    def __init__(self, line):
        if not line:
            line = repr(line)
        self.args = line,
        self.line = line


class LineTooLong(HTTPException):
    def __init__(self, line_type):
        HTTPException.__init__(self, "got more than %d bytes when reading %s"
                                     % (_MAXLINE, line_type))


class RemoteDisconnected(ConnectionResetError, BadStatusLine):
    def __init__(self, *pos, **kw):
        BadStatusLine.__init__(self, "")
        ConnectionResetError.__init__(self, *pos, **kw)


# for backwards compatibility
error = HTTPException
