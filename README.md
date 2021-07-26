# Django-Runserve-

## 引言

python manage.py runserver  是 使用python django框架进行开发时我们经常在命令行中敲击的命令，这个命令可以快速在本地启动django服务。

## 代码解读
###### ps: django 2.2.6

#### ●Step1


~~~python
import os
import sys


def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'testrunsever.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
~~~

~~~python
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "testrunsever.settings")
~~~

- 这里是设置了环境变量，指定"DJANGO_SETTINGS_MODULE"的值为 "testrunsever.settings"，目的是指定django的配置文件路径。

#### ●Step2

~~~python
execute_from_command_line(sys.argv)
~~~

- sys.argv是一个由命令行指令"python"之后的指令组成的一个列表，比如现在这里是['manage.py', 'runserver']

~~~python
def execute_from_command_line(argv=None):
    """Run a ManagementUtility."""  命令管理工具
    utility = ManagementUtility(argv)
    utility.execute()
~~~

- ManagementUtility封装了django admin and manage.py实用程序的逻辑，对于参数列表会进行一个简单的初始化。

####  ●Step3

~~~python
    def execute(self):
        """
        Given the command-line arguments, figure out which subcommand is being
        run, create a parser appropriate to that command, and run it.
        """
        try:
            subcommand = self.argv[1]
        except IndexError:
            subcommand = 'help'  # Display help if no arguments were given.

        # Preprocess options to extract --settings and --pythonpath.
        # These options could affect the commands that are available, so they
        # must be processed early.
        parser = CommandParser(usage='%(prog)s subcommand [options] [args]', add_help=False, allow_abbrev=False)
        parser.add_argument('--settings')
        parser.add_argument('--pythonpath')
        parser.add_argument('args', nargs='*')  # catch-all
~~~

- 这个函数主要处理子命令的执行，这里的子命令是相对于django-admin.py和manage.py的，举个例子：python manage.py runserver这里的runserver就是子命令。
- CommandParser这个类是对`ArgumentParser`的继承封装，而`ArgumentParser`是python基础类包中的一个类，这个函数的目的是将`ArgumentParser`封装成符合django内部调用的接口形式。接着对对诸如--settings和--pythonpath等参数进行抽取，预处理。因为这些的设置会影响其他参数的运行。<https://docs.python.org/2/library/argparse.html>  
argparse模块使编写用户友好的命令行界面变得容易。该程序定义了所需的参数，而argparse将找出如何从sys.argv中解析这些参数。 argparse模块还会自动生成帮助和使用消息，并在用户为程序提供无效参数时发出错误。

```python
	try:
	    options, args = parser.parse_known_args(self.argv[2:])
	    handle_default_options(options)
	except CommandError:
	    pass  # Ignore any option errors at this point.
	        
```

- parse\_known\_args的工作方式与parse_args非常相似，只是在存在额外参数时不会产生错误。它返回一个包含填充命名空间和剩余参数字符串列表的两项元组。也就是说，这个函数将当前脚本需要命令参数和其他脚本所需的命令行进行分离，它的返回结果是一个tuple，包含一个填充好的命名空间和剩余的参数字符串列表（parse\_known\_args函数里args里args参数为空列表）。这里的options的值为Namespace(args=[], pythonpath=None, settings=None)，args的值为ManagementUtility对象。  
python path: <https://code.djangoproject.com/wiki/PythonPath>  

- handle\_default\_options(options)实现了两个功能:
（1）如果options中包含`setting`则配置环境变量；（2）如果options中包含`pythonpath`则设置python模块的搜索路径。

```python
try:
            settings.INSTALLED_APPS
        except ImproperlyConfigured as exc:
            self.settings_exception = exc
        except ImportError as exc:
            self.settings_exception = exc

        if settings.configured:
            # Start the auto-reloading dev server even if the code is broken.
            # The hardcoded condition is a code smell but we can't rely on a
            # flag on the command class because we haven't located it yet.
            if subcommand == 'runserver' and '--noreload' not in self.argv:
                try:
                    autoreload.check_errors(django.setup)()
                except Exception:
                    # The exception will be raised later in the child process
                    # started by the autoreloader. Pretend it didn't happen by
                    # loading an empty list of applications.
                    apps.all_models = defaultdict(OrderedDict)
                    apps.app_configs = OrderedDict()
                    apps.apps_ready = apps.models_ready = apps.ready = True

                    # Remove options not compatible with the built-in runserver
                    # (e.g. options for the contrib.staticfiles' runserver).
                    # Changes here require manually testing as described in
                    # #27522.
                    _parser = self.fetch_command('runserver').create_parser('django', 'runserver')
                    _options, _args = _parser.parse_known_args(self.argv[2:])
                    for _arg in _args:
                        self.argv.remove(_arg)

            # In all other cases, django.setup() is required to succeed.
            else:
                django.setup()
```

- autoreload.check_errors()，一个装饰器函数，用来检查捕捉一些错误.
    
```python
def setup(set_prefix=True):
    """
    Configure the settings (this happens as a side effect of accessing the
    first setting), configure logging and populate the app registry.
    Set the thread-local urlresolvers script prefix if `set_prefix` is True.
    """
    from django.apps import apps
    from django.conf import settings
    from django.urls import set_script_prefix
    from django.utils.log import configure_logging

    configure_logging(settings.LOGGING_CONFIG, settings.LOGGING)
    if set_prefix:
        set_script_prefix(
            '/' if settings.FORCE_SCRIPT_NAME is None else settings.FORCE_SCRIPT_NAME
        )
    apps.populate(settings.INSTALLED_APPS)
```
- 负责初始化日志模块以及所有应用配置设置，配置日志记录并填充应用程序注册表。  
apps.populate(settings.INSTALLED_APPS)，加载应用程序配置和模型。  

- app_config = AppConfig.create(Aentry)生成了一个AppConfig实例，self.app_configs[app_config.label] = app_config将所有的app实例放到一个order_dict中维护。
- app\_config.import\_models()分别导入所有app的model
- app_config.ready() 初始app配置，每一个app模块中都有重写这个方法，所以django源码中这个方法没有代码。

```python
self.autocomplete()
```

- self.autocomplete()这个函数主要的功能是通过BASH去输出执行建议,通常可以忽略。

```python

        if subcommand == 'help':
            if '--commands' in args:
                sys.stdout.write(self.main_help_text(commands_only=True) + '\n')
            elif not options.args:
                sys.stdout.write(self.main_help_text() + '\n')
            else:
                self.fetch_command(options.args[0]).print_help(self.prog_name, options.args[0])
        # Special-cases: We want 'django-admin --version' and
        # 'django-admin --help' to work, for backwards compatibility.
        elif subcommand == 'version' or self.argv[1:] == ['--version']:
            sys.stdout.write(django.get_version() + '\n')
        elif self.argv[1:] in (['--help'], ['-h']):
            sys.stdout.write(self.main_help_text() + '\n')
        else:
            self.fetch_command(subcommand).run_from_argv(self.argv)
```

- 第一步是会根据subcommand（runserver），去django.core.management.commands中查找对应的command类，其次是将命令参数作为参数传递给执行函数执行(run\_from\_argv(self.argv))。  


```python
        def fetch_command(self, subcommand):
        """
        Try to fetch the given subcommand, printing a message with the
        appropriate command called from the command line (usually
        "django-admin" or "manage.py") if it can't be found.
        """
        # Get commands outside of try block to prevent swallowing exceptions
        commands = get_commands()  # app名称与模块映射字典，字典的key是app名称，value是这个命令实现所在的文件路径。
        try:
            app_name = commands[subcommand]  # 获取命令名称所在的路径或者实例
        except KeyError:
            if os.environ.get('DJANGO_SETTINGS_MODULE'):
                # If `subcommand` is missing due to misconfigured settings, the
                # following line will retrigger an ImproperlyConfigured exception
                # (get_commands() swallows the original one) so the user is
                # informed about it.
                settings.INSTALLED_APPS
            else:
                sys.stderr.write("No Django settings specified.\n")
            possible_matches = get_close_matches(subcommand, commands)
            sys.stderr.write('Unknown command: %r' % subcommand)
            if possible_matches:
                sys.stderr.write('. Did you mean %s?' % possible_matches[0])
            sys.stderr.write("\nType '%s help' for usage.\n" % self.prog_name)
            sys.exit(1)
        if isinstance(app_name, BaseCommand):  # 判断app_name是否是基本命令的实例，还是命令的路径
            # If the command is already loaded, use it directly.
            klass = app_name
        else:
            klass = load_command_class(app_name, subcommand)  # 如果是路径则导入该命令
        return klass  # 将命令的实例化对象返回
```

- self.fetch_command()这个函数完成的功能是，是利用django内置的命令管理工具去匹配到具体的模块，例如self.fetch\_command(subcommand)其实就相当于是self.fetch\_command(‘runserver’)，它最终找到了django.contrib.staticfiles.management.commands.runserver.Command这个命令工具。  
- django中的命令工具代码组织采用的是策略模式+接口模式，也就是说django.core.management.commands这个目录下面存在各种命令工具，每个工具下面都有一个Command接口，当匹配到’runserver’时调用’runserver’命令工具的Command接口，当匹配到’migrate’时调用’migrate’命令工具的Command接口。

```python
      def run_from_argv(self, argv):
        """
        Set up any environment changes requested (e.g., Python path
        and Django settings), then run this command. If the
        command raises a ``CommandError``, intercept it and print it sensibly
        to stderr. If the ``--traceback`` option is present or the raised
        ``Exception`` is not ``CommandError``, raise it.
        """
        self._called_from_command_line = True
        parser = self.create_parser(argv[0], argv[1]) # 还是生成一个命令解析器
		  
		 # options:Namespace(addrport='0.0.0.0:8001', insecure_serving=False, no_color=False,   
		 pythonpath=None, settings=None, traceback=False, use_ipv6=False, use_reloader=True,  
		  use_static_handler=True, use_threading=True, verbosity=1)  
		  
        options = parser.parse_args(argv[2:])
        cmd_options = vars(options) # 根据options生成配置信息的字典
        # Move positional args out of options to mimic legacy optparse
        args = cmd_options.pop('args', ())
        handle_default_options(options)  # 设置默认参数  DJANGO_SETTINGS_MODULE and Python path
        try:
            self.execute(*args, **cmd_options)
        except Exception as e:
            if options.traceback or not isinstance(e, CommandError):
                raise

            # SystemCheckError takes care of its own formatting.
            if isinstance(e, SystemCheckError):
                self.stderr.write(str(e), lambda x: x)
            else:
                self.stderr.write('%s: %s' % (e.__class__.__name__, e))
            sys.exit(1)
        finally:
            try:
                connections.close_all()
            except ImproperlyConfigured:
                # Ignore if connections aren't setup at this point (e.g. no
                # configured settings).
                pass
```


- run\_from\_argv()这个函数的作用就是设置好环境变量，然后取运行指令。其中默认启动在127.0.0.1:8000端口就在此函数中实现的。


```python
      def handle(self, *args, **options):
        if not settings.DEBUG and not settings.ALLOWED_HOSTS:
            raise CommandError('You must set settings.ALLOWED_HOSTS if DEBUG is False.')

        self.use_ipv6 = options['use_ipv6']  # 检查输入参数中是否是ipv6格式，检查当前python是否支持ipv6
        if self.use_ipv6 and not socket.has_ipv6:
            raise CommandError('Your Python does not support IPv6.')
        self._raw_ipv6 = False
        if not options['addrport']:  # 如果输入参数中没有输入端口则使用默认的端口
            self.addr = ''
            self.port = self.default_port  # 默认端口 8000
        else:
            m = re.match(naiveip_re, options['addrport'])
            if m is None:
                raise CommandError('"%s" is not a valid port number '
                                   'or address:port pair.' % options['addrport'])
            self.addr, _ipv4, _ipv6, _fqdn, self.port = m.groups()
            if not self.port.isdigit():
                raise CommandError("%r is not a valid port number." % self.port)
            if self.addr:
                if _ipv6:
                    self.addr = self.addr[1:-1]
                    self.use_ipv6 = True
                    self._raw_ipv6 = True
                elif self.use_ipv6 and not _fqdn:
                    raise CommandError('"%s" is not a valid IPv6 address.' % self.addr)
        if not self.addr:
            self.addr = self.default_addr_ipv6 if self.use_ipv6 else self.default_addr
            self._raw_ipv6 = self.use_ipv6
        self.run(**options)
```
- 服务的地址与端口配置。  
 
     
```python
	  def restart_with_reloader():
	    new_environ = {**os.environ, DJANGO_AUTORELOAD_ENV: 'true'}
	    args = get_child_arguments()  # args ["可执行的python的文件地址", "manage.py", "runserver"]
	    while True:
	    	 # 创建一个子进程，p.wait(timeout=timeout)的作用是主进程会等待子进程结束后才继续执行
	        exit_code = subprocess.call(args, env=new_environ, close_fds=False) 
	        if exit_code != 3:
	            return exit_cod
```

- 利用 python manage.py runserver启动一个新进程，并在这个进程中的环境变量中添加RUN_MAIN=true, subprocess.call会阻塞并一直等待进程退出并返回exit\_code。   


```python
	 def start_django(reloader, main_func, *args, **kwargs):
	    ensure_echo_on()
	
	    main_func = check_errors(main_func)
	    django_main_thread = threading.Thread(target=main_func, args=args, kwargs=kwargs, name='django-main-thread')
	    django_main_thread.setDaemon(True)
	    django_main_thread.start()
	
	    while not reloader.should_stop:
	        try:
	            reloader.run(django_main_thread) # 比较项目文件是否更改
	        except WatchmanUnavailable as ex:
	            # It's possible that the watchman service shuts down or otherwise
	            # becomes unavailable. In that case, use the StatReloader.
	            reloader = StatReloader()
	            logger.error('Error connecting to Watchman: %s', ex)
	            logger.info('Watching for file changes with %s', reloader.__class__.__name__)
```
- 在子进程中开启一个django服务主线程，之后所有的django服务都是在这个线程中执行。  
- django 程序启动的时候，会启动两个进程（不是线程），在子进程上，监听文件是否被修改,若修改的话，退出当前进程，并返回exit_code=3
- 比较项目代码是否更改的原理是：遍历项目所有文件状态的最后修改时间和上一次时间做对比，将文件名称作为key在上次修改时间记录dict中查询，然后使用本次时间比较上次时间，就可以知道文件是否被修改

```python
	  def inner_run(self, *args, **options):
        # If an exception was silenced in ManagementUtility.execute in order
        # to be raised in the child process, raise it now.
        autoreload.raise_last_exception()

        threading = options['use_threading']  # 是否开启多线程模式，当不传入时则默认为多线程模式运行
        # 'shutdown_message' is a stealth option.
        shutdown_message = options.get('shutdown_message', '')
        quit_command = 'CTRL-BREAK' if sys.platform == 'win32' else 'CONTROL-C'  # 打印停止服务信息

        self.stdout.write("Performing system checks...\n\n")
        self.check(display_num_errors=True) # 使用系统框架进行django项目检查，如果有严重错误则抛出commandError,反之将警告打印
        # Need to check migrations here, so can't use the
        # requires_migrations_check attribute.
        self.check_migrations() # 检查是否migrations是否与数据库一致
        now = datetime.now().strftime('%B %d, %Y - %X')
        self.stdout.write(now) # 打印时间信息
        self.stdout.write((
            "Django version %(version)s, using settings %(settings)r\n"
            "Starting development server at %(protocol)s://%(addr)s:%(port)s/\n"
            "Quit the server with %(quit_command)s.\n"
        ) % {
            "version": self.get_version(),
            "settings": settings.SETTINGS_MODULE,
            "protocol": self.protocol,
            "addr": '[%s]' % self.addr if self._raw_ipv6 else self.addr,
            "port": self.port,
            "quit_command": quit_command,
        })

        try:
            handler = self.get_handler(*args, **options) # 获取信息处理的handler,返回StaticFilesHandler
            run(self.addr, int(self.port), handler,
                ipv6=self.use_ipv6, threading=threading, server_cls=self.server_cls)  # 调用运行函数
        except socket.error as e:
            # Use helpful error messages instead of ugly tracebacks.
            ERRORS = {
                errno.EACCES: "You don't have permission to access that port.",
                errno.EADDRINUSE: "That port is already in use.",
                errno.EADDRNOTAVAIL: "That IP address can't be assigned to.",
            }
            try:
                error_text = ERRORS[e.errno]
            except KeyError:
                error_text = e
            self.stderr.write("Error: %s" % error_text)
            # Need to use an OS exit because sys.exit doesn't work in a thread
            os._exit(1)
        except KeyboardInterrupt:
            if shutdown_message:
                self.stdout.write(shutdown_message)
            sys.exit(0)
```
handler = self.get_handler(*args, **options)  

- 它负责获取WSGIHandler。
- self.get_handler并不会返回一个常规的WSGIHandler而是返回一个StaticFilesHandler。
- StaticFilesHandler类对象继承WSGIHandler，它的目的是为了判断每个请求，如果是常规的url请求则直接分配到某个view中去执行，如果是静态文件规则那么将不会找view而是响应这个文件。
- 在DEBUG=False的场景下返回的是一个普通的Handler,这就会导致无法访问静态文件

```python
def run(addr, port, wsgi_handler, ipv6=False, threading=False, server_cls=WSGIServer):
    server_address = (addr, port)
    if threading:
    	 # 生成一个继承自socketserver.ThreadingMixIn, WSGIServer的类
        httpd_cls = type('WSGIServer', (socketserver.ThreadingMixIn, server_cls), {})
    else:
        httpd_cls = server_cls
    httpd = httpd_cls(server_address, WSGIRequestHandler, ipv6=ipv6) # 实例化该类
    if threading:
        # ThreadingMixIn.daemon_threads indicates how threads will behave on an
        # abrupt shutdown; like quitting the server by the user or restarting
        # by the auto-reloader. True means the server will not wait for thread
        # termination before it quits. This will make auto-reloader faster
        # and will prevent the need to kill the server manually if a thread
        # isn't terminating correctly.
        # ThreadingMixIn.daemon_threads表示线程在突然关闭时的行为方式;
        # 比如用户退出服务器或通过自动重新加载器重新启动。
        # True表示服务器在退出之前不会等待线程终止。
        # 这将使自动重新加载器更快，并且如果线程没有正确终止，将防止需要手动终止服务器。
        httpd.daemon_threads = True # True表示服务器在退出之前不会等待线程终止
    httpd.set_app(wsgi_handler)
    httpd.serve_forever()

```
- httpd\_cls = type(‘WSGIServer’, (socketserver.ThreadingMixIn, server\_cls), {}) 是一种很特殊的写法，通过代码块中WSGIServer类对象可以看出它只继承了wsgiref.simple\_server.WSGIServer、object这两个类对象，但是通过type这种写法相当于是强行赋予它一个socketserver.ThreadingMixIn继承对象，它的用意是每次调用这个对象的时候都会单独启用一个线程来处理。  

- httpd = httpd_cls(server\_address, WSGIRequestHandler, ipv6=ipv6)这行代码非常重要，因为它是WSGI服务器与django之间相互通信的唯一枢纽通道，也就是说，当WSGI服务对象收到socket请求后，会将这个请求传递给django的WSGIRequestHandler。
- httpd.set\_app(wsgi\_handler)是将django.contrib.staticfiles.handlers.StaticFilesHandler 传递给WSGIServer当作一个application，当WSGIServer收到网络请求后，可以将数据分发给django.core.servers.basehttp.WSGIRequestHandler，最终由django.core.servers.basehttp.WSGIRequestHandler将数据传递给application(即：django.contrib.staticfiles.handlers.StaticFilesHandler)。
httpd.serve.forever()启动非堵塞网络监听服务。


