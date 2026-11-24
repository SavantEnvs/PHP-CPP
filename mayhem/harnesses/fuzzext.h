/**
 *  fuzzext.h — shared scaffolding for the PHP-CPP fuzz harnesses.
 *
 *  PHP-CPP is a library for writing PHP extensions, so every harness defines a small test
 *  extension with it (classes with magic methods, ArrayAccess, Countable, Serializable, native
 *  functions) and runs inside the PHP embed SAPI (libphp). The extension is registered as a real
 *  startup module (php_module_startup's additional_module), so MINIT/RINIT/RSHUTDOWN all run.
 *
 *  State: every input runs in its own PHP request (php_request_shutdown + php_request_startup
 *  after each input), which resets userspace functions, classes, constants, globals and the
 *  error_reporting level. The only state kept across inputs is the module/class registration,
 *  which is fixed by this file and never changed by an input.
 *
 *  PHP reports fatal errors by zend_bailout() (a longjmp to the nearest zend_try); that is the
 *  engine's own error contract, so the harness catches it with zend_try like every embedder.
 */
#pragma once

#include <phpcpp.h>
#include <sapi/embed/php_embed.h>
#include <main/php_main.h>
#include <main/SAPI.h>
#include <Zend/zend_exceptions.h>

#include <map>
#include <string>
#include <cstdint>
#include <cstring>

/* the current fuzz input, readable from PHP through fuzz_input() */
static const uint8_t *g_fuzz_data = nullptr;
static size_t g_fuzz_size = 0;

/**
 *  Test class: magic methods, ArrayAccess, Countable and Serializable, all backed by a map.
 */
class FuzzObj : public Php::Base, public Php::ArrayAccess, public Php::Countable, public Php::Serializable
{
public:
    std::map<std::string, Php::Value> props;
    int64_t value = 0;

    void __construct(Php::Parameters &params) { if (!params.empty()) value = params[0].numericValue(); }
    Php::Value getValue() const { return value; }
    void setValue(Php::Parameters &params) { if (!params.empty()) value = params[0].numericValue(); }

    Php::Value __get(const Php::Value &key) const
    {
        auto it = props.find(key.stringValue());
        return it == props.end() ? Php::Value() : it->second;
    }
    void __set(const Php::Value &key, const Php::Value &v) { props[key.stringValue()] = v; }
    bool __isset(const Php::Value &key) const { return props.count(key.stringValue()) > 0; }
    void __unset(const Php::Value &key) { props.erase(key.stringValue()); }
    Php::Value __call(const char *method, Php::Parameters &params) const
    {
        Php::Value r(method);
        for (auto &p : params) r += p.stringValue();
        return r;
    }
    static Php::Value __callStatic(const char *method, Php::Parameters &params)
    {
        return (int64_t)params.size() + (int64_t)std::strlen(method);
    }
    // wrapping (unsigned) arithmetic: `value` is user-controlled, so test-extension code must not overflow
    Php::Value __invoke(Php::Parameters &params) const { return (int64_t)((uint64_t)params.size() + (uint64_t)value); }
    Php::Value __toString() const { return std::to_string(value); }
    Php::Value __toInteger() const { return value; }
    Php::Value __toFloat() const { return (double)value; }
    Php::Value __toBool() const { return value != 0; }
    int __compare(const FuzzObj &that) const { return value < that.value ? -1 : (value > that.value ? 1 : 0); }
    void __clone() { props["cloned"] = true; }

    // ArrayAccess
    bool offsetExists(const Php::Value &key) override { return props.count(key.stringValue()) > 0; }
    void offsetSet(const Php::Value &key, const Php::Value &v) override { props[key.stringValue()] = v; }
    Php::Value offsetGet(const Php::Value &key) override { return __get(key); }
    void offsetUnset(const Php::Value &key) override { props.erase(key.stringValue()); }

    // Countable
    long count() override { return (long)props.size(); }

    // Serializable
    std::string serialize() override { return std::to_string(value); }
    void unserialize(const char *input, size_t size) override
    {
        value = 0;
        uint64_t v = 0;   // wrapping (unsigned) so a long digit string cannot overflow in test-extension code
        for (size_t i = 0; i < size && input[i] >= '0' && input[i] <= '9'; i++) v = v * 10 + (uint64_t)(input[i] - '0');
        value = (int64_t)v;
    }
};

/** A class without any magic, to compare against */
class FuzzPlain : public Php::Base {};

/** native functions exposed to PHP */
static Php::Value fuzz_input() { return Php::Value((const char *)g_fuzz_data, (int)g_fuzz_size); }
static Php::Value fuzz_concat(Php::Parameters &params)
{
    std::string r;
    for (auto &p : params) r += p.stringValue();
    return r;
}
static void fuzz_error_reporting(Php::Parameters &params)
{
    // the C++ side of error_reporting (upstream fix 5c9a31a18c)
    if (!params.empty()) Php::error_reporting((Php::Message)(int)params[0].numericValue());
}
static Php::Value fuzz_value_call(Php::Parameters &params)
{
    // Value::isCallable / Value::call on a PHP-supplied value (upstream fix 2c0a23180c)
    if (params.size() < 2) return nullptr;
    Php::Value target = params[0];
    std::string name = params[1].stringValue();
    if (!target.isObject()) return target.isCallable();
    if (!target.isCallable(name.c_str())) return false;
    return target.call(name.c_str());
}
static Php::Value fuzz_compare_str(Php::Parameters &params)
{
    // Value comparison with C strings (upstream fix 3cee025c67)
    if (params.size() < 2) return nullptr;
    std::string s = params[1].stringValue();
    Php::Array r;
    r[0] = params[0] == s.c_str();
    r[1] = params[0] < s;
    r[2] = params[0] > s.c_str();
    r[3] = params[0].strcmp(s.c_str());
    return r;
}

/** the per-target body, run inside a PHP request */
static void (*g_fuzz_body)() = nullptr;
static void fuzz_body_native() { if (g_fuzz_body) g_fuzz_body(); }

static Php::Extension &fuzz_extension()
{
    static Php::Extension ext("phpcpp_fuzz", "1.0");
    static bool init = false;
    if (init) return ext;
    init = true;

    Php::Class<FuzzObj> obj("FuzzObj");
    obj.method<&FuzzObj::__construct>("__construct");
    obj.method<&FuzzObj::getValue>("getValue");
    obj.method<&FuzzObj::setValue>("setValue", { Php::ByVal("v", Php::Type::Numeric) });
    obj.property("prop", "default");
    obj.property("CONSTX", 42, Php::Const);
    obj.constant("CONSTY", "y");
    ext.add(std::move(obj));

    Php::Class<FuzzPlain> plain("FuzzPlain");
    ext.add(std::move(plain));

    ext.add<fuzz_input>("fuzz_input");
    ext.add<fuzz_concat>("fuzz_concat");
    ext.add<fuzz_error_reporting>("fuzz_error_reporting", { Php::ByVal("level", Php::Type::Numeric) });
    ext.add<fuzz_value_call>("fuzz_value_call");
    ext.add<fuzz_compare_str>("fuzz_compare_str");
    ext.add<fuzz_body_native>("fuzz_body");
    ext.add(Php::Constant("FUZZ_CONST", 7));
    return ext;
}

static size_t fuzz_discard_write(const char *, size_t n) { return n; }
static zend_module_entry *g_fuzz_entry = nullptr;

/**
 *  Functions that touch the host (processes, files, cwd, signals, network, sleeping) are disabled
 *  so an input can neither change process or host state that outlives it nor stall on I/O;
 *  everything else stays. disable_functions cannot block classes (SplFileObject, the directory
 *  iterators) or every stream opener (gz*, stream wrappers), so FUZZ_BASEDIR below confines all
 *  path-based stream access as well.
 */
static const char *const FUZZ_DISABLED =
    "exec,system,passthru,shell_exec,proc_open,popen,pcntl_exec,pcntl_fork,mail,"
    "fopen,file_put_contents,file_get_contents,file,readfile,unlink,rename,rmdir,mkdir,copy,touch,"
    "chmod,chown,chgrp,symlink,link,tempnam,tmpfile,fsockopen,pfsockopen,stream_socket_client,"
    "stream_socket_server,socket_create,dl,sleep,usleep,time_nanosleep,time_sleep_until,"
    "set_time_limit,ini_set,ini_alter,putenv,header,setcookie,opendir,scandir,glob,dir,"
    "highlight_file,show_source,php_strip_whitespace,parse_ini_file,move_uploaded_file,"
    "error_log,syslog,openlog,register_shutdown_function,register_tick_function,"
    "spl_autoload_register,chdir,chroot,umask,lchown,lchgrp,gzopen,gzfile,readgzfile,"
    "session_start,session_save_path,proc_nice,ftok,pcntl_alarm,pcntl_signal,pcntl_sigprocmask,"
    "pcntl_signal_dispatch,pcntl_async_signals,pcntl_wait,pcntl_waitpid,pcntl_rfork,pcntl_forkx,"
    "pcntl_setpriority,pcntl_setcpuaffinity";

/**
 *  open_basedir: every path-based open (fopen-family, SplFileObject/SplFileInfo::openFile,
 *  DirectoryIterator & co, gz*, compress.zlib://, session files, chdir) must resolve under this
 *  directory. It does not exist and mkdir is disabled, so no input can create, read or write a
 *  host file; php://memory, php://temp and php://stdout stay usable.
 */
static const char *const FUZZ_BASEDIR = "/nonexistent/phpcpp-fuzz";

/**
 *  SAPI startup hook: registers the test extension as a startup module and adds disable_functions
 *  to the embed SAPI's INI. It must be INI, read during module startup: zend_disable_functions()
 *  called after startup desynchronises the persistent-function count, and every later request
 *  then silently loses functions at shutdown.
 */
static int fuzz_sapi_startup(sapi_module_struct *sm)
{
    static std::string ini;
    ini = std::string(sm->ini_entries ? sm->ini_entries : "") + "disable_functions=" + FUZZ_DISABLED + "\n"
        + "open_basedir=" + FUZZ_BASEDIR + "\n";
    sm->ini_entries = (char *)ini.c_str();
    return php_module_startup(sm, g_fuzz_entry);
}

static void fuzz_php_init()
{
    // the Zend allocator hides emalloc/efree from ASan; use the system allocator instead
    setenv("USE_ZEND_ALLOC", "0", 1);
    g_fuzz_entry = (zend_module_entry *)fuzz_extension().module();
    php_embed_module.php_ini_ignore = 1;   // never load the distro php.ini (it loads opcache.so)
    php_embed_module.ub_write = fuzz_discard_write;
    php_embed_module.startup = fuzz_sapi_startup;
    php_embed_init(0, nullptr);
    EG(error_reporting) = 0;
}

/** run one input: eval `code` in the current request, then start a fresh request */
static void fuzz_php_run(const char *code, size_t len)
{
    zend_first_try {
        zend_eval_stringl((char *)code, len, nullptr, (char *)"fuzz");
    } zend_end_try();
    if (EG(exception)) zend_clear_exception();
    php_request_shutdown(nullptr);
    php_request_startup();
    EG(error_reporting) = 0;
}
