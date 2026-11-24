/**
 *  fuzz_api — PHP-CPP's helpers that hand strings to the engine (include/call.h, script.h,
 *  globals.h; zend/script.cpp, opcodes.h, eval.cpp, constantfuncs.cpp, exists.cpp, inivalue.cpp,
 *  globals.cpp, exception_handler.cpp, function.cpp): Php::Script(name, code).valid()/execute(),
 *  Php::eval, Php::define/constant/defined, Php::class_exists, Php::ini_get, Php::GLOBALS,
 *  Php::error_reporting and Php::call. Php::call takes its function name from a fixed allow-list
 *  (fuzzed arguments); code run by Script/eval is subject to the same disable_functions and open_basedir as
 *  every target (fuzzext.h). Runs inside a native function, since executing code needs a frame.
 */
#include "fuzzext.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

static FuzzedDataProvider *g_fdp = nullptr;

static const char *const CALLABLE[] = {
    "strtoupper", "strlen", "str_repeat", "substr", "implode", "explode", "array_reverse", "json_encode",
    "json_decode", "intval", "floatval", "sprintf", "str_pad", "array_merge", "count", "is_callable",
    "method_exists", "property_exists", "var_export", "serialize", "unserialize", "error_reporting",
    "fuzz_concat", "fuzz_value_call", "fuzz_compare_str", "strrev", "base64_decode", "array_keys",
};

static Php::Value fuzz_arg(FuzzedDataProvider &fdp)
{
    switch (fdp.ConsumeIntegralInRange<int>(0, 5)) {
    case 0: return fdp.ConsumeIntegralInRange<int64_t>(-1000, 1000);
    case 1: return fdp.ConsumeFloatingPoint<double>();
    case 2: return fdp.ConsumeBool();
    case 3: { Php::Array a; for (int i = fdp.ConsumeIntegralInRange<int>(0, 3); i > 0; i--) a[fdp.ConsumeRandomLengthString(8)] = fdp.ConsumeRandomLengthString(8); return a; }
    case 4: return Php::Object("FuzzObj", fdp.ConsumeIntegralInRange<int32_t>(-9, 9));
    default: return fdp.ConsumeRandomLengthString(64);
    }
}

static void api_body()
{
    FuzzedDataProvider &fdp = *g_fdp;
    volatile uint64_t sink = 0;   // unsigned: the fold wraps instead of overflowing (harness UB)
    for (int steps = 0; steps < 16 && fdp.remaining_bytes() > 0; steps++) {
        try {
            switch (fdp.ConsumeIntegralInRange<int>(0, 10)) {
            case 0: { std::string name = fdp.ConsumeRandomLengthString(16), code = fdp.ConsumeRandomLengthString(512);
                      Php::Script script(name.c_str(), code.c_str(), code.size());
                      if (script.valid()) sink += script.execute().size();
                      break; }
            case 1: { std::string code = fdp.ConsumeRandomLengthString(512); sink += Php::eval(code).size(); break; }
            case 2: { std::string n = fdp.ConsumeRandomLengthString(32); sink += Php::define(n, fuzz_arg(fdp)); break; }
            case 3: { std::string n = fdp.ConsumeRandomLengthString(32); sink += Php::defined(n); sink += Php::constant(n).size(); break; }
            case 4: { std::string n = fdp.ConsumeRandomLengthString(32); sink += Php::class_exists(n.c_str(), n.size(), false); break; }
            case 5: { std::string n = fdp.ConsumeRandomLengthString(32);
                      Php::IniValue v = Php::ini_get(n.c_str()); sink += (uint64_t)v.numericValue() + v.boolValue() + v.stringValue().size(); break; }
            case 6: { std::string k = fdp.ConsumeRandomLengthString(16); Php::GLOBALS[k] = fuzz_arg(fdp); break; }
            case 7: { std::string k = fdp.ConsumeRandomLengthString(16); Php::Value v = Php::GLOBALS[k]; sink += v.size(); break; }
            case 8: { // C++ error_reporting followed by userspace error_reporting() (fix 5c9a31a18c)
                      Php::error_reporting((Php::Message)fdp.ConsumeIntegral<int>());
                      sink += (uint64_t)Php::eval("return error_reporting(E_ALL);").numericValue(); break; }
            case 9: { const char *fn = CALLABLE[fdp.ConsumeIntegralInRange<size_t>(0, sizeof(CALLABLE) / sizeof(CALLABLE[0]) - 1)];
                      switch (fdp.ConsumeIntegralInRange<int>(0, 2)) {
                      case 0: sink += Php::call(fn, fuzz_arg(fdp)).size(); break;
                      case 1: sink += Php::call(fn, fuzz_arg(fdp), fuzz_arg(fdp)).size(); break;
                      default: sink += Php::call(fn, fuzz_arg(fdp), fuzz_arg(fdp), fuzz_arg(fdp)).size(); break;
                      }
                      break; }
            default: { Php::Value v = fuzz_arg(fdp); sink += v.isCallable(); if (v.isCallable()) sink += v().size(); break; }
            }
        } catch (Php::Throwable &) {
            // PHP exceptions surfaced as C++ exceptions
        }
        if (EG(exception)) zend_clear_exception();
    }
    (void)sink;
}

static const char CALL[] = "fuzz_body();";

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    g_fuzz_body = api_body;
    fuzz_php_init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    g_fdp = &fdp;
    fuzz_php_run(CALL, sizeof(CALL) - 1);
    g_fdp = nullptr;
    return 0;
}
