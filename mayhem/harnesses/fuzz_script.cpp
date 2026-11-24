/**
 *  fuzz_script — the input is PHP source, evaluated against classes and functions registered with
 *  PHP-CPP (Php::Class<T> handlers in zend/classimpl.cpp: magic methods, ArrayAccess, Countable,
 *  Serializable, casts, compare, clone; native functions with typed parameters; constants).
 *  Host-touching builtins are disabled (fuzzext.h); each input gets a fresh PHP request.
 */
#include "fuzzext.h"

extern "C" int LLVMFuzzerInitialize(int *, char ***) { fuzz_php_init(); return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    g_fuzz_data = data; g_fuzz_size = size;
    std::string code((const char *)data, size);
    fuzz_php_run(code.c_str(), code.size());
    return 0;
}
