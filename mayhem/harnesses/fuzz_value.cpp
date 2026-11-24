/**
 *  fuzz_value — an op interpreter over the public Php::Value API (include/value.h,
 *  zend/value.cpp, arithmetic.h, hashmember.cpp, valueiterator.cpp): build values (null, bool,
 *  int, double, string, array, Php::Object of a registered class), compare them with Values,
 *  C strings and std::strings, do arithmetic, casts, array get/set/unset/contains, iteration,
 *  clone, setType, isCallable/call. It runs inside a native function called from PHP, because
 *  Values that call into userspace need a live execute frame.
 */
#include "fuzzext.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <vector>
#include <cstring>

static FuzzedDataProvider *g_fdp = nullptr;

static const Php::Type TYPES[] = {
    Php::Type::Null, Php::Type::Numeric, Php::Type::Float, Php::Type::Bool, Php::Type::Array,
    Php::Type::Object, Php::Type::String, Php::Type::Callable, Php::Type::False, Php::Type::True,
};

static void value_body()
{
    FuzzedDataProvider &fdp = *g_fdp;
    std::vector<Php::Value> r(6);
    auto reg = [&]() -> Php::Value & { return r[fdp.ConsumeIntegralInRange<size_t>(0, r.size() - 1)]; };
    volatile uint64_t sink = 0;   // unsigned: the fold wraps instead of overflowing (harness UB)

    for (int steps = 0; steps < 64 && fdp.remaining_bytes() > 0; steps++) {
        try {
            switch (fdp.ConsumeIntegralInRange<int>(0, 27)) {
            case 0: reg() = fdp.ConsumeIntegral<int64_t>(); break;
            case 1: reg() = fdp.ConsumeFloatingPoint<double>(); break;
            case 2: reg() = fdp.ConsumeRandomLengthString(64); break;
            case 3: reg() = fdp.ConsumeBool(); break;
            case 4: reg() = nullptr; break;
            case 5: reg() = Php::Array(); break;
            case 6: reg() = Php::Object("FuzzObj", fdp.ConsumeIntegral<int32_t>()); break;
            case 7: reg() = Php::Object("FuzzPlain"); break;
            case 8: { // compare with const char* / std::string (fix 3cee025c67)
                std::string s = fdp.ConsumeRandomLengthString(32);
                Php::Value &a = reg();
                sink += (a == s.c_str()) + (a != s) + (a < s.c_str()) + (a > s) + (a <= s) + (a >= s.c_str());
                sink += a.strcmp(s.c_str());
                break;
            }
            case 9: { Php::Value &a = reg(), &b = reg(); sink += (a == b) + (a < b) + (a > b) + (a != b); break; }
            case 10: { int64_t n = fdp.ConsumeIntegral<int64_t>(); Php::Value &a = reg();
                       sink += (a == n) + (a < n) + (a > (double)n) + (a == (bool)n); break; }
            case 11: { Php::Value &a = reg(), &b = reg();
                       switch (fdp.ConsumeIntegralInRange<int>(0, 4)) {
                       case 0: a += b; break; case 1: a -= b; break; case 2: a *= b; break;
                       case 3: a /= b; break; default: a %= b; break; }
                       break; }
            case 12: { Php::Value &a = reg(); int64_t n = fdp.ConsumeIntegral<int64_t>();
                       switch (fdp.ConsumeIntegralInRange<int>(0, 4)) {
                       case 0: a = a + n; break; case 1: a = a - n; break; case 2: a = a * n; break;
                       case 3: a = a / n; break; default: a = a % n; break; }
                       break; }
            case 13: { Php::Value &a = reg(); std::string s = fdp.ConsumeRandomLengthString(16);
                       if (fdp.ConsumeBool()) a += s; else a += s.c_str(); break; }
            case 14: { Php::Value &a = reg();
                       // fold the double without a float->int cast (UB when out of range / NaN)
                       double d = a.floatValue(); int64_t bits; std::memcpy(&bits, &d, sizeof bits);
                       sink += a.stringValue().size() + (uint64_t)a.numericValue() + (uint64_t)bits + a.boolValue() + (uint64_t)a.size();
                       break; }
            case 15: { Php::Value &a = reg(); sink += a.vectorValue<std::string>().size() + a.mapValue().size(); break; }
            case 16: { Php::Value &a = reg(); std::string k = fdp.ConsumeRandomLengthString(16);
                       Php::Value &v = reg(); if (fdp.ConsumeBool()) a.set(k, v); else a.set(fdp.ConsumeIntegral<int32_t>(), v); break; }
            case 17: { Php::Value &a = reg(); std::string k = fdp.ConsumeRandomLengthString(16);
                       reg() = fdp.ConsumeBool() ? a.get(k) : a.get(fdp.ConsumeIntegral<int32_t>()); break; }
            case 18: { Php::Value &a = reg(); std::string k = fdp.ConsumeRandomLengthString(16);
                       sink += a.contains(k) + a.contains(fdp.ConsumeIntegral<int32_t>()); break; }
            case 19: { Php::Value &a = reg(); std::string k = fdp.ConsumeRandomLengthString(16);
                       if (fdp.ConsumeBool()) a.unset(k); else a.unset(fdp.ConsumeIntegral<int32_t>()); break; }
            case 20: { Php::Value &a = reg(); for (auto &it : a) sink += it.first.size() + it.second.size(); break; }
            case 21: { Php::Value &a = reg(); reg() = fdp.ConsumeBool() ? a.clone() : a.clone(TYPES[fdp.ConsumeIntegralInRange<size_t>(0, 9)]); break; }
            case 22: { reg().setType(TYPES[fdp.ConsumeIntegralInRange<size_t>(0, 9)]); break; }
            case 23: { // isCallable / call on a method name (fix 2c0a23180c)
                       Php::Value &a = reg(); std::string m = fdp.ConsumeRandomLengthString(16);
                       if (a.isObject() && a.isCallable(m.c_str())) reg() = a.call(m.c_str());
                       else sink += a.isCallable(); break; }
            case 24: { Php::Value &a = reg(); std::string k = fdp.ConsumeRandomLengthString(16);
                       reg() = a[k]; break; }
            case 25: { Php::Value &a = reg(), &b = reg(); a[fdp.ConsumeRandomLengthString(8)] = b; break; }
            case 26: { Php::Value &a = reg(); sink += a.instanceOf("FuzzObj") + a.derivedFrom("FuzzObj") + a.isString() + a.isArray(); break; }
            default: { Php::error_reporting((Php::Message)fdp.ConsumeIntegral<int>()); sink += Php::error_reporting().numericValue(); break; }
            }
        } catch (Php::Throwable &) {
            // PHP exceptions (TypeError, DivisionByZeroError, ...) surfaced as C++ exceptions
        }
        if (EG(exception)) zend_clear_exception();
    }
    (void)sink;
}

static const char CALL[] = "fuzz_body();";

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    g_fuzz_body = value_body;
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
