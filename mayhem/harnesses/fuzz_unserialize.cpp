/**
 *  fuzz_unserialize — the input is a PHP serialize() string handed to unserialize(), limited to
 *  the PHP-CPP-registered classes, so the bytes reach ClassImpl's serialize/unserialize handlers
 *  (Php::Serializable) and object creation/destruction. A resulting value is then counted,
 *  cloned, compared, iterated, cast and serialized again through the same handlers.
 */
#include "fuzzext.h"

static const char SCRIPT[] =
    "try {"
    "  $v = unserialize(fuzz_input(), ['allowed_classes' => ['FuzzObj', 'FuzzPlain']]);"
    "  $all = is_array($v) ? $v : [$v];"
    "  foreach ($all as $o) {"
    "    if (!is_object($o)) continue;"
    "    try { @count($o); } catch (\\Throwable $e) {}"
    "    try { $c = clone $o; $r = ($c == $o); $r = ($o < $c); } catch (\\Throwable $e) {}"
    "    try { $s = serialize($o); unserialize($s, ['allowed_classes' => ['FuzzObj', 'FuzzPlain']]); } catch (\\Throwable $e) {}"
    "    try { $x = (string)$o; } catch (\\Throwable $e) {}"
    "    try { foreach ($o as $k => $val) {} } catch (\\Throwable $e) {}"
    "    try { $r = isset($o['a']); $r = $o['a'] ?? null; } catch (\\Throwable $e) {}"
    "    try { $r = fuzz_value_call($o, 'getValue'); $r = fuzz_compare_str($o, '1'); } catch (\\Throwable $e) {}"
    "  }"
    "} catch (\\Throwable $e) {}";

extern "C" int LLVMFuzzerInitialize(int *, char ***) { fuzz_php_init(); return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    g_fuzz_data = data; g_fuzz_size = size;
    fuzz_php_run(SCRIPT, sizeof(SCRIPT) - 1);
    return 0;
}
