/**
 *  phpcpp_php — the oracle's PHP runner: an embed-SAPI "php" that loads one PHP-CPP extension
 *  (a .so exporting get_module(), as upstream's tests/ build them) and runs one script with it,
 *  exiting with the script's exit status. Used by mayhem/test.sh to run upstream's tests/.
 *  Usage: phpcpp_php <extension.so> <script.php>
 */
#include <sapi/embed/php_embed.h>
#include <main/php_main.h>
#include <dlfcn.h>
#include <cstdio>

static zend_module_entry *g_entry = nullptr;
static int runner_startup(sapi_module_struct *sm) { return php_module_startup(sm, g_entry); }

int main(int argc, char **argv)
{
    if (argc < 3) { std::fprintf(stderr, "usage: %s <extension.so> <script.php>\n", argv[0]); return 2; }
    void *h = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    if (!h) { std::fprintf(stderr, "%s\n", dlerror()); return 2; }
    auto get_module = (void *(*)())dlsym(h, "get_module");
    if (!get_module) { std::fprintf(stderr, "no get_module in %s\n", argv[1]); return 2; }
    g_entry = (zend_module_entry *)get_module();

    // the distro ini is read (like `php` does) so the shared DOM extension the traverse tests use loads
    php_embed_module.startup = runner_startup;
    int rc = 0;
    PHP_EMBED_START_BLOCK(argc - 2, argv + 2)
        zend_file_handle fh;
        zend_stream_init_filename(&fh, argv[2]);
        php_execute_script(&fh);
        rc = EG(exit_status);
        zend_destroy_file_handle(&fh);
    PHP_EMBED_END_BLOCK()
    return rc;
}
