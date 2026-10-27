/* Relocatable launcher for the GPGP private GnuPG runtime.
 * Source is included with the runtime distribution. */
#include <mach-o/dyld.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
int main(int argc, char **argv) {
    (void)argc;
    char path[PATH_MAX], resolved[PATH_MAX], target[PATH_MAX];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) || !realpath(path, resolved)) return 70;
    char *name = strrchr(resolved, '/');
    if (!name) return 70;
    char tool[128];
    if (strlen(name + 1) >= sizeof(tool)) return 70;
    strcpy(tool, name + 1); *name = 0;
    char *parent = strrchr(resolved, '/');
    if (!parent) return 70;
    *parent = 0;
    if (setenv("GPGP_GNUPG_ROOT", resolved, 1)) return 70;
    int length;
    if (!strcmp(tool, "pinentry") || !strcmp(tool, "pinentry-mac"))
        length = snprintf(target, sizeof(target), "%s/libexec/pinentry-mac.app/Contents/MacOS/pinentry-mac", resolved);
    else
        length = snprintf(target, sizeof(target), "%s/bin/.%s-real", resolved, tool);
    if (length < 0 || (size_t)length >= sizeof(target)) return 70;
    execv(target, argv);
    perror("GPGP bundled runtime could not launch");
    return 71;
}
