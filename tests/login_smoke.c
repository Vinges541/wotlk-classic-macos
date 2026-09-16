/* Synthetic launcher credentials only. Never print preference/token values. */
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    CFPropertyListRef token = CFPreferencesCopyAppValue(
        CFSTR("Launch Options/WoW/WEB_TOKEN"), CFSTR("net.battle"));
    if (argc == 2 && strcmp(argv[1], "reject") == 0) {
        assert(token == NULL);
        return 0;
    }
    assert(token && CFGetTypeID(token) == CFDataGetTypeID());
    CSSM_DATA input = {(CSSM_SIZE)CFDataGetLength(token), (uint8 *)CFDataGetBytePtr(token)};
    CSSM_DATA output = {0, NULL}, remaining = {0, NULL};
    CSSM_SIZE written = 0;
    assert(CSSM_DecryptData(0, &input, 1, &output, 1, &written, &remaining) == 0);
    const char *expected = "HP-0123456789012345678901234567890123456789";
    assert(written == strlen(expected) && output.Length == written);
    assert(memcmp(output.Data, expected, written) == 0);
    assert(remaining.Length == 0 && remaining.Data == NULL);
    free(output.Data);

    /* Unrelated crypto input must be handled by Security.framework, not our ticket adapter. */
    uint8 unrelated[64] = {0};
    input.Data = unrelated; input.Length = sizeof unrelated;
    output.Data = NULL; output.Length = 0;
    assert(CSSM_DecryptData(0, &input, 1, &output, 1, &written, &remaining) != 0);

    CFPropertyListRef account = CFPreferencesCopyAppValue(
        CFSTR("Launch Options/WoW/GAME_ACCOUNT"), CFSTR("net.battle"));
    assert(account && CFEqual(account, CFSTR("SYNTHETIC")));
    CFRelease(account);
    CFPropertyListRef endpoint = CFPreferencesCopyAppValue(
        CFSTR("Launch Options/WoW/CONNECTION_STRING"), CFSTR("net.battle"));
    assert(endpoint && CFEqual(endpoint, CFSTR("localhost.:1119")));
    CFRelease(endpoint);
    CFPropertyListRef other = CFPreferencesCopyAppValue(
        CFSTR("Launch Options/WoW/WEB_TOKEN"), CFSTR("dev.wrath.synthetic-test"));
    assert(other == NULL);
    CFRelease(token);
    return 0;
}
