#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 3;
    unsigned char bytes[32769];
    size_t size = fread(bytes, 1, sizeof(bytes), file);
    fclose(file);
    if (size < 256 || size >= sizeof(bytes)) return 4;
    CFDataRef data = CFDataCreate(NULL, bytes, size);
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, data);
    CFRelease(data);
    if (!cert) return 5;
    CFArrayRef settings = NULL;
    OSStatus settings_status = SecTrustSettingsCopyTrustSettings(cert, kSecTrustSettingsDomainUser, &settings);
    printf("user_trust_settings_status=%d count=%ld\n", (int)settings_status,
           settings ? CFArrayGetCount(settings) : 0);
    if (settings) CFRelease(settings);
    CFStringRef hostname = CFStringCreateWithCString(NULL, argv[2], kCFStringEncodingUTF8);
    SecPolicyRef policy = SecPolicyCreateSSL(true, hostname);
    SecTrustRef trust = NULL;
    OSStatus status = SecTrustCreateWithCertificates(cert, policy, &trust);
    SecTrustResultType result = kSecTrustResultInvalid;
    if (!status) status = SecTrustEvaluate(trust, &result);
    printf("trust_status=%d trust_result=%d\n", (int)status, (int)result);
    if (trust) CFRelease(trust);
    CFRelease(policy); CFRelease(hostname); CFRelease(cert);
    return status != 0;
}
