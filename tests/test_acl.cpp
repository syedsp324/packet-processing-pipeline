
#include <iostream>
#include "acl.hpp"
#include "headers.hpp"

int main() {
    ACLFirewall firewall;

    // Rule 1: Deny UDP traffic to port 53.
    firewall.add_rule({
        0, 0, 0, 0,
        17, 53,
        ACLAction::DENY
    });

    // Rule 2: Allow UDP traffic to port 443.
    firewall.add_rule({
        0, 0, 0, 0,
        17, 443,
        ACLAction::ALLOW
    });

    // Test cases: source IP, destination IP, protocol, destination port.
    struct TestCase {
        const char* name;
        std::uint32_t src_ip;
        std::uint32_t dst_ip;
        std::uint8_t protocol;
        std::uint16_t dst_port;
        ACLAction expected;
    };

    const TestCase tests[] = {
        {"UDP/53 denied",  0x0A000001, 0x08080808, 17, 53,  ACLAction::DENY},
        {"UDP/443 allowed",0x0A000001, 0x08080808, 17, 443, ACLAction::ALLOW},
        {"TCP/443 default denied",0x0A000001, 0x08080808, 6, 443, ACLAction::DENY},
        {"TCP/80 default denied", 0x0A000001, 0x08080808, 6, 80,  ACLAction::DENY}
    };

    bool all_passed = true;

    for (const auto& test : tests) {
        const ACLAction actual = firewall.evaluate(
            test.src_ip,
            test.dst_ip,
            test.protocol,
            test.dst_port
        );

        const bool passed = actual == test.expected;
        std::cout << test.name << ": "
                  << (passed ? "PASS" : "FAIL") << '\n';

        if (!passed)
            all_passed = false;
    }

    std::cout << "\nACL tests: "
              << (all_passed ? "ALL PASSED" : "FAILED") << '\n';

    return all_passed ? 0 : 1;
}
