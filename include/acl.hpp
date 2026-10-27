
#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Defines whether a matching packet is allowed or denied.
enum class ACLAction {
    ALLOW,
    DENY
};

// One firewall rule.
struct ACLRule {
    std::uint32_t src_ip{};       // Source IPv4 address
    std::uint32_t src_mask{};     // Source subnet mask
    std::uint32_t dst_ip{};       // Destination IPv4 address
    std::uint32_t dst_mask{};     // Destination subnet mask
    std::uint8_t protocol{};      // 0 = any, 6 = TCP, 17 = UDP
    std::uint16_t dst_port{};     // 0 = any destination port
    ACLAction action{ACLAction::DENY};
};

// Checks packet information against ordered ACL rules.
class ACLFirewall {
public:
    // Add a rule; earlier rules have higher priority.
    void add_rule(const ACLRule& rule);

    // Return the action of the first matching rule.
    ACLAction evaluate(
        std::uint32_t src_ip,
        std::uint32_t dst_ip,
        std::uint8_t protocol,
        std::uint16_t dst_port
    ) const;

private:
    std::vector<ACLRule> rules_;
};
