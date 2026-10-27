
#include "acl.hpp"

// Append a rule; rules are evaluated in insertion order.
void ACLFirewall::add_rule(const ACLRule& rule) {
    rules_.push_back(rule);
}

// Apply the first matching rule.
ACLAction ACLFirewall::evaluate(
    std::uint32_t src_ip,
    std::uint32_t dst_ip,
    std::uint8_t protocol,
    std::uint16_t dst_port
) const {
    for (const auto& rule : rules_) {
        // Check source and destination subnet matches.
        const bool source_matches =
            (src_ip & rule.src_mask) == (rule.src_ip & rule.src_mask);

        const bool destination_matches =
            (dst_ip & rule.dst_mask) == (rule.dst_ip & rule.dst_mask);

        // A zero protocol or port means any value.
        const bool protocol_matches =
            rule.protocol == 0 || rule.protocol == protocol;

        const bool port_matches =
            rule.dst_port == 0 || rule.dst_port == dst_port;

        if (source_matches && destination_matches &&
            protocol_matches && port_matches) {
            return rule.action;
        }
    }

    // Default-deny: unmatched packets are blocked.
    return ACLAction::DENY;
}
