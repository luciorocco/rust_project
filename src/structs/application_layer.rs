#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppProtocol {
    /// File Transfer Protocol
    FTP,
    /// Secure Shell
    SSH,
    /// Telnet
    Telnet,
    /// Simple Mail Transfer Protocol
    SMTP,
    /// Terminal Access Controller Access-Control System
    TACACS,
    /// Domain Name System
    DNS,
    /// Dynamic Host Configuration Protocol
    DHCP,
    /// Trivial File Transfer Protocol
    TFTP,
    /// Hypertext Transfer Protocol
    HTTP,
    /// Post Office Protocol
    POP,
    /// Network Time Protocol
    NTP,
    /// NetBIOS
    NetBIOS,
    /// Post Office Protocol 3 over TLS/SSL
    POP3S,
    /// Internet Message Access Protocol
    IMAP,
    /// Simple Network Management Protocol
    SNMP,
    /// Border Gateway Protocol
    BGP,
    /// Lightweight Directory Access Protocol
    LDAP,
    ///Hypertext Transfer Protocol over TLS/SSL
    HTTPS,
    /// Lightweight Directory Access Protocol over TLS/SSL
    LDAPS,
    /// File Transfer Protocol over TLS/SSL
    FTPS,
    /// Multicast DNS
    #[allow(non_camel_case_types)]
    mDNS,
    ///Internet Message Access Protocol over TLS/SSL
    IMAPS,
    /// Simple Service Discovery Protocol
    SSDP,
    /// Extensible Messaging and Presence Protocol |
    XMPP,
    /// not identified
    Other,
}
pub fn from_port_to_application_protocol(port: u16) -> AppProtocol {
    match port {
        20..=21 => AppProtocol::FTP,
        22 => AppProtocol::SSH,
        23 => AppProtocol::Telnet,
        25 => AppProtocol::SMTP,
        49 => AppProtocol::TACACS,
        53 => AppProtocol::DNS,
        67..=68 => AppProtocol::DHCP,
        69 => AppProtocol::TFTP,
        80 | 8080 => AppProtocol::HTTP,
        109..=110 => AppProtocol::POP,
        123 => AppProtocol::NTP,
        137..=139 => AppProtocol::NetBIOS,
        143 | 220 => AppProtocol::IMAP,
        161..=162 | 199 => AppProtocol::SNMP,
        179 => AppProtocol::BGP,
        389 => AppProtocol::LDAP,
        443 => AppProtocol::HTTPS,
        636 => AppProtocol::LDAPS,
        989..=990 => AppProtocol::FTPS,
        993 => AppProtocol::IMAPS,
        995 => AppProtocol::POP3S,
        1900 => AppProtocol::SSDP,
        5222 => AppProtocol::XMPP,
        5353 => AppProtocol::mDNS,
        _ => AppProtocol::Other,
    }
}