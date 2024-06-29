# Estat extensions and prefixes
ESTAT_TCP_EXT, ESTAT_TCP_PFX = ".csv", "tcp_trace"
ESTAT_UDP_EXT, ESTAT_UDP_PFX = ".csv", "udp_trace"
ESTAT_TCP_LOG_PERIODIC_EXT, ESTAT_TCP_LOG_PERIODIC_PFX = ".csv", "tcp_trace_log_periodic"

# Tstat trace files options
TSTAT_EXT, TSTAT_PFX = ".pcap.out", "tstat_trace"

# Wireshark trace files options
WIRESHARK_EXT, WIRESHARK_PFX = ".pcap", "wireshark_trace"

# Streambot trace files options
STREAMBOT_EXT, STREAMBOT_PFX = ".csv", "streambot_trace"


ESTAT_L7_PROTOCOL_TCP = {

    0:      "UNKNOWN",
    1:      "HTTP",
    2:      "RTSP",
    4:      "RTP",
    8:      "ICY",
    16:     "RTCP",
    32:     "MSN",
    64:     "YMSG",
    128:    "XMPP",
    256:    "P2P",
    512:    "SKYPE",
    1024:   "SMTP",
    2048:   "POP3",
    4096:   "IMAP4",
    8192:   "TLS",
    16384:  "ED2K",
    32768:  "SSH",
    65536:  "RTMP",
    131072: "MSE/PE",
}

ESTAT_L7_PROTOCOL_UDP = {

    0:  "UNKNOWN",
    1:  "FIRST_RTP",
    2:  "FIRST_RTCP",
    3:  "RTP",
    4:  "RTCP",
    5:  "SKYPE_E2E",
    6:  "SKYPE_E2O",
    7:  "SKYPE_SIG",
    8:  "P2P_ED2K",
    9:  "P2P_KAD",
    10: "P2P_KADU",
    11: "P2P_GNU",
    12: "P2P_BT",
    13: "P2P_DC",
    14: "P2P_KAZAA",
    15: "P2P_PPLIVE",
    16: "P2P_SOPCAST",
    17: "P2P_TVANTS",
    18: "P2P_OKAD",
    19: "DNS",
    20: "P2P_UTP",
    21: "P2P_UTPBT",
    22: "UDP_VOD",
    23: "P2P_PPSTREAM",
    24: "TEREDO",
    25: "UDP_SIP",
    26: "UDP_DTLS",
    27: "UDP_QUIC"

}

ESTAT_TCP_SUMMARY_COLUMNS = {

    # Basic info about the connection
    "CLIENT_IP_ADDRESS":    0,
    "SERVER_IP_ADDRESS":    14,
    "CLIENT_L4_PORT":       1,
    "SERVER_L4_PORT":       15,
    "PROTOCOL":             41,

    # Info about flow timing
    "TIME_ABS_START": 28, # When the flow has started
    "TIME_ABS_END":   29, # When the flow has finished

    # Server identity info
    "SERVER_CNAME_CLIENT_HELLO":     115, # The server canonical name is extracted from Client Hello during TLS hadshake
    "SERVER_CNAME_SERVER_HELLO":     116, # The server canonical name is extracted from Server Hello during TLS handshake
    "SERVER_CNAME_CLIENT_DNS_QUERY": 126, # The server canonical name is extracted when client queries the DNS
    "SERVER_CNAME_HTTP_HOSTNAME":    130, # The server canonical name is extracted directly from HTTP replies, if any

    # Volume statistics about the connection from client perspective
    "CLIENT_BYTES": 12, # How many payload bytes the client has generated in total

    # Volume statistics about the connection from server perspective
    "SERVER_BYTES": 24, # How many payload bytes the server has generated in total

}

ESTAT_UDP_SUMMARY_COLUMNS = {

    # Basic info about the connection
    "CLIENT_IP_ADDRESS":    0,
    "SERVER_IP_ADDRESS":    14,
    "CLIENT_L4_PORT":       1,
    "SERVER_L4_PORT":       15,
    "PROTOCOL":             41,

    # Info about flow timing
    "TIME_ABS_START": 28, # When the flow has started
    "TIME_ABS_END":   29, # When the flow has finished

    # Server identity info
    "SERVER_CNAME_CLIENT_HELLO":     115, # The server canonical name is extracted from Client Hello during TLS hadshake
    "SERVER_CNAME_SERVER_HELLO":     116, # The server canonical name is extracted from Server Hello during TLS handshake
    "SERVER_CNAME_CLIENT_DNS_QUERY": 126, # The server canonical name is extracted when client queries the DNS
    "SERVER_CNAME_HTTP_HOSTNAME":    130, # The server canonical name is extracted directly from HTTP replies, if any

    # Volume statistics about the connection from client perspective
    "CLIENT_BYTES": 12, # How many payload bytes the client has generated in total

    # Volume statistics about the connection from server perspective
    "SERVER_BYTES": 24, # How many payload bytes the server has generated in total

}


ESTAT_TCP_LOG_PERIODIC_SUMMARY_COLUMNS = {

    # Basic info about the connection
    "CLIENT_IP_ADDRESS":    0,
    "SERVER_IP_ADDRESS":    2,
    "CLIENT_L4_PORT":       1,
    "SERVER_L4_PORT":       3,

    # Info about the bin (a snapshot of the flow)
    "TIME_ABS_START": 4, # When the bin has started
    "TIME_REL_START": 5, # When the bin has started from the first bin
    "TIME_REL_END":   6, # When the bin has ended up from the first bin
    "TIME_BIN_DELTA": 7, # The bin duration

    # Volume statistics about the connection from client perspective
    "C_PKTS_ALL":   8,      # How many packets the client has generated in total
    "C_RSTS_PKTS":  9,      # How many packets with RST flag the client has emitted
    "C_ACKS_PKTS": 10,      # How many packets with ACK flag the client has emitted
    "C_PURE_ACKS_PKTS": 11, # How many packets with ACK and no data the client has emitted
    "C_BYTES": 12,          # How many payload bytes the client has generated in total
    "C_PKTS_WITH_DATA": 13, # How many packets with data the client has emitted
    "C_BYTES_ALL": 14,      # How many payload bytes the client has generated purely
    "C_PKTS_RETX": 15,      # How many packets the client has retrasmitted
    "C_BYTS_RETX": 16,      # How many bytes the client has retrasmitted

    # Volume statistics about the connection from server perspective
    "S_PKTS_ALL":   20,     # How many packets the server has generated in total
    "S_RSTS_PKTS":  21,     # How many packets with RST flag the server has emitted
    "S_ACKS_PKTS":  22,     # How many packets with ACK flag the server has emitted
    "S_PURE_ACKS_PKTS": 23, # How many packets with ACK and no data the server has emitted
    "S_BYTES": 24,          # How many payload bytes the server has generated in total
    "S_PKTS_WITH_DATA": 25, # How many packets with data the server has emitted
    "S_BYTES_ALL": 26,      # How many payload bytes the server has generated purely
    "S_PKTS_RETX": 27,      # How many packets the server has retrasmitted
    "S_BYTS_RETX": 28,      # How many bytes the server has retrasmitted

}


# Token delimiters when building a frame
STREAMBOT_TRACE_COLUMNS_DELIMITER = "\t"
TSTAT_TRACE_COLUMNS_DELIMITER = " "

# Binaries
TSTAT_BINARY_PATH = "/usr/local/bin/tstat"