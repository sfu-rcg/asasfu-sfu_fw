define sfu_fw::sourceip::simpleloopd($trustedIP, $filternum = '010', $servicename = undef, $proto, $dport = undef, $sport = undef) {
  firewall { "${filternum} accept ${proto} ${servicename} connections from these trusted IPs ${trustedIP}":
    proto   => $proto,
    action  => 'accept',
    source  => $trustedIP,
    dport   => $dport,
    sport   => $sport,
  }
}
