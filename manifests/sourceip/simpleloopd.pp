define sfu_fw::sourceip::simpleloopd($filternum = '010', $servicename = undef, $proto, $dport = undef, $sport = undef) {
  firewall { "${filternum} accept ${proto} ${servicename} connections from these trusted IPs ${name}":
    proto   => $proto,
    action  => 'accept',
    source  => $name,
    dport   => $dport,
    sport   => $sport,
  }
}
