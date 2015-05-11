class sfu_fw::rcgdefaultfwrules {
# These will apply to any machine on the network
  $trustedIPsnfs = [ '199.60.0.0/20', '199.60.16.11/32', '142.58.41.0/24', '199.60.17.34/32', '199.60.17.33/32', '199.60.17.53/32', '142.58.53.0/24', '142.58.185.0/24', '142.58.188.0/24' ]
  $trustedIPsrshd = [ '199.60.1.59', '199.60.1.21', '199.60.1.6', '199.60.1.2', '199.60.1.117' ]
  $trusted5555 = [ '199.60.0.0/20', '192.168.2.0/24' ]
  define trust_these_IPs_rshd() {
    firewall { "004 accept rshd trusted IPs ${name}":
      proto   => 'tcp',
      dport   => '514',
      action  => 'accept',
      source  => $name, 
    }  
  }
/*  firewall { '005 deny all remaining untrusted to rshd':
    proto   => 'tcp',
    dport   => '514',
    action  => 'drop',
  }
*/  
  define trust_these_IPs_nfs_tcp() {
    firewall { "006 accept tcp NFS connections from these trusted IPs ${name}":
      proto   => 'tcp',
      action  => 'accept',
      source  => $name, 
      dport   => [ '111', '2049', '4001', '4002', '4003', '4004' ],
    }
  }  
  define trust_these_IPs_nfs_udp() {
    firewall { "007 accept udp NFS connections from these trusted IPs ${name}":
      proto   => 'udp',
      action  => 'accept',
      source  => $name, 
      dport   => [ '111', '2049', '4001', '4002', '4003', '4004' ],
    }
  }  
  define trust_these_5555() {
    firewall { "008 accept port 5555 from these trusted IPs ${name}":
      proto   => 'tcp',
      action  => 'accept',
      source  => $name, 
      dport   => '5555',
    }
  }  
  trust_these_IPs_rshd{$trustedIPsrshd:}
  trust_these_IPs_nfs_tcp{$trustedIPsnfs:}
  trust_these_IPs_nfs_udp{$trustedIPsnfs:}
  trust_these_5555{$trusted5555:}
}
