define sfu_fw::sourceip::simpleloop($filternum = '010', $servicename = undef, $trustedIPs = undef, $proto, $dport = undef, $sport = undef) {

 # define trust_these_IPs($filternum = '010', $servicename = undef, $proto, $dport = undef, $sport = undef) {
 #   firewall { "${filternum} accept ${proto} ${servicename} connections from these trusted IPs ${name}":
 #     proto   => $proto,
 #     action  => 'accept',
 #     source  => $name, 
 #     dport   => $dport,
 #     sport   => $sport,
 #   }
 # }  
  if $trustedIPs {
    validate_array($trustedIPs)
    validate_re($filternum, '^[0-9]{3}$', 'Your filternum has to contain a number from 000 to 999 as it is used to organize IPTables rules')
    validate_re($proto,'^[a-zA-Z0-9]+$', 'Apply a proper protocol name to val $proto')
    unless $trustedIPs == [] {
      $IPs_count = inline_template('<%- count = 0 -%><%- trustedIPs.each do |source_key| -%><%= count -%>,<%- count = count.to_i + 1 -%><%- end -%>')
      $IPs_count_array = split($IPs_count, ',')
      
      #$simpleloopd_name = $IPs_count $servicename $proto $filternum

      sfu_fw::sourceip::simpleloopd { "${IPs_count} ${servicename} ${proto} ${filternum}":
        trustedIP   => $trustedIPs[inline_template('<%= @IPs_count_array.shift -%>')],
        filternum   => $filternum,
        servicename => $servicename,
        proto       => $proto,
        dport       => $dport,
        sport       => $sport,
      }
    }
  }
}
