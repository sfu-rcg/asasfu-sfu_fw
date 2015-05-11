class sfu_fw::basefirewall {
  Firewall {
    before  => Class['sfu_fw::post'],
    require => Class['sfu_fw::pre'],
  }
  class { ['sfu_fw::pre', 'sfu_fw::post']: }
}
