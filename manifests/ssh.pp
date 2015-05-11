# Plan is to have this module utilize sourcing another module via collector and tags to pull in values for trusted networks
# If $public is set to true we will still source the trusted networks and create the rules as well as adding allow all SSH
# as this will allow us to choose to do rate limiting and other options against untrusted networks.
class sfu_fw::ssh(
  $public = false,
  ) {
  validate_bool($public)

  if $public == true {
    notify { "You chose to have your SSH server PUBLIC": }
  }
  firewall { '022 allow SSH access':
    port   => [ '22' ],
    proto  => tcp,
    action => accept,
  }
}
