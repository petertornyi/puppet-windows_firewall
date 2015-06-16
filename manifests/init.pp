# Author::    Liam Bennett (mailto:liamjbennett@gmail.com)
# Copyright:: Copyright (c) 2014 Liam Bennett
# License::   MIT

# == Class: windows_firewall
#
# Module to manage the windows firewall and it's configured exceptions
#
# === Requirements/Dependencies
#
# Currently reequires the puppetlabs/stdlib module on the Puppet Forge in
# order to validate much of the the provided configuration.
#
# === Parameters
#
# [*ensure*]
# Control the state of the windows firewall application
#
# === Examples
#
# To ensure that windows_firwall is running:
#
#   class { 'windows_firewall':
#     ensure => 'running',
#   }
#
class windows_firewall (
    $ensure = 'running'
) {

    validate_re($ensure,['^(running|stopped)$'])
    $firewall_name = 'MpsSvc'
    $firewall_profiles = ['DomainProfile', 'PublicProfile', 'StandardProfile']

    case $ensure {
        'running': { $enabled = true }
        default  : { $enabled = false }
    }

    service { 'windows_firewall':
      ensure => $ensure,
      name   => $firewall_name,
      enable => $enabled,
    }

    windows_firewall::config::firewall_service { $firewall_profiles:
        enabled => $enabled
    }
}
