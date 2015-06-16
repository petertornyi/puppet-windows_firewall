# Author::    Liam Bennett (mailto:liamjbennett@gmail.com)
# Copyright:: Copyright (c) 2014 Liam Bennett
# License::   MIT

# == Define: windows_firewall::exception
#
# This defined type manages exceptions in the windows firewall
#
# === Requirements/Dependencies
#
# Currently reequires the puppetlabs/stdlib module on the Puppet Forge in
# order to validate much of the the provided configuration.
#
# === Parameters
#
# [*ensure*]
# Control the existence of a rule
#
# [*direction*]
# Specifies whether this rule matches inbound or outbound network traffic.
#
# [*action*]
# Specifies what Windows Firewall with Advanced Security does to filter network packets that match the criteria specified in this rule.
#
# [*enabled*]
# Specifies whether the rule is currently enabled.
#
# [*protocol*]
# Specifies that network packets with a matching IP protocol match this rule.
#
# [*remote_ip*]
# Specifies remote hosts that can use this rule.
#
# [*local_port*]
# Specifies that network packets with matching IP port numbers matched by this rule.
#
# [*display_name*]
# Specifies the rule name assigned to the rule that you want to display
#
# [*description*]
# Provides information about the firewall rule.
#
# [*allow_edge_traversal*]
# Specifies that the traffic for this exception traverses an edge device
#
# [*update*]
# Specifies what to do in case of rule with matching name but different content already exists
#  true  : content of existing rule will be updated (default)
#  false : new rule will be created with the new values
#
# === Examples
#
#  Exception for protocol/port:
#
#   windows_firewall::exception { 'WINRM-HTTP-In-TCP':
#     ensure       => present,
#     direction    => 'in',
#     action       => 'Allow',
#     enabled      => 'yes',
#     protocol     => 'TCP',
#     local_port   => '5985',
#     remote_ip    => '10.0.0.1,10.0.0.2'
#     program      => undef,
#     display_name => 'Windows Remote Management HTTP-In',
#     description  => 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]',
#   }
#
#  Exception for program path:
#
#   windows_firewall::exception { 'myapp':
#     ensure       => present,
#     direction    => 'in',
#     action       => 'Allow',
#     enabled      => 'yes',
#     program      => 'C:\\myapp.exe',
#     display_name => 'My App',
#     description  => 'Inbound rule for My App',
#   }
#
define windows_firewall::exception(
  $ensure               = 'present',
  $direction            = '',
  $action               = '',
  $enabled              = 'yes',
  $protocol             = '',
  $local_port           = '',
  $remote_ip            = '',
  $program              = undef,
  $display_name         = '',
  $description          = '',
  $allow_edge_traversal = 'no',
  $update               = true

) {

  # Check if we're allowing a program or port/protocol and validate accordingly
  if $program == undef {
    $port_param = 'localport'
    $fw_command = 'portopening'
    validate_re($protocol,['^(TCP|UDP|ICMPv(4|6))$'])
    if $protocol =~ /ICMPv(4|6)/ {
      $allow_context = "protocol=${protocol}"
    } else {
      $allow_context = "protocol=${protocol} ${port_param}=${local_port}"
      validate_re($local_port,['^(any|([0-9]{1,5})|([0-9]{1,5})[-]([0-9]{1,5}))$'])
    }
  } else {
    $fw_command    = 'allowedprogram'
    $allow_context = "program=\"${program}\""
    validate_absolute_path($program)
  }

  # Validate common parameters
  validate_re($ensure,['^(present|absent)$'])
  validate_slength($display_name,255)
  validate_re($enabled,['^(yes|no)$'])
  validate_re($allow_edge_traversal,['^(yes|no)$'])
  validate_slength($description,255)
  validate_re($direction,['^(in|out)$'])
  validate_re($action,['^(allow|block)$'])

  # Map values for the PowerShell check
  case $protocol {
    'TCP'    : { $ps_protocol = '6' }
    'UDP'    : { $ps_protocol = '17' }
    'ICMPv4' : { $ps_protocol = '1' }
    'ICMPv6' : { $ps_protocol = '58' }
    default  : {}
  }
  case downcase($action) {
    'allow' : { $ps_action = '1' }
    'block' : { $ps_action = '2' }
    default : {}
  }
  case downcase($enabled) {
    'yes'   : { $ps_enabled = 'True' }
    'no'    : { $ps_enabled = 'False' }
    default : {}
  }
  case downcase($direction) {
    'in'    : { $ps_direction = '1' }
    'out'   : { $ps_direction = '2' }
    default : {}
  }
  case downcase($allow_edge_traversal) {
    'yes'   : { $ps_traversal = 'True'}
    'no'    : { $ps_traversal = 'False' }
    default : {}
  }
  if $remote_ip == '' {
    $ps_remote_ip = '*'
  }
  else {
    $ps_remote_ip = $remote_ip
  }

 # Set pathes and commands to check for existing rules
  $netsh_bin            = 'C:\Windows\System32\netsh.exe'
  $ps_bin               = 'C:\Windows\system32\WindowsPowershell\v1.0\powershell.exe'
  $check_rule_existance = "${netsh_bin} advfirewall firewall show rule name=\"${display_name}\""
  $ps_searches          = [ "(\$_.Name -eq '${display_name}')",
                            "-and (\$_.Protocol -eq '${ps_protocol}')",
                            "-and (\$_.LocalPorts -eq '${local_port}')",
                            "-and (\$_.Enabled -eq \$${ps_enabled})",
                            "-and (\$_.Action -eq '${ps_action}')",
                            "-and (\$_.Direction -eq '${ps_direction}')",
                            "-and (\$_.RemoteAddresses -eq '${ps_remote_ip}')",
                            "-and (\$_.Description -eq '${description}')",
                            "-and (\$_.EdgeTraversal -eq \$${ps_traversal})"]
  $ps_search            = join($ps_searches, ' ')
  $detailed_search_ps   = "(New-object -comObject HNetCfg.FwPolicy2).Rules | Where-Object { ${ps_search} }"
  $detailed_search_cmd  = "${ps_bin} -Command \"if (${detailed_search_ps}) {exit 0} exit 1\""
  $netsh_delete_cmd     = "${netsh_bin} advfirewall firewall delete rule name=\"${display_name}\""
  $rule_details         = [ "description=\"${description}\"",
                            "dir=${direction}",
                            "action=${action}",
                            "enable=${enabled}",
                            "edge=${allow_edge_traversal}",
                            "${allow_context}",
                            "remoteip=\"${remote_ip}\""]
  $rule_details_arg     = join($rule_details, ' ')
  $netsh_create_cmd     = "${netsh_bin} advfirewall firewall add rule name=\"${display_name}\" ${rule_details_arg}"

  # Define command in case of rule with the defined display name already exists
  if $update {
    $netsh_update_cmd = "${netsh_bin} advfirewall firewall set rule name=\"${display_name}\" new ${rule_details_arg}"
    $update_title     = "Update rule ${display_name}"
  } else {
    $netsh_update_cmd = $netsh_create_cmd
    $update_title     = "Create new rule ${display_name}"
  }

  if $ensure == 'present' {
    # Create a new one if there is no rule found with the defined display name
    exec { "Create rule ${display_name}":
      command  => $netsh_create_cmd,
      provider => windows,
      unless   => $check_rule_existance,
      } ~>
    # If rule with $display_name already exists use the update_cmd
    exec { $update_title:
      command  => $netsh_update_cmd,
      provider => windows,
      unless   => $detailed_search_cmd,
      }
  } else {
    exec { "Remove rule ${display_name}":
      command  => $netsh_delete_cmd,
      provider => windows,
      unless   => $check_rule_existance,
    }
  }
}
