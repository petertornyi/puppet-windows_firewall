class windows_firewall::config {

  # enable/disable firewall using Registry
	define firewall_service ($enabled) {

		# Set registry value to be used
		case $enabled {
			true  : { $data = '1' }
			false : { $data = '0' }
			default   : { fail('Unknown firewall state') }
		}

		$reg_base_path = 'HKLM\SYSTEM\ControlSet\services\SharedAccess\Parameters\FirewallPolicy'

		registry_value { 'EnableFirewall':
			ensure => 'present',
			path   => "${reg_base_path}\\${name}\\EnableFirewall",
			type   => 'dword',
			data   => $data
		}
	}
}