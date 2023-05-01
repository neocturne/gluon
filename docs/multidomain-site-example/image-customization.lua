features {
	'autoupdater',
	'nftables-filter-multicast',
	'nftables-filter-ra-dhcp',
	'nftables-limit-arp',
	'mesh-batman-adv-15',
	'mesh-vpn-fastd',
	'respondd',
	'status-page',
	'web-advanced',
	'web-wizard',
}

packages {
	'iwinfo',
}

if not device_class('tiny') then
	features {'wireless-encryption-wpa3'}
end
