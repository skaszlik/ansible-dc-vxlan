import ipaddress


class Rule:
    id = "204"
    description = "Verify bootstrap configuration"
    severity = "HIGH"

    @classmethod
    def match(cls, data_model):
        results = []
        switches = []
        dhcp = None

        # Map fabric types to the keys used in the data model based on controller fabric types
        fabric_type_map = {
            "VXLAN_EVPN": "ibgp",
            "eBGP_VXLAN": "ebgp",
            "External": "external"
        }

        fabric_type = fabric_type_map.get(data_model['vxlan']['fabric']['type'])

        bootstrap_keys = ['vxlan', 'global', fabric_type]
        check = cls.data_model_key_check(data_model, bootstrap_keys)
        if fabric_type in check['keys_found']:
            bootstrap_keys = ['vxlan', 'global', fabric_type, 'bootstrap', 'enable_bootstrap']
            check = cls.data_model_key_check(data_model, bootstrap_keys)

        if fabric_type in check['keys_not_found'] or 'enable_bootstrap' in check['keys_not_found']:
            bootstrap_keys = ['vxlan', 'global', 'bootstrap', 'enable_bootstrap']
            check = cls.data_model_key_check(data_model, bootstrap_keys)

        if 'enable_bootstrap' in check['keys_found']:
            if fabric_type in bootstrap_keys:
                bootstrap_keys = ['vxlan', 'global', fabric_type, 'bootstrap', 'enable_local_dhcp_server']
            else:
                bootstrap_keys = ['vxlan', 'global', 'bootstrap', 'enable_local_dhcp_server']
            check = cls.data_model_key_check(data_model, bootstrap_keys)
            enable_local_dhcp_server = cls.safeget(data_model, bootstrap_keys)
            if 'enable_local_dhcp_server' in check['keys_found'] and enable_local_dhcp_server:
                if fabric_type in bootstrap_keys:
                    bootstrap_keys = ['vxlan', 'global', fabric_type, 'bootstrap', 'dhcp_version']
                else:
                    bootstrap_keys = ['vxlan', 'global', 'bootstrap', 'dhcp_version']
                check = cls.data_model_key_check(data_model, bootstrap_keys)
                if 'dhcp_version' in check['keys_found']:
                    if cls.safeget(data_model, bootstrap_keys) == 'DHCPv4':
                        dhcp = 'dhcp_v4'
                    elif cls.safeget(data_model, bootstrap_keys) == 'DHCPv6':
                        dhcp = 'dhcp_v6'
                else:
                    results.append(f"A vxlan.global.{fabric_type}.bootstrap.dhcp_version is required for bootstrap in a VXLAN type fabric.")
                    return results

        if dhcp:
            if fabric_type in bootstrap_keys:
                bootstrap_keys = ['vxlan', 'global', fabric_type, 'bootstrap', dhcp, 'domain_name']
            else:
                bootstrap_keys = ['vxlan', 'global', 'bootstrap', dhcp, 'domain_name']
            check = cls.data_model_key_check(data_model, bootstrap_keys)
            if dhcp in check['keys_not_found']:
                results.append(
                    "When vxlan.global.bootstrap.dhcp_version is defined, either "
                    "vxlan.global.bootstrap.dhcpv4 or vxlan.global.bootstrap.dhcpv6 must be defined in the data model."
                )
                return results

            if 'domain_name' in check['keys_found'] and fabric_type in ("ibgp", "ebgp"):
                results.append(f"vxlan.global.bootstrap.{dhcp}.domain_name is not supported for bootstrap in a VXLAN type fabric.")
            elif 'domain_name' in check['keys_not_found'] and fabric_type == "external":
                results.append(f"vxlan.global.bootstrap.{dhcp}.domain_name is required for bootstrap in an External type fabric.")

            # Validate DHCP multi_subnet_scope (NDFC BOOTSTRAP_MULTISUBNET) format and gateway uniqueness.
            if fabric_type in bootstrap_keys:
                dhcp_block = cls.safeget(data_model, ['vxlan', 'global', fabric_type, 'bootstrap', dhcp])
                multisubnet_path = f"vxlan.global.{fabric_type}.bootstrap.{dhcp}.multi_subnet_scope"
            else:
                dhcp_block = cls.safeget(data_model, ['vxlan', 'global', 'bootstrap', dhcp])
                multisubnet_path = f"vxlan.global.bootstrap.{dhcp}.multi_subnet_scope"
            if isinstance(dhcp_block, dict) and dhcp_block.get('multi_subnet_scope'):
                version = 4 if dhcp == 'dhcp_v4' else 6
                prefix_min, prefix_max = (8, 30) if version == 4 else (64, 126)
                results.extend(
                    cls.validate_multi_subnet_scope(
                        dhcp_block.get('multi_subnet_scope'),
                        dhcp_block.get('switch_mgmt_default_gw'),
                        version, prefix_min, prefix_max, multisubnet_path,
                    )
                )

        dm_check = cls.data_model_key_check(data_model, ['vxlan', 'topology', 'switches'])
        if 'switches' in dm_check['keys_data']:
            switches = data_model['vxlan']['topology']['switches']

        # Check if any switch has a poap key defined
        poap_switches = []
        for switch in switches:
            dm_check = cls.data_model_key_check(switch, ['poap'])
            if 'poap' in dm_check['keys_data']:
                poap_switches.append(switch['name'])

        if not poap_switches:
            return results

        enable_bootstrap = None
        bootstrap_enable_keys = ['vxlan', 'global', fabric_type, 'bootstrap', 'enable_bootstrap']
        check = cls.data_model_key_check(data_model, bootstrap_enable_keys)
        if 'enable_bootstrap' in check['keys_found']:
            enable_bootstrap = cls.safeget(data_model, bootstrap_enable_keys)

        # Fall back to the common path if not found under fabric-type-specific path
        if enable_bootstrap is None:
            bootstrap_enable_keys = ['vxlan', 'global', 'bootstrap', 'enable_bootstrap']
            check = cls.data_model_key_check(data_model, bootstrap_enable_keys)
            if 'enable_bootstrap' in check['keys_found']:
                enable_bootstrap = cls.safeget(data_model, bootstrap_enable_keys)

        if enable_bootstrap is not True:
            for switch_name in poap_switches:
                results.append(
                    f"vxlan.topology.switches.{switch_name} has poap defined but "
                    f"vxlan.global.bootstrap.enable_bootstrap is not set to true."
                )

        return results

    @classmethod
    def validate_multi_subnet_scope(cls, multi_subnet_scope, primary_gw, version, prefix_min, prefix_max, path):
        results = []
        seen_gateways = []

        for raw_line in str(multi_subnet_scope).splitlines():
            line = raw_line.strip()
            # Skip blank lines and NDFC comment lines (lines prefixed with #)
            if not line or line.startswith('#'):
                continue

            parts = [part.strip() for part in line.split(',')]
            if len(parts) != 4:
                results.append(
                    f"{path} scope '{line}' is not a valid NDFC BOOTSTRAP_MULTISUBNET entry. "
                    f"Each line must have exactly 4 comma-separated values formatted as "
                    f"'Start_IP, End_IP, Gateway, Prefix' (e.g. '10.6.0.2, 10.6.0.9, 10.6.0.1, 24'). "
                    f"Enter one subnet scope per line; lines starting with '#' are treated as comments and ignored."
                )
                continue

            start_ip, end_ip, gateway, prefix = parts

            for label, address in (("Start_IP", start_ip), ("End_IP", end_ip), ("Gateway", gateway)):
                if not cls.is_valid_ip(address, version):
                    results.append(
                        f"{path} scope '{line}' has an invalid IPv{version} {label} '{address}'."
                    )

            if not cls.is_valid_prefix(prefix, prefix_min, prefix_max):
                results.append(
                    f"{path} scope '{line}' has an invalid Prefix '{prefix}'. "
                    f"Expected an integer between {prefix_min} and {prefix_max}."
                )

            if cls.is_valid_ip(gateway, version):
                if primary_gw is not None and cls.same_ip(gateway, str(primary_gw)):
                    results.append(
                        f"{path} scope '{line}' gateway '{gateway}' must not be the same as the "
                        f"primary switch_mgmt_default_gw '{primary_gw}'. NDFC rejects repeated gateways."
                    )
                if any(cls.same_ip(gateway, seen) for seen in seen_gateways):
                    results.append(
                        f"{path} gateway '{gateway}' is repeated across multi_subnet_scope entries. "
                        f"Each subnet scope must use a unique gateway."
                    )
                seen_gateways.append(gateway)

        return results

    @classmethod
    def is_valid_ip(cls, address, version):
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return ip.version == version

    @classmethod
    def same_ip(cls, address_a, address_b):
        try:
            return ipaddress.ip_address(address_a) == ipaddress.ip_address(address_b)
        except ValueError:
            return address_a == address_b

    @classmethod
    def is_valid_prefix(cls, prefix, prefix_min, prefix_max):
        try:
            value = int(prefix)
        except (ValueError, TypeError):
            return False
        return prefix_min <= value <= prefix_max

    @classmethod
    def data_model_key_check(cls, tested_object, keys):
        dm_key_dict = {'keys_found': [], 'keys_not_found': [], 'keys_data': [], 'keys_no_data': []}
        for key in keys:
            if tested_object and key in tested_object:
                dm_key_dict['keys_found'].append(key)
                tested_object = tested_object[key]
                if tested_object:
                    dm_key_dict['keys_data'].append(key)
                else:
                    dm_key_dict['keys_no_data'].append(key)
            else:
                dm_key_dict['keys_not_found'].append(key)
        return dm_key_dict

    @classmethod
    def safeget(cls, dict, keys):
        # Utility function to safely get nested dictionary values
        for key in keys:
            if dict is None:
                return None
            if key in dict:
                dict = dict[key]
            else:
                return None

        return dict
