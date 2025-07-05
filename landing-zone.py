"""
Azure Infrastructure Visualizer with Landing Zone Selection, Monitoring, and DR.
"""
import os
import json
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.policyinsights import PolicyInsightsClient
from azure.mgmt.managementgroups import ManagementGroupsAPI
from azure.mgmt.security import SecurityCenter
from azure.mgmt.advisor import AdvisorManagementClient
from azure.mgmt.reservations import AzureReservationAPI
from azure.mgmt.resource import PolicyClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.avs import AVSClient
from azure.mgmt.trafficmanager import TrafficManagerManagementClient
from azure.mgmt.cdn import CdnManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.mgmt.sql import SqlManagementClient
import networkx as nx
from pyvis.network import Network
from flask import Flask, render_template, send_from_directory, jsonify, session, redirect, url_for, request

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session management.  Change this in production!

# --- Authentication Helper ---
def authenticate():
    """Authenticates to Azure using DefaultAzureCredential."""
    try:
        credential = DefaultAzureCredential()
        resource_client_temp = ResourceManagementClient(credential, 'common')
        subscriptions = list(resource_client_temp.subscriptions.list())
        if not subscriptions:
            raise Exception('No Azure subscriptions found or accessible. Please ensure you are logged in via `az login`.')
        subscription_id_env = os.environ.get('AZURE_SUBSCRIPTION_ID')
        current_subscription = None
        if subscription_id_env:
            for sub in subscriptions:
                if sub.id.split('/')[-1] == subscription_id_env:
                    current_subscription = sub
                    break
            if not current_subscription:
                print(f"Warning: AZURE_SUBSCRIPTION_ID '{subscription_id_env}' not found among accessible subscriptions. Using the first accessible subscription.")
                current_subscription = subscriptions[0]
        else:
            current_subscription = subscriptions[0]
        subscription_id = current_subscription.id.split('/')[-1]
        print(f'Using Azure Subscription: {current_subscription.display_name} (ID: {subscription_id})')
        network_client = NetworkManagementClient(credential, subscription_id)
        resource_client = ResourceManagementClient(credential, subscription_id)
        authorization_client = AuthorizationManagementClient(credential, subscription_id)
        policy_client = PolicyClient(credential, subscription_id)
        security_client = SecurityCenter(credential, subscription_id)
        advisor_client = AdvisorManagementClient(credential, subscription_id)
        monitor_client = MonitorManagementClient(credential, subscription_id)
        avs_client = AVSClient(credential, subscription_id)
        traffic_manager_client = TrafficManagerManagementClient(credential, subscription_id)
        front_door_client = CdnManagementClient(credential, subscription_id)
        compute_client = ComputeManagementClient(credential, subscription_id)
        storage_client = StorageManagementClient(credential, subscription_id)
        recovery_services_client = RecoveryServicesClient(credential, subscription_id)
        sql_client = SqlManagementClient(credential, subscription_id)
        management_groups_client = ManagementGroupsAPI(credential)
        reservations_client = AzureReservationAPI(credential)
        return (network_client, resource_client, authorization_client, policy_client, management_groups_client, security_client, advisor_client, reservations_client, current_subscription, monitor_client, avs_client, traffic_manager_client, front_door_client, compute_client, storage_client, recovery_services_client, sql_client)
    except Exception as e:
        print(f'Error authenticating to Azure: {e}')
        print('Please ensure you are logged in via Azure CLI (`az login`) or have appropriate environment variables set.')
        return None  # Indicate authentication failure

# --- Resource Discovery ---
def discover_azure_resources(network_client, authorization_client, policy_client, management_groups_client, security_client, advisor_client, reservations_client, current_subscription, monitor_client, avs_client, traffic_manager_client, front_door_client, compute_client, storage_client, recovery_services_client, sql_client):
    resources = {'management_groups': {}, 'subscriptions': {}, 'virtual_networks': {}, 'vnet_gateways': {}, 'vnet_peerings': {}, 'subnets': {}, 'virtual_wans': {}, 'virtual_hubs': {}, 'hub_connections': {}, 'route_tables': {}, 'nsgs': {}, 'policy_assignments': {}, 'role_assignments': {}, 'defender_for_cloud': {}, 'cost_advisor_recommendations': [], 'reservations': [], 'express_route_circuits': {}, 'local_network_gateways': {}, 'express_route_connections': {}, 'avs_private_clouds': {}, 'traffic_managers': {}, 'front_doors': {}, 'application_gateways': {}, 'public_load_balancers': {}, 'nat_gateways': {}, 'route_server': {}, 'virtual_machines': {}, 'storage_accounts': {}, 'private_load_balancers': {}}
    print('\n--- Discovering Azure Resources ---')
    print('Discovering Management Groups...')
    try:
        for mg in management_groups_client.management_groups.list():
            resources['management_groups'][mg.id] = mg
    except Exception as e:
        print(f'  Warning: Could not list Management Groups (permission issue?): {e}')
    resources['subscriptions'][current_subscription.id] = current_subscription
    try:
        sub_id_path = f"/subscriptions/{current_subscription.id.split('/')[-1]}"
        sub_details = management_groups_client.entities.get_subscription_info(subscription_id=sub_id_path)
        if sub_details and sub_details.parent_group_id:
            mg_full_id = f'/providers/Microsoft.Management/managementGroups/{sub_details.parent_group_id}'
            if mg_full_id not in resources['management_groups']:
                mg_placeholder = type('obj', (object,), {'id': mg_full_id, 'name': sub_details.parent_group_id, 'display_name': sub_details.parent_group_id, 'type': 'Microsoft.Management/managementGroups'})()
                resources['management_groups'][mg_full_id] = mg_placeholder
            resources['subscriptions'][current_subscription.id].parent_mg_id = mg_full_id
            print(f"  Subscription '{current_subscription.display_name}' linked to parent MG.")
    except Exception as e:
        print(f'  Warning: Could not determine parent Management Group for subscription: {e}')
    print('Discovering Virtual Networks and their Subnets/Peerings...')
    for vnet in network_client.virtual_networks.list_all():
        resources['virtual_networks'][vnet.id] = vnet
        for subnet in vnet.subnets:
            subnet.vnet_id = vnet.id
            resources['subnets'][subnet.id] = subnet
        if vnet.virtual_network_peerings:
            for peering in vnet.virtual_network_peerings:
                peering.vnet_id = vnet.id
                resources['vnet_peerings'][peering.id] = peering
    print('Discovering Virtual Network Gateways...')
    for gw in network_client.virtual_network_gateways.list_all():
        resources['vnet_gateways'][gw.id] = gw
        gw.monitoring_enabled = is_monitoring_enabled(monitor_client, gw.id)
    print('Discovering Virtual WANs, Hubs, and Connections...')
    for wan in network_client.virtual_wans.list_all():
        resources['virtual_wans'][wan.id] = wan
        if wan.virtual_hubs:
            for hub_ref in wan.virtual_hubs:
                hub_id = hub_ref.id
                try:
                    rg_name = hub_id.split('/resourceGroups/')[1].split('/providers/')[0]
                    hub_name = hub_id.split('/')[-1]
                    hub = network_client.virtual_hubs.get(resource_group_name=rg_name, virtual_hub_name=hub_name)
                    resources['virtual_hubs'][hub.id] = hub
                    if hub.virtual_hub_connections:
                        for conn in hub.virtual_hub_connections:
                            conn.hub_id = hub.id
                            resources['hub_connections'][conn.id] = conn
                except Exception as e:
                    print(f'  Warning: Could not fetch details for Virtual Hub {hub_id}: {e}')
    print('Discovering Route Tables...')
    for rt in network_client.route_tables.list_all():
        resources['route_tables'][rt.id] = rt
    print('Discovering Network Security Groups (and their rules)...')
    for nsg in network_client.network_security_groups.list_all():
        resources['nsgs'][nsg.id] = nsg
        nsg.security_rule_summary = {'inbound_allow_any_source': False, 'inbound_allow_any_port': False, 'outbound_allow_any_destination': False, 'total_rules': len(nsg.security_rules) if nsg.security_rules else 0}
        if nsg.security_rules:
            for rule in nsg.security_rules:
                if rule.direction == 'Inbound' and rule.access == 'Allow':
                    if rule.source_address_prefix in ('*', 'Internet') or '0.0.0.0/0' in (rule.source_address_prefixes or []):
                        nsg.security_rule_summary['inbound_allow_any_source'] = True
                    if rule.destination_port_range == '*' or rule.destination_port_ranges == ['*']:
                        nsg.security_rule_summary['inbound_allow_any_port'] = True
                elif rule.direction == 'Outbound' and rule.access == 'Allow':
                    if rule.destination_address_prefix in ('*', 'Internet') or '0.0.0.0/0' in (rule.destination_address_prefixes or []):
                        nsg.security_rule_summary['outbound_allow_any_destination'] = True
    print('Discovering Express Route Circuits...')
    for circuit in network_client.express_route_circuits.list_all():
        resources['express_route_circuits'][circuit.id] = circuit
        circuit.monitoring_enabled = is_monitoring_enabled(monitor_client, circuit.id)
    print('Discovering Local Network Gateways...')
    for lgw in network_client.local_network_gateways.list_all():
        resources['local_network_gateways'][lgw.id] = lgw
    print('Discovering Express Route Connections...')
    for circuit in resources['express_route_circuits'].values():
        if circuit.peerings:
            for peering in circuit.peerings:
                if peering.connections:
                    for connection in peering.connections:
                        resources['express_route_connections'][connection.id] = connection
    print('Discovering Azure VMware Solution (AVS) Private Clouds...')
    try:
        for avs in avs_client.private_clouds.list():
            resources['avs_private_clouds'][avs.id] = avs
    except Exception as e:
        print(f'  Warning: Could not list AVS Private Clouds (permission issue?): {e}')
    print('Discovering Traffic Managers...')
    try:
        for tm in traffic_manager_client.profiles.list_all():
            resources['traffic_managers'][tm.id] = tm
            tm.degraded_endpoints = any((ep.monitor_status == 'Degraded' for ep in tm.endpoints if tm.endpoints is not None))
    except Exception as e:
        print(f'  Warning: Could not list Traffic Managers: {e}')
    print('Discovering Azure Front Doors...')
    try:
        for fd in front_door_client.front_doors.list():
            resources['front_doors'][fd.id] = fd
            fd.waf_enabled = any((fd.frontend_endpoints[i].web_application_firewall_policy is not None for i in range(len(fd.frontend_endpoints)) if fd.frontend_endpoints is not None))
    except Exception as e:
        print(f'  Warning: Could not list Front Doors: {e}')
    print('Discovering Application Gateways...')
    try:
        for agw in network_client.application_gateways.list_all():
            resources['application_gateways'][agw.id] = agw
            agw.waf_enabled = agw.web_application_firewall_configuration is not None and agw.web_application_firewall_configuration.enabled
    except Exception as e:
        print(f'  Warning: Could not list Application Gateways: {e}')
    print('Discovering Public Load Balancers...')
    try:
        for lb in network_client.load_balancers.list_all():
            resources['public_load_balancers'][lb.id] = lb
            lb.nsg_associated = any((be.network_security_group is not None for be in lb.backend_address_pools if lb.backend_address_pools is not None))
    except Exception as e:
        print(f'  Warning: Could not list Public Load Balancers: {e}')
    print('Discovering NAT Gateways...')
    try:
        for ngw in network_client.nat_gateways.list_all():
            resources['nat_gateways'][ngw.id] = ngw
            ngw.idle_timeout_configured = ngw.idle_timeout_in_minutes is not None
    except Exception as e:
        print(f'  Warning: Could not list NAT Gateways: {e}')
    print('Discovering Route Server...')
    try:
        for rs in network_client.route_servers.list_all():
            resources['route_server'][rs.id] = rs
            rs.peerings_configured = rs.peerings is not None and len(rs.peerings) > 0
    except Exception as e:
        print(f'  Warning: Could not list Route Server: {e}')
    print('Discovering Virtual Machines...')
    try:
        for vm in compute_client.virtual_machines.list_all():
            rg = vm.id.split('/')[4]
            vm_details = compute_client.virtual_machines.get(rg, vm.name)
            vm.backup_enabled = False
            vm.monitoring_enabled = is_monitoring_enabled(monitor_client, vm.id)
            resources['virtual_machines'][vm.id] = vm_details
    except Exception as e:
        print(f'  Warning: Could not list Virtual Machines: {e}')
    print('Discovering Storage Accounts...')
    try:
        for sa in storage_client.storage_accounts.list():
            rg = sa.id.split('/')[4]
            sa_details = storage_client.storage_accounts.get_properties(rg, sa.name).resource
            sa.backup_enabled = False
            resources['storage_accounts'][sa.id] = sa_details
    except Exception as e:
        print(f'  Warning: Could not list Storage Accounts: {e}')
    print('Discovering Private Load Balancers...')
    try:
        for lb in network_client.load_balancers.list_all():
            if lb.type == 'Internal':
                resources['private_load_balancers'][lb.id] = lb
    except Exception as e:
        print(f'  Warning: Could not list Private Load Balancers: {e}')
    print('Discovering Azure Policy Assignments (at MG and Subscription scopes)...')
    try:
        for policy_assignment in policy_client.policy_assignments.list():
            resources['policy_assignments'][policy_assignment.id] = policy_assignment
        for (mg_id, mg) in resources['management_groups'].items():
            try:
                for pa in policy_client.policy_assignments.list_for_management_group(management_group_id=mg.name):
                    resources['policy_assignments'][pa.id] = pa
            except Exception as e:
                print(f"  Warning: Could not list policies for Management Group '{mg.name}': {e}")
    except Exception as e:
        print(f'  Warning: Could not list Policy Assignments (permission issue?): {e}')
    print('Discovering IAM Role Assignments (at MG and Subscription scopes)...')
    try:
        for ra in authorization_client.role_assignments.list():
            resources['role_assignments'][ra.id] = ra
        for mg_id in resources['management_groups']:
            try:
                for ra in authorization_client.role_assignments.list_for_scope(scope=mg_id):
                    resources['role_assignments'][ra.id] = ra
            except Exception as e:
                print(f"  Warning: Could not list Role Assignments for Management Group '{resources['management_groups'][mg_id].name}': {e}")
    except Exception as e:
        print(f'  Warning: Could not list Role Assignments (permission issue?): {e}')
    print('Discovering Azure Security Center (Defender for Cloud) data...')
    try:
        secure_score_summary = None
        for score in security_client.security_scores.list():
            if score.id.endswith('securityScores/asc_default'):
                secure_score_summary = {'current_score': score.score.current, 'max_score': score.score.max, 'percentage': score.score.percentage, 'unhealthy_resource_count': score.score.unhealthy_resource_count}
                break
        high_severity_recommendations = 0
        total_recommendations = 0
        all_assessments = list(security_client.assessments.list())
        for assessment in all_assessments:
            total_recommendations += 1
            if assessment.status and assessment.status.code == 'Unhealthy' and (assessment.status.cause == 'High'):
                high_severity_recommendations += 1
        resources['defender_for_cloud'][current_subscription.id] = {'secure_score_summary': secure_score_summary, 'high_severity_recommendations': high_severity_recommendations, 'total_recommendations': total_recommendations, 'assessments': all_assessments}
    except Exception as e:
        print(f'  Warning: Could not list Azure Security Center data (permission issue?): {e}')
    print('Discovering Azure Cost Advisor recommendations...')
    try:
        cost_recommendations = list(advisor_client.recommendations.list(filter="category eq 'Cost'"))
        resources['cost_advisor_recommendations'] = cost_recommendations
    except Exception as e:
        print(f'  Warning: Could not list Azure Cost Advisor recommendations (permission issue?): {e}')
    print('Discovering Azure Reservations...')
    try:
        reservations = list(reservations_client.reservation.list_all())
        resources['reservations'] = reservations
    except Exception as e:
        print(f'  Warning: Could not list Azure Reservations (permission issue?): {e}')
    print('\n--- Discovery Summary ---')
    print(f"  Management Groups: {len(resources['management_groups'])}")
    print(f"  Subscriptions: {len(resources['subscriptions'])}")
    print(f"  Virtual Networks: {len(resources['virtual_networks'])}")
    print(f"  Subnets: {len(resources['subnets'])}")
    print(f"  VNet Gateways: {len(resources['vnet_gateways'])}")
    print(f"  VNet Peerings: {len(resources['vnet_peerings'])}")
    print(f"  Virtual WANs: {len(resources['virtual_wans'])}")
    print(f"  Virtual Hubs: {len(resources['virtual_hubs'])}")
    print(f"  Hub Connections: {len(resources['hub_connections'])}")
    print(f"  Route Tables: {len(resources['route_tables'])}")
    print(f"  Network Security Groups: {len(resources['nsgs'])}")
    print(f"  Policy Assignments: {len(resources['policy_assignments'])}")
    print(f"  Role Assignments (total): {len(resources['role_assignments'])}")
    print(f"  Defender for Cloud Status (for current sub): {('Present' if resources['defender_for_cloud'] else 'Not Found')}")
    print(f"  Cost Advisor Recommendations: {len(resources['cost_advisor_recommendations'])}")
    print(f"  Azure Reservations: {len(resources['reservations'])}")
    print(f"  Express Route Circuits: {len(resources['express_route_circuits'])}")
    print(f"  Local Network Gateways: {len(resources['local_network_gateways'])}")
    print(f"  Express Route Connections: {len(resources['express_route_connections'])}")
    print(f"  AVS Private Clouds: {len(resources['avs_private_clouds'])}")
    print(f"  Traffic Managers: {len(resources['traffic_managers'])}")
    print(f"  Front Doors: {len(resources['front_doors'])}")
    print(f"  Application Gateways: {len(resources['application_gateways'])}")
    print(f"  Public Load Balancers: {len(resources['public_load_balancers'])}")
    print(f"  NAT Gateways: {len(resources['nat_gateways'])}")
    print(f"  Route Server: {len(resources['route_server'])}")
    print(f"  Virtual Machines: {len(resources['virtual_machines'])}")
    print(f"  Storage Accounts: {len(resources['storage_accounts'])}")
    print(f"  Private Load Balancers: {len(resources['private_load_balancers'])}")
    return resources

# --- Monitoring Status ---
def is_monitoring_enabled(monitor_client, resource_id):
    try:
        settings = list(monitor_client.diagnostic_settings.list(resource_id))
        return len(settings) > 0
    except Exception as e:
        print(f'  Warning: Could not check monitoring status for {resource_id}: {e}')
        return False

# --- Dependency Graph ---
def build_dependency_graph(resources, current_subscription_id):
    G = nx.DiGraph()
    print('\n--- Mapping Dependencies and Building Graph ---')
    color_map = {'management_groups': '#FF6347', 'subscriptions': '#4682B4', 'virtual_networks': '#6A5ACD', 'subnets': '#ADD8E6', 'vnet_gateways': '#FFD700', 'vnet_peerings': '#FFA07A', 'virtual_wans': '#8A2BE2', 'virtual_hubs': '#DA70D6', 'hub_connections': '#FF69B4', 'route_tables': '#32CD32', 'nsgs': '#FF4500', 'policy_assignments': '#1E90FF', 'defender_for_cloud': '#8B008B', 'express_route_circuits': '#008080', 'local_network_gateways': '#A0522D', 'express_route_connections': '#D2691E', 'avs_private_clouds': '#00CED1', 'traffic_managers': '#F08080', 'front_doors': '#98FB98', 'application_gateways': '#BDB76B', 'public_load_balancers': '#E9967A', 'nat_gateways': '#8FBC8F', 'route_server': '#BC8F8F', 'virtual_machines': '#FF7F50', 'storage_accounts': '#87CEEB', 'private_load_balancers': '#FFA07A', 'default': '#CCCCCC'}
    shape_map = {'management_groups': 'diamond', 'subscriptions': 'box', 'virtual_networks': 'box', 'virtual_wans': 'box', 'virtual_hubs': 'box', 'policy_assignments': 'star', 'defender_for_cloud': 'triangle', 'express_route_circuits': 'circle', 'local_network_gateways': 'square', 'express_route_connections': 'triangle', 'avs_private_clouds': 'hexagon', 'traffic_managers': 'ellipse', 'front_doors': 'invtriangle', 'application_gateways': 'octagon', 'public_load_balancers': 'vee', 'nat_gateways': 'invvee', 'route_server': 'parallelogram', 'virtual_machines': 'house', 'storage_accounts': 'cylinder', 'private_load_balancers': 'vee', 'default': 'dot'}
    for (res_type, res_dict_or_list) in resources.items():
        if res_type in ['role_assignments', 'cost_advisor_recommendations', 'reservations', 'virtual_machines', 'storage_accounts', 'private_load_balancers']:
            continue
        if res_type == 'defender_for_cloud':
            for (sub_id, data) in res_dict_or_list.items():
                if sub_id != current_subscription_id:
                    continue
                node_id = f"defender_for_cloud_{sub_id.split('/')[-1]}"
                node_label = 'Defender for Cloud'
                title_info = f"Type: Defender for Cloud\nScope: Subscription {sub_id.split('/')[-1]}"
                if data.get('secure_score_summary'):
                    score = data['secure_score_summary']
                    title_info += f"\nSecure Score: {score['current_score']}/{score['max_score']} ({score['percentage']:.2f}%)"
                    title_info += f"\nUnhealthy Resources: {score['unhealthy_resource_count']}"
                title_info += f"\nHigh Severity Recommendations: {data.get('high_severity_recommendations', 0)}"
                title_info += f"\nTotal Recommendations: {data.get('total_recommendations', 0)}"
                title_info += '\n(See JSON report for details)'
                G.add_node(node_id, label=node_label, type='Defender for Cloud', group='defender_for_cloud', color=color_map['defender_for_cloud'], shape=shape_map['defender_for_cloud'], title=title_info)
                if sub_id in G:
                    G.add_edge(sub_id, node_id, label='managed by')
            continue
        for (res_id, res_obj) in res_dict_or_list.items():
            node_label = res_obj.name
            node_type_display = res_type.replace('_', ' ').title()
            title_info = f'Type: {node_type_display}\nName: {res_obj.name}\nID: {res_id}'
            if res_type == 'subnets':
                vnet_name = resources['virtual_networks'].get(res_obj.vnet_id).name if res_obj.vnet_id in resources['virtual_networks'] else 'Unknown VNet'
                node_label = f'Subnet: {res_obj.name}\n({vnet_name})'
            elif res_type == 'vnet_peerings':
                vnet_name = resources['virtual_networks'].get(res_obj.vnet_id).name if res_obj.vnet_id in resources['virtual_networks'] else 'Unknown VNet'
                node_label = f'Peering: {res_obj.name}\n({vnet_name})'
            elif res_type == 'hub_connections':
                hub_name = resources['virtual_hubs'].get(res_obj.hub_id).name if res_obj.hub_id in resources['virtual_hubs'] else 'Unknown Hub'
                node_label = f'Conn: {res_obj.name}\n({hub_name})'
            elif res_type == 'nsgs':
                nsg_summary = res_obj.security_rule_summary
                node_label = f'NSG: {res_obj.name}'
                title_info += '\n\n--- NSG Rules Summary ---\n'
                title_info += f"  Total Rules: {nsg_summary['total_rules']}\n"
                if nsg_summary['inbound_allow_any_source']:
                    title_info += "  RISK: Inbound 'Allow' from Any Source (e.g., Internet)\n"
                if nsg_summary['inbound_allow_any_port']:
                    title_info += "  RISK: Inbound 'Allow' to Any Port (*)\n"
                if nsg_summary['outbound_allow_any_destination']:
                    title_info += "  RISK: Outbound 'Allow' to Any Destination (e.g., Internet)\n"
            elif res_type == 'policy_assignments':
                node_label = f'Policy: {res_obj.display_name or res_obj.name}'
                title_info += f"\nDescription: {res_obj.description or 'N/A'}"
                title_info += f'\nScope: {res_obj.scope}'
                title_info += f"\nPolicy Definition: {res_obj.policy_definition_id.split('/')[-1]}"
                title_info += f"\nEnforcement Mode: {res_obj.enforcement_mode or 'Default'}"
            elif res_type == 'subscriptions':
                node_label = f'Subscription: {res_obj.display_name or res_obj.name}'
            elif res_type == 'management_groups':
                node_label = f'MG: {res_obj.display_name or res_obj.name}'
            elif res_type == 'vnet_gateways':
                node_label = f'VNet GW: {res_obj.name}'
                title_info += f'\nMonitoring Enabled: {res_obj.monitoring_enabled}'
            elif res_type == 'express_route_circuits':
                node_label = f'ER Circuit: {res_obj.name}'
                title_info += f'\nMonitoring Enabled: {res_obj.monitoring_enabled}'
            elif res_type == 'local_network_gateways':
                node_label = f'Local GW: {res_obj.name}'
            elif res_type == 'express_route_connections':
                node_label = f'ER Connection: {res_obj.name}'
            elif res_type == 'avs_private_clouds':
                node_label = f'AVS: {res_obj.name}'
            elif res_type == 'traffic_managers':
                node_label = f'TM: {res_obj.name}'
                title_info += f'\nDegraded Endpoints: {res_obj.degraded_endpoints}'
            elif res_type == 'front_doors':
                node_label = f'FD: {res_obj.name}'
                title_info += f'\nWAF Enabled: {res_obj.waf_enabled}'
            elif res_type == 'application_gateways':
                node_label = f'AGW: {res_obj.name}'
                title_info += f'\nWAF Enabled: {res_obj.waf_enabled}'
            elif res_type == 'public_load_balancers':
                node_label = f'LB: {res_obj.name}'
                title_info += f'\nNSG Associated: {res_obj.nsg_associated}'
            elif res_type == 'nat_gateways':
                node_label = f'NAT GW: {res_obj.name}'
                title_info += f'\nIdle Timeout Configured: {res_obj.idle_timeout_configured}'
            elif res_type == 'route_server':
                node_label = f'Route Server: {res_obj.name}'
                title_info += f'\nPeerings Configured: {res_obj.peerings_configured}'
            G.add_node(res_id, label=node_label, type=node_type_display, group=res_type, color=color_map.get(res_type, color_map['default']), shape=shape_map.get(res_type, shape_map['default']), title=title_info)
    for (sub_id, sub) in resources['subscriptions'].items():
        if hasattr(sub, 'parent_mg_id') and sub.parent_mg_id in G:
            G.add_edge(sub.parent_mg_id, sub_id, label='contains')
    for (vnet_id, vnet) in resources['virtual_networks'].items():
        sub_id_from_vnet = '/subscriptions/' + vnet.id.split('/subscriptions/')[1].split('/')[0]
        if sub_id_from_vnet in G:
            G.add_edge(sub_id_from_vnet, vnet_id, label='owns')
        else:
            print((f'  Warning: V'
f'net {vnet.name} is in a subscription ({sub_id_from_vnet}) not added to graph.'))
    for (pa_id, pa) in resources['policy_assignments'].items():
        scope_id = pa.scope
        if scope_id.startswith('/providers/Microsoft.Management/managementGroups/'):
            if scope_id in G:
                G.add_edge(scope_id, pa_id, label='assigned to')
        elif scope_id.startswith('/subscriptions/'):
            sub_id = '/subscriptions/' + scope_id.split('/subscriptions/')[1].split('/')[0]
            if sub_id in G:
                G.add_edge(sub_id, pa_id, label='assigned to')
    for (vnet_id, vnet) in resources['virtual_networks'].items():
        for subnet in vnet.subnets:
            if subnet.id in G:
                G.add_edge(vnet_id, subnet.id, label='contains')
    for (subnet_id, subnet) in resources['subnets'].items():
        if subnet.network_security_group and subnet.network_security_group.id in G:
            G.add_edge(subnet_id, subnet.network_security_group.id, label='secured by')
    for (subnet_id, subnet) in resources['subnets'].items():
        if subnet.route_table and subnet.route_table.id in G:
            G.add_edge(subnet_id, subnet.route_table.id, label='routes via')
    for (gw_id, gw) in resources['vnet_gateways'].items():
        if gw.ip_configurations:
            for ip_config in gw.ip_configurations:
                if ip_config.subnet and ip_config.subnet.id in G:
                    G.add_edge(gw_id, ip_config.subnet.id, label='uses subnet')
    for (peering_id, peering) in resources['vnet_peerings'].items():
        if peering.remote_virtual_network and peering.remote_virtual_network.id in G:
            if peering.vnet_id in G:
                G.add_edge(peering.vnet_id, peering_id, label='has peering')
            if peering_id in G and peering.remote_virtual_network.id in G:
                G.add_edge(peering_id, peering.remote_virtual_network.id, label='peers with')
        else:
            print(f'  Warning: Peering "{peering.name}" has no valid remote VNet or remote VNet not found.')
    for (wan_id, wan) in resources['virtual_wans'].items():
        if wan.virtual_hubs:
            for hub_ref in wan.virtual_hubs:
                hub_id = hub_ref.id
                if hub_id in resources['virtual_hubs'] and wan_id in G and (hub_id in G):
                    G.add_edge(wan_id, hub_id, label='contains hub')
                    hub = resources['virtual_hubs'][hub_id]
                    if hub.virtual_hub_connections:
                        for conn in hub.virtual_hub_connections:
                            conn_id = conn.id
                            if conn_id in resources['hub_connections'] and hub_id in G and (conn_id in G):
                                G.add_edge(hub_id, conn_id, label='has connection')
                                if conn.remote_virtual_network and conn.remote_virtual_network.id in resources['virtual_networks'] and (conn_id in G) and (conn.remote_virtual_network.id in G):
                                    G.add_edge(conn_id, conn.remote_virtual_network.id, label='connects to VNet')
                                else:
                                    print(f'  Warning: Hub connection "{conn.name}" has no valid remote VNet or VNet not found.')
    for (circuit_id, circuit) in resources['express_route_circuits'].items():
        if circuit.peerings:
            for peering in circuit.peerings:
                if peering.connections:
                    for connection in peering.connections:
                        conn_id = connection.id
                        if conn_id in resources['express_route_connections'] and circuit_id in G and (conn_id in G):
                            G.add_edge(circuit_id, conn_id, label='has connection')
                            if connection.remote_virtual_network_id and connection.remote_virtual_network_id in resources['virtual_networks'] and (conn_id in G) and (connection.remote_virtual_network_id in G):
                                G.add_edge(conn_id, connection.remote_virtual_network_id, label='connects to VNet')
                            else:
                                print(f'  Warning: Express Route connection "{connection.name}" has no valid remote VNet or VNet not found.')
    for (lgw_id, lgw) in resources['local_network_gateways'].items():
        if lgw.express_route_connections:
            for conn in lgw.express_route_connections:
                if conn.id in resources['express_route_connections'] and lgw_id in G and (conn.id in G):
                    G.add_edge(lgw_id, conn.id, label='connects to')
    for (avs_id, avs) in resources['avs_private_clouds'].items():
        sub_id_from_avs = '/subscriptions/' + avs.id.split('/subscriptions/')[1].split('/')[0]
        if sub_id_from_avs in G:
            G.add_edge(sub_id_from_avs, avs_id, label='contains')
        else:
            print(f'  Warning: AVS Private Cloud {avs.name} is in a subscription ({sub_id_from_avs}) not added to graph.')
    for (tm_id, tm) in resources['traffic_managers'].items():
        sub_id_from_tm = '/subscriptions/' + tm.id.split('/subscriptions/')[1].split('/')[0]
        if sub_id_from_tm in G:
            G.add_edge(sub_id_from_tm, tm_id, label='contains')
        else:
            print(f'  Warning: Traffic Manager {tm.name} is in a subscription ({sub_id_from_tm}) not added to graph.')
    for (fd_id, fd) in resources['front_doors'].items():
        sub_id_from_fd = '/subscriptions/' + fd.id.split('/subscriptions/')[1].split('/')[0]
        if sub_id_from_fd in G:
            G.add_edge(sub_id_from_fd, fd_id, label='contains')
        else:
            print(f'  Warning: Front Door {fd.name} is in a subscription ({sub_id_from_fd}) not added to graph.')
    for (agw_id, agw) in resources['application_gateways'].items():
        sub_id_from_agw = '/subscriptions/' + agw.id.split('/subscriptions/')[1].split('/')[0]
        if sub_id_from_agw in G:
            G.add_edge(sub_id_from_agw, agw_id, label='contains')
        else:
            print(f'  Warning: Application Gateway {agw.name} is in a subscription ({sub_id_from_agw}) not added to graph.')
    for (lb_id, lb) in resources['public_load_balancers'].items():
        sub_id_from_lb = '/subscriptions/' + lb.id.split('/subscriptions/')[1].split('/')[0]
        if sub_id_from_lb in G:
            G.add_edge(sub_id_from_lb, lb_id, label='contains')
        else:
            print(f'  Warning: Public Load Balancer {lb.name} is in a subscription ({sub_id_from_lb}) not added to graph.')
    for (ngw_id, ngw) in resources['nat_gateways'].items():
        sub_id_from_ngw = '/subscriptions/' + ngw.id.split('/subscriptions/')[1].split('/')[0]
        if sub_id_from_ngw in G:
            G.add_edge(sub_id_from_ngw, ngw_id, label='contains')
        else:
            print(f'  Warning: NAT Gateway {ngw.name} is in a subscription ({sub_id_from_ngw}) not added to graph.')
    for (rs_id, rs) in resources['route_server'].items():
        sub_id_from_rs = '/subscriptions/' + rs.id.split('/subscriptions/')[1].split('/')[0]
        if sub_id_from_rs in G:
            G.add_edge(sub_id_from_rs, rs_id, label='contains')
        else:
            print(f'  Warning: Route Server {rs.name} is in a subscription ({sub_id_from_rs}) not added to graph.')
    for (vm_id, vm) in resources['virtual_machines'].items():
        sub_id_from_vm = '/subscriptions/' + vm.id.split('/subscriptions/')[1].split('/')[0]
        if sub_id_from_vm in G:
            G.add_edge(sub_id_from_vm, vm_id, label='contains')
        else:
            print(f'  Warning: Virtual Machine {vm.name} is in a subscription ({sub_id_from_vm}) not added to graph.')
    for (sa_id, sa) in resources['storage_accounts'].items():
        sub_id_from_sa = '/subscriptions/' + sa.id.split('/subscriptions/')[1].split('/')[0]
        if sub_id_from_sa in G:
            G.add_edge(sub_id_from_sa, sa_id, label='contains')
        else:
            print(f'  Warning: Storage Account {sa.name} is in a subscription ({sub_id_from_sa}) not added to graph.')
    for (lb_id, lb) in resources['private_load_balancers'].items():
        sub_id_from_lb = '/subscriptions/' + lb.id.split('/subscriptions/')[1].split('/')[0]
        if sub_id_from_lb in G:
            G.add_edge(sub_id_from_lb, lb_id, label='contains')
        else:
            print(f'  Warning: Private Load Balancer {lb.name} is in a subscription ({sub_id_from_lb}) not added to graph.')
    print(f'Graph built with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges.')
    return G

# --- Monitoring Status ---
def get_alert_rules(monitor_client, resource_id):
    try:
        alert_rules = list(monitor_client.alert_rules.list_by_resource_group(resource_id))
        return alert_rules
    except Exception as e:
        print(f'  Warning: Could not list alert rules for {resource_id}: {e}')
        return []

def get_dr_status(resources):
    dr_status = {
        'virtual_machines': {},
        'storage_accounts': {},
        'sql_databases': {},
        'virtual_networks': {}
    }

    # Virtual Machines
    for vm_id, vm in resources['virtual_machines'].items():
        rg = vm.id.split('/')[4]
        try:
            vm_details = compute_client.virtual_machines.get(rg, vm.name)
            dr_status['virtual_machines'][vm_id] = {
                'name': vm.name,
                'replication_enabled': hasattr(vm_details, 'extended_location') and vm_details.extended_location.type == 'Recovery'
            }
        except Exception as e:
            print(f'  Warning: Could not get DR status for VM {vm.name}: {e}')
            dr_status['virtual_machines'][vm_id] = {
                'name': vm.name,
                'replication_enabled': False
            }

    # Storage Accounts
    for sa_id, sa in resources['storage_accounts'].items():
        rg = sa.id.split('/')[4]
        try:
            sa_details = storage_client.storage_accounts.get_properties(rg, sa.name)
            dr_status['storage_accounts'][sa_id] = {
                'name': sa.name,
                'redundancy': sa_details.sku.name
            }
        except Exception as e:
            print(f'  Warning: Could not get DR status for Storage Account {sa.name}: {e}')
            dr_status['storage_accounts'][sa_id] = {
                'name': sa.name,
                'redundancy': 'Unknown'
            }

    # SQL Databases
    for sub_id, sub in resources['subscriptions'].items():
        try:
            for db in sql_client.databases.list_by_server(sub.id.split('/')[4], sub.id.split('/')[8]):
                db_id = db.id
                dr_status['sql_databases'][db_id] = {
                    'name': db.name,
                    'geo_backup_enabled': db.geo_backup_enabled,
                    'active_geo_replica_link_id': db.active_geo_replica_link_id
                }
        except Exception as e:
            print(f'  Warning: Could not get DR status for SQL Databases in Subscription {sub.display_name}: {e}')

    # Virtual Networks
    for vnet_id, vnet in resources['virtual_networks'].items():
        try:
            # Assuming a secondary VNet in a different region is considered DR-enabled
            sub_id = '/subscriptions/' + vnet.id.split('/subscriptions/')[1].split('/')[0]
            vnet_list = list(network_client.virtual_networks.list_all())
            secondary_vnets = [v for v in vnet_list if v.location != vnet.location and v.subscription_id == sub_id]
            dr_status['virtual_networks'][vnet_id] = {
                'name': vnet.name,
                'secondary_vnets': [v.name for v in secondary_vnets]
            }
        except Exception as e:
            print(f'  Warning: Could not get DR status for Virtual Network {vnet.name}: {e}')
            dr_status['virtual_networks'][vnet_id] = {
                'name': vnet.name,
                'secondary_vnets': []
            }

    return dr_status

# --- Visualization and Reporting ---
def visualize_graph(graph, output_filename='azure_network_dependencies_extended.html'):
    net = Network(notebook=True, height='800px', width='100%', bgcolor='#222222', font_color='white', cdn_resources='remote', select_menu=True, filter_menu=True)
    for (node_id, attrs) in graph.nodes(data=True):
        net.add_node(node_id, label=attrs['label'], title=attrs['title'], group=attrs['group'], color=attrs['color'], shape=attrs['shape'])
    for (source, target, attrs) in graph.edges(data=True):
        net.add_edge(source, target, title=attrs.get('label', ''), label=attrs.get('label', ''), color='#CCCCCC', arrows='to')
    net.set_options('\n    var options = {\n      "physics": {\n        "enabled": true,\n        "barnesHut": {\n          "gravitationalConstant": -3000,\n          "centralGravity": 0.2,\n          "springLength": 120,\n          "springConstant": 0.05,\n          "damping": 0.1,\n          "avoidOverlap": 0.2\n        },\n        "maxVelocity": 50,\n        "minVelocity": 0.1,\n        "solver": "barnesHut",\n        "stabilization": {\n          "enabled": true,\n          "iterations": 1000,\n          "updateInterval": 25,\n          "onlyDynamicEdges": false,\n          "fit": true\n        },\n        "timestep": 0.5,\n        "adaptiveTimestep": true\n      },\n      "interaction": {\n        "hover": true,\n        "navigationButtons": true,\n        "zoomView": true\n      },\n      "nodes": {\n        "font": {\n          "size": 12\n        }\n      },\n      "edges": {\n        "font": {\n          "size": 10,\n          "align": "top"\n        },\n        "smooth": {\n          "type": "continuous"\n        }\n      }\n    }\n    ')
    print('\n--- Generating Visualization ---')
    print(f'Saving interactive graph to {output_filename}...')
    net.show(output_filename)
    print('Visualization complete. Open the HTML file in your web browser to view the report.')

class AzureResourceEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, '__dict__'):
            return {k: v for (k, v) in obj.__dict__.items() if not k.startswith('_')}
        return json.JSONEncoder.default(self, obj)

@app.route('/')
def index():
    if 'landing_zone_selected' not in session:
        return render_template('landing_zone_selection.html')
    elif session['landing_zone_selected']:
        (network_client, resource_client, authorization_client, policy_client, management_groups_client, security_client, advisor_client, reservations_client, current_subscription, monitor_client, avs_client, traffic_manager_client, front_door_client, compute_client, storage_client, recovery_services_client, sql_client) = authenticate()
        if network_client:
            resources = discover_azure_resources(network_client, authorization_client, policy_client, management_groups_client, security_client, advisor_client, reservations_client, current_subscription, monitor_client, avs_client, traffic_manager_client, front_door_client, compute_client, storage_client, recovery_services_client, sql_client)
            dependency_graph = build_dependency_graph(resources, current_subscription.id)
            if dependency_graph.nodes:
                visualize_graph(dependency_graph)
            else:
                print('No resources found in the subscription to visualize.')
            return render_template('index.html')
        else:
            return 'Error: Could not authenticate to Azure. Please check your credentials and try again.'
    else:
        return 'Closing browser as per your request.'

@app.route('/monitoring')
def monitoring():
    (network_client, resource_client, authorization_client, policy_client, management_groups_client, security_client, advisor_client, reservations_client, current_subscription, monitor_client, avs_client, traffic_manager_client, front_door_client, compute_client, storage_client, recovery_services_client, sql_client) = authenticate()
    resources = discover_azure_resources(network_client, authorization_client, policy_client, management_groups_client, security_client, advisor_client, reservations_client, current_subscription, monitor_client, avs_client, traffic_manager_client, front_door_client, compute_client, storage_client, recovery_services_client, sql_client)
    alert_rules = {}
    for res_type, res_dict in resources.items():
        for res_id, res_obj in res_dict.items():
            alert_rules[res_id] = get_alert_rules(monitor_client, res_id)
    return render_template('monitoring.html', alert_rules=alert_rules)

@app.route('/dr')
def dr():
    (network_client, resource_client, authorization_client, policy_client, management_groups_client, security_client, advisor_client, reservations_client, current_subscription, monitor_client, avs_client, traffic_manager_client, front_door_client, compute_client, storage_client, recovery_services_client, sql_client) = authenticate()
    resources = discover_azure_resources(network_client, authorization_client, policy_client, management_groups_client, security_client, advisor_client, reservations_client, current_subscription, monitor_client, avs_client, traffic_manager_client, front_door_client, compute_client, storage_client, recovery_services_client, sql_client)
    dr_status = get_dr_status(resources)
    return render_template('dr.html', dr_status=dr_status)

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory('.', filename)

@app.route('/api/resources')
def get_resources():
    (network_client, resource_client, authorization_client, policy_client, management_groups_client, security_client, advisor_client, reservations_client, current_subscription, monitor_client, avs_client, traffic_manager_client, front_door_client, compute_client, storage_client, recovery_services_client, sql_client) = authenticate()
    resources = discover_azure_resources(network_client, authorization_client, policy_client, management_groups_client, security_client, advisor_client, reservations_client, current_subscription, monitor_client, avs_client, traffic_manager_client, front_door_client, compute_client, storage_client, recovery_services_client, sql_client)
    return jsonify(resources)

@app.route('/landing_zone_selection', methods=['POST'])
def landing_zone_selection():
    landing_zone_selected = request.form.get('landing_zone_selected') == 'true'
    session['landing_zone_selected'] = landing_zone_selected
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
