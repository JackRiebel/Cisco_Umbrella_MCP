import os
from typing import List, Dict, Any, Optional
import asyncio
import json
from dotenv import load_dotenv
import httpx
from pydantic import BaseModel
from fastmcp import FastMCP
import time
import uuid

# Load environment variables
load_dotenv()

# Configuration
API_BASE_URL = os.getenv("UMBRELLA_API_BASE_URL", "https://api.umbrella.com")
API_TOKEN = os.getenv("UMBRELLA_API_TOKEN")

if not API_TOKEN:
    raise ValueError("UMBRELLA_API_TOKEN environment variable is required. Ensure it includes necessary scopes (e.g., deployments, reports, admin, investigate).")

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json"
}

# Pydantic models for validation
class Organization(BaseModel):
    id: str
    name: Optional[str] = None

class Report(BaseModel):
    domain: Optional[str] = None
    count: Optional[int] = None
    category: Optional[str] = None

class Policy(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    bundle_type_id: Optional[str] = None  # Added for SAML Bypass (January 11, 2024)

class NetworkDevice(BaseModel):
    id: str
    name: Optional[str] = None
    ip_address: Optional[str] = None
    status: Optional[str] = None

class RoamingClient(BaseModel):
    id: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    last_seen: Optional[str] = None
    swg_status: Optional[str] = None  # Added December 19, 2024
    last_sync_swg_status: Optional[str] = None  # Added December 19, 2024
    anyconnect_device_id: Optional[str] = None  # Added October 7, 2024

class DestinationList(BaseModel):
    id: str
    name: Optional[str] = None
    description: Optional[str] = None
    bundle_type_id: Optional[str] = None  # Added for SAML Bypass (January 11, 2024)

class Identity(BaseModel):
    id: str
    username: Optional[str] = None
    email: Optional[str] = None

class Investigation(BaseModel):
    id: str
    status: Optional[str] = None
    created_at: Optional[str] = None

class TunnelGroup(BaseModel):
    id: str
    name: Optional[str] = None
    status: Optional[str] = None
    ip_address: Optional[str] = None
    vpn_type: Optional[str] = None
    created_at: Optional[str] = None
    initialized: Optional[bool] = None
    site_origin_id: Optional[str] = None  # Added April 14, 2022

class DNSGlobalSetting(BaseModel):
    id: str
    name: Optional[str] = None
    value: Any
    description: Optional[str] = None

class UserDetail(BaseModel):
    id: str
    username: Optional[str] = None
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role_ids: Optional[List[str]] = None
    status: Optional[str] = None

class Role(BaseModel):
    id: str
    name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[str]] = None

class APIKey(BaseModel):
    id: str
    key_prefix: Optional[str] = None
    description: Optional[str] = None  # Added September 13, 2023
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    status: Optional[str] = None
    allowed_ips: Optional[List[str]] = None  # Added January 11, 2024

class AppDiscoveryApplication(BaseModel):
    id: str
    name: Optional[str] = None
    first_detected: Optional[str] = None
    last_detected: Optional[str] = None
    weighted_risk: Optional[float] = None
    subcategory: Optional[str] = None  # Added September 23, 2025
    subcategory_content_types: Optional[List[str]] = None  # Added September 23, 2025
    attributes: Optional[Dict[str, Any]] = None  # Added November 27, 2023

class InternalDomain(BaseModel):
    id: str
    name: Optional[str] = None
    site_ids: Optional[List[str]] = None  # Added September 25, 2023

class InternalNetwork(BaseModel):
    id: str
    name: Optional[str] = None
    ip_address: Optional[str] = None

class Site(BaseModel):
    id: str
    name: Optional[str] = None
    description: Optional[str] = None
    site_origin_id: Optional[str] = None  # Added April 14, 2022

class VirtualAppliance(BaseModel):
    id: str
    name: Optional[str] = None
    status: Optional[str] = None

class Tag(BaseModel):
    id: str
    name: Optional[str] = None
    description: Optional[str] = None

class SWGDeviceSetting(BaseModel):
    device_id: str
    swg_enabled: Optional[bool] = None

class ApiUsageReport(BaseModel):
    timestamp: Optional[str] = None
    request_count: Optional[int] = None
    response_count: Optional[int] = None
    key_id: Optional[str] = None

class ProviderCustomer(BaseModel):
    id: str
    name: Optional[str] = None
    addon_dlp: Optional[bool] = None  # Added April 14, 2022
    addon_cdfw_l7: Optional[bool] = None  # Added April 14, 2022
    addon_rbi: Optional[bool] = None  # Added April 14, 2022

class ProviderCname(BaseModel):
    id: str
    name: Optional[str] = None
    value: Optional[str] = None

class ProviderContact(BaseModel):
    id: str
    name: Optional[str] = None
    email: Optional[str] = None

class ProviderLogo(BaseModel):
    id: str
    name: Optional[str] = None
    url: Optional[str] = None

class Network(BaseModel):
    id: str
    name: Optional[str] = None
    ip_address: Optional[str] = None
    status: Optional[str] = None

class DataCenter(BaseModel):
    id: str
    name: Optional[str] = None
    region: Optional[str] = None

class Customer(BaseModel):
    id: str
    name: Optional[str] = None
    email: Optional[str] = None

class CustomerDeal(BaseModel):
    id: str
    name: Optional[str] = None
    status: Optional[str] = None

class CustomerAddress(BaseModel):
    id: str
    email: Optional[str] = None

# Initialize FastMCP server
mcp = FastMCP("umbrella_mcp")

# Helper for API calls with rate limiting and error handling
async def make_api_request(method: str, endpoint: str, params: Optional[Dict] = None, data: Optional[Dict] = None, max_retries: int = 3) -> Dict[str, Any]:
    url = f"{API_BASE_URL}/{endpoint.lstrip('/')}"
    print(f"Making {method} request to {url} with params: {params}")  # Debug log
    retry_count = 0
    while retry_count < max_retries:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.request(method, url, headers=HEADERS, params=params, json=data)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                return {"error": "Authentication failed. Check your API token and ensure it has the required scopes (e.g., deployments, reports, admin, investigate)."}
            elif e.response.status_code == 429:
                wait_time = 2 ** retry_count  # Exponential backoff: 1s, 2s, 4s
                print(f"Rate limit exceeded. Retrying in {wait_time} seconds...")
                await asyncio.sleep(wait_time)
                retry_count += 1
            else:
                return {"error": f"API error: {e.response.status_code} - {e.response.text}"}
        except httpx.RequestError as e:
            return {"error": f"Network error: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}
    return {"error": f"Max retries ({max_retries}) exceeded for {method} {url}"}

@mcp.tool()
async def get_organizations() -> str:
    """
    Retrieve organizations from Umbrella.
    Scope: admin
    """
    data = await make_api_request("GET", "admin/v2/organizations")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    orgs = [Organization(id=str(org.get("organizationId")), name=org.get("name")).dict() for org in data]
    if not orgs:
        return json.dumps({"message": "No organizations found."}, indent=2)
    return json.dumps(orgs, indent=2)

@mcp.tool()
async def get_reports(report_type: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve reports for a specific report type (e.g., activity/dns, activity/proxy).
    Scope: reports
    Note: Use httperrors, filternoisydomains, datalosspreventionstate query parameters as needed (April 23, 2021).
    """
    endpoint = f"reports/v2/{report_type}"
    data = await make_api_request("GET", endpoint, params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    reports = [Report(
        domain=r.get("domain"),
        count=r.get("count"),
        category=r.get("category")
    ).dict() for r in data.get("data", [])]
    if not reports:
        return json.dumps({"message": f"No reports found for {report_type}."}, indent=2)
    return json.dumps(reports, indent=2)

@mcp.tool()
async def get_policies(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve policies from Umbrella.
    Scope: policies
    """
    data = await make_api_request("GET", "deployments/v2/policies", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    policies = [Policy(
        id=str(pol.get("id")),
        name=pol.get("name"),
        description=pol.get("description"),
        bundle_type_id=pol.get("bundleTypeId")
    ).dict() for pol in data]
    if not policies:
        return json.dumps({"message": "No policies found."}, indent=2)
    return json.dumps(policies, indent=2)

@mcp.tool()
async def update_policy_identities(policy_id: str, origin_id: str, updates: Dict[str, Any]) -> str:
    """
    Update identities for a specific policy.
    Scope: deployments
    """
    data = await make_api_request("PUT", f"deployments/v2/policies/{policy_id}/identities/{origin_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_policy_identities(policy_id: str, origin_id: str) -> str:
    """
    Delete identities from a specific policy.
    Scope: deployments
    """
    data = await make_api_request("DELETE", f"deployments/v2/policies/{policy_id}/identities/{origin_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Identities for policy {policy_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_networks(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve networks associated with the Umbrella organization.
    Scope: deployments
    """
    data = await make_api_request("GET", "deployments/v2/networks", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    networks = [Network(
        id=str(dev.get("id")),
        name=dev.get("name"),
        ip_address=dev.get("ipAddress"),
        status=dev.get("status")
    ).dict() for dev in data]
    if not networks:
        return json.dumps({"message": "No networks found."}, indent=2)
    return json.dumps(networks, indent=2)

@mcp.tool()
async def get_network_by_id(network_id: str) -> str:
    """
    Retrieve a specific network.
    Scope: deployments
    """
    data = await make_api_request("GET", f"deployments/v2/networks/{network_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    network = Network(
        id=str(data.get("id")),
        name=data.get("name"),
        ip_address=data.get("ipAddress"),
        status=data.get("status")
    ).dict()
    return json.dumps(network, indent=2)

@mcp.tool()
async def create_network(network_data: Dict[str, Any]) -> str:
    """
    Create a new network.
    Scope: deployments
    """
    data = await make_api_request("POST", "deployments/v2/networks", data=network_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_network(network_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific network.
    Scope: deployments
    """
    data = await make_api_request("PUT", f"deployments/v2/networks/{network_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_network(network_id: str) -> str:
    """
    Delete a specific network.
    Scope: deployments
    """
    data = await make_api_request("DELETE", f"deployments/v2/networks/{network_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Network {network_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_network_policies(network_id: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve policies for a specific network.
    Scope: deployments
    """
    data = await make_api_request("GET", f"deployments/v2/networks/{network_id}/policies", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    policies = [Policy(
        id=str(p.get("id")),
        name=p.get("name"),
        description=p.get("description"),
        bundle_type_id=p.get("bundleTypeId")
    ).dict() for p in data.get("policies", [])]
    if not policies:
        return json.dumps({"message": f"No policies found for network {network_id}."}, indent=2)
    return json.dumps(policies, indent=2)

@mcp.tool()
async def get_network_devices(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve network devices associated with the Umbrella organization.
    Scope: deployments
    """
    data = await make_api_request("GET", "deployments/v2/networkdevices", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    devices = [NetworkDevice(
        id=str(dev.get("id")),
        name=dev.get("name"),
        ip_address=dev.get("ipAddress"),
        status=dev.get("status")
    ).dict() for dev in data]
    if not devices:
        return json.dumps({"message": "No network devices found."}, indent=2)
    return json.dumps(devices, indent=2)

@mcp.tool()
async def get_network_device_by_id(origin_id: str) -> str:
    """
    Retrieve a specific network device.
    Scope: deployments
    """
    data = await make_api_request("GET", f"deployments/v2/networkdevices/{origin_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    device = NetworkDevice(
        id=str(data.get("id")),
        name=data.get("name"),
        ip_address=data.get("ipAddress"),
        status=data.get("status")
    ).dict()
    return json.dumps(device, indent=2)

@mcp.tool()
async def create_network_device(device_data: Dict[str, Any]) -> str:
    """
    Create a new network device.
    Scope: deployments
    """
    data = await make_api_request("POST", "deployments/v2/networkdevices", data=device_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_network_device(origin_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific network device.
    Scope: deployments
    """
    data = await make_api_request("PATCH", f"deployments/v2/networkdevices/{origin_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_network_device(origin_id: str) -> str:
    """
    Delete a specific network device.
    Scope: deployments
    """
    data = await make_api_request("DELETE", f"deployments/v2/networkdevices/{origin_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Network device {origin_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_roaming_clients(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve roaming clients information.
    Scope: deployments
    Query params: swgStatus (December 19, 2024)
    """
    data = await make_api_request("GET", "deployments/v2/roamingcomputers", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    clients = [RoamingClient(
        id=str(client.get("id")),
        hostname=client.get("hostname"),
        ip_address=client.get("ipAddress"),
        last_seen=client.get("lastSeen"),
        swg_status=client.get("swgStatus"),
        last_sync_swg_status=client.get("lastSyncSwgStatus"),
        anyconnect_device_id=client.get("anyconnectDeviceId")
    ).dict() for client in data]
    if not clients:
        return json.dumps({"message": "No roaming clients found."}, indent=2)
    return json.dumps(clients, indent=2)

@mcp.tool()
async def get_roaming_client_by_id(device_id: str) -> str:
    """
    Retrieve specific roaming client information.
    Scope: deployments
    """
    data = await make_api_request("GET", f"deployments/v2/roamingcomputers/{device_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    client = RoamingClient(
        id=str(data.get("id")),
        hostname=data.get("hostname"),
        ip_address=data.get("ipAddress"),
        last_seen=data.get("lastSeen"),
        swg_status=data.get("swgStatus"),
        last_sync_swg_status=data.get("lastSyncSwgStatus"),
        anyconnect_device_id=data.get("anyconnectDeviceId")
    ).dict()
    return json.dumps(client, indent=2)

@mcp.tool()
async def update_roaming_client(device_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific roaming client.
    Scope: deployments
    """
    data = await make_api_request("PUT", f"deployments/v2/roamingcomputers/{device_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_roaming_client(device_id: str) -> str:
    """
    Delete a specific roaming client.
    Scope: deployments
    """
    data = await make_api_request("DELETE", f"deployments/v2/roamingcomputers/{device_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Roaming client {device_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_roaming_clients_org_info() -> str:
    """
    Retrieve organization info for roaming clients.
    Scope: deployments
    """
    data = await make_api_request("GET", "deployments/v2/roamingcomputers/orgInfo")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_destination_lists(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve destination lists used in Umbrella policies.
    Scope: policies
    """
    data = await make_api_request("GET", "policies/v2/destinationlists", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    lists = [DestinationList(
        id=str(dl.get("id")),
        name=dl.get("name"),
        description=dl.get("description"),
        bundle_type_id=dl.get("bundleTypeId")
    ).dict() for dl in data.get("destinationLists", [])]
    if not lists:
        return json.dumps({"message": "No destination lists found."}, indent=2)
    return json.dumps(lists, indent=2)

@mcp.tool()
async def create_destination_list(list_data: Dict[str, Any]) -> str:
    """
    Create a new destination list.
    Scope: policies
    """
    data = await make_api_request("POST", "policies/v2/destinationlists", data=list_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_destination_list_by_id(destination_list_id: str) -> str:
    """
    Retrieve a specific destination list.
    Scope: policies
    """
    data = await make_api_request("GET", f"policies/v2/destinationlists/{destination_list_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    list_data = DestinationList(
        id=str(data.get("id")),
        name=data.get("name"),
        description=data.get("description"),
        bundle_type_id=data.get("bundleTypeId")
    ).dict()
    return json.dumps(list_data, indent=2)

@mcp.tool()
async def update_destination_list(destination_list_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific destination list.
    Scope: policies
    """
    data = await make_api_request("PATCH", f"policies/v2/destinationlists/{destination_list_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_destination_list(destination_list_id: str) -> str:
    """
    Delete a specific destination list.
    Scope: policies
    """
    data = await make_api_request("DELETE", f"policies/v2/destinationlists/{destination_list_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Destination list {destination_list_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_destinations_in_list(destination_list_id: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve destinations in a destination list.
    Scope: policies
    """
    data = await make_api_request("GET", f"policies/v2/destinationlists/{destination_list_id}/destinations", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def add_destinations_to_list(destination_list_id: str, destinations: List[str]) -> str:
    """
    Add destinations to a destination list.
    Scope: policies
    """
    data = await make_api_request("POST", f"policies/v2/destinationlists/{destination_list_id}/destinations", data={"destinations": destinations})
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def remove_destinations_from_list(destination_list_id: str, destinations: List[str]) -> str:
    """
    Remove destinations from a destination list.
    Scope: policies
    """
    data = await make_api_request("DELETE", f"policies/v2/destinationlists/{destination_list_id}/destinations/remove", data={"destinations": destinations})
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_domain_categorization(domain: str) -> str:
    """
    Get domain categorization.
    Scope: investigate
    """
    endpoint = f"investigate/v2/domains/categorization/{domain}"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def post_investigate_domain_categorization(domains: List[str]) -> str:
    """
    Batch get domain categorization.
    Scope: investigate
    """
    endpoint = "investigate/v2/domains/categorization"
    data = await make_api_request("POST", endpoint, data={"domains": domains})
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_domain_volume(domain: str) -> str:
    """
    Get domain volume.
    Scope: investigate
    """
    endpoint = f"investigate/v2/domains/volume/{domain}"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_recommendations(domain: str) -> str:
    """
    Get domain recommendations.
    Scope: investigate
    """
    endpoint = f"investigate/v2/recommendations/name/{domain}.json"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_pdns_name(domain: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Get passive DNS for domain name.
    Scope: investigate
    Query params: limit (October 22, 2021)
    """
    endpoint = f"investigate/v2/pdns/name/{domain}"
    data = await make_api_request("GET", endpoint, params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_pdns_domain(domain: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Get passive DNS for domain.
    Scope: investigate
    Query params: limit (October 22, 2021)
    """
    endpoint = f"investigate/v2/pdns/domain/{domain}"
    data = await make_api_request("GET", endpoint, params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_pdns_ip(ip: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Get passive DNS for IP.
    Scope: investigate
    Query params: limit (October 22, 2021)
    """
    endpoint = f"investigate/v2/pdns/ip/{ip}"
    data = await make_api_request("GET", endpoint, params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_pdns_raw(anystring: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Get raw passive DNS.
    Scope: investigate
    Query params: limit (October 22, 2021)
    """
    endpoint = f"investigate/v2/pdns/raw/{anystring}"
    data = await make_api_request("GET", endpoint, params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_links(domain: str) -> str:
    """
    Get links for domain.
    Scope: investigate
    """
    endpoint = f"investigate/v2/links/name/{domain}"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_security(domain: str) -> str:
    """
    Get security info for domain.
    Scope: investigate
    Note: Some fields (e.g., dga_score, perplexity) deprecated (December 1, 2021).
    """
    endpoint = f"investigate/v2/security/name/{domain}"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_domain_risk_score(domain: str) -> str:
    """
    Get domain risk score.
    Scope: investigate
    """
    endpoint = f"investigate/v2/domains/risk-score/{domain}"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_bgp_routes_as_for_ip(ip: str) -> str:
    """
    Get BGP routes AS for IP.
    Scope: investigate
    """
    endpoint = f"investigate/v2/bgp_routes/ip/{ip}/as_for_ip.json"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_bgp_routes_prefixes_for_asn(asn: str) -> str:
    """
    Get BGP routes prefixes for ASN.
    Scope: investigate
    """
    endpoint = f"investigate/v2/bgp_routes/asn/{asn}/prefixes_for_asn.json"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_whois_domain(domain: str) -> str:
    """
    Get WHOIS for domain.
    Scope: investigate
    """
    endpoint = f"investigate/v2/whois/{domain}"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_whois_domain_history(domain: str) -> str:
    """
    Get WHOIS history for domain.
    Scope: investigate
    """
    endpoint = f"investigate/v2/whois/{domain}/history"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_whois_nameserver(nameserver: str) -> str:
    """
    Get WHOIS for nameserver.
    Scope: investigate
    """
    endpoint = f"investigate/v2/whois/nameservers/{nameserver}"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_whois_nameservers() -> str:
    """
    Get all WHOIS nameservers.
    Scope: investigate
    """
    endpoint = "investigate/v2/whois/nameservers"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_whois_email(email: str) -> str:
    """
    Get WHOIS for email.
    Scope: investigate
    """
    endpoint = f"investigate/v2/whois/emails/{email}"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_whois_search(search_field: str, regex_expression: str) -> str:
    """
    Search WHOIS.
    Scope: investigate
    """
    endpoint = f"investigate/v2/whois/search/{search_field}/{regex_expression}"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_search(expression: str) -> str:
    """
    Search investigate.
    Scope: investigate
    """
    endpoint = f"investigate/v2/search/{expression}"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_top_million() -> str:
    """
    Get top million domains.
    Scope: investigate
    """
    endpoint = "investigate/v2/topmillion"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_samples(destination: str) -> str:
    """
    Get samples for destination.
    Scope: investigate
    """
    endpoint = f"investigate/v2/samples/{destination}"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_sample(hash_value: str) -> str:
    """
    Get sample by hash.
    Scope: investigate
    """
    endpoint = f"investigate/v2/sample/{hash_value}"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_sample_artifacts(hash_value: str) -> str:
    """
    Get sample artifacts by hash.
    Scope: investigate
    """
    endpoint = f"investigate/v2/sample/{hash_value}/artifacts"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_sample_connections(hash_value: str) -> str:
    """
    Get sample connections by hash.
    Scope: investigate
    """
    endpoint = f"investigate/v2/sample/{hash_value}/connections"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_sample_behaviors(hash_value: str) -> str:
    """
    Get sample behaviors by hash.
    Scope: investigate
    """
    endpoint = f"investigate/v2/sample/{hash_value}/behaviors"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_timeline(name: str) -> str:
    """
    Get timeline for name.
    Scope: investigate
    """
    endpoint = f"investigate/v2/timeline/{name}"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_investigate_subdomains(domain: str) -> str:
    """
    Get subdomains for domain.
    Scope: investigate
    """
    endpoint = f"investigate/v2/subdomains/{domain}"
    data = await make_api_request("GET", endpoint)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_tunnel_groups(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve network tunnel groups or VPN configurations.
    Scope: deployments
    Query params: filters (siteOriginId, April 14, 2022)
    """
    data = await make_api_request("GET", "deployments/v2/tunnels", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    groups = [TunnelGroup(
        id=str(g.get("id")),
        name=g.get("name"),
        status=g.get("status"),
        ip_address=g.get("ipAddress"),
        vpn_type=g.get("vpnType"),
        created_at=g.get("createdAt"),
        initialized=g.get("initialized"),
        site_origin_id=g.get("siteOriginId")
    ).dict() for g in data.get("tunnels", [])]
    if not groups:
        return json.dumps({"message": "No tunnel groups found."}, indent=2)
    return json.dumps(groups, indent=2)

@mcp.tool()
async def create_tunnel_group(group_data: Dict[str, Any]) -> str:
    """
    Create a new network tunnel group.
    Scope: deployments
    `group_data` should contain 'name', 'ipAddress', 'vpnType', 'siteOriginId', etc.
    """
    data = await make_api_request("POST", "deployments/v2/tunnels", data=group_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_tunnel_group(group_id: str, updates: Dict[str, Any]) -> str:
    """
    Update an existing network tunnel group.
    Scope: deployments
    `updates` should contain fields to be updated (e.g., 'status', 'name', 'siteOriginId').
    """
    data = await make_api_request("PUT", f"deployments/v2/tunnels/{group_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_tunnel_group(group_id: str) -> str:
    """
    Delete a network tunnel group.
    Scope: deployments
    """
    data = await make_api_request("DELETE", f"deployments/v2/tunnels/{group_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Tunnel group {group_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_tunnel_policies(tunnel_id: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve policies for a specific tunnel.
    Scope: deployments
    """
    data = await make_api_request("GET", f"deployments/v2/tunnels/{tunnel_id}/policies", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    policies = [Policy(
        id=str(p.get("id")),
        name=p.get("name"),
        description=p.get("description"),
        bundle_type_id=p.get("bundleTypeId")
    ).dict() for p in data.get("policies", [])]
    if not policies:
        return json.dumps({"message": f"No policies found for tunnel {tunnel_id}."}, indent=2)
    return json.dumps(policies, indent=2)

@mcp.tool()
async def create_tunnel_key(tunnel_id: str, key_data: Dict[str, Any]) -> str:
    """
    Create a new key for a specific tunnel.
    Scope: deployments
    """
    data = await make_api_request("POST", f"deployments/v2/tunnels/{tunnel_id}/keys", data=key_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_tunnel_state(group_id: str) -> str:
    """
    Get tunnel state for a specific tunnel.
    Scope: deployments
    """
    data = await make_api_request("GET", f"deployments/v2/tunnels/{group_id}/state")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_all_tunnels_state() -> str:
    """
    Get state for all tunnels.
    Scope: deployments
    """
    data = await make_api_request("GET", "deployments/v2/tunnelsState")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_tunnel_events(tunnel_id: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Get debugging events for a specific tunnel.
    Scope: deployments
    """
    data = await make_api_request("GET", f"deployments/v2/tunnels/{tunnel_id}/events", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_tunnel_global_events(tunnel_id: str, source_ip: str) -> str:
    """
    Get global debugging events for a specific tunnel by source IP.
    Scope: deployments
    """
    data = await make_api_request("GET", f"deployments/v2/tunnels/{tunnel_id}/globalEvents/sourceIp/{source_ip}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_data_centers(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve data centers for network tunnels.
    Scope: deployments
    """
    data = await make_api_request("GET", "deployments/v2/datacenters", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    data_centers = [DataCenter(
        id=str(dc.get("id")),
        name=dc.get("name"),
        region=dc.get("region")
    ).dict() for dc in data.get("dataCenters", [])]
    if not data_centers:
        return json.dumps({"message": "No data centers found."}, indent=2)
    return json.dumps(data_centers, indent=2)

@mcp.tool()
async def get_sites(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve sites from Umbrella.
    Scope: deployments
    Query params: filters (siteOriginId, April 14, 2022)
    """
    data = await make_api_request("GET", "deployments/v2/sites", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    sites = [Site(
        id=str(site.get("id")),
        name=site.get("name"),
        description=site.get("description"),
        site_origin_id=site.get("siteOriginId")
    ).dict() for site in data]
    if not sites:
        return json.dumps({"message": "No sites found."}, indent=2)
    return json.dumps(sites, indent=2)

@mcp.tool()
async def get_site_by_id(site_id: str) -> str:
    """
    Retrieve a specific site.
    Scope: deployments
    """
    data = await make_api_request("GET", f"deployments/v2/sites/{site_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    site = Site(
        id=str(data.get("id")),
        name=data.get("name"),
        description=data.get("description"),
        site_origin_id=data.get("siteOriginId")
    ).dict()
    return json.dumps(site, indent=2)

@mcp.tool()
async def create_site(site_data: Dict[str, Any]) -> str:
    """
    Create a new site.
    Scope: deployments
    """
    data = await make_api_request("POST", "deployments/v2/sites", data=site_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_site(site_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific site.
    Scope: deployments
    """
    data = await make_api_request("PUT", f"deployments/v2/sites/{site_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_site(site_id: str) -> str:
    """
    Delete a specific site.
    Scope: deployments
    """
    data = await make_api_request("DELETE", f"deployments/v2/sites/{site_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Site {site_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_app_discovery_applications(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve App Discovery applications.
    Scope: reports
    Query params: subcategory, subcategory_content_types (September 23, 2025), sort (firstDetected, lastDetected, name, weightedRisk, October 5, 2023)
    """
    data = await make_api_request("GET", "reports/v2/appDiscovery/applications", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    apps = [AppDiscoveryApplication(
        id=str(app.get("id")),
        name=app.get("name"),
        first_detected=app.get("firstDetected"),
        last_detected=app.get("lastDetected"),
        weighted_risk=app.get("weightedRisk"),
        subcategory=app.get("subcategory"),
        subcategory_content_types=app.get("subcategoryContentTypes"),
        attributes=app.get("attributes")
    ).dict() for app in data.get("applications", [])]
    if not apps:
        return json.dumps({"message": "No applications found."}, indent=2)
    return json.dumps(apps, indent=2)

@mcp.tool()
async def update_app_discovery_applications(updates: Dict[str, Any]) -> str:
    """
    Update App Discovery applications.
    Scope: reports
    """
    data = await make_api_request("PATCH", "reports/v2/appDiscovery/applications", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_app_discovery_application_info(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve App Discovery applications info.
    Scope: reports
    Query params: subcategory, subcategory_content_types (September 23, 2025)
    """
    data = await make_api_request("GET", "reports/v2/appDiscovery/applications/info", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_app_discovery_application_by_id(application_id: str) -> str:
    """
    Retrieve a specific App Discovery application.
    Scope: reports
    """
    data = await make_api_request("GET", f"reports/v2/appDiscovery/applications/{application_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    app = AppDiscoveryApplication(
        id=str(data.get("id")),
        name=data.get("name"),
        first_detected=data.get("firstDetected"),
        last_detected=data.get("lastDetected"),
        weighted_risk=data.get("weightedRisk"),
        subcategory=data.get("subcategory"),
        subcategory_content_types=data.get("subcategoryContentTypes"),
        attributes=data.get("attributes")
    ).dict()
    return json.dumps(app, indent=2)

@mcp.tool()
async def update_app_discovery_application(application_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific App Discovery application.
    Scope: reports
    """
    data = await make_api_request("PATCH", f"reports/v2/appDiscovery/applications/{application_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_app_discovery_application_risk(application_id: str) -> str:
    """
    Retrieve risk for a specific App Discovery application.
    Scope: reports
    """
    data = await make_api_request("GET", f"reports/v2/appDiscovery/applications/{application_id}/risk")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_app_discovery_application_identities(application_id: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve identities for a specific App Discovery application.
    Scope: reports
    Query params: sort (firstDetected, lastDetected, October 5, 2023)
    """
    data = await make_api_request("GET", f"reports/v2/appDiscovery/applications/{application_id}/identities", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    identities = [Identity(
        id=str(i.get("id")),
        username=i.get("username"),
        email=i.get("email")
    ).dict() for i in data.get("identities", [])]
    if not identities:
        return json.dumps({"message": f"No identities found for application {application_id}."}, indent=2)
    return json.dumps(identities, indent=2)

@mcp.tool()
async def get_app_discovery_protocols(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve App Discovery protocols.
    Scope: reports
    Query params: sort (firstDetected, lastDetected, October 5, 2023)
    """
    data = await make_api_request("GET", "reports/v2/appDiscovery/protocols", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_app_discovery_protocol_by_id(protocol_id: str) -> str:
    """
    Retrieve a specific App Discovery protocol.
    Scope: reports
    """
    data = await make_api_request("GET", f"reports/v2/appDiscovery/protocols/{protocol_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_app_discovery_protocol_identities(protocol_id: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve identities for a specific App Discovery protocol.
    Scope: reports
    """
    data = await make_api_request("GET", f"reports/v2/appDiscovery/protocols/{protocol_id}/identities", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_app_discovery_application_categories(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve App Discovery application categories.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/appDiscovery/applicationCategories", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_requests_by_hour(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve requests by hour.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/requests-by-hour", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_requests_by_hour_by_type(type: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve requests by hour by type.
    Scope: reports
    """
    data = await make_api_request("GET", f"reports/v2/requests-by-hour/{type}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_requests_by_timerange(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve requests by time range.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/requests-by-timerange", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_requests_by_timerange_by_type(type: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve requests by time range by type.
    Scope: reports
    """
    data = await make_api_request("GET", f"reports/v2/requests-by-timerange/{type}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_categories_by_hour(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve categories by hour.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/categories-by-hour", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_categories_by_hour_by_type(type: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve categories by hour by type.
    Scope: reports
    """
    data = await make_api_request("GET", f"reports/v2/categories-by-hour/{type}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_categories_by_timerange(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve categories by time range.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/categories-by-timerange", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_categories_by_timerange_by_type(type: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve categories by time range by type.
    Scope: reports
    """
    data = await make_api_request("GET", f"reports/v2/categories-by-timerange/{type}", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_deployment_status(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve deployment status.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/deployment-status", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_bandwidth_by_hour(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve bandwidth by hour.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/bandwidth-by-hour", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_bandwidth_by_timerange(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve bandwidth by time range.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/bandwidth-by-timerange", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_summaries_by_rule_intrusion(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve summaries by intrusion rule.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/summaries-by-rule/intrusion", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_applications(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve reference applications.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/applications", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_categories(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve reference categories.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/categories", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_identities(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve reference identities.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/identities", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    identities = [Identity(
        id=str(i.get("id")),
        username=i.get("username"),
        email=i.get("email")
    ).dict() for i in data.get("identities", [])]
    if not identities:
        return json.dumps({"message": "No identities found."}, indent=2)
    return json.dumps(identities, indent=2)

@mcp.tool()
async def get_reports_identity_by_id(identity_id: str) -> str:
    """
    Retrieve a specific reference identity.
    Scope: reports
    """
    data = await make_api_request("GET", f"reports/v2/identities/{identity_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    identity = Identity(
        id=str(data.get("id")),
        username=data.get("username"),
        email=data.get("email")
    ).dict()
    return json.dumps(identity, indent=2)

@mcp.tool()
async def create_reports_identity(identity_data: Dict[str, Any]) -> str:
    """
    Create a new reference identity.
    Scope: reports
    """
    data = await make_api_request("POST", "reports/v2/identities", data=identity_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_threat_types(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve reference threat types.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/threat-types", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_threat_type_by_id(threat_type_id: str) -> str:
    """
    Retrieve a specific reference threat type.
    Scope: reports
    """
    data = await make_api_request("GET", f"reports/v2/threat-types/{threat_type_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_threat_names(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve reference threat names.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/threat-names", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_threat_name_by_id(threat_name_id: str) -> str:
    """
    Retrieve a specific reference threat name.
    Scope: reports
    """
    data = await make_api_request("GET", f"reports/v2/threat-names/{threat_name_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_api_usage_requests(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve API usage requests.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/apiUsage/requests", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    reports = [ApiUsageReport(
        timestamp=r.get("timestamp"),
        request_count=r.get("requestCount"),
        response_count=r.get("responseCount"),
        key_id=r.get("keyId")
    ).dict() for r in data.get("requests", [])]
    if not reports:
        return json.dumps({"message": "No API usage requests found."}, indent=2)
    return json.dumps(reports, indent=2)

@mcp.tool()
async def get_reports_api_usage_responses(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve API usage responses.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/apiUsage/responses", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    reports = [ApiUsageReport(
        timestamp=r.get("timestamp"),
        request_count=r.get("requestCount"),
        response_count=r.get("responseCount"),
        key_id=r.get("keyId")
    ).dict() for r in data.get("responses", [])]
    if not reports:
        return json.dumps({"message": "No API usage responses found."}, indent=2)
    return json.dumps(reports, indent=2)

@mcp.tool()
async def get_reports_api_usage_keys(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve API usage keys.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/apiUsage/keys", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    keys = [APIKey(
        id=str(k.get("id")),
        key_prefix=k.get("keyPrefix"),
        description=k.get("description"),
        created_at=k.get("createdAt"),
        expires_at=k.get("expiresAt"),
        status=k.get("status"),
        allowed_ips=k.get("allowedIps")
    ).dict() for k in data.get("keys", [])]
    if not keys:
        return json.dumps({"message": "No API usage keys found."}, indent=2)
    return json.dumps(keys, indent=2)

@mcp.tool()
async def get_reports_api_usage_summary(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve API usage summary.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/apiUsage/summary", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_providers_deployments(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve provider deployments for managed organizations.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/providers/deployments", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_providers_requests_by_hour(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve provider requests by hour for managed organizations.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/providers/requests-by-hour", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_providers_requests_by_timerange(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve provider requests by time range for managed organizations.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/providers/requests-by-timerange", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_providers_requests_by_org(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve provider requests by organization for managed organizations.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/providers/requests-by-org", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_providers_requests_by_category(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve provider requests by category for managed organizations.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/providers/requests-by-category", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_providers_requests_by_destination(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve provider requests by destination for managed organizations.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/providers/requests-by-destination", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_providers_category_requests_by_org(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve provider category requests by organization for managed organizations.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/providers/category-requests-by-org", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_providers_consoles(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve provider consoles for managed organizations.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/providers/consoles", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_providers_customers_download_report_requests(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve provider customers download report requests for managed organizations.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/providers/customers/downloadReportRequests", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def create_reports_providers_customers_security_report(customer_id: str, report_data: Dict[str, Any]) -> str:
    """
    Create security report request for a customer in managed organizations.
    Scope: reports
    """
    data = await make_api_request("POST", f"reports/v2/providers/customers/{customer_id}/securityReportRequests", data=report_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_reports_providers_categories(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve provider categories for managed organizations.
    Scope: reports
    """
    data = await make_api_request("GET", "reports/v2/providers/categories", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_internal_domains(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve internal domains.
    Scope: deployments
    """
    data = await make_api_request("GET", "deployments/v2/internaldomains", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    domains = [InternalDomain(
        id=str(d.get("id")),
        name=d.get("name"),
        site_ids=d.get("siteIds")
    ).dict() for d in data]
    if not domains:
        return json.dumps({"message": "No internal domains found."}, indent=2)
    return json.dumps(domains, indent=2)

@mcp.tool()
async def get_internal_domain_by_id(internal_domain_id: str) -> str:
    """
    Retrieve a specific internal domain.
    Scope: deployments
    """
    data = await make_api_request("GET", f"deployments/v2/internaldomains/{internal_domain_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    domain = InternalDomain(
        id=str(data.get("id")),
        name=data.get("name"),
        site_ids=data.get("siteIds")
    ).dict()
    return json.dumps(domain, indent=2)

@mcp.tool()
async def create_internal_domain(domain_data: Dict[str, Any]) -> str:
    """
    Create a new internal domain.
    Scope: deployments
    """
    data = await make_api_request("POST", "deployments/v2/internaldomains", data=domain_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_internal_domain(internal_domain_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific internal domain.
    Scope: deployments
    """
    data = await make_api_request("PUT", f"deployments/v2/internaldomains/{internal_domain_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_internal_domain(internal_domain_id: str) -> str:
    """
    Delete a specific internal domain.
    Scope: deployments
    """
    data = await make_api_request("DELETE", f"deployments/v2/internaldomains/{internal_domain_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Internal domain {internal_domain_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_internal_networks(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve internal networks.
    Scope: deployments
    """
    data = await make_api_request("GET", "deployments/v2/internalnetworks", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    networks = [InternalNetwork(
        id=str(n.get("id")),
        name=n.get("name"),
        ip_address=n.get("ipAddress")
    ).dict() for n in data.get("internalNetworks", [])]
    if not networks:
        return json.dumps({"message": "No internal networks found."}, indent=2)
    return json.dumps(networks, indent=2)

@mcp.tool()
async def get_internal_network_by_id(internal_network_id: str) -> str:
    """
    Retrieve a specific internal network.
    Scope: deployments
    """
    data = await make_api_request("GET", f"deployments/v2/internalnetworks/{internal_network_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    network = InternalNetwork(
        id=str(data.get("id")),
        name=data.get("name"),
        ip_address=data.get("ipAddress")
    ).dict()
    return json.dumps(network, indent=2)

@mcp.tool()
async def create_internal_network(network_data: Dict[str, Any]) -> str:
    """
    Create a new internal network.
    Scope: deployments
    """
    data = await make_api_request("POST", "deployments/v2/internalnetworks", data=network_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_internal_network(internal_network_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific internal network.
    Scope: deployments
    """
    data = await make_api_request("PUT", f"deployments/v2/internalnetworks/{internal_network_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_internal_network(internal_network_id: str) -> str:
    """
    Delete a specific internal network.
    Scope: deployments
    """
    data = await make_api_request("DELETE", f"deployments/v2/internalnetworks/{internal_network_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Internal network {internal_network_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_internal_network_policies(internal_network_id: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve policies for a specific internal network.
    Scope: deployments
    """
    data = await make_api_request("GET", f"deployments/v2/internalnetworks/{internal_network_id}/policies", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    policies = [Policy(
        id=str(p.get("id")),
        name=p.get("name"),
        description=p.get("description"),
        bundle_type_id=p.get("bundleTypeId")
    ).dict() for p in data.get("policies", [])]
    if not policies:
        return json.dumps({"message": f"No policies found for internal network {internal_network_id}."}, indent=2)
    return json.dumps(policies, indent=2)

@mcp.tool()
async def get_tags(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve tags.
    Scope: deployments
    """
    data = await make_api_request("GET", "deployments/v2/tags", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    tags = [Tag(
        id=str(t.get("id")),
        name=t.get("name"),
        description=t.get("description")
    ).dict() for t in data]
    if not tags:
        return json.dumps({"message": "No tags found."}, indent=2)
    return json.dumps(tags, indent=2)

@mcp.tool()
async def create_tag(tag_data: Dict[str, Any]) -> str:
    """
    Create a new tag.
    Scope: deployments
    """
    data = await make_api_request("POST", "deployments/v2/tags", data=tag_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_tag_devices(tag_id: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve devices for a specific tag.
    Scope: deployments
    """
    data = await make_api_request("GET", f"deployments/v2/tags/{tag_id}/devices", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def create_tag_devices(tag_id: str, device_data: Dict[str, Any]) -> str:
    """
    Create devices for a specific tag.
    Scope: deployments
    """
    data = await make_api_request("POST", f"deployments/v2/tags/{tag_id}/devices", data=device_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_tag_devices(tag_id: str, device_data: Dict[str, Any]) -> str:
    """
    Delete devices from a specific tag.
    Scope: deployments
    """
    data = await make_api_request("DELETE", f"deployments/v2/tags/{tag_id}/devices", data=device_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Devices for tag {tag_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_virtual_appliances(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve virtual appliances.
    Scope: deployments
    """
    data = await make_api_request("GET", "deployments/v2/virtualappliances", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    appliances = [VirtualAppliance(
        id=str(va.get("id")),
        name=va.get("name"),
        status=va.get("status")
    ).dict() for va in data]
    if not appliances:
        return json.dumps({"message": "No virtual appliances found."}, indent=2)
    return json.dumps(appliances, indent=2)

@mcp.tool()
async def get_virtual_appliance_by_id(virtual_appliance_id: str) -> str:
    """
    Retrieve a specific virtual appliance.
    Scope: deployments
    """
    data = await make_api_request("GET", f"deployments/v2/virtualappliances/{virtual_appliance_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    appliance = VirtualAppliance(
        id=str(data.get("id")),
        name=data.get("name"),
        status=data.get("status")
    ).dict()
    return json.dumps(appliance, indent=2)

@mcp.tool()
async def update_virtual_appliance(virtual_appliance_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific virtual appliance.
    Scope: deployments
    """
    data = await make_api_request("PUT", f"deployments/v2/virtualappliances/{virtual_appliance_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_virtual_appliance(virtual_appliance_id: str) -> str:
    """
    Delete a specific virtual appliance.
    Scope: deployments
    """
    data = await make_api_request("DELETE", f"deployments/v2/virtualappliances/{virtual_appliance_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Virtual appliance {virtual_appliance_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_swg_device_settings(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve secure web gateway device settings.
    Scope: deployments
    """
    data = await make_api_request("POST", "deployments/v2/deviceSettings/SWGEnabled/list", data=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    settings = [SWGDeviceSetting(
        device_id=str(s.get("deviceId")),
        swg_enabled=s.get("swgEnabled")
    ).dict() for s in data.get("settings", [])]
    if not settings:
        return json.dumps({"message": "No SWG device settings found."}, indent=2)
    return json.dumps(settings, indent=2)

@mcp.tool()
async def set_swg_device_setting(device_data: Dict[str, Any]) -> str:
    """
    Set secure web gateway device settings.
    Scope: deployments
    """
    data = await make_api_request("POST", "deployments/v2/deviceSettings/SWGEnabled/set", data=device_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def remove_swg_device_setting(device_data: Dict[str, Any]) -> str:
    """
    Remove secure web gateway device settings.
    Scope: deployments
    """
    data = await make_api_request("POST", "deployments/v2/deviceSettings/SWGEnabled/remove", data=device_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_users(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve user accounts.
    Scope: admin
    """
    data = await make_api_request("GET", "admin/v2/users", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    users = [UserDetail(
        id=str(u.get("id")),
        username=u.get("username"),
        email=u.get("email"),
        first_name=u.get("firstName"),
        last_name=u.get("lastName"),
        role_ids=u.get("roleIds"),
        status=u.get("status")
    ).dict() for u in data]
    if not users:
        return json.dumps({"message": "No users found."}, indent=2)
    return json.dumps(users, indent=2)

@mcp.tool()
async def get_user_by_id(user_id: str) -> str:
    """
    Retrieve a specific user account.
    Scope: admin
    """
    data = await make_api_request("GET", f"admin/v2/users/{user_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    user = UserDetail(
        id=str(data.get("id")),
        username=data.get("username"),
        email=data.get("email"),
        first_name=data.get("firstName"),
        last_name=data.get("lastName"),
        role_ids=data.get("roleIds"),
        status=data.get("status")
    ).dict()
    return json.dumps(user, indent=2)

@mcp.tool()
async def create_user(user_data: Dict[str, Any]) -> str:
    """
    Create a new user account.
    Scope: admin
    """
    data = await make_api_request("POST", "admin/v2/users", data=user_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_user(user_id: str) -> str:
    """
    Delete a specific user account.
    Scope: admin
    """
    data = await make_api_request("DELETE", f"admin/v2/users/{user_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"User {user_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_roles(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve user roles.
    Scope: admin
    """
    data = await make_api_request("GET", "admin/v2/roles", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    roles = [Role(
        id=str(r.get("id")),
        name=r.get("name"),
        description=r.get("description"),
        permissions=r.get("permissions")
    ).dict() for r in data.get("roles", [])]
    if not roles:
        return json.dumps({"message": "No roles found."}, indent=2)
    return json.dumps(roles, indent=2)

@mcp.tool()
async def rotate_s3_bucket_key() -> str:
    """
    Rotate the Cisco-managed S3 bucket key.
    Scope: admin
    """
    data = await make_api_request("POST", "admin/v2/iam/rotateKey")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_api_keys(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve API keys.
    Scope: admin
    """
    data = await make_api_request("GET", "admin/v2/apiKeys", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    keys = [APIKey(
        id=str(k.get("id")),
        key_prefix=k.get("keyPrefix"),
        description=k.get("description"),
        created_at=k.get("createdAt"),
        expires_at=k.get("expiresAt"),
        status=k.get("status"),
        allowed_ips=k.get("allowedIps")
    ).dict() for k in data.get("apiKeys", [])]
    if not keys:
        return json.dumps({"message": "No API keys found."}, indent=2)
    return json.dumps(keys, indent=2)

@mcp.tool()
async def get_api_key_by_id(api_key_id: str) -> str:
    """
    Retrieve a specific API key.
    Scope: admin
    """
    data = await make_api_request("GET", f"admin/v2/apiKeys/{api_key_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    key = APIKey(
        id=str(data.get("id")),
        key_prefix=data.get("keyPrefix"),
        description=data.get("description"),
        created_at=data.get("createdAt"),
        expires_at=data.get("expiresAt"),
        status=data.get("status"),
        allowed_ips=data.get("allowedIps")
    ).dict()
    return json.dumps(key, indent=2)

@mcp.tool()
async def create_api_key(key_data: Dict[str, Any]) -> str:
    """
    Create a new API key.
    Scope: admin
    """
    data = await make_api_request("POST", "admin/v2/apiKeys", data=key_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_api_key(api_key_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific API key.
    Scope: admin
    """
    data = await make_api_request("PATCH", f"admin/v2/apiKeys/{api_key_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_api_key(api_key_id: str) -> str:
    """
    Delete a specific API key.
    Scope: admin
    """
    data = await make_api_request("DELETE", f"admin/v2/apiKeys/{api_key_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"API key {api_key_id} deleted successfully."}, indent=2)

@mcp.tool()
async def refresh_api_key(api_key_id: str) -> str:
    """
    Refresh a specific API key.
    Scope: admin
    """
    data = await make_api_request("POST", f"admin/v2/apiKeys/{api_key_id}/refresh")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def reset_customer_password(customer_id: str, password_data: Dict[str, Any]) -> str:
    """
    Update a customer's password.
    Scope: admin
    """
    data = await make_api_request("POST", f"admin/v2/passwordResets/{customer_id}", data=password_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_providers_customers(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve customers for managed organizations.
    Scope: admin
    """
    data = await make_api_request("GET", "admin/v2/providers/customers", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    customers = [ProviderCustomer(
        id=str(c.get("id")),
        name=c.get("name"),
        addon_dlp=c.get("addonDlp"),
        addon_cdfw_l7=c.get("addonCdfwL7"),
        addon_rbi=c.get("addonRbi")
    ).dict() for c in data.get("customers", [])]
    if not customers:
        return json.dumps({"message": "No customers found."}, indent=2)
    return json.dumps(customers, indent=2)

@mcp.tool()
async def get_provider_customer_by_id(customer_id: str) -> str:
    """
    Retrieve a specific customer for managed organizations.
    Scope: admin
    """
    data = await make_api_request("GET", f"admin/v2/providers/customers/{customer_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    customer = ProviderCustomer(
        id=str(data.get("id")),
        name=data.get("name"),
        addon_dlp=data.get("addonDlp"),
        addon_cdfw_l7=data.get("addonCdfwL7"),
        addon_rbi=data.get("addonRbi")
    ).dict()
    return json.dumps(customer, indent=2)

@mcp.tool()
async def create_provider_customer(customer_data: Dict[str, Any]) -> str:
    """
    Create a new customer for managed organizations.
    Scope: admin
    """
    data = await make_api_request("POST", "admin/v2/providers/customers", data=customer_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_provider_customer(customer_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific customer for managed organizations.
    Scope: admin
    """
    data = await make_api_request("PUT", f"admin/v2/providers/customers/{customer_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_provider_customer(customer_id: str) -> str:
    """
    Delete a specific customer for managed organizations.
    Scope: admin
    """
    data = await make_api_request("DELETE", f"admin/v2/providers/customers/{customer_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Customer {customer_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_provider_customer_access_request(customer_id: str, access_request_id: str) -> str:
    """
    Retrieve a specific access request for a customer.
    Scope: admin
    """
    data = await make_api_request("GET", f"admin/v2/providers/customers/{customer_id}/accessRequests/{access_request_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def create_provider_customer_access_request(customer_id: str, request_data: Dict[str, Any]) -> str:
    """
    Create a new access request for a customer.
    Scope: admin
    """
    data = await make_api_request("POST", f"admin/v2/providers/customers/{customer_id}/accessRequests", data=request_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_provider_customer_access_request(customer_id: str, access_request_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific access request for a customer.
    Scope: admin
    """
    data = await make_api_request("PUT", f"admin/v2/providers/customers/{customer_id}/accessRequests/{access_request_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_provider_customer_trial_strengths(customer_id: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve trial strengths for a specific customer.
    Scope: admin
    """
    data = await make_api_request("GET", f"admin/v2/providers/customers/{customer_id}/trialStrengths", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_provider_customer_trial_conversion(customer_id: str, conversion_data: Dict[str, Any]) -> str:
    """
    Update trial conversion for a specific customer.
    Scope: admin
    """
    data = await make_api_request("PUT", f"admin/v2/providers/customers/{customer_id}/trialconversions", data=conversion_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_provider_customer_packages(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve customer packages for managed organizations.
    Scope: admin
    """
    data = await make_api_request("GET", "admin/v2/providers/customers/packages", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_managed_customers(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve managed customers.
    Scope: admin
    """
    data = await make_api_request("GET", "admin/v2/managed/customers", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    customers = [Customer(
        id=str(c.get("id")),
        name=c.get("name"),
        email=c.get("email")
    ).dict() for c in data.get("customers", [])]
    if not customers:
        return json.dumps({"message": "No managed customers found."}, indent=2)
    return json.dumps(customers, indent=2)

@mcp.tool()
async def get_managed_customer_by_id(customer_id: str) -> str:
    """
    Retrieve a specific managed customer.
    Scope: admin
    """
    data = await make_api_request("GET", f"admin/v2/managed/customers/{customer_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    customer = Customer(
        id=str(data.get("id")),
        name=data.get("name"),
        email=data.get("email")
    ).dict()
    return json.dumps(customer, indent=2)

@mcp.tool()
async def create_managed_customer(customer_data: Dict[str, Any]) -> str:
    """
    Create a new managed customer.
    Scope: admin
    """
    data = await make_api_request("POST", "admin/v2/managed/customers", data=customer_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_managed_customer(customer_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific managed customer.
    Scope: admin
    """
    data = await make_api_request("PUT", f"admin/v2/managed/customers/{customer_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_managed_customer(customer_id: str) -> str:
    """
    Delete a specific managed customer.
    Scope: admin
    """
    data = await make_api_request("DELETE", f"admin/v2/managed/customers/{customer_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Managed customer {customer_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_customer_addresses(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve customer addresses by email.
    Scope: admin
    """
    data = await make_api_request("GET", "admin/v2/providers/customerAddresses", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    addresses = [CustomerAddress(
        id=str(a.get("id")),
        email=a.get("email")
    ).dict() for a in data.get("customerAddresses", [])]
    if not addresses:
        return json.dumps({"message": "No customer addresses found."}, indent=2)
    return json.dumps(addresses, indent=2)

@mcp.tool()
async def get_customer_deal_by_id(deal_id: str) -> str:
    """
    Retrieve a specific customer deal.
    Scope: admin
    """
    data = await make_api_request("GET", f"admin/v2/providers/customerDeals/{deal_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    deal = CustomerDeal(
        id=str(data.get("id")),
        name=data.get("name"),
        status=data.get("status")
    ).dict()
    return json.dumps(deal, indent=2)

@mcp.tool()
async def update_customer_deal(deal_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific customer deal.
    Scope: admin
    """
    data = await make_api_request("PUT", f"admin/v2/providers/customerDeals/{deal_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_config_cnames(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve configured CNAMEs.
    Scope: admin
    """
    data = await make_api_request("GET", "admin/v2/config/cnames", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    cnames = [ProviderCname(
        id=str(c.get("id")),
        name=c.get("name"),
        value=c.get("value")
    ).dict() for c in data.get("cnames", [])]
    if not cnames:
        return json.dumps({"message": "No CNAMEs found."}, indent=2)
    return json.dumps(cnames, indent=2)

@mcp.tool()
async def get_config_cname_by_id(cname_id: str) -> str:
    """
    Retrieve a specific configured CNAME.
    Scope: admin
    """
    data = await make_api_request("GET", f"admin/v2/config/cnames/{cname_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    cname = ProviderCname(
        id=str(data.get("id")),
        name=data.get("name"),
        value=data.get("value")
    ).dict()
    return json.dumps(cname, indent=2)

@mcp.tool()
async def create_config_cname(cname_data: Dict[str, Any]) -> str:
    """
    Create a new configured CNAME.
    Scope: admin
    """
    data = await make_api_request("POST", "admin/v2/config/cnames", data=cname_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_config_cname(cname_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific configured CNAME.
    Scope: admin
    """
    data = await make_api_request("PUT", f"admin/v2/config/cnames/{cname_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_config_cname(cname_id: str) -> str:
    """
    Delete a specific configured CNAME.
    Scope: admin
    """
    data = await make_api_request("DELETE", f"admin/v2/config/cnames/{cname_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"CNAME {cname_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_config_contacts(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve configured contacts.
    Scope: admin
    """
    data = await make_api_request("GET", "admin/v2/config/contacts", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    contacts = [ProviderContact(
        id=str(c.get("id")),
        name=c.get("name"),
        email=c.get("email")
    ).dict() for c in data.get("contacts", [])]
    if not contacts:
        return json.dumps({"message": "No contacts found."}, indent=2)
    return json.dumps(contacts, indent=2)

@mcp.tool()
async def get_config_contact_by_id(contact_id: str) -> str:
    """
    Retrieve a specific configured contact.
    Scope: admin
    """
    data = await make_api_request("GET", f"admin/v2/config/contacts/{contact_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    contact = ProviderContact(
        id=str(data.get("id")),
        name=data.get("name"),
        email=data.get("email")
    ).dict()
    return json.dumps(contact, indent=2)

@mcp.tool()
async def create_config_contact(contact_data: Dict[str, Any]) -> str:
    """
    Create a new configured contact.
    Scope: admin
    """
    data = await make_api_request("POST", "admin/v2/config/contacts", data=contact_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_config_contact(contact_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific configured contact.
    Scope: admin
    """
    data = await make_api_request("PUT", f"admin/v2/config/contacts/{contact_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_config_contact(contact_id: str) -> str:
    """
    Delete a specific configured contact.
    Scope: admin
    """
    data = await make_api_request("DELETE", f"admin/v2/config/contacts/{contact_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Contact {contact_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_config_logos(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve configured logos.
    Scope: admin
    """
    data = await make_api_request("GET", "admin/v2/config/logos", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    logos = [ProviderLogo(
        id=str(l.get("id")),
        name=l.get("name"),
        url=l.get("url")
    ).dict() for l in data.get("logos", [])]
    if not logos:
        return json.dumps({"message": "No logos found."}, indent=2)
    return json.dumps(logos, indent=2)

@mcp.tool()
async def get_config_logo_by_id(logo_id: str) -> str:
    """
    Retrieve a specific configured logo.
    Scope: admin
    """
    data = await make_api_request("GET", f"admin/v2/config/logos/{logo_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    logo = ProviderLogo(
        id=str(data.get("id")),
        name=data.get("name"),
        url=data.get("url")
    ).dict()
    return json.dumps(logo, indent=2)

@mcp.tool()
async def create_config_logo(logo_data: Dict[str, Any]) -> str:
    """
    Create a new configured logo.
    Scope: admin
    """
    data = await make_api_request("POST", "admin/v2/config/logos", data=logo_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_config_logo(logo_id: str, updates: Dict[str, Any]) -> str:
    """
    Update a specific configured logo.
    Scope: admin
    """
    data = await make_api_request("PUT", f"admin/v2/config/logos/{logo_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_config_logo(logo_id: str) -> str:
    """
    Delete a specific configured logo.
    Scope: admin
    """
    data = await make_api_request("DELETE", f"admin/v2/config/logos/{logo_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Logo {logo_id} deleted successfully."}, indent=2)

if __name__ == "__main__":
    mcp.run(transport="stdio")  # Use stdio for Claude Desktop integration
