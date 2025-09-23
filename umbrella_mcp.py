import os
from typing import List, Dict, Any, Optional
import asyncio
import json
from dotenv import load_dotenv
import httpx
from pydantic import BaseModel
from fastmcp import FastMCP

# Load environment variables
load_dotenv()

# Configuration
API_BASE_URL = os.getenv("UMBRELLA_API_BASE_URL", "https://api.umbrella.com")
API_TOKEN = os.getenv("UMBRELLA_API_TOKEN")

if not API_TOKEN:
    raise ValueError("UMBRELLA_API_TOKEN environment variable is required")

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

class EnforcementEvent(BaseModel):
    id: str
    timestamp: str
    client_ip: str
    domain: str
    action: str

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

class DestinationList(BaseModel):
    id: str
    name: Optional[str] = None
    description: Optional[str] = None

class Identity(BaseModel):
    id: str
    username: Optional[str] = None
    email: Optional[str] = None

class Investigation(BaseModel):
    id: str
    status: Optional[str] = None
    created_at: Optional[str] = None

class Alert(BaseModel):
    id: str
    severity: Optional[str] = None
    description: Optional[str] = None

class LogEntry(BaseModel):
    id: str
    timestamp: str
    message: str

class TaskResult(BaseModel):
    task_id: Optional[str] = None
    status: Optional[str] = None

class TunnelGroup(BaseModel):
    id: str
    name: Optional[str] = None
    status: Optional[str] = None
    ip_address: Optional[str] = None
    vpn_type: Optional[str] = None
    created_at: Optional[str] = None

class DNSGlobalSetting(BaseModel):
    id: str
    name: Optional[str] = None
    value: Any
    description: Optional[str] = None

class DNSPolicyRule(BaseModel):
    id: str
    name: Optional[str] = None
    priority: Optional[int] = None
    action: Optional[str] = None
    criteria: Optional[Dict[str, Any]] = None

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

class Group(BaseModel):
    id: str
    name: Optional[str] = None
    description: Optional[str] = None
    member_ids: Optional[List[str]] = None

class APIKey(BaseModel):
    id: str
    key_prefix: Optional[str] = None
    description: Optional[str] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    status: Optional[str] = None

class AutomationWorkflow(BaseModel):
    id: str
    name: Optional[str] = None
    status: Optional[str] = None
    last_run_at: Optional[str] = None
    description: Optional[str] = None

class ThreatFeedSource(BaseModel):
    id: str
    name: Optional[str] = None
    url: Optional[str] = None
    status: Optional[str] = None
    last_updated: Optional[str] = None

class ThreatIntelIntegration(BaseModel):
    id: str
    name: Optional[str] = None
    type: Optional[str] = None
    status: Optional[str] = None
    configuration: Optional[Dict[str, Any]] = None

# Initialize FastMCP server
mcp = FastMCP("umbrella_mcp")

# Helper for API calls with rate limiting and error handling
async def make_api_request(method: str, endpoint: str, params: Optional[Dict] = None, data: Optional[Dict] = None) -> Dict[str, Any]:
    url = f"{API_BASE_URL}/{endpoint.lstrip('/')}"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(method, url, headers=HEADERS, params=params, json=data)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            return {"error": "Authentication failed. Check your API token."}
        elif e.response.status_code == 429:
            await asyncio.sleep(1)
            return {"error": "Rate limit exceeded. Please try again later."}
        else:
            return {"error": f"API error: {e.response.status_code} - {e.response.text}"}
    except httpx.RequestError as e:
        return {"error": f"Network error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

@mcp.tool()
async def get_organizations() -> str:
    data = await make_api_request("GET", "organizations/v1/organizations")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    orgs = [Organization(id=str(org.get("id")), name=org.get("name")).dict() for org in data]
    if not orgs:
        return json.dumps({"message": "No organizations found."}, indent=2)
    return json.dumps(orgs, indent=2)

@mcp.tool()
async def get_reports(report_type: str, params: Optional[Dict[str, Any]] = None) -> str:
    endpoint = f"reports/v2/{report_type}"
    data = await make_api_request("GET", endpoint, params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_policies() -> str:
    data = await make_api_request("GET", "policies/v1/policies")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    policies = [Policy(id=str(pol.get("id")), name=pol.get("name"), description=pol.get("description")).dict() for pol in data]
    if not policies:
        return json.dumps({"message": "No policies found."}, indent=2)
    return json.dumps(policies, indent=2)

@mcp.tool()
async def get_enforcement_events(params: Optional[Dict[str, Any]] = None) -> str:
    data = await make_api_request("GET", "enforcement/v2/events", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    events = [EnforcementEvent(
        id=str(ev.get("id")),
        timestamp=ev.get("timestamp"),
        client_ip=ev.get("clientIp"),
        domain=ev.get("domain"),
        action=ev.get("action")
    ).dict() for ev in data.get("events", [])]
    if not events:
        return json.dumps({"message": "No enforcement events found."}, indent=2)
    return json.dumps(events, indent=2)

@mcp.tool()
async def get_network_devices(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve network devices associated with the Umbrella organization.
    """
    data = await make_api_request("GET", "network-devices/v1/devices", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    devices = [NetworkDevice(
        id=str(dev.get("id")),
        name=dev.get("name"),
        ip_address=dev.get("ipAddress"),
        status=dev.get("status")
    ).dict() for dev in data.get("devices", [])]
    if not devices:
        return json.dumps({"message": "No network devices found."}, indent=2)
    return json.dumps(devices, indent=2)

@mcp.tool()
async def get_roaming_clients(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve roaming clients information.
    """
    data = await make_api_request("GET", "identities/v1/roaming-computers", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    clients = [RoamingClient(
        id=str(client.get("id")),
        hostname=client.get("hostname"),
        ip_address=client.get("ipAddress"),
        last_seen=client.get("lastSeen")
    ).dict() for client in data.get("roamingComputers", [])]
    if not clients:
        return json.dumps({"message": "No roaming clients found."}, indent=2)
    return json.dumps(clients, indent=2)

@mcp.tool()
async def get_destination_lists(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve destination lists used in Umbrella policies.
    """
    data = await make_api_request("GET", "destination-lists/v1/lists", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    lists = [DestinationList(
        id=str(dl.get("id")),
        name=dl.get("name"),
        description=dl.get("description")
    ).dict() for dl in data.get("destinationLists", [])]
    if not lists:
        return json.dumps({"message": "No destination lists found."}, indent=2)
    return json.dumps(lists, indent=2)

@mcp.tool()
async def get_identities(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve identities (users/groups) information.
    """
    data = await make_api_request("GET", "identities/v1/identities", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    identities = [Identity(
        id=str(identity.get("id")),
        username=identity.get("username"),
        email=identity.get("email")
    ).dict() for identity in data.get("identities", [])]
    if not identities:
        return json.dumps({"message": "No identities found."}, indent=2)
    return json.dumps(identities, indent=2)

@mcp.tool()
async def get_investigations(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve security investigations.
    """
    data = await make_api_request("GET", "investigations/v1/investigations", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    investigations = [Investigation(
        id=str(inv.get("id")),
        status=inv.get("status"),
        created_at=inv.get("createdAt")
    ).dict() for inv in data.get("investigations", [])]
    if not investigations:
        return json.dumps({"message": "No investigations found."}, indent=2)
    return json.dumps(investigations, indent=2)

@mcp.tool()
async def get_alerts(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve security alerts.
    """
    data = await make_api_request("GET", "alerts/v1/alerts", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    alerts = [Alert(
        id=str(alert.get("id")),
        severity=alert.get("severity"),
        description=alert.get("description")
    ).dict() for alert in data.get("alerts", [])]
    if not alerts:
        return json.dumps({"message": "No alerts found."}, indent=2)
    return json.dumps(alerts, indent=2)

@mcp.tool()
async def get_logs(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve logs for auditing and compliance.
    """
    data = await make_api_request("GET", "logs/v1/logs", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    logs = [LogEntry(
        id=str(log.get("id")),
        timestamp=log.get("timestamp"),
        message=log.get("message")
    ).dict() for log in data.get("logs", [])]
    if not logs:
        return json.dumps({"message": "No logs found."}, indent=2)
    return json.dumps(logs, indent=2)

@mcp.tool()
async def run_umbrella_task(task_type: str, params: Dict[str, Any]) -> str:
    """
    Run an Umbrella automation task if applicable.
    Note: Umbrella API may not support generic task execution; this is a placeholder.
    """
    return json.dumps({"message": "Umbrella API does not support generic task execution via this endpoint."}, indent=2)

@mcp.tool()
async def get_tunnel_groups(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve network tunnel groups or VPN configurations.
    """
    data = await make_api_request("GET", "tunnel-groups/v1/groups", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    groups = [TunnelGroup(
        id=str(g.get("id")),
        name=g.get("name"),
        status=g.get("status"),
        ip_address=g.get("ipAddress"),
        vpn_type=g.get("vpnType"),
        created_at=g.get("createdAt")
    ).dict() for g in data.get("tunnelGroups", [])]
    if not groups:
        return json.dumps({"message": "No tunnel groups found."}, indent=2)
    return json.dumps(groups, indent=2)

@mcp.tool()
async def create_tunnel_group(group_data: Dict[str, Any]) -> str:
    """
    Create a new network tunnel group.
    `group_data` should contain 'name', 'ipAddress', 'vpnType', etc.
    """
    data = await make_api_request("POST", "tunnel-groups/v1/groups", data=group_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_tunnel_group(group_id: str, updates: Dict[str, Any]) -> str:
    """
    Update an existing network tunnel group.
    `updates` should contain fields to be updated (e.g., 'status', 'name').
    """
    data = await make_api_request("PUT", f"tunnel-groups/v1/groups/{group_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_tunnel_group(group_id: str) -> str:
    """
    Delete a network tunnel group.
    """
    data = await make_api_request("DELETE", f"tunnel-groups/v1/groups/{group_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Tunnel group {group_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_global_dns_settings() -> str:
    """
    Retrieve global DNS configurations.
    """
    data = await make_api_request("GET", "dns-settings/v1/global")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    settings = [DNSGlobalSetting(
        id=str(s.get("id")),
        name=s.get("name"),
        value=s.get("value"),
        description=s.get("description")
    ).dict() for s in data.get("settings", [])]
    if not settings:
        return json.dumps({"message": "No global DNS settings found."}, indent=2)
    return json.dumps(settings, indent=2)

@mcp.tool()
async def update_global_dns_settings(settings_data: Dict[str, Any]) -> str:
    """
    Update global DNS configurations.
    `settings_data` should be a dictionary of settings to update.
    """
    data = await make_api_request("PUT", "dns-settings/v1/global", data=settings_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def get_dns_policy_rules(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve DNS policy rules beyond destination lists.
    """
    data = await make_api_request("GET", "dns-policies/v1/rules", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    rules = [DNSPolicyRule(
        id=str(r.get("id")),
        name=r.get("name"),
        priority=r.get("priority"),
        action=r.get("action"),
        criteria=r.get("criteria")
    ).dict() for r in data.get("policyRules", [])]
    if not rules:
        return json.dumps({"message": "No DNS policy rules found."}, indent=2)
    return json.dumps(rules, indent=2)

@mcp.tool()
async def create_dns_policy_rule(rule_data: Dict[str, Any]) -> str:
    """
    Create a new DNS policy rule.
    `rule_data` should contain 'name', 'priority', 'action', 'criteria', etc.
    """
    data = await make_api_request("POST", "dns-policies/v1/rules", data=rule_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_dns_policy_rule(rule_id: str, updates: Dict[str, Any]) -> str:
    """
    Update an existing DNS policy rule.
    `updates` should contain fields to be updated (e.g., 'name', 'action').
    """
    data = await make_api_request("PUT", f"dns-policies/v1/rules/{rule_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_dns_policy_rule(rule_id: str) -> str:
    """
    Delete a DNS policy rule.
    """
    data = await make_api_request("DELETE", f"dns-policies/v1/rules/{rule_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"DNS policy rule {rule_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_all_users(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve detailed user information, including roles.
    """
    data = await make_api_request("GET", "users/v1/users", params=params)
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
    ).dict() for u in data.get("users", [])]
    if not users:
        return json.dumps({"message": "No users found."}, indent=2)
    return json.dumps(users, indent=2)

@mcp.tool()
async def create_user(user_data: Dict[str, Any]) -> str:
    """
    Create a new user.
    `user_data` should contain 'username', 'email', 'firstName', 'lastName', 'password', etc.
    """
    data = await make_api_request("POST", "users/v1/users", data=user_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_user(user_id: str, updates: Dict[str, Any]) -> str:
    """
    Update an existing user.
    `updates` should contain fields to be updated (e.g., 'email', 'status').
    """
    data = await make_api_request("PUT", f"users/v1/users/{user_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_user(user_id: str) -> str:
    """
    Delete a user.
    """
    data = await make_api_request("DELETE", f"users/v1/users/{user_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"User {user_id} deleted successfully."}, indent=2)

@mcp.tool()
async def get_roles() -> str:
    """
    Retrieve available roles and their permissions.
    """
    data = await make_api_request("GET", "roles/v1/roles")
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
async def assign_user_role(user_id: str, role_id: str) -> str:
    """
    Assign a specific role to a user.
    """
    data = await make_api_request("POST", f"users/v1/users/{user_id}/roles", data={"roleId": role_id})
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def remove_user_role(user_id: str, role_id: str) -> str:
    """
    Remove a specific role from a user.
    """
    data = await make_api_request("DELETE", f"users/v1/users/{user_id}/roles/{role_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Role {role_id} removed from user {user_id} successfully."}, indent=2)

@mcp.tool()
async def get_groups(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve user groups.
    """
    data = await make_api_request("GET", "groups/v1/groups", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    groups = [Group(
        id=str(g.get("id")),
        name=g.get("name"),
        description=g.get("description"),
        member_ids=g.get("memberIds")
    ).dict() for g in data.get("groups", [])]
    if not groups:
        return json.dumps({"message": "No groups found."}, indent=2)
    return json.dumps(groups, indent=2)

@mcp.tool()
async def create_group(group_data: Dict[str, Any]) -> str:
    """
    Create a new user group.
    `group_data` should contain 'name', 'description', etc.
    """
    data = await make_api_request("POST", "groups/v1/groups", data=group_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_group(group_id: str, updates: Dict[str, Any]) -> str:
    """
    Update an existing user group.
    `updates` should contain fields to be updated (e.g., 'name', 'description').
    """
    data = await make_api_request("PUT", f"groups/v1/groups/{group_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_group(group_id: str) -> str:
    """
    Delete a user group.
    """
    data = await make_api_request("DELETE", f"groups/v1/groups/{group_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"Group {group_id} deleted successfully."}, indent=2)

@mcp.tool()
async def add_user_to_group(group_id: str, user_id: str) -> str:
    """
    Add a user to a specific group.
    """
    data = await make_api_request("POST", f"groups/v1/groups/{group_id}/members", data={"userId": user_id})
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def remove_user_from_group(group_id: str, user_id: str) -> str:
    """
    Remove a user from a specific group.
    """
    data = await make_api_request("DELETE", f"groups/v1/groups/{group_id}/members/{user_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"User {user_id} removed from group {group_id} successfully."}, indent=2)

@mcp.tool()
async def get_api_keys(params: Optional[Dict[str, Any]] = None) -> str:
    """
    Retrieve information about API keys. (Note: Full keys are usually not returned for security).
    """
    data = await make_api_request("GET", "api-keys/v1/keys", params=params)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    keys = [APIKey(
        id=str(key.get("id")),
        key_prefix=key.get("keyPrefix"),
        description=key.get("description"),
        created_at=key.get("createdAt"),
        expires_at=key.get("expiresAt"),
        status=key.get("status")
    ).dict() for key in data.get("apiKeys", [])]
    if not keys:
        return json.dumps({"message": "No API keys found."}, indent=2)
    return json.dumps(keys, indent=2)

@mcp.tool()
async def create_api_key(key_data: Dict[str, Any]) -> str:
    """
    Create a new API key.
    `key_data` should contain 'description', 'expiresAt', etc.
    """
    data = await make_api_request("POST", "api-keys/v1/keys", data=key_data)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def update_api_key(key_id: str, updates: Dict[str, Any]) -> str:
    """
    Update an existing API key.
    `updates` should contain fields to be updated (e.g., 'description', 'status').
    """
    data = await make_api_request("PUT", f"api-keys/v1/keys/{key_id}", data=updates)
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
async def delete_api_key(key_id: str) -> str:
    """
    Delete an API key.
    """
    data = await make_api_request("DELETE", f"api-keys/v1/keys/{key_id}")
    if "error" in data:
        return json.dumps({"error": data["error"]}, indent=2)
    return json.dumps({"message": f"API key {key_id} deleted successfully."}, indent=2)

@mcp.resource("greeting: //{name}")
def greeting(name: str) -> str:
    """
    Greet a user by name.

    Args:
        name: The name to include in the greeting.

    Returns:
        A greeting message.
    """
    return f"Hello {name}!"

if __name__ == "__main__":
    mcp.run(transport="stdio") # Use stdio for Claude Desktop integration
