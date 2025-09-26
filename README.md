# Umbrella MCP

Umbrella MCP is a Python-based Model Context Protocol (MCP) server for Cisco Umbrella. It provides tools for querying the Cisco Umbrella API to discover, monitor, and manage your Umbrella security environment.


## Features

- **Organization Management**: Retrieve and manage Umbrella organizations
- **Policy Management**: View and manage DNS and security policies
- **Report Generation**: Access various Umbrella reports and analytics
- **Enforcement Events**: Monitor security enforcement actions and events
- **Identity Management**: Manage users, groups, and API keys
- **Network Monitoring**: Track network devices, roaming clients, and tunnel groups
- **Advanced Security**: Access investigations, alerts, and threat intelligence

## Installation

1. Clone the repository:

```
   git clone https://github.com/JackRiebel/Umbrella_MCP.git
   cd Umbrella_MCP
```

Create a virtual environment and activate it:
```
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

Install dependencies:
```
pip install -r requirements.txt
```


Configuration

Copy the example environment file:
```
cp .env-example .env
```

Update the .env file with your Umbrella API token and base URL:
```
UMBRELLA_API_BASE_URL=https://api.umbrella.com
UMBRELLA_API_TOKEN=Your_Umbrella_API_Token_here
```


Usage with Claude Desktop Client

Configure Claude Desktop to use this MCP server:

Open Claude Desktop

Navigate to Settings > Developer > Edit Config

Add the following configuration to claude_desktop_config.json:
```
{
  "mcpServers": {
    "Umbrella_MCP": {
      "command": "/path/to/Umbrella_MCP/.venv/bin/fastmcp",
      "args": [
        "/path/to/Umbrella_MCP/umbrella_mcp.py"
      ]
    }
  }
}
```

Replace /path/to/Umbrella_MCP with the actual path to your repository



Restart Claude Desktop

Interact with the Umbrella MCP via Claude Desktop


# Network Tools Guide
## Table of Contents

- Organization Management Tools
- Policy Management Tools
- Report Management Tools
- Enforcement Event Tools
- Identity Management Tools
- Security Monitoring Tools
- Network Configuration Tools

## Organization Management Tools
- GET /organizations - Retrieve a list of Umbrella organizations.
- GET /organizations/{org_id} - Get details of a specific organization.
  
## Policy Management Tools
- GET /policies - Retrieve all security policies.
- GET /dns-policies/rules - Retrieve DNS policy rules.
- POST /dns-policies/rules - Create a new DNS policy rule.
- PUT /dns-policies/rules/{rule_id} - Update an existing DNS policy rule.
- DELETE /dns-policies/rules/{rule_id} - Delete a DNS policy rule.
- 
## Report Management Tools
- GET /reports/{report_type} - Generate various Umbrella reports (domains, categories, etc.).
- GET /reports/enforcement - Get enforcement report data.
- 
## Enforcement Event Tools
- GET /enforcement/events - Retrieve security enforcement events.
- GET /enforcement/events/{event_id} - Get details of a specific enforcement event.

## Identity Management Tools
- GET /identities - Retrieve user and group identities.
- GET /users - Retrieve detailed user information.
- POST /users - Create a new user.
- PUT /users/{user_id} - Update an existing user.
- DELETE /users/{user_id} - Delete a user.
- GET /groups - Retrieve user groups.
- POST /groups - Create a new user group.
- PUT /groups/{group_id} - Update an existing user group.
- DELETE /groups/{group_id} - Delete a user group.
- POST /groups/{group_id}/members - Add user to group.
- DELETE /groups/{group_id}/members/{user_id} - Remove user from group.
- GET /roles - Retrieve available roles and permissions.
- POST /users/{user_id}/roles - Assign role to user.
- DELETE /users/{user_id}/roles/{role_id} - Remove role from user.
- GET /api-keys - Retrieve API key information.
- POST /api-keys - Create a new API key.
- PUT /api-keys/{key_id} - Update an existing API key.
- DELETE /api-keys/{key_id} - Delete an API key.
  
## Security Monitoring Tools
- GET /investigations - Retrieve security investigations.
- GET /alerts - Retrieve security alerts.
- GET /logs - Retrieve audit logs.
- GET /destination-lists - Retrieve destination lists for policies.
  
## Network Configuration Tools
- GET /network-devices - Retrieve network devices.
- GET /roaming-clients - Retrieve roaming client information.
- GET /tunnel-groups - Retrieve VPN tunnel groups.
- POST /tunnel-groups - Create a new tunnel group.
- PUT /tunnel-groups/{group_id} - Update an existing tunnel group.
- DELETE /tunnel-groups/{group_id} - Delete a tunnel group.
- GET /dns-settings/global - Retrieve global DNS settings.
- PUT /dns-settings/global - Update global DNS settings.
  
## Best Practices
- Error Handling: Check API responses for errors.
- Rate Limiting: Implement delays to respect Umbrella API rate limits.
- Security: Keep API tokens secure and rotate them regularly.
- Validation: Use provided Pydantic schemas for data validation.

## Troubleshooting
- Authentication Errors: Verify the API token and its permissions.
- Rate Limiting: Implement delays if rate limit errors occur.
- Resource Not Found: Ensure correct IDs (organization, policy, user) are used.

# Disclaimer
This software is provided "AS IS" without warranty. Use in production environments at your own risk. Ensure API tokens are stored securely and rotated regularly.
About
Umbrella MCP server for managing Cisco Umbrella resources via the API.
