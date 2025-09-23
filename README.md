# Umbrella MCP

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
   git clone https://github.com/JackRiebel/Umbrella_MCP.git   cd Umbrella_MCP
```
2. Create a virtual environment and activate it:
```
   python -m venv .venv   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```
3. Install dependencies:
```
   pip install -r requirements.txt
```
## Configuration

1. Copy the example environment file:
```
   cp .env-example .env
```
2. Update the `.env` file with your Umbrella API token and base URL:
```
   UMBRELLA_API_BASE_URL=https://api.umbrella.com
   UMBRELLA_API_TOKEN=Your_Umbrella_API_Token_here
```
## Usage with Claude Desktop Client

1. Configure Claude Desktop to use this MCP server:

* Open Claude Desktop
* Navigate to Settings > Developer > Edit Config
* Add the following configuration to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "Umbrella_MCP": {
      "command": "/path/to/Umbrella_MCP/.venv/bin/python",
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
GET /organizations - Retrieve a list of Umbrella organizations.
GET /organizations/{org_id} - Get details of a specific organization.

## Policy Management Tools
GET /policies - Retrieve all security policies.
GET /policies/{policy_id} - Get details of a specific policy.
GET /dns-policies/rules - Retrieve DNS policy rules.
POST /dns-policies/rules - Create a new DNS policy rule.
PUT /dns-policies/rules/{rule_id} - Update an existing DNS policy rule.
DELETE /dns-policies/rules/{rule_id} - Delete a DNS policy rule.

## Report Management Tools
GET /reports/{report_type} - Generate various Umbrella reports (domains, categories, etc.).
GET /reports/enforcement - Get enforcement report data.

## Enforcement Event Tools
GET /enforcement/events - Retrieve security enforcement events.
GET /enforcement/events/{event_id} - Get details of a specific enforcement event.

## Identity Management Tools
GET /identities - Retrieve user and group identities.
GET /users - Retrieve detailed user information.
POST /users - Create a new user.
PUT /users/{user_id} - Update an existing user.
DELETE /users/{user_id} - Delete a user.
GET /groups - Retrieve user groups.
POST /groups - Create a new user group.
PUT /groups/{group_id} - Update an existing user group.
DELETE /groups/{group_id} - Delete a user group.
POST /groups/{group_id}/members - Add user to group.
DELETE /groups/{group_id}/members/{user_id} - Remove user from group.
GET /roles - Retrieve available roles and permissions.
POST /users/{user_id}/roles - Assign role to user.
DELETE /users/{user_id}/roles/{role_id} - Remove role from user.
GET /api-keys - Retrieve API key information.
POST /api-keys - Create a new API key.
PUT /api-keys/{key_id} - Update an existing API key.
DELETE /api-keys/{key_id} - Delete an API key.

## Security Monitoring Tools
GET /investigations - Retrieve security investigations.
GET /alerts - Retrieve security alerts.
GET /logs - Retrieve audit logs.
GET /destination-lists - Retrieve destination lists for policies.

## Network Configuration Tools
GET /network-devices - Retrieve network devices.
GET /roaming-clients - Retrieve roaming client information.
GET /tunnel-groups - Retrieve VPN tunnel groups.
POST /tunnel-groups - Create a new tunnel group.
PUT /tunnel-groups/{group_id} - Update an existing tunnel group.
DELETE /tunnel-groups/{group_id} - Delete a tunnel group.
GET /dns-settings/global - Retrieve global DNS settings.
PUT /dns-settings/global - Update global DNS settings.

## Best Practices
Error Handling: Always check API responses for errors and handle them appropriately.
Rate Limiting: Implement delays to respect Umbrella API rate limits (typically 100 requests per minute).
Security: Keep API tokens secure, rotate them regularly, and use environment variables for storage.
Validation: Use provided Pydantic schemas for data validation and type safety.
Pagination: Handle paginated responses using limit and offset parameters where supported.
Async Operations: Use asynchronous functions for better performance with multiple API calls.

## Troubleshooting
Authentication Errors: Verify the API token is valid and has the required scopes (e.g., org:read, policy:write).
Rate Limiting: If you receive 429 errors, implement exponential backoff and retry logic.
Resource Not Found: Ensure correct IDs (organization, policy, user) are used in API calls.
Network Issues: Check SSL verification settings and firewall rules for API access.
Parameter Validation: Ensure all required parameters are provided in the correct format.

## Example Usage
Getting Started with Basic Queries
# Example: Get all organizations
organizations = await get_organizations()
print(json.loads(organizations))

# Example: Get enforcement events for the last 24 hours
params = {"from": "2025-09-22T00:00:00Z", "to": "2025-09-23T23:59:59Z"}
events = await get_enforcement_events(params)
print(json.loads(events))

Managing Users and Groups
# Create a new user
user_data = {
    "username": "jdoe",
    "email": "john.doe@company.com",
    "firstName": "John",
    "lastName": "Doe",
    "password": "SecurePassword123!"
}
new_user = await create_user(user_data)

# Create a group and add the user
group_data = {"name": "Network Admins", "description": "Administrators for network operations"}
new_group = await create_group(group_data)

# Add user to group
await add_user_to_group(group_id="group123", user_id="user456")

Policy Management
# Get all DNS policy rules
rules = await get_dns_policy_rules()

# Create a new DNS policy rule
rule_data = {
    "name": "Block Social Media",
    "priority": 10,
    "action": "BLOCK",
    "criteria": {
        "categories": ["SOCIAL_NETWORKS"],
        "domains": ["facebook.com", "twitter.com"]
    }
}
new_rule = await create_dns_policy_rule(rule_data)

API Response Format
All API responses follow this standard format:
{
  "data": {
    // Resource-specific data
  },
  "meta": {
    "count": 25,
    "limit": 100,
    "offset": 0,
    "total": 150
  }
}

Error responses:
{
  "error": {
    "code": "AUTH_INVALID_TOKEN",
    "message": "Invalid authentication token provided",
    "details": "Token has expired or is malformed"
  }
}

Supported API Versions
This MCP server supports Cisco Umbrella API v2.x endpoints including:

Organizations API (v1)
Policies API (v1)
Reports API (v2)
Enforcement API (v2)
Identities API (v1)
Investigations API (v1)
Alerts API (v1)

Development
Contributing

Fork the repository
Create a feature branch (git checkout -b feature/AmazingFeature)
Commit your changes (git commit -m 'Add some AmazingFeature')
Push to the branch (git push origin feature/AmazingFeature)
Open a Pull Request

Local Development
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Lint code
flake8 .

# Format code
black .

Testing
Unit tests are located in the tests/ directory. Run with:
pytest -v

Integration tests require a valid Umbrella API token and can be run with:
pytest tests/integration/ -m integration

Deployment
Docker
# Dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["python", "umbrella_mcp.py"]

Environment Variables



Variable
Description
Required
Default



UMBRELLA_API_BASE_URL
Umbrella API base URL
Yes
https://api.umbrella.com


UMBRELLA_API_TOKEN
API authentication token
Yes
None


LOG_LEVEL
Logging level
No
INFO


MCP_PORT
MCP server port
No
8000


SSL_VERIFY
SSL certificate verification
No
false


Security Considerations

API Token Security:

Never commit API tokens to version control
Use environment variables or secure vaults
Rotate tokens regularly (90-day recommendation)


Network Security:

Use HTTPS for all API communications
Implement IP whitelisting where possible
Monitor API usage for anomalies


Data Protection:

Sensitive data (IPs, domains) should be masked in logs
Implement data retention policies
Use RBAC for API access control



Rate Limiting
The Umbrella API enforces rate limits:

100 requests per minute per organization
10 concurrent requests maximum
24-hour limit: 144,000 requests per organization

The MCP server implements automatic retry logic with exponential backoff for 429 responses.
Error Codes



Code
Description
HTTP Status



AUTH_INVALID_TOKEN
Invalid or expired token
401


RATE_LIMIT_EXCEEDED
Too many requests
429


ORG_NOT_FOUND
Organization not found
404


PERMISSION_DENIED
Insufficient permissions
403


VALIDATION_ERROR
Invalid request parameters
400


INTERNAL_SERVER_ERROR
Umbrella API error
500


Logging
The server uses structured JSON logging:
{
  "timestamp": "2025-09-23T10:30:45Z",
  "level": "INFO",
  "service": "umbrella-mcp",
  "message": "Successfully retrieved 25 enforcement events",
  "request_id": "req-12345",
  "organization_id": "org-67890",
  "duration_ms": 245
}

Monitoring and Metrics
Available Metrics

umbrella.api.requests.total - Total API requests
umbrella.api.response_time - API response duration
umbrella.mcp.tools.invoked - MCP tool invocations
umbrella.errors.total - Error count by type

Health Check Endpoint
GET /health

Response:
{
  "status": "healthy",
  "timestamp": "2025-09-23T10:30:45Z",
  "api_connectivity": "connected",
  "uptime": "2h30m"
}

Support
Community Support

GitHub Issues
Discussions

Cisco Support

Cisco DevNet Umbrella API
Umbrella Technical Support

License
This project is licensed under the MIT License - see the LICENSE file for details.
Disclaimer
This software is provided "AS IS" without warranty. Use in production environments at your own risk. Ensure API tokens are stored securely and rotated regularly. SSL verification is disabled by default for development purposes only.
About
Local MCP Server for Cisco Umbrella (Not intended for production use)
Releases
No releases published
Packages
No packages published
Footer
© 2025 GitHub, Inc.```
