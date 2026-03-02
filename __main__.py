"""An Azure RM Python Pulumi program"""

import pulumi

from pulumi_azure_native import resources
import pulumi_azure_native.app as containerapps 
import pulumi_azure_native.operationalinsights as operationalinsights

from pulumi_azure_native import cdn

# 1. Configuración y Grupo de Recursos
config = pulumi.Config()
stack = pulumi.get_stack()
resource_group = resources.ResourceGroup(f"rg-poc-eltablero-{stack}")

# 2. Log Analytics (Requerido para el Environment de ACA)
workspace = operationalinsights.Workspace(
    "log-analytics",
    resource_group_name=resource_group.name,
    sku=operationalinsights.WorkspaceSkuArgs(name="PerGB2018")
)

workspace_keys = operationalinsights.get_shared_keys_output(
    resource_group_name=resource_group.name,
    workspace_name=workspace.name
)

# 3. Azure Container Apps Environment
# Este es el "clúster" lógico donde viven ambos contenedores
aca_env = containerapps.ManagedEnvironment(
    "aca-env",
    resource_group_name=resource_group.name,
    app_logs_configuration=containerapps.AppLogsConfigurationArgs(
        destination="log-analytics",
        log_analytics_configuration=containerapps.LogAnalyticsConfigurationArgs(
            customer_id=workspace.customer_id,
            shared_key=workspace_keys.primary_shared_key,
        ),
    ),
)

# 4. Backend Service (FastAPI)
backend_app = containerapps.ContainerApp(
    "backend-api",
    resource_group_name=resource_group.name,
    managed_environment_id=aca_env.id,
    configuration=containerapps.ConfigurationArgs(
        ingress=containerapps.IngressArgs(
            external=True, # Permitir tráfico desde internet
            target_port=8000,
        ),
    ),
    template=containerapps.TemplateArgs(
        containers=[containerapps.ContainerArgs(
            name="fastapi-backend",
            image="mcr.microsoft.com/azuredocs/containerapps-helloworld", # Reemplazar por tu imagen en ACR
            resources=containerapps.ContainerResourcesArgs(cpu=0.5, memory="1Gi"),
        )],
    ),
)

# 6. Politica WAF (En cdn v3.14.0 el recurso se llama Policy)
waf_policy = cdn.Policy(
    "waf-policy",
    resource_group_name=resource_group.name,
    location="Global",
    sku=cdn.SkuArgs(name="Standard_AzureFrontDoor"),
    policy_settings=cdn.PolicySettingsArgs(
        enabled_state="Enabled",
        mode="Prevention",
        default_custom_block_response_status_code=403,
    ),
    custom_rules=cdn.CustomRuleListArgs(
        rules=[
            {
                "name": "rate-limit-api",
                "priority": 1,
                "ruleType": "RateLimitRule",
                "action": "Block",
                "rateLimitThreshold": 1000,
                "rateLimitDurationInMinutes": 1,
                "matchConditions": [{
                    "matchVariable": "RequestUri",
                    "operator": "BeginsWith",
                    "matchValue": ["/api"],
                }]
            },
            {
                "name": "rate-limit-frontend",
                "priority": 2,
                "ruleType": "RateLimitRule",
                "action": "Block",
                "rateLimitThreshold": 2000,
                "rateLimitDurationInMinutes": 1,
                "matchConditions": [{
                    "matchVariable": "RequestUri",
                    "operator": "NotBeginsWith",
                    "matchValue": ["/api"],
                }]
            },
            {
                "name": "block-sql-injection",
                "priority": 3,
                "ruleType": "MatchRule",
                "action": "Block",
                "matchConditions": [{
                    "matchVariable": "QueryString",
                    "operator": "Contains",
                    "matchValue": ["union", "select", "insert", "drop"],
                    "transforms": ["Lowercase"],
                }]
            },
            {
                "name": "block-xss-attempts",
                "priority": 4,
                "ruleType": "MatchRule",
                "action": "Block",
                "matchConditions": [{
                    "matchVariable": "QueryString",
                    "operator": "Contains",
                    "matchValue": ["<script", "javascript:", "onerror="],
                    "transforms": ["Lowercase"],
                }]
            }
        ]
    )
)

# 7.1 Perfil de Front Door (Standard)
fd_profile = cdn.Profile(
    "frontdoor-profile",
    resource_group_name=resource_group.name,
    sku=cdn.SkuArgs(name="Standard_AzureFrontDoor"),
)

# 7.2 Endpoint (La URL de entrada)
fd_endpoint = cdn.AFDEndpoint(
    "fd-endpoint",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    enabled_state="Enabled",
)

# 7.3 Origin Group
fd_origin_group = cdn.AFDOriginGroup(
    "fd-origin-group",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    load_balancing_settings=cdn.LoadBalancingSettingsParametersArgs(
        sample_size=4,
        successful_samples_required=3,
    ),
    health_probe_settings=cdn.HealthProbeParametersArgs(
        probe_path="/",
        probe_protocol="Https",
        probe_request_type="HEAD",
        probe_interval_in_seconds=30,
    ),
)

# 7.4 Origin para Backend
fd_origin_backend = cdn.AFDOrigin(
    "fd-origin-backend",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    origin_group_name=fd_origin_group.name,
    host_name=backend_app.configuration.apply(lambda c: c.ingress.fqdn),
    http_port=80,
    https_port=443,
    origin_host_header=backend_app.configuration.apply(lambda c: c.ingress.fqdn),
)

# 7.5 Rutas
# Ruta para API Backend
fd_route_api = cdn.Route(
    "fd-route-api",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    endpoint_name=fd_endpoint.name,
    origin_group=fd_origin_group.id,
    supported_protocols=["Http", "Https"],
    patterns_to_match=["/api/*"],
    forwarding_protocol="HttpsOnly",
    link_to_default_domain="Enabled",
    https_redirect="Enabled",
)

# 7.6 Vinculacion de WAF (Security Policy)
# En Standard/Premium, el WAF se vincula mediante una Security Policy
security_policy = cdn.SecurityPolicy(
    "fd-security-policy",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    parameters=cdn.SecurityPolicyWebApplicationFirewallParametersArgs(
        type="WebApplicationFirewall",
        waf_policy={"id": waf_policy.id},
        associations=[
            cdn.SecurityPolicyWebApplicationFirewallAssociationArgs(
                domains=[cdn.ActivatedResourceReferenceArgs(id=fd_endpoint.id)],
                patterns_to_match=["/api/*"],
            ),
        ],
    ),
)

# 5. Frontend Service (React/Static)
# Ahora que Front Door está definido, podemos usarlo para la URL de API
frontend_app = containerapps.ContainerApp(
    "frontend-web",
    resource_group_name=resource_group.name,
    managed_environment_id=aca_env.id,
    configuration=containerapps.ConfigurationArgs(
        ingress=containerapps.IngressArgs(
            external=True,
            target_port=80,
        ),
    ),
    template=containerapps.TemplateArgs(
        containers=[containerapps.ContainerArgs(
            name="react-frontend",
            image="mcr.microsoft.com/azuredocs/containerapps-helloworld", # Reemplazar por tu imagen
            env=[
                containerapps.EnvironmentVarArgs(
                    name="API_URL",
                    value=fd_endpoint.host_name.apply(lambda fqdn: f"https://{fqdn}/api")
                ),
                containerapps.EnvironmentVarArgs(
                    name="WAF_PROTECTED",
                    value="true"
                )
            ],
            resources=containerapps.ContainerResourcesArgs(cpu=0.5, memory="1Gi"),
        )],
    ),
    opts=pulumi.ResourceOptions(depends_on=[security_policy])
)

# 7.4b Origin para Frontend (para acceso directo sin WAF si es necesario)
fd_origin_frontend = cdn.AFDOrigin(
    "fd-origin-frontend",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    origin_group_name=fd_origin_group.name,
    host_name=frontend_app.configuration.apply(lambda c: c.ingress.fqdn),
    http_port=80,
    https_port=443,
    origin_host_header=frontend_app.configuration.apply(lambda c: c.ingress.fqdn),
    opts=pulumi.ResourceOptions(depends_on=[frontend_app])
)

# 7.5b Ruta para Frontend
fd_route_frontend = cdn.Route(
    "fd-route-frontend",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    endpoint_name=fd_endpoint.name,
    origin_group=fd_origin_group.id,
    supported_protocols=["Http", "Https"],
    patterns_to_match=["/*"],
    forwarding_protocol="HttpsOnly",
    link_to_default_domain="Enabled",
    https_redirect="Enabled",
    opts=pulumi.ResourceOptions(depends_on=[fd_origin_frontend])
)

# Outputs
pulumi.export("backend_url", backend_app.configuration.apply(lambda c: c.ingress.fqdn))
pulumi.export("frontend_url", frontend_app.configuration.apply(lambda c: c.ingress.fqdn))
pulumi.export("front_door_url", fd_endpoint.host_name)
pulumi.export("front_door_endpoint_id", fd_endpoint.id)
pulumi.export("waf_policy_id", waf_policy.id)
