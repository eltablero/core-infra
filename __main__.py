"""An Azure RM Python Pulumi program"""

import pulumi
from pulumi_azure_native import resources, containerapps, operationalinsights, frontdoor

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

# 3. Azure Container Apps Environment
# Este es el "clúster" lógico donde viven ambos contenedores
aca_env = containerapps.ManagedEnvironment(
    "aca-env",
    resource_group_name=resource_group.name,
    app_logs_configuration=containerapps.AppLogsConfigurationArgs(
        destination="log-analytics",
        log_analytics_configuration=containerapps.LogAnalyticsConfigurationArgs(
            customer_id=workspace.customer_id,
            shared_key=workspace.primary_shared_key,
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

# 5. Frontend Service (React/Static)
# Consumimos la URL del backend dinámicamente
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
                    value=backend_app.configuration.apply(lambda c: f"https://{c.ingress.fqdn}")
                )
            ],
            resources=containerapps.ContainerResourcesArgs(cpu=0.5, memory="1Gi"),
        )],
    ),
)

# 6. política WAF con regla de rate‑limit
waf = frontdoor.WebApplicationFirewallPolicy(
    "waf-policy",
    resource_group_name=resource_group.name,
    policy_settings=frontdoor.PolicySettingsArgs(
        enabled=True,
        mode="Prevention",  # o Detection
    ),
    custom_rules=[frontdoor.CustomRuleArgs(
        name="limit-backend",
        priority=1,
        rule_type="RateLimitRule",
        rate_limit_rule=frontdoor.RateLimitRuleArgs(
            count=100,             # 100 requests
            interval_in_minutes=1, # por minuto
            action="Block",
        ),
        match_conditions=[frontdoor.MatchConditionArgs(
            match_variables=[frontdoor.MatchVariableArgs(
                variable_name="RequestHeaders",
                selector="Host",
            )],
            operator="Equal",
            values=["backend-api.${stack}.azurecontainerapps.io"],
        )]
    ), frontdoor.CustomRuleArgs(            # misma regla para frontend
        name="limit-frontend",
        priority=2,
        rule_type="RateLimitRule",
        rate_limit_rule=frontdoor.RateLimitRuleArgs(
            count=200,
            interval_in_minutes=1,
            action="Block",
        ),
        match_conditions=[frontdoor.MatchConditionArgs(
            match_variables=[frontdoor.MatchVariableArgs(
                variable_name="RequestHeaders",
                selector="Host",
            )],
            operator="Equal",
            values=["frontend-web.${stack}.azurecontainerapps.io"],
        )]
    )]
)

# 7. Front Door que apunta a las dos apps y usa la WAF anterior
fd = frontdoor.FrontDoor(
    "frontdoor",
    resource_group_name=resource_group.name,
    routing_rules=[
        frontdoor.RoutingRuleArgs(
            name="backend-rule",
            frontend_endpoints=["defaultFrontendEndpoint"],
            accepted_protocols=["Http","Https"],
            patterns_to_match=["/*"],
            forwarding_configuration=frontdoor.ForwardingConfigurationArgs(
                backend_pool_name="backendPool",
            ),
        ),
        frontdoor.RoutingRuleArgs(
            name="frontend-rule",
            frontend_endpoints=["defaultFrontendEndpoint"],
            accepted_protocols=["Http","Https"],
            patterns_to_match=["/app/*"],
            forwarding_configuration=frontdoor.ForwardingConfigurationArgs(
                backend_pool_name="frontendPool",
            ),
        ),
    ],
    backend_pools=[
        frontdoor.BackendPoolArgs(
            name="backendPool",
            backends=[frontdoor.BackendArgs(
                address=backend_app.configuration.apply(lambda c: c.ingress.fqdn),
                http_port=80,
                https_port=443,
            )],
        ),
        frontdoor.BackendPoolArgs(
            name="frontendPool",
            backends=[frontdoor.BackendArgs(
                address=frontend_app.configuration.apply(lambda c: c.ingress.fqdn),
                http_port=80,
                https_port=443,
            )],
        ),
    ],
    web_application_firewall_policy_link=frontdoor.WebApplicationFirewallPolicyLinkArgs(
        id=waf.id,
    ),
)


# Outputs
pulumi.export("backend_url", backend_app.configuration.apply(lambda c: c.ingress.fqdn))
pulumi.export("frontend_url", frontend_app.configuration.apply(lambda c: c.ingress.fqdn))
