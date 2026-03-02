"""An Azure RM Python Pulumi program"""

import pulumi

from pulumi_azure_native import resources
from pulumi_azure_native import containerregistry as acr
import pulumi_azure_native.app as containerapps
import pulumi_azure_native.operationalinsights as operationalinsights

from pulumi_azure_native import cdn
from pulumi_azure_native import authorization

# Import the frontdoor WAF Policy from the generated local SDK.
# Azure retired CDN WAF (cdn.Policy), so we use frontdoor.Policy instead.
import pulumi_azure_native_frontdoor_v20240201.frontdoor as frontdoor

# 1. Configuración y Grupo de Recursos
#
# El registro de contenedores y las versiones de imagen se definen en el
# archivo de configuración (`Pulumi.<stack>.yaml` o un fichero custom que se
# incluya en el repositorio).  Por ejemplo:
#
#   pulumi config set acrName miejemploacr
#   pulumi config set imageTag v1.2.3
#
# Esto permite variar el valor sin tocar el código.
config = pulumi.Config()
stack = pulumi.get_stack()

# dinámicos para el ACR y las etiquetas de las imágenes (se cargan mediante
# `pulumi config set` en el repo).
acr_name = config.require("acr-name")
fn_core_bff_image_tag = config.require("fn-core-bff-image-tag")

resource_group = resources.ResourceGroup(f"rg-poc-eltablero-{stack}")

registry = acr.get_registry_output(
    resource_group_name=resource_group.name,
    registry_name=acr_name
)


# helper used to sanity‑check ARM resource IDs passed into the program.  Azure
# strongly validates the "/subscriptions/.../providers/.../..." format and will
# reject anything else with the `ArmResourceId has incorrect formatting` error.
#
# We use this whenever an ID comes from configuration or another stack so that
# we fail early with a clearer message instead of waiting for Azure to respond.
def expect_arm_id(val: pulumi.Input[str]) -> pulumi.Output[str]:
    def check(v: str) -> str:
        if not v or not v.startswith("/subscriptions/"):
            raise ValueError(f"not a valid ARM id: {v}")
        return v
    return pulumi.Output.from_input(val).apply(check)


# 2. Log Analytics (Requerido para el Environment de ACA)
workspace = operationalinsights.Workspace(
    "log-analytics",
    resource_group_name=resource_group.name,
    sku=operationalinsights.WorkspaceSkuArgs(name="PerGB2018"),
)

workspace_keys = operationalinsights.get_shared_keys_output(
    resource_group_name=resource_group.name,
    workspace_name=workspace.name,
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

# 4. core-bff (Backend API)
backend_app = containerapps.ContainerApp(
    "core-bff",
    resource_group_name=resource_group.name,
    managed_environment_id=aca_env.id,
    identity=containerapps.ManagedServiceIdentityArgs(
        type="SystemAssigned",
    ),
    configuration=containerapps.ConfigurationArgs(
        ingress=containerapps.IngressArgs(external=True, target_port=8000),
        registries=[containerapps.RegistryCredentialsArgs(
            server=registry.login_server,
            identity="system" # Simplificado
        )]
    ),
    template=containerapps.TemplateArgs(
        containers=[containerapps.ContainerArgs(
            name="core-bff",
            image=pulumi.Output.all(registry.login_server, fn_core_bff_image_tag).apply(
                lambda args: f"{args[0]}/{args[1]}"
            ),
            resources=containerapps.ContainerResourcesArgs(cpu=0.5, memory="1Gi"),
        )],
    ),
)

# 6. Politica WAF — using frontdoor.Policy (azure-native frontdoor module).
# Azure retired cdn.Policy (CDN WAF), so this resource must live under the
# frontdoor namespace instead.
# explicitly set the Azure name rather than relying on the Pulumi
# resource name; it avoids surprises with characters that Azure might reject.
# the dash in "waf-policy" is permitted but some Azure services are stricter,
# so being explicit helps debug later.
waf_policy = frontdoor.Policy(
    "wafpolicy",
    resource_group_name=resource_group.name,
    policy_name="wafpolicy",            # same as the logical name, safe ID
    location="Global",
    sku=frontdoor.SkuArgs(name=frontdoor.SkuName.STANDARD_AZURE_FRONT_DOOR),
    policy_settings=frontdoor.PolicySettingsArgs(
        enabled_state=frontdoor.PolicyEnabledState.ENABLED,
        mode=frontdoor.PolicyMode.PREVENTION,
        custom_block_response_status_code=403,
    ),
    custom_rules=frontdoor.CustomRuleListArgs(
        rules=[
            frontdoor.CustomRuleArgs(
                name="ratelimitapi",
                priority=1,
                rule_type=frontdoor.RuleType.RATE_LIMIT_RULE,
                action=frontdoor.ActionType.BLOCK,
                rate_limit_threshold=1000,
                rate_limit_duration_in_minutes=1,
                match_conditions=[
                    frontdoor.MatchConditionArgs(
                        match_variable=frontdoor.MatchVariable.REQUEST_URI,
                        operator=frontdoor.Operator.BEGINS_WITH,
                        match_value=["/api"],
                    )
                ],
            ),
            frontdoor.CustomRuleArgs(
                name="ratelimitfrontend",
                priority=2,
                rule_type=frontdoor.RuleType.RATE_LIMIT_RULE,
                action=frontdoor.ActionType.BLOCK,
                rate_limit_threshold=2000,
                rate_limit_duration_in_minutes=1,
                match_conditions=[
                    frontdoor.MatchConditionArgs(
                        match_variable=frontdoor.MatchVariable.REQUEST_URI,
                        operator=frontdoor.Operator.BEGINS_WITH,
                        negate_condition=True,
                        match_value=["/api"],
                    )
                ],
            ),
            frontdoor.CustomRuleArgs(
                name="blocksqlinjection",
                priority=3,
                rule_type=frontdoor.RuleType.MATCH_RULE,
                action=frontdoor.ActionType.BLOCK,
                match_conditions=[
                    frontdoor.MatchConditionArgs(
                        match_variable=frontdoor.MatchVariable.QUERY_STRING,
                        operator=frontdoor.Operator.CONTAINS,
                        match_value=["union", "select", "insert", "drop"],
                        transforms=[frontdoor.TransformType.LOWERCASE],
                    )
                ],
            ),
            frontdoor.CustomRuleArgs(
                name="blockxssattempts",
                priority=4,
                rule_type=frontdoor.RuleType.MATCH_RULE,
                action=frontdoor.ActionType.BLOCK,
                match_conditions=[
                    frontdoor.MatchConditionArgs(
                        match_variable=frontdoor.MatchVariable.QUERY_STRING,
                        operator=frontdoor.Operator.CONTAINS,
                        match_value=["<script", "javascript:", "onerror="],
                        transforms=[frontdoor.TransformType.LOWERCASE],
                    )
                ],
            ),
        ]
    ),
)

# 7.1 Perfil de Front Door (Standard)
# this SKU only supports a global location, so specify it explicitly.
fd_profile = cdn.Profile(
    "frontdoor-profile",
    resource_group_name=resource_group.name,
    location="Global",
    sku=cdn.SkuArgs(name="Standard_AzureFrontDoor"),
)

# 7.2 Endpoint (La URL de entrada)
fd_endpoint = cdn.AFDEndpoint(
    "fd-endpoint",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    enabled_state="Enabled",
)

# 7.3 Origin Groups (separate for backend and frontend routing)
fd_origin_group_backend = cdn.AFDOriginGroup(
    "fd-origin-group-backend",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    load_balancing_settings=cdn.LoadBalancingSettingsParametersArgs(
        sample_size=4,
        successful_samples_required=3,
    ),
    health_probe_settings=cdn.HealthProbeParametersArgs(
        probe_path="/",
        probe_protocol=cdn.ProbeProtocol.HTTPS,
        probe_request_type=cdn.HealthProbeRequestType.HEAD,
        probe_interval_in_seconds=30,
    ),
)

fd_origin_group_frontend = cdn.AFDOriginGroup(
    "fd-origin-group-frontend",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    load_balancing_settings=cdn.LoadBalancingSettingsParametersArgs(
        sample_size=4,
        successful_samples_required=3,
    ),
    health_probe_settings=cdn.HealthProbeParametersArgs(
        probe_path="/",
        probe_protocol=cdn.ProbeProtocol.HTTPS,
        probe_request_type=cdn.HealthProbeRequestType.HEAD,
        probe_interval_in_seconds=30,
    ),
)

# 7.4 Origin para Backend
fd_origin_backend = cdn.AFDOrigin(
    "fd-origin-backend",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    origin_group_name=fd_origin_group_backend.name,
    host_name=backend_app.configuration.apply(
        lambda c: c.ingress.fqdn if c and c.ingress else ""
    ),
    http_port=80,
    https_port=443,
    origin_host_header=backend_app.configuration.apply(
        lambda c: c.ingress.fqdn if c and c.ingress else ""
    ),
)

# 7.5 Rutas
# Ruta para API Backend.
# depends_on ensures the origin is fully provisioned before the route is
# created, which avoids the "origin group has no enabled origins" error.
fd_route_api = cdn.Route(
    "fd-route-api",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    endpoint_name=fd_endpoint.name,
    origin_group=cdn.ResourceReferenceArgs(
        id=fd_origin_group_backend.id,
    ),
    supported_protocols=["Http", "Https"],
    patterns_to_match=["/api/*"],
    forwarding_protocol="HttpsOnly",
    link_to_default_domain="Enabled",
    https_redirect="Enabled",
    opts=pulumi.ResourceOptions(depends_on=[fd_origin_backend]),
)

# 7.6 Vinculacion de WAF (Security Policy)
# En Standard/Premium, el WAF se vincula mediante una Security Policy
security_policy = cdn.SecurityPolicy(
    "fd-security-policy",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    parameters=cdn.SecurityPolicyWebApplicationFirewallParametersArgs(
        type="WebApplicationFirewall",
        waf_policy=cdn.ResourceReferenceArgs(id=expect_arm_id(waf_policy.id)),  # validate format

        associations=[
            cdn.SecurityPolicyWebApplicationFirewallAssociationArgs(
                domains=[cdn.ActivatedResourceReferenceArgs(id=expect_arm_id(fd_endpoint.id))],
                patterns_to_match=["/*"],  # AFDX requires "/*" for security policies
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
        containers=[
            containerapps.ContainerArgs(
                name="react-frontend",
                image="mcr.microsoft.com/azuredocs/containerapps-helloworld",
                env=[
                    containerapps.EnvironmentVarArgs(
                        name="API_URL",
                        value=fd_endpoint.host_name.apply(
                            lambda fqdn: f"https://{fqdn}/api"
                        ),
                    ),
                    containerapps.EnvironmentVarArgs(
                        name="WAF_PROTECTED",
                        value="true",
                    ),
                ],
                resources=containerapps.ContainerResourcesArgs(cpu=0.5, memory="1Gi"),
            )
        ],
    ),
    opts=pulumi.ResourceOptions(depends_on=[security_policy]),
)

# 7.4b Origin para Frontend (para acceso directo sin WAF si es necesario)
fd_origin_frontend = cdn.AFDOrigin(
    "fd-origin-frontend",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    origin_group_name=fd_origin_group_frontend.name,
    host_name=frontend_app.configuration.apply(
        lambda c: c.ingress.fqdn if c and c.ingress else ""
    ),
    http_port=80,
    https_port=443,
    origin_host_header=frontend_app.configuration.apply(
        lambda c: c.ingress.fqdn if c and c.ingress else ""
    ),
    opts=pulumi.ResourceOptions(depends_on=[frontend_app]),
)

# 7.5b Ruta para Frontend
fd_route_frontend = cdn.Route(
    "fd-route-frontend",
    resource_group_name=resource_group.name,
    profile_name=fd_profile.name,
    endpoint_name=fd_endpoint.name,
    origin_group=cdn.ResourceReferenceArgs(
        id=fd_origin_group_frontend.id,
    ),
    supported_protocols=["Http", "Https"],
    patterns_to_match=["/*"],
    forwarding_protocol="HttpsOnly",
    link_to_default_domain="Enabled",
    https_redirect="Enabled",
    opts=pulumi.ResourceOptions(depends_on=[fd_origin_frontend]),
)

# Outputs
pulumi.export(
    "backend_url",
    backend_app.configuration.apply(
        lambda c: c.ingress.fqdn if c and c.ingress else ""
    ),
)
pulumi.export(
    "frontend_url",
    frontend_app.configuration.apply(
        lambda c: c.ingress.fqdn if c and c.ingress else ""
    ),
)
pulumi.export("front_door_url", fd_endpoint.host_name)
pulumi.export("front_door_endpoint_id", expect_arm_id(fd_endpoint.id))

pulumi.export("waf_policy_id", expect_arm_id(waf_policy.id))