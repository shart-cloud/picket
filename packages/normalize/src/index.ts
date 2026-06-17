import { assertOcsfEvent, type OcsfClass, type OcsfEvent, type OcsfStatus } from "@picket/core";

type JsonObject = Record<string, unknown>;

export function normalizeCloudTrail(raw: JsonObject): OcsfEvent {
  const eventName = stringValue(raw.eventName) ?? "unknown";
  const sourceIPAddress = stringValue(raw.sourceIPAddress);
  const awsRegion = stringValue(raw.awsRegion);
  const eventSource = stringValue(raw.eventSource);
  const userIdentity = objectValue(raw.userIdentity);
  const responseElements = objectValue(raw.responseElements);
  const errorCode = stringValue(raw.errorCode);

  return assertOcsfEvent({
    time: isoTime(raw.eventTime),
    source: "aws_cloudtrail",
    category: "identity_access",
    class_name: cloudTrailClass(eventName),
    activity_name: eventName,
    status: errorCode ? "failure" : "success",
    message: errorCode ? `${eventName} failed: ${errorCode}` : `${eventName} succeeded`,
    actor: {
      user: {
        uid: stringValue(userIdentity.principalId),
        name: stringValue(userIdentity.userName) ?? stringValue(userIdentity.arn),
        type: stringValue(userIdentity.type)
      }
    },
    src_endpoint: {
      ip: sourceIPAddress
    },
    api: {
      operation: eventName,
      service: {
        name: eventSource
      }
    },
    cloud: {
      provider: "aws",
      region: awsRegion,
      account: {
        uid: stringValue(raw.recipientAccountId) ?? stringValue(userIdentity.accountId)
      }
    },
    metadata: {
      product_name: "AWS CloudTrail",
      original_uid: stringValue(raw.eventID),
      raw_event: raw
    },
    ...(eventName === "ConsoleLogin"
      ? {
          user: {
            uid: stringValue(userIdentity.principalId),
            name: stringValue(userIdentity.userName),
            type: stringValue(userIdentity.type)
          },
          http_request: {
            user_agent: stringValue(raw.userAgent)
          },
          message: `Console login ${(stringValue(responseElements.ConsoleLogin) ?? "unknown").toLowerCase()}`
        }
      : {})
  });
}

const VPC_FLOW_LOG_FIELDS = [
  "version",
  "account_id",
  "interface_id",
  "srcaddr",
  "dstaddr",
  "srcport",
  "dstport",
  "protocol",
  "packets",
  "bytes",
  "start",
  "end",
  "action",
  "log_status"
] as const;

export function parseVpcFlowLogs(body: string): JsonObject[] {
  const out: JsonObject[] = [];
  for (const line of body.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const parts = trimmed.split(/\s+/);
    if (parts[0] === "version" || parts.length < VPC_FLOW_LOG_FIELDS.length) continue;
    const record: JsonObject = {};
    for (const [i, field] of VPC_FLOW_LOG_FIELDS.entries()) record[field] = parts[i];
    out.push(record);
  }
  return out;
}

export function normalizeVpcFlowLog(raw: JsonObject): OcsfEvent {
  const action = stringValue(raw.action)?.toUpperCase();
  const status: OcsfStatus = action === "ACCEPT" ? "success" : action === "REJECT" ? "failure" : "unknown";
  const start = numberValue(raw.start);
  const end = numberValue(raw.end);
  const srcaddr = dashToUndefined(stringValue(raw.srcaddr));
  const dstaddr = dashToUndefined(stringValue(raw.dstaddr));
  const srcport = dashToUndefined(stringValue(raw.srcport));
  const dstport = dashToUndefined(stringValue(raw.dstport));
  const protocol = protocolName(stringValue(raw.protocol));

  return assertOcsfEvent({
    time: epochSecondsToIso(end ?? start),
    source: "aws_vpc_flow",
    category: "network_activity",
    class_name: "network_activity",
    activity_name: action ?? "UNKNOWN",
    status,
    message: `${action ?? "UNKNOWN"} ${protocol} ${srcaddr ?? "?"}:${srcport ?? "?"} -> ${dstaddr ?? "?"}:${dstport ?? "?"}`,
    src_endpoint: {
      ip: srcaddr
    },
    dst_endpoint: {
      ip: dstaddr
    },
    cloud: {
      provider: "aws",
      account: {
        uid: dashToUndefined(stringValue(raw.account_id))
      }
    },
    metadata: {
      product_name: "AWS VPC Flow Logs",
      original_uid: [raw.account_id, raw.interface_id, raw.start, raw.end, raw.srcaddr, raw.dstaddr, raw.srcport, raw.dstport]
        .map((value) => String(value ?? ""))
        .join(":"),
      raw_event: raw
    }
  });
}

export function normalizeGuardDuty(raw: JsonObject): OcsfEvent {
  const detail = objectValue(raw.detail);
  const finding = Object.keys(detail).length > 0 ? detail : raw;
  const service = objectValue(finding.service);
  const action = objectValue(service.action);
  const resource = objectValue(finding.resource);
  const accountId = stringValue(finding.accountId) ?? stringValue(raw.account) ?? stringValue(raw.accountId);
  const region = stringValue(finding.region) ?? stringValue(raw.region);
  const type = stringValue(finding.type) ?? stringValue(raw["detail-type"]) ?? "GuardDuty finding";
  const severity = numberValue(finding.severity);
  const actionName = firstStringKey(action) ?? type;
  const remoteIp = guardDutyRemoteIp(action);

  return assertOcsfEvent({
    time: isoTime(finding.updatedAt ?? finding.createdAt ?? raw.time),
    source: "aws_guardduty",
    category: "findings",
    class_name: "detection_finding",
    activity_name: type,
    status: severity === undefined ? "unknown" : severity >= 4 ? "failure" : "success",
    message: stringValue(finding.description) ?? type,
    src_endpoint: {
      ip: remoteIp
    },
    dst_endpoint: {
      uid: stringValue(resource.resourceType),
      name: guardDutyResourceName(resource)
    },
    api: {
      operation: actionName,
      service: { name: "guardduty" }
    },
    cloud: {
      provider: "aws",
      region,
      account: { uid: accountId }
    },
    metadata: {
      product_name: "AWS GuardDuty",
      original_uid: stringValue(finding.id) ?? stringValue(raw.id),
      raw_event: raw
    }
  });
}

export function normalizeGcpCloudAudit(raw: JsonObject): OcsfEvent {
  const proto = objectValue(raw.protoPayload);
  const authn = objectValue(proto.authenticationInfo);
  const reqMeta = objectValue(proto.requestMetadata);
  const resource = objectValue(raw.resource);
  const labels = objectValue(resource.labels);
  const statusBlock = objectValue(proto.status);
  const method = stringValue(proto.methodName) ?? "unknown";
  const code = numberValue(statusBlock.code);

  return assertOcsfEvent({
    time: isoTime(raw.timestamp ?? raw.receiveTimestamp),
    source: "gcp_cloud_audit",
    category: "identity_access",
    class_name: "api_activity",
    activity_name: method,
    status: code === undefined || code === 0 ? "success" : "failure",
    message: stringValue(proto.resourceName) ?? method,
    actor: {
      user: {
        uid: stringValue(authn.principalSubject) ?? stringValue(authn.principalEmail),
        name: stringValue(authn.principalEmail),
        email: stringValue(authn.principalEmail)
      }
    },
    src_endpoint: {
      ip: stringValue(reqMeta.callerIp)
    },
    api: {
      operation: method,
      service: { name: stringValue(proto.serviceName) ?? "gcp" }
    },
    cloud: {
      provider: "gcp",
      region: stringValue(labels.location) ?? stringValue(labels.zone),
      account: { uid: stringValue(labels.project_id), name: stringValue(labels.project_id) }
    },
    http_request: {
      user_agent: stringValue(reqMeta.callerSuppliedUserAgent)
    },
    metadata: {
      product_name: "GCP Cloud Audit Logs",
      original_uid: stringValue(raw.insertId),
      raw_event: raw
    }
  });
}

export function normalizeAzureActivity(raw: JsonObject): OcsfEvent {
  const claims = objectValue(raw.claims);
  const authorization = objectValue(raw.authorization);
  const httpRequest = objectValue(raw.httpRequest);
  const caller = stringValue(raw.caller) ?? stringValue(claims.upn) ?? stringValue(claims.appid);
  const operation = stringValue(raw.operationName) ?? stringValue(raw.operationNameValue) ?? stringValue(authorization.action) ?? "unknown";
  const statusText = stringValue(raw.status) ?? stringValue(raw.resultType);

  return assertOcsfEvent({
    time: isoTime(raw.eventTimestamp ?? raw.time ?? raw.submissionTimestamp),
    source: "azure_activity",
    category: "identity_access",
    class_name: "api_activity",
    activity_name: operation,
    status: azureStatus(statusText),
    message: stringValue(raw.description) ?? stringValue(raw.resultDescription) ?? operation,
    actor: {
      user: {
        uid: stringValue(claims.oid) ?? stringValue(claims.appid) ?? caller,
        name: caller,
        email: caller?.includes("@") ? caller : undefined,
        type: stringValue(claims.idtyp)
      }
    },
    src_endpoint: {
      ip: stringValue(raw.callerIpAddress) ?? stringValue(httpRequest.clientIpAddress)
    },
    api: {
      operation,
      service: { name: stringValue(raw.resourceProviderName) ?? "azure" }
    },
    cloud: {
      provider: "azure",
      region: stringValue(raw.resourceRegion),
      account: { uid: stringValue(raw.subscriptionId), name: stringValue(raw.tenantId) }
    },
    http_request: {
      http_method: stringValue(httpRequest.method),
      url: stringValue(httpRequest.uri)
    },
    metadata: {
      product_name: "Azure Activity Log",
      original_uid: stringValue(raw.eventDataId) ?? stringValue(raw.correlationId),
      raw_event: raw
    }
  });
}

export function normalizeAzureAdSignin(raw: JsonObject): OcsfEvent {
  const statusBlock = objectValue(raw.status);
  const device = objectValue(raw.deviceDetail);
  const location = objectValue(raw.location);
  const errorCode = numberValue(statusBlock.errorCode);
  const userPrincipalName = stringValue(raw.userPrincipalName);
  const appDisplayName = stringValue(raw.appDisplayName) ?? stringValue(raw.resourceDisplayName) ?? "unknown";

  return assertOcsfEvent({
    time: isoTime(raw.createdDateTime ?? raw.time),
    source: "azure_ad_signin",
    category: "identity_access",
    class_name: "authentication",
    activity_name: `Sign-in to ${appDisplayName}`,
    status: errorCode === undefined || errorCode === 0 ? "success" : "failure",
    message: stringValue(statusBlock.failureReason) ?? stringValue(statusBlock.additionalDetails) ?? `Sign-in to ${appDisplayName}`,
    actor: {
      user: {
        uid: stringValue(raw.userId) ?? userPrincipalName,
        name: stringValue(raw.userDisplayName) ?? userPrincipalName,
        email: userPrincipalName,
        type: stringValue(raw.signInEventTypes)
      }
    },
    user: {
      uid: stringValue(raw.userId) ?? userPrincipalName,
      name: stringValue(raw.userDisplayName) ?? userPrincipalName,
      email: userPrincipalName
    },
    src_endpoint: {
      ip: stringValue(raw.ipAddress),
      name: stringValue(device.displayName),
      uid: stringValue(device.deviceId),
      country: stringValue(location.countryOrRegion),
      region: stringValue(location.state),
      city: stringValue(location.city)
    },
    api: {
      operation: "signin",
      service: { name: appDisplayName }
    },
    cloud: {
      provider: "azure",
      account: { uid: stringValue(raw.tenantId) }
    },
    metadata: {
      product_name: "Azure AD Sign-in Logs",
      original_uid: stringValue(raw.id) ?? stringValue(raw.correlationId),
      raw_event: raw
    }
  });
}

export function normalizeGithubAudit(raw: JsonObject): OcsfEvent {
  const action = stringValue(raw.action) ?? stringValue(raw.operation_type) ?? "unknown";
  const actor = stringValue(raw.actor) ?? stringValue(raw.actor_login);
  const statusText = stringValue(raw.status) ?? stringValue(raw.result);

  return assertOcsfEvent({
    time: isoTime(raw["@timestamp"] ?? raw.created_at ?? raw.timestamp),
    source: "github_audit",
    category: "identity_access",
    class_name: githubAuditClass(action),
    activity_name: action,
    status: githubAuditStatus(statusText),
    message: stringValue(raw.message) ?? action,
    actor: {
      user: {
        uid: stringValue(raw.actor_id) ?? actor,
        name: actor,
        email: stringValue(raw.actor_email)
      }
    },
    user: {
      uid: stringValue(raw.user_id) ?? stringValue(raw.user) ?? stringValue(raw.target_login),
      name: stringValue(raw.user) ?? stringValue(raw.target_login)
    },
    src_endpoint: {
      ip: stringValue(raw.actor_ip) ?? stringValue(raw.ip)
    },
    api: {
      operation: action,
      service: { name: "github" }
    },
    cloud: {
      provider: "github",
      account: { uid: stringValue(raw.org) ?? stringValue(raw.enterprise), name: stringValue(raw.org) }
    },
    metadata: {
      product_name: "GitHub Audit Log",
      original_uid: stringValue(raw._document_id) ?? stringValue(raw.id),
      raw_event: raw
    }
  });
}

export function normalizeM365Management(raw: JsonObject): OcsfEvent {
  const operation = stringValue(raw.Operation) ?? stringValue(raw.operation) ?? "unknown";
  const workload = stringValue(raw.Workload) ?? stringValue(raw.workload) ?? "m365";
  const result = stringValue(raw.ResultStatus) ?? stringValue(raw.resultStatus);
  const userId = stringValue(raw.UserId) ?? stringValue(raw.userId);
  const objectId = stringValue(raw.ObjectId) ?? stringValue(raw.objectId);

  return assertOcsfEvent({
    time: isoTime(raw.CreationTime ?? raw.creationTime ?? raw.time),
    source: "m365_management",
    category: "identity_access",
    class_name: m365Class(operation, workload),
    activity_name: operation,
    status: m365Status(result),
    message: objectId ? `${operation} ${objectId}` : operation,
    actor: {
      user: {
        uid: userId,
        name: userId,
        email: userId?.includes("@") ? userId : undefined,
        type: stringValue(raw.UserType) ?? stringValue(raw.userType)
      }
    },
    user: {
      uid: userId,
      name: userId,
      email: userId?.includes("@") ? userId : undefined
    },
    src_endpoint: {
      ip: stringValue(raw.ClientIP) ?? stringValue(raw.clientIp) ?? stringValue(raw.ClientIPAddress)
    },
    api: {
      operation,
      service: { name: workload }
    },
    cloud: {
      provider: "microsoft365",
      account: {
        uid: stringValue(raw.OrganizationId) ?? stringValue(raw.TenantId) ?? stringValue(raw.tenantId),
        name: stringValue(raw.OrganizationName)
      }
    },
    metadata: {
      product_name: "Microsoft 365 Management Activity",
      original_uid: stringValue(raw.Id) ?? stringValue(raw.id),
      raw_event: raw
    }
  });
}

export function normalizeOkta(raw: JsonObject): OcsfEvent {
  const actor = objectValue(raw.actor);
  const client = objectValue(raw.client);
  const outcome = objectValue(raw.outcome);
  const request = objectValue(raw.request);
  const ipChain = arrayValue(client.ipChain);
  const firstIp = objectValue(ipChain[0]);
  const geographicalContext = objectValue(firstIp.geographicalContext);
  const userAgent = objectValue(client.userAgent);
  const eventType = stringValue(raw.eventType) ?? "unknown";

  return assertOcsfEvent({
    time: isoTime(raw.published),
    source: "okta_auth",
    category: "identity_access",
    class_name: oktaClass(eventType),
    activity_name: stringValue(raw.displayMessage) ?? stringValue(raw.eventType) ?? "unknown",
    status: oktaStatus(stringValue(outcome.result)),
    message: stringValue(raw.displayMessage),
    actor: {
      user: {
        uid: stringValue(actor.id),
        name: stringValue(actor.displayName),
        email: stringValue(actor.alternateId),
        type: stringValue(actor.type)
      }
    },
    user: {
      uid: stringValue(actor.id),
      name: stringValue(actor.displayName),
      email: stringValue(actor.alternateId),
      type: stringValue(actor.type)
    },
    src_endpoint: {
      ip: stringValue(client.ipAddress) ?? stringValue(firstIp.ip),
      country: stringValue(geographicalContext.country),
      region: stringValue(geographicalContext.state),
      city: stringValue(geographicalContext.city)
    },
    http_request: {
      user_agent: stringValue(userAgent.rawUserAgent),
      url: stringValue(request.uri)
    },
    metadata: {
      product_name: "Okta System Log",
      original_uid: stringValue(raw.uuid),
      raw_event: raw
    }
  });
}

export type K8sFlavor = "eks" | "gke" | "aks" | "generic";

export interface K8sAuditNormalizeOptions {
  flavor?: K8sFlavor;
}

export function parseNdjson(body: string): JsonObject[] {
  const out: JsonObject[] = [];
  for (const line of body.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        out.push(parsed as JsonObject);
      }
    } catch {
      /* skip malformed line */
    }
  }
  return out;
}

export function flavorOfRecord(record: JsonObject): K8sFlavor | undefined {
  const provider = typeof record.cloud_provider === "string" ? record.cloud_provider : undefined;
  if (provider === "aws") return "eks";
  if (provider === "gcp") return "gke";
  if (provider === "azure") return "aks";
  if (provider === "generic") return "generic";
  return undefined;
}

export function normalizeK8sAudit(raw: JsonObject, opts: K8sAuditNormalizeOptions = {}): OcsfEvent {
  const flavor = opts.flavor ?? inferK8sFlavor(raw);
  const clusterName = stringValue(raw.cluster_name) ?? "unknown";
  const clusterRegion = stringValue(raw.cluster_region);
  const cloudAccount = stringValue(raw.cloud_account);
  const cloudProvider = stringValue(raw.cloud_provider) ?? flavor;

  if (flavor === "gke") {
    return normalizeGkeLogEntry(raw, { clusterName, clusterRegion, cloudAccount, cloudProvider });
  }

  const audit = extractK8sAuditEvent(raw, flavor);
  const user = objectValue(audit.user);
  const objectRef = objectValue(audit.objectRef);
  const responseStatus = objectValue(audit.responseStatus);
  const sourceIPs = arrayValue(audit.sourceIPs);
  const verb = stringValue(audit.verb) ?? "unknown";
  const code = numberValue(responseStatus.code);
  const status: OcsfStatus = code === undefined ? "unknown" : code < 400 ? "success" : "failure";

  return assertOcsfEvent({
    time: isoTime(audit.requestReceivedTimestamp ?? audit.stageTimestamp ?? raw.time),
    source: "kubernetes_audit",
    category: "identity_access",
    class_name: "api_activity",
    activity_name: verb,
    status,
    message: `${verb} ${stringValue(objectRef.resource) ?? "?"}${objectRef.namespace ? ` in ${stringValue(objectRef.namespace)}` : ""}${code !== undefined ? ` -> ${code}` : ""}`,
    actor: {
      user: {
        uid: stringValue(user.uid),
        name: stringValue(user.username),
        type: k8sUserType(stringValue(user.username))
      }
    },
    src_endpoint: {
      ip: stringValue(sourceIPs[0])
    },
    api: {
      operation: verb,
      service: { name: "kubernetes" }
    },
    cloud: {
      provider: cloudProvider,
      region: clusterRegion,
      account: { uid: cloudAccount, name: clusterName }
    },
    http_request: {
      user_agent: stringValue(audit.userAgent),
      url: stringValue(audit.requestURI)
    },
    metadata: {
      product_name: `Kubernetes Audit (${flavor})`,
      original_uid: stringValue(audit.auditID),
      raw_event: raw
    }
  });
}

export function normalizeCloudflareAudit(raw: JsonObject): OcsfEvent {
  const actor = objectValue(raw.Actor);
  const interfaceValue = objectValue(raw.Interface);
  const metadata = objectValue(raw.Metadata);

  return assertOcsfEvent({
    time: isoTime(raw.When),
    source: "cloudflare_audit",
    category: "identity_access",
    class_name: "api_activity",
    activity_name: stringValue(raw.Action) ?? "unknown",
    status: "success",
    message: stringValue(raw.Action),
    actor: {
      user: {
        uid: stringValue(actor.ID),
        email: stringValue(actor.Email),
        type: stringValue(actor.Type)
      }
    },
    src_endpoint: {
      ip: stringValue(interfaceValue.IPAddress)
    },
    api: {
      operation: stringValue(raw.Action),
      service: {
        name: "cloudflare"
      }
    },
    cloud: {
      provider: "cloudflare",
      account: {
        uid: stringValue(raw.AccountID) ?? stringValue(metadata.account_id)
      }
    },
    metadata: {
      product_name: "Cloudflare Audit Logs",
      original_uid: stringValue(raw.ID),
      raw_event: raw
    }
  });
}

function cloudTrailClass(eventName: string): OcsfClass {
  if (eventName === "ConsoleLogin") return "authentication";
  if (eventName.toLowerCase().includes("user")) return "account_change";
  return "api_activity";
}

function oktaClass(eventType: string): OcsfClass {
  if (eventType.startsWith("user.authentication")) return "authentication";
  if (eventType.startsWith("user.lifecycle") || eventType.startsWith("group.user_membership")) return "account_change";
  return "api_activity";
}

function oktaStatus(result: string | undefined): OcsfStatus {
  if (result === "SUCCESS") return "success";
  if (result === "FAILURE" || result === "DENY") return "failure";
  return "unknown";
}

function githubAuditClass(action: string): OcsfClass {
  if (action.includes("oauth_authorization") || action.includes("login") || action.includes("saml")) return "authentication";
  if (action.includes("team") || action.includes("member") || action.includes("org.add") || action.includes("org.remove")) return "account_change";
  return "api_activity";
}

function githubAuditStatus(status: string | undefined): OcsfStatus {
  if (!status) return "unknown";
  const normalized = status.toLowerCase();
  if (normalized === "success" || normalized === "succeeded" || normalized === "ok") return "success";
  if (normalized === "failure" || normalized === "failed" || normalized === "error" || normalized === "denied") return "failure";
  return "unknown";
}

function m365Class(operation: string, workload: string): OcsfClass {
  const text = `${workload}.${operation}`.toLowerCase();
  if (text.includes("login") || text.includes("signin") || text.includes("userloggedin")) return "authentication";
  if (text.includes("add member") || text.includes("remove member") || text.includes("user") || text.includes("role")) return "account_change";
  return "api_activity";
}

function m365Status(status: string | undefined): OcsfStatus {
  if (!status) return "unknown";
  const normalized = status.toLowerCase();
  if (normalized === "succeeded" || normalized === "success" || normalized === "true") return "success";
  if (normalized === "failed" || normalized === "failure" || normalized === "error" || normalized === "false") return "failure";
  return "unknown";
}

function azureStatus(status: string | undefined): OcsfStatus {
  if (!status) return "unknown";
  const normalized = status.toLowerCase();
  if (normalized === "succeeded" || normalized === "success" || normalized === "started") return "success";
  if (normalized === "failed" || normalized === "failure") return "failure";
  return "unknown";
}

function firstStringKey(value: JsonObject): string | undefined {
  return Object.keys(value).find((key) => key.length > 0);
}

function guardDutyResourceName(resource: JsonObject): string | undefined {
  const instance = objectValue(resource.instanceDetails);
  const container = objectValue(resource.containerDetails);
  const accessKey = objectValue(resource.accessKeyDetails);
  return stringValue(instance.instanceId) ?? stringValue(container.containerRuntime) ?? stringValue(accessKey.userName);
}

function guardDutyRemoteIp(action: JsonObject): string | undefined {
  const network = objectValue(action.networkConnectionAction);
  const remote = objectValue(network.remoteIpDetails);
  const portProbe = objectValue(action.portProbeAction);
  const portProbeDetails = arrayValue(portProbe.portProbeDetails);
  const firstProbe = objectValue(portProbeDetails[0]);
  const probeRemote = objectValue(firstProbe.remoteIpDetails);
  const awsApi = objectValue(action.awsApiCallAction);
  const apiRemote = objectValue(awsApi.remoteIpDetails);
  return stringValue(remote.ipAddressV4) ?? stringValue(probeRemote.ipAddressV4) ?? stringValue(apiRemote.ipAddressV4);
}

function inferK8sFlavor(raw: JsonObject): K8sFlavor {
  const provider = stringValue(raw.cloud_provider);
  if (provider === "aws") return "eks";
  if (provider === "gcp") return "gke";
  if (provider === "azure") return "aks";
  return "generic";
}

function extractK8sAuditEvent(raw: JsonObject, flavor: K8sFlavor): JsonObject {
  if (flavor === "aks") {
    const properties = objectValue(raw.properties);
    const logField = properties.log;
    if (typeof logField === "string") {
      try {
        const parsed = JSON.parse(logField);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          return parsed as JsonObject;
        }
      } catch {
        /* fall through */
      }
    }
  }
  return raw;
}

function normalizeGkeLogEntry(
  raw: JsonObject,
  ctx: { clusterName: string; clusterRegion?: string; cloudAccount?: string; cloudProvider: string }
): OcsfEvent {
  const proto = objectValue(raw.protoPayload);
  const authn = objectValue(proto.authenticationInfo);
  const reqMeta = objectValue(proto.requestMetadata);
  const method = stringValue(proto.methodName) ?? "unknown";
  const verb = method.split(".").pop() ?? "unknown";
  const statusBlock = objectValue(proto.status);
  const code = numberValue(statusBlock.code);
  const status: OcsfStatus = code === undefined ? "success" : code === 0 ? "success" : "failure";

  return assertOcsfEvent({
    time: isoTime(raw.timestamp),
    source: "kubernetes_audit",
    category: "identity_access",
    class_name: "api_activity",
    activity_name: method,
    status,
    message: `${method} ${stringValue(proto.resourceName) ?? ""}`.trim(),
    actor: {
      user: {
        uid: stringValue(authn.principalSubject) ?? stringValue(authn.principalEmail),
        name: stringValue(authn.principalEmail),
        email: stringValue(authn.principalEmail),
        type: stringValue(authn.principalType)
      }
    },
    src_endpoint: {
      ip: stringValue(reqMeta.callerIp)
    },
    api: {
      operation: verb,
      service: { name: stringValue(proto.serviceName) ?? "kubernetes" }
    },
    cloud: {
      provider: ctx.cloudProvider,
      region: ctx.clusterRegion,
      account: { uid: ctx.cloudAccount, name: ctx.clusterName }
    },
    http_request: {
      user_agent: stringValue(reqMeta.callerSuppliedUserAgent)
    },
    metadata: {
      product_name: "Kubernetes Audit (gke)",
      original_uid: stringValue(raw.insertId),
      raw_event: raw
    }
  });
}

function k8sUserType(username: string | undefined): string | undefined {
  if (!username) return undefined;
  if (username === "system:anonymous" || username === "system:unauthenticated") return "Anonymous";
  if (username.startsWith("system:serviceaccount:")) return "ServiceAccount";
  if (username.startsWith("system:")) return "System";
  return "User";
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.length > 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function isoTime(value: unknown): string {
  const text = stringValue(value);
  if (!text) return new Date(0).toISOString();

  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) return new Date(0).toISOString();

  return parsed.toISOString();
}

function epochSecondsToIso(value: number | undefined): string {
  if (value === undefined) return new Date(0).toISOString();
  return new Date(value * 1000).toISOString();
}

function dashToUndefined(value: string | undefined): string | undefined {
  return value && value !== "-" ? value : undefined;
}

function protocolName(value: string | undefined): string {
  if (value === "6") return "tcp";
  if (value === "17") return "udp";
  if (value === "1") return "icmp";
  return value ?? "unknown";
}

function stringValue(value: unknown, fallback?: string): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function objectValue(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonObject) : {};
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}
