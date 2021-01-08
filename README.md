# APICURIO Security Gateway

## Description
It adds some basic authorization-check for API-requests to APICURIO. It is intended to run this service in front of APICURIO (e.g. as a sidecar-container in Kubernetes). It is used to authorize api-request made by API-Clients, e.g. kafka-producers and/or consumers. Protecting the UI is not the goal - if you want to to this, you can use https://oauth2-proxy.github.io/oauth2-proxy/docs/ and combine it with the Security-Gateway

It uses Keycloak as identity-provider where all API-Clients have to be configured as confidential-clients in Keycloak.

Credentials can be presented either as

* Bearer token
* Basic-Auth credentials where client-id and client-secret are used as username/password. The security-gateway internally "converts" basic-auth credentials to a bearer-token

Out of the box the API is protected as follows

* GET requests - no auth required
* POST/PUT requests - requires **registry-writer** role
* DELETE requests - requires **registry-admin** role

This is achieved by using Spring-Cloud-Gateway. More fine-grained control (e.g. resource-based) could be achieved by adding more route-configurations, but it would make more sense to use Keycloak-Authorization-Services for that.

## Keycloak configuration
### Apicurio resource-server
Add a keycloak-client with the following specs

* Client-Id: an id, eg. apicurio-registry
* Protocol: openid-connect
* Access-type: confidential
* Disable all flows except **Service Accounts enabled**

After adding the client, you have to add roles to the client. Out of the box 2 roles are supported. There default-names are

* registry-writer
* registry-admin

You can use different names, but make sure to provide the when running the security-gateway (see Configuration)  

### Apicurio-Clients
Every client that needs access has to be added as confidential-client to keycloak. 

* Client-Id: an id, eg. apicurio-registry
* Protocol: openid-connect
* Access-type: confidential
* Disable all flows except **Service Accounts enabled**

Then add the roles defined in the resource-server-client to the Apicurio-Client (under Service-Account Roles). If a client should be able to perform write **and** delete operations, it needs both roles.

## Configuration

The Gateway can be configured by setting env-variables.

| *Variable* | *Description* |
| --- | --- |
| `APICURIO_URL` | The Base-URL of Apicurio|
| `KEYCLOAK_SERVER_URL` | The base-url of your keycloak installation. Usually this has the following format https://my-auth-server.somedomain.com/auth. It is recommended to use **SSL** |
| `KEYCLOAK_REALM_ID` | Name of the keycloak-realm  |
| `KEYCLOAK_RESOURCE_ID` | Name of the resource-server keycloak client, e.g. apicurio-registry |
| `ROLE_WRITER` | Name of the writer-role, defaults to **registry-writer**  |
| `ROLE_ADMIN` | Name of the admin-role, defaults to **registry-admin**  |
| `GATEWAY_PORT` | Port the application is listening on, defaults to **8080**  |
| `APICURIO_CATCHALL_URL` | URL to API-Curio. Defaults to `APICURIO_URL` . Useful if the UI is protected by an Oauth-proxy |


## Extended configuration
Since this is a spring-boot application it can be configured with the application.yml file in src/main/resources. It uses Spring-Cloud-Gateway, so all configuration described here (https://docs.spring.io/spring-cloud-gateway/docs/current/reference/html/#configuring-route-predicate-factories-and-gateway-filter-factories) is available.

This is the default configuration for the apicurio-security-gateway.

```
    routes:
      - id: apicurio-api-get
        uri: ${APICURIO_URL:#{null}}
        predicates:
         - Path=/api/**
         - Method=GET
      - id: apicurio-api-write
        uri: ${APICURIO_URL:#{null}}
        predicates:
         - Path=/api/**
         - Method=POST,PUT
        filters:
          - KeyCloakBasicAuthToTokenFilter
          - KeyCloakFilter=requiredRole,${KEYCLOAK_RESOURCE_ID}:${ROLE_WRITER:registry-writer}
      - id: apicurio-api-delete
        uri: ${APICURIO_URL:#{null}}
        predicates:
         - Path=/api/**
         - Method=DELETE
        filters:
          - KeyCloakBasicAuthToTokenFilter
          - KeyCloakFilter=requiredRole,${KEYCLOAK_RESOURCE_ID}:${ROLE_ADMIN:registry-admin}
      - id: apicurio-catchall
        uri: ${APICURIO_URL:#{null}}
        predicates:
         - Path=/**
```

It is easy to add an additional role for READ-Access, e.g

```
    routes:
      - id: apicurio-api-get
        uri: ${APICURIO_URL:#{null}}
        predicates:
         - Path=/api/**
         - Method=GET
        filters:
         - KeyCloakBasicAuthToTokenFilter
         - KeyCloakFilter=requiredRole,${KEYCLOAK_RESOURCE_ID}:${ROLE_WRITER:registry-read}
```

Or you can add more roles for the global-rules, metadata, whatever. You can protect single artifacts, by placing more specific routes above the default ones.  But as stated above - it might make more sense to use Keycloak-authorization-services for that.


