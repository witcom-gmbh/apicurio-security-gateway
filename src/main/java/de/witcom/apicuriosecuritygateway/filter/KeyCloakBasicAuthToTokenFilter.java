package de.witcom.apicuriosecuritygateway.filter;

import java.net.URI;
import java.util.List;

import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;

import de.witcom.apicuriosecuritygateway.config.ApplicationProperties;
import lombok.extern.apachecommons.CommonsLog;
import reactor.core.publisher.Mono;

@CommonsLog
@Component
public class KeyCloakBasicAuthToTokenFilter extends  AbstractGatewayFilterFactory<Object> {
	
	private static final String WWW_AUTH_HEADER = "WWW-Authenticate";
	
	@Autowired
	ApplicationProperties appProperties;
	
	public GatewayFilter apply() {
		return apply((Object) null);
	}

	@Override
	public GatewayFilter apply(Object config) {
		
		return (exchange, chain) -> {

			List<String> authHeaders = exchange.getRequest().getHeaders().getOrEmpty("Authorization");
			//No Authorization-Header at all - let access fail
			if (authHeaders == null || authHeaders.isEmpty()) {
				log.debug("No Auth-Header present");
				return this.onError(exchange,"No access to the requested resource");
			}

			String tokenString = null;
	        for (String authHeader : authHeaders) {
	            String[] split = authHeader.trim().split("\\s+");
	            if (split.length != 2) continue;
	            if (!split[0].equalsIgnoreCase("Basic")) continue;
	            tokenString = split[1];
	        }

	        //No Basic-Auth ? End filter, there might be a bearer token...
	        if (tokenString == null) {
	        	log.debug("No Basic-Auth-Header present");
	            return chain.filter(exchange);
	        }
	        
	        AccessTokenResponse atr=null;        
	        try {
	        	//Extract username and password 
	            String userpw=new String(Base64.decode(tokenString));
	            int seperatorIndex = userpw.indexOf(":");
	            String user = userpw.substring(0, seperatorIndex);
	            String pw = userpw.substring(seperatorIndex + 1).trim();
	            //get Token
	            atr = getToken(user, pw);
	            tokenString = atr.getToken();
	        } catch (Exception e) {
	            log.debug("Failed to obtain token", e);
	            return this.onError(exchange,"No access to the requested resource");
	        }
	        
	        String authHeader = "Bearer " + tokenString;
	        
	        ServerHttpRequest request = exchange.getRequest().mutate()
					.header(HttpHeaders.AUTHORIZATION, authHeader)
					.build();
			
			return chain.filter(exchange.mutate().request(request).build());
		};
	}
	
	/**
	 * Get token for username/password
	 * Use client_credentials grant
	 * 
	 * @param username
	 * @param password
	 * @return
	 * @throws Exception
	 */
	protected AccessTokenResponse getToken(String username, String password) throws Exception {
		ResponseEntity<AccessTokenResponse> response = null;

		RestTemplate restTemplate = new RestTemplate();
		
		//Build basic-auth header for client_credentials grant
		String auth = username+":"+password;
        String authHeader = "Basic " + Base64.encodeBytes(auth.getBytes());
        
        HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", authHeader);
		
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

		MultiValueMap<String, String> map= new LinkedMultiValueMap<String, String>();
		map.add(OAuth2Constants.GRANT_TYPE, OAuth2Constants.CLIENT_CREDENTIALS);
		//client_id is the username
		map.add("client_id", username);
		
		org.springframework.http.HttpEntity<MultiValueMap<String, String>> request = new org.springframework.http.HttpEntity<MultiValueMap<String, String>>(map, headers);

		URI url = KeycloakUriBuilder.fromUri(appProperties.getKeycloakConfig().getKeycloakServerUrl().trim())
                .path(ServiceUrlConstants.TOKEN_PATH).build(appProperties.getKeycloakConfig().getKeycloakRealmId().trim());
		
		response = restTemplate.postForEntity( url , request , AccessTokenResponse.class );
		
		int status = response.getStatusCodeValue();
		AccessTokenResponse entity = response.getBody();
        if (status != 200) {
            
            throw new java.io.IOException("Bad status: " + status);
        }
        if (entity == null) {
            throw new java.io.IOException("No Entity");
        }

        return (entity);
        
	}

	private Mono<Void> onError(ServerWebExchange exchange, String err)
    {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().add(WWW_AUTH_HEADER, this.formatErrorMsg(err));

        return response.setComplete();
    }

	private String formatErrorMsg(String msg)
    {
        return String.format("Bearer realm=\""+appProperties.getKeycloakConfig().getKeycloakRealmId().trim()+"\", " +
                "error=\"https://tools.ietf.org/html/rfc7519\", " +
                "error_description=\"%s\" ",  msg);
    }

}
