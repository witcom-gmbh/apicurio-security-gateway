package de.witcom.apicuriosecuritygateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "application", ignoreUnknownFields = false)
public class ApplicationProperties {
    
    private final KeycloakConfig keycloakConfig = new KeycloakConfig();
    private final ApicurioConfig registry = new ApicurioConfig();
    
    public static class ApicurioConfig {
    	private String url="";

		public String getUrl() {
			return url;
		}

		public void setUrl(String url) {
			this.url = url;
		}
    	
    	
    	
    }


    public static class KeycloakConfig {

        private String keycloakServerUrl="";
        private String keycloakRealmId="";

        public String getKeycloakServerUrl() {
            return keycloakServerUrl;
        }

        public void setKeycloakServerUrl(String keycloakServerUrl) {
            this.keycloakServerUrl = keycloakServerUrl;
        }

        public String getKeycloakRealmId() {
            return keycloakRealmId;
        }

        public void setKeycloakRealmId(String keycloakRealmId) {
            this.keycloakRealmId = keycloakRealmId;
        }

    }
    
    public ApicurioConfig getRegistry() {
    	return registry;
    }
    
    public KeycloakConfig getKeycloakConfig(){
        return keycloakConfig;
    }
    
    
}
