package org.jboss.aerogear.keycloakclient;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.codehaus.jackson.map.ObjectMapper;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.models.Constants;
import org.keycloak.services.util.HttpClientBuilder;
import org.keycloak.util.KeycloakUriBuilder;

import javax.ws.rs.core.HttpHeaders;
import java.io.IOException;
import java.io.InputStream;

/**
 * Created by sebastienblanc on 5/28/15.
 */
public class KeycloakClient {

    private Keycloak keycloak;
    private RealmResource realm;
    private HttpClient client;
    public KeycloakClient() {
        keycloak = Keycloak.getInstance("http://localhost:8080/auth", "aerogear", "admin", "seb", Constants.ADMIN_CONSOLE_CLIENT_ID);
        realm = keycloak.realm("aerogear");
        client = new HttpClientBuilder().disableTrustManager()
                .build();
    }

    public void adminReset(String password) throws IOException{
        String adminToken = keycloak.tokenManager().getAccessTokenString();
        try {
            HttpPut put = new HttpPut(KeycloakUriBuilder
                    .fromUri("http://localhost:8080" + "/auth")
                    .path("/admin/realms/aerogear/users/admin/reset-password")
                    .build("aerogear"));
            put.addHeader("Authorization", "Bearer " + adminToken);
            put.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");

            CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
            credentialRepresentation.setTemporary(false);
            credentialRepresentation.setType(CredentialRepresentation.PASSWORD);
            credentialRepresentation.setValue(password);


            put.setEntity(new StringEntity(convertToJsonString(credentialRepresentation)));
            HttpResponse response = client.execute(put);
            boolean status = response.getStatusLine().getStatusCode() != 204;
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                return;
            }
            InputStream is = entity.getContent();
            if (is != null)
                is.close();
            if (status) {
                System.out.println(" STATUS : " + status);
            }
        } finally {
            client.getConnectionManager().shutdown();
            //let's create a "normal" user
        }
    }

    public void createUser(String userName) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(userName);
        realm.users().create(user);
    }

    public static void main(String [] args)
    {
        KeycloakClient keycloakClient = new KeycloakClient();
        try {
            keycloakClient.adminReset("password");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String convertToJsonString(Object object) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(object);
    }
}
