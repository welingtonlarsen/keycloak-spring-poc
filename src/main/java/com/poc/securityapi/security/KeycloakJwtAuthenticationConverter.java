package com.poc.securityapi.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Reference code:
 * https://github.com/msmacorin/spring-boot-keycloak/blob/master/src/main/java/br/com/macorin/securityapi/infra/securities/KeycloakJwtAuthenticationConverter.java
 */
@Component
@RequiredArgsConstructor
public class KeycloakJwtAuthenticationConverter
    implements Converter<Jwt, AbstractAuthenticationToken> {

  JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter =
      new JwtGrantedAuthoritiesConverter();
  private final ObjectMapper objectMapper;

  @Override
  public AbstractAuthenticationToken convert(Jwt jwt) {
    Collection<GrantedAuthority> authorities =
        Stream.concat(
                defaultGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractAuthorities(jwt).stream())
            .collect(Collectors.toSet());
    return new JwtAuthenticationToken(jwt, authorities);
  }

  private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
    Set<String> rolesWithPrefix = new HashSet<>();
    rolesWithPrefix.addAll(getRealmRoles(jwt));
    rolesWithPrefix.addAll(getResourceRoles(jwt));
    return AuthorityUtils.createAuthorityList(rolesWithPrefix.toArray(new String[0]));
  }

  private Set<String> getRealmRoles(Jwt jwt) {
    JsonNode realmAccessJson =
        objectMapper.convertValue(jwt.getClaim("realm_access"), JsonNode.class);
    Set<String> rolesWithPrefix = new HashSet<>();
    realmAccessJson
        .get("roles")
        .forEach(role -> rolesWithPrefix.add(createRoleWithPrefix(role.asText())));
    return rolesWithPrefix;
  }

  // TODO - Refactor this method
  private Set<String> getResourceRoles(Jwt jwt) {
    Set<String> rolesWithPrefix = new HashSet<>();
    Map<String, JsonNode> map =
        objectMapper.convertValue(
            jwt.getClaim("resource_access"), new TypeReference<Map<String, JsonNode>>() {});
    for (Map.Entry<String, JsonNode> jsonNode : map.entrySet()) {
      jsonNode
          .getValue()
          .elements()
          .forEachRemaining(
              e ->
                  e.elements()
                      .forEachRemaining(
                          r ->
                              rolesWithPrefix.add(
                                  createRoleWithPrefix(jsonNode.getKey(), r.asText()))));
    }
    return rolesWithPrefix;
  }

  private String createRoleWithPrefix(String... values) {
    StringBuilder role = new StringBuilder("ROLE");
    for (String value : values) {
      role.append("_").append(value.toUpperCase());
    }
    return role.toString();
  }
}
