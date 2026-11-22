package zrouga.spring.security;

import java.util.List;

public interface AuthUser {

    Long getId();

    String getEmail();

    String getPassword();

    List<String> getRoles();

    Boolean getStatus();
}
