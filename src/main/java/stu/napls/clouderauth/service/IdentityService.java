package stu.napls.clouderauth.service;

import stu.napls.clouderauth.model.Identity;

public interface IdentityService {
    Identity update(Identity identity);

    Identity findByUsername(String username);

    Identity findByUsernameAndSource(String username, String source);

    Identity findByUuid(String uuid);
}
