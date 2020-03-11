package stu.napls.clouderauth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import stu.napls.clouderauth.model.Identity;

public interface IdentityRepository extends JpaRepository<Identity, Long> {
    Identity findByUsername(String username);

    Identity findByUsernameAndSource(String username, String source);

    Identity findByUuid(String uuid);
}
