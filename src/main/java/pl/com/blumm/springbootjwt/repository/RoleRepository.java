package pl.com.blumm.springbootjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.com.blumm.springbootjwt.model.ERole;
import pl.com.blumm.springbootjwt.model.Role;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(ERole name);

}
