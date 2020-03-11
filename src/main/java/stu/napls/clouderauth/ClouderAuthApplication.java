package stu.napls.clouderauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class ClouderAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(ClouderAuthApplication.class, args);
    }

}
