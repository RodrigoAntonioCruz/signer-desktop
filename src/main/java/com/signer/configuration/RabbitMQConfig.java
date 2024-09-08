package com.signer.configuration;

import org.springframework.amqp.core.Queue;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitMQConfig {

    @Bean
    public Queue toSignQueue() {
        return new Queue("to-sign-002321", false);
    }

    @Bean
    public Queue signedQueue() {
        return new Queue("signed-002321", false);
    }
}
