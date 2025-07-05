package com.zsq.winter.encrypt.config;

import com.zsq.winter.encrypt.aspect.CryptoAspect;
import com.zsq.winter.encrypt.entity.BannerCreator;
import com.zsq.winter.encrypt.entity.CryptoProperties;
import com.zsq.winter.encrypt.service.CryptoService;
import com.zsq.winter.encrypt.service.impl.CryptoDefaultServiceImpl;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(CryptoProperties.class)
// @ConditionalOnProperty注解确保了只有在指定的属性都存在时，相关的Bean才会被创建。matchIfMissing = false表示如果配置文件中缺少这些属性，则不会创建Bean。
@ConditionalOnProperty(prefix = "winter-crypto", name = {"encrypt-key", "decrypt-key", "iv"}, matchIfMissing = false)
/**
 * CryptoAutoConfiguration类用于自动配置加密和解密功能。
 * 它依赖于CryptoProperties类中的配置属性，并根据这些属性的存在与否来决定是否创建相关的Bean。
 */
public class CryptoAutoConfiguration {

    /**
     * 创建并返回一个CryptoService实例。
     * 如果容器中不存在其他CryptoService实现类，则创建一个默认实现类的实例。
     *
     * @return CryptoService的实例，用于提供加密和解密服务。
     */
    @Bean
    // 当不存在CryptoService的实现类时，使用默认的加解密方法，否则使用使用者自定义的
    @ConditionalOnMissingBean
    public CryptoService getCryptoService() {
        return new CryptoDefaultServiceImpl();
    }

    /**
     * 创建并返回一个CryptoAspect实例。
     * 这个实例将使用提供的CryptoProperties和CryptoService来进行初始化。
     *
     * @param cryptoProperties 包含加密和解密相关的配置属性。
     * @param cryptoService 提供加密和解密服务的实例。
     * @return 初始化后的CryptoAspect实例。
     */
    @Bean
    public CryptoAspect cryptoAspect(CryptoProperties cryptoProperties, CryptoService cryptoService) {
        return new CryptoAspect(cryptoProperties, cryptoService);
    }

    /**
     * 创建并返回一个BannerCreator实例，用于在应用启动时输出定制的banner。
     * 这个实例将使用提供的CryptoProperties中的日志配置来进行初始化。
     *
     * @param cryptoProperties 包含日志相关的配置属性。
     * @return 初始化后的BannerCreator实例，用于输出定制的banner。
     */
    @Bean("winterCryptoBanner")
    public BannerCreator bannerCreator(CryptoProperties cryptoProperties) {
        return new BannerCreator(cryptoProperties);
    }

}
