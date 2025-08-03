package com.zsq.winter.encrypt.config;

import com.zsq.winter.encrypt.aspect.CryptoAspect;
import com.zsq.winter.encrypt.entity.BannerCreator;
import com.zsq.winter.encrypt.entity.CryptoProperties;
import com.zsq.winter.encrypt.factory.ContainerCryptoStrategyFactory;
import com.zsq.winter.encrypt.service.ContainerCryptoService;
import com.zsq.winter.encrypt.service.CryptoService;
import com.zsq.winter.encrypt.service.impl.CryptoDefaultServiceImpl;
import com.zsq.winter.encrypt.strategy.CollectionCryptoStrategy;
import com.zsq.winter.encrypt.strategy.impl.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * 加密解密功能自动配置类
 * 
 * <p>该类负责自动配置加密和解密功能，包括：</p>
 * <ul>
 *   <li>加密解密服务Bean的创建</li>
 *   <li>AOP切面的配置</li>
 *   <li>容器加密解密策略的注册</li>
 *   <li>启动Banner的创建</li>
 * </ul>
 * 
 * <p>配置条件：只有当配置文件中包含以下属性时才会启用：</p>
 * <ul>
 *   <li>winter-crypto.aes.key：AES密钥</li>
 *   <li>winter-crypto.aes.iv：AES初始化向量</li>
 *   <li>winter-crypto.des.key：DES密钥</li>
 *   <li>winter-crypto.des.iv：DES初始化向量</li>
 *   <li>winter-crypto.rsa.private-key：RSA私钥</li>
 *   <li>winter-crypto.rsa.public-key：RSA公钥</li>
 * </ul>
 * 
 * @author dadandiaoming
 * @since 1.0.0
 * @see CryptoProperties
 * @see CryptoService
 * @see CryptoAspect
 */
@Configuration
@EnableConfigurationProperties(CryptoProperties.class)
@ConditionalOnProperty(prefix = "winter-crypto", name = {"aes.key", "aes.iv"}, matchIfMissing = false)
public class CryptoAutoConfiguration {

    /**
     * 创建默认的加密解密服务Bean
     * 
     * <p>如果容器中不存在其他CryptoService实现类，则创建一个默认实现类的实例。
     * 使用{@link ConditionalOnMissingBean}注解确保只有在没有其他实现时才创建默认实现。</p>
     *
     * @return CryptoService的默认实现实例
     * @see CryptoDefaultServiceImpl
     */
    @Bean
    @ConditionalOnMissingBean
    public CryptoService getCryptoService() {
        return new CryptoDefaultServiceImpl();
    }

    /**
     * 创建加密解密切面Bean
     * 
     * <p>该切面负责拦截带有{@link com.zsq.winter.encrypt.annotation.Encrypt}和
     * {@link com.zsq.winter.encrypt.annotation.Decrypt}注解的方法，自动进行加密解密处理。</p>
     *
     * @param cryptoProperties 加密配置属性，包含密钥等信息
     * @param cryptoService 加密解密服务实例
     * @param containerCryptoService 容器加密解密服务
     * @return 初始化后的CryptoAspect实例
     * @see CryptoAspect
     */
    @Bean
    public CryptoAspect cryptoAspect(CryptoProperties cryptoProperties, CryptoService cryptoService, ContainerCryptoService containerCryptoService) {
        return new CryptoAspect(cryptoProperties, cryptoService, containerCryptoService);
    }

    /**
     * 创建启动Banner创建器Bean
     * 
     * <p>用于在应用启动时输出定制的banner，显示加密模块的版本信息。</p>
     *
     * @param cryptoProperties 包含日志相关的配置属性
     * @return 初始化后的BannerCreator实例
     * @see BannerCreator
     */
    @Bean("winterCryptoBanner")
    public BannerCreator bannerCreator(CryptoProperties cryptoProperties) {
        return new BannerCreator(cryptoProperties);
    }

    /**
     * 创建List集合加密解密策略Bean
     * 
     * @return ListCryptoStrategy实例
     */
    @Bean
    public ListCryptoStrategy listCryptoStrategy() {
        return new ListCryptoStrategy();
    }

    /**
     * 创建Set集合加密解密策略Bean
     * 
     * @return SetCryptoStrategy实例
     */
    @Bean
    public SetCryptoStrategy setCryptoStrategy() {
        return new SetCryptoStrategy();
    }

    /**
     * 创建Map集合加密解密策略Bean
     * 
     * @return MapCryptoStrategy实例
     */
    @Bean
    public MapCryptoStrategy mapCryptoStrategy() {
        return new MapCryptoStrategy();
    }



    /**
     * 创建Array数组加密解密策略Bean
     * 
     * @return ArrayCryptoStrategy实例
     */
    @Bean
    public ArrayCryptoStrategy arrayCryptoStrategy() {
        return new ArrayCryptoStrategy();
    }

    /**
     * 创建容器加密解密策略工厂Bean
     * 
     * <p>该工厂负责管理所有类型的集合加密解密策略，根据容器类型选择合适的策略。</p>
     *
     * @param strategies 所有策略实现的列表，由Spring自动注入
     * @return ContainerCryptoStrategyFactory实例
     * @see ContainerCryptoStrategyFactory
     */
    @Bean
    public ContainerCryptoStrategyFactory containerCryptoStrategyFactory(List<CollectionCryptoStrategy> strategies) {
        return new ContainerCryptoStrategyFactory(strategies);
    }

    /**
     * 创建容器加密解密服务Bean
     * 
     * <p>该服务负责处理各种容器类型（List、Set、Map、Array）的加密解密操作。</p>
     *
     * @param strategyFactory 策略工厂，用于获取具体的加密解密策略
     * @return ContainerCryptoService实例
     * @see ContainerCryptoService
     */
    @Bean
    public ContainerCryptoService containerCryptoService(ContainerCryptoStrategyFactory strategyFactory) {
        return new ContainerCryptoService(strategyFactory);
    }
}
