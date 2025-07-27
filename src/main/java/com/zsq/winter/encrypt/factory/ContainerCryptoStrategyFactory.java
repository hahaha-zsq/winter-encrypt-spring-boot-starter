package com.zsq.winter.encrypt.factory;

import com.zsq.winter.encrypt.enums.CollectionStrategyType;
import com.zsq.winter.encrypt.strategy.CollectionCryptoStrategy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Lazy;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 容器加密解密策略工厂
 * 
 * <p>使用工厂模式管理不同的容器加密解密策略，根据容器类型自动选择合适的策略进行处理。
 * 该工厂在Spring容器启动时自动注册所有可用的策略实现。</p>
 * 
 * <p>支持的策略类型：</p>
 * <ul>
 *   <li>{@link CollectionStrategyType#ARRAY} - 数组策略</li>
 *   <li>{@link CollectionStrategyType#LIST} - List集合策略</li>
 *   <li>{@link CollectionStrategyType#SET} - Set集合策略</li>
 *   <li>{@link CollectionStrategyType#MAP} - Map集合策略</li>
 *   <li>{@link CollectionStrategyType#QUEUE} - Queue集合策略</li>
 * </ul>
 * 
 * @author dadandiaoming
 * @since 1.0.0
 * @see CollectionCryptoStrategy
 * @see CollectionStrategyType
 */
@Slf4j
public class ContainerCryptoStrategyFactory implements InitializingBean {

    /**
     * 所有可用的策略实现列表
     */
    private final List<CollectionCryptoStrategy> strategies;
    
    /**
     * 策略类型到策略实现的映射表
     */
    private final Map<CollectionStrategyType, CollectionCryptoStrategy> strategyTypeMap = new HashMap<>();

    /**
     * 构造函数
     * 
     * <p>通过依赖注入获取所有可用的策略实现，使用{@link Lazy}注解避免循环依赖。</p>
     *
     * @param strategies 所有策略实现的列表，由Spring自动注入
     */
    public ContainerCryptoStrategyFactory(@Lazy List<CollectionCryptoStrategy> strategies) {
        this.strategies = strategies;
    }

    /**
     * 初始化方法
     * 
     * <p>在Spring容器启动完成后，将所有策略实现注册到策略映射表中，
     * 以便后续根据容器类型快速获取对应的策略。</p>
     */
    @Override
    public void afterPropertiesSet() {
        log.info("初始化容器加密解密策略工厂，共找到 {} 个策略", strategies.size());
        for (CollectionCryptoStrategy strategy : strategies) {
            log.info("注册策略: {}，类型: {}", strategy.getStrategyName(), strategy.getStrategyType());
            strategyTypeMap.put(strategy.getStrategyType(), strategy);
        }
    }

    /**
     * 根据策略类型获取对应的策略实现
     * 
     * <p>根据容器类型返回对应的加密解密策略，如果找不到对应的策略则返回null。</p>
     *
     * @param type 策略类型枚举
     * @return 对应的策略实现，如果不存在则返回null
     * @see CollectionStrategyType
     */
    public CollectionCryptoStrategy getStrategy(CollectionStrategyType type) {
        return strategyTypeMap.get(type);
    }
    
    /**
     * 获取所有可用的策略实现
     * 
     * <p>返回所有已注册的策略实现列表，可用于调试或管理目的。</p>
     *
     * @return 所有策略实现的列表
     */
    public List<CollectionCryptoStrategy> getAllStrategies() {
        return strategies;
    }
} 