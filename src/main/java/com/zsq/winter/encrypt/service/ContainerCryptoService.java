package com.zsq.winter.encrypt.service;

import com.zsq.winter.encrypt.annotation.FieldDecrypt;
import com.zsq.winter.encrypt.annotation.FieldEncrypt;
import com.zsq.winter.encrypt.enums.CollectionStrategyType;
import com.zsq.winter.encrypt.exception.CryptoException;
import com.zsq.winter.encrypt.factory.ContainerCryptoStrategyFactory;
import com.zsq.winter.encrypt.strategy.CollectionCryptoStrategy;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.ObjectUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;

/**
 * 容器加密解密服务
 * 使用策略模式和工厂模式处理各种容器类型（集合、映射、数组）的加密解密
 */
@Getter
@Slf4j
public class ContainerCryptoService {

    /**
     *  获取策略工厂
     */
    private final ContainerCryptoStrategyFactory strategyFactory;

    public ContainerCryptoService(ContainerCryptoStrategyFactory strategyFactory) {
        this.strategyFactory = strategyFactory;
    }

    /**
     * 根据容器对象类型获取策略类型
     *
     * @param container 容器对象
     * @return 策略类型
     */
    private CollectionStrategyType getStrategyType(Object container) {
        if (Objects.isNull(container)) {
            return null;
        }
        if (container.getClass().isArray()) {
            return CollectionStrategyType.ARRAY;
        } else if (container instanceof List) {
            return CollectionStrategyType.LIST;
        } else if (container instanceof Set) {
            return CollectionStrategyType.SET;
        } else if (container instanceof Map) {
            return CollectionStrategyType.MAP;
        } else if (container instanceof Queue) {
            return CollectionStrategyType.QUEUE;
        }
        
        return null;
    }

    /**
     * 加密容器
     *
     * @param container 待加密的容器即需加密的内容
     * @param cryptoService 加密服务
     * @param annotation 加密注解
     * @param encryptKey 加密密钥
     * @param iv 初始化向量
     * @return 加密后的容器
     * @throws CryptoException 当加密过程中发生错误时抛出
     */
    public Object encryptContainer(Object container, CryptoService cryptoService, 
                                  FieldEncrypt annotation, String encryptKey, String iv) {
        // 检查容器是否为null（允许空容器）
        if (Objects.isNull(container)) {
            log.error("加密失败：容器不能为null");
            throw CryptoException.emptyData("加密", null);
        }

        // RSA加密特有的预处理
        if (annotation.cryptoType() == com.zsq.winter.encrypt.enums.CryptoType.RSA) {
            return encryptRsaContainer(container, cryptoService, annotation, encryptKey, iv);
        }

        // 获取对应的策略类型
        CollectionStrategyType strategyType = getStrategyType(container);
        if (Objects.isNull(strategyType)) {
            String containerType = container.getClass().getSimpleName();
            log.error("不支持的容器类型: {}, 容器对象: {}", containerType, container);
            throw CryptoException.unsupportedContainerType("加密", containerType, container);
        }

        // 获取对应的策略
        CollectionCryptoStrategy strategy = strategyFactory.getStrategy(strategyType);
        if (Objects.isNull(strategy)) {
            log.error("未找到策略类型 {} 对应的加密策略", strategyType);
            throw CryptoException.generalError(
                String.format("未找到策略类型 %s 对应的加密策略", strategyType), 
                null, 
                "加密", 
                container
            );
        }

        try {
            log.debug("使用策略 {} 加密容器类型: {}", strategy.getStrategyName(), container.getClass().getSimpleName());
            // 使用对应容器的策略类进行加密逻辑处理
            return strategy.encrypt(container, cryptoService, annotation, encryptKey, iv);
        } catch (CryptoException e) {
            log.error("容器加密失败，容器类型: {}, 策略: {}, 错误类型: {}, 错误: {}", 
                container.getClass().getSimpleName(), strategy.getStrategyName(), e.getErrorType(), e.getMessage());
            throw e; // 重新抛出自定义异常
        } catch (Exception e) {
            log.error("加密容器失败，容器类型: {}, 策略: {}", container.getClass().getSimpleName(), strategy.getStrategyName(), e);
            throw CryptoException.generalError("加密容器失败", e, "加密", container);
        }
    }

    /**
     * RSA容器加密
     * 
     * <p>专门处理RSA容器加密，包含RSA特有的优化和错误处理。</p>
     *
     * @param container 待加密的容器
     * @param cryptoService 加密服务
     * @param annotation 加密注解
     * @param privateKey RSA私钥
     * @param publicKey RSA公钥
     * @return 加密后的容器
     * @throws CryptoException 当RSA加密过程中发生错误时抛出
     */
    public Object encryptRsaContainer(Object container, CryptoService cryptoService,
                                      FieldEncrypt annotation, String privateKey, String publicKey) {
        // 获取对应的策略类型
        CollectionStrategyType strategyType = getStrategyType(container);
        if (Objects.isNull(strategyType)) {
            String containerType = container.getClass().getSimpleName();
            log.error("RSA加密不支持的容器类型: {}, 容器对象: {}", containerType, container);
            throw CryptoException.unsupportedContainerType("RSA加密", containerType, container);
        }

        // 获取对应的策略
        CollectionCryptoStrategy strategy = strategyFactory.getStrategy(strategyType);
        if (Objects.isNull(strategy)) {
            log.error("未找到策略类型 {} 对应的RSA加密策略", strategyType);
            throw CryptoException.generalError(
                String.format("未找到策略类型 %s 对应的RSA加密策略", strategyType), 
                null, 
                "RSA加密", 
                container
            );
        }

        try {
            log.debug("使用RSA策略 {} 加密容器类型: {}", strategy.getStrategyName(), container.getClass().getSimpleName());
            
            // RSA加密特有的优化：检查容器大小
            int containerSize = getContainerSize(container);
            if (containerSize > 100) {
                log.warn("RSA加密大型容器，元素数量: {}，可能影响性能", containerSize);
            }
            
            // 使用对应容器的策略类进行RSA加密逻辑处理
            return strategy.encryptRsa(container, cryptoService, annotation, privateKey, publicKey);
        } catch (CryptoException e) {
            log.error("RSA容器加密失败，容器类型: {}, 策略: {}, 错误类型: {}, 错误: {}", 
                container.getClass().getSimpleName(), strategy.getStrategyName(), e.getErrorType(), e.getMessage());
            throw e; // 重新抛出自定义异常
        } catch (Exception e) {
            log.error("RSA加密容器失败，容器类型: {}, 策略: {}", container.getClass().getSimpleName(), strategy.getStrategyName(), e);
            throw CryptoException.generalError("RSA加密容器失败", e, "RSA加密", container);
        }
    }

    /**
     * 解密容器
     *
     * @param container 待解密的容器
     * @param cryptoService 解密服务
     * @param annotation 解密注解
     * @param decryptKey 解密密钥
     * @param iv 初始化向量
     * @return 解密后的容器
     * @throws CryptoException 当解密过程中发生错误时抛出
     */
    public Object decryptContainer(Object container, CryptoService cryptoService, 
                                  FieldDecrypt annotation, String decryptKey, String iv) {
        // 检查容器是否为null（允许空容器）
        if (Objects.isNull(container)) {
            log.error("解密失败：容器不能为null，容器: {}", container);
            throw CryptoException.emptyData("解密", container);
        }

        // RSA解密特有的预处理
        if (annotation.cryptoType() == com.zsq.winter.encrypt.enums.CryptoType.RSA) {
            return decryptRsaContainer(container, cryptoService, annotation, decryptKey, iv);
        }

        // 获取对应的策略类型
        CollectionStrategyType strategyType = getStrategyType(container);
        if (Objects.isNull(strategyType)) {
            String containerType = container.getClass().getSimpleName();
            log.error("不支持的容器类型: {}, 容器对象: {}", containerType, container);
            throw CryptoException.unsupportedContainerType("解密", containerType, container);
        }

        // 获取对应的策略
        CollectionCryptoStrategy strategy = strategyFactory.getStrategy(strategyType);
        if (Objects.isNull(strategy)) {
            log.error("未找到策略类型 {} 对应的解密策略", strategyType);
            throw CryptoException.generalError(
                String.format("未找到策略类型 %s 对应的解密策略", strategyType), 
                null, 
                "解密", 
                container
            );
        }

        try {
            log.debug("使用策略 {} 解密容器类型: {}", strategy.getStrategyName(), container.getClass().getSimpleName());
            // 使用对应容器的策略类进行解密处理
            return strategy.decrypt(container, cryptoService, annotation, decryptKey, iv);
        } catch (CryptoException e) {
            log.error("容器解密失败，容器类型: {}, 策略: {}, 错误类型: {}, 错误: {}", 
                container.getClass().getSimpleName(), strategy.getStrategyName(), e.getErrorType(), e.getMessage());
            throw e; // 重新抛出自定义异常
        } catch (Exception e) {
            log.error("解密容器失败，容器类型: {}, 策略: {}", container.getClass().getSimpleName(), strategy.getStrategyName(), e);
            throw CryptoException.generalError("解密容器失败", e, "解密", container);
        }
    }

    /**
     * RSA容器解密
     * 
     * <p>专门处理RSA容器解密，包含RSA特有的优化和错误处理。</p>
     *
     * @param container 待解密的容器
     * @param annotation 解密注解
     * @param cryptoService 解密服务
     * @param publicKey RSA公钥
     * @param privateKey RSA私钥
     * @return 解密后的容器
     * @throws CryptoException 当RSA解密过程中发生错误时抛出
     */
    public Object decryptRsaContainer(Object container, CryptoService cryptoService,
                                      FieldDecrypt annotation, String publicKey, String privateKey) {
        // 获取对应的策略类型
        CollectionStrategyType strategyType = getStrategyType(container);
        if (Objects.isNull(strategyType)) {
            String containerType = container.getClass().getSimpleName();
            log.error("RSA解密不支持的容器类型: {}, 容器对象: {}", containerType, container);
            throw CryptoException.unsupportedContainerType("RSA解密", containerType, container);
        }

        // 获取对应的策略
        CollectionCryptoStrategy strategy = strategyFactory.getStrategy(strategyType);
        if (Objects.isNull(strategy)) {
            log.error("未找到策略类型 {} 对应的RSA解密策略", strategyType);
            throw CryptoException.generalError(
                String.format("未找到策略类型 %s 对应的RSA解密策略", strategyType), 
                null, 
                "RSA解密", 
                container
            );
        }

        try {
            log.debug("使用RSA策略 {} 解密容器类型: {}", strategy.getStrategyName(), container.getClass().getSimpleName());
            
            // RSA解密特有的优化：检查容器大小
            int containerSize = getContainerSize(container);
            if (containerSize > 100) {
                log.warn("RSA解密大型容器，元素数量: {}，可能影响性能", containerSize);
            }
            
            // 使用对应容器的策略类进行RSA解密逻辑处理
            return strategy.decryptRsa(container, cryptoService, annotation, publicKey, privateKey);
        } catch (CryptoException e) {
            log.error("RSA容器解密失败，容器类型: {}, 策略: {}, 错误类型: {}, 错误: {}", 
                container.getClass().getSimpleName(), strategy.getStrategyName(), e.getErrorType(), e.getMessage());
            throw e; // 重新抛出自定义异常
        } catch (Exception e) {
            log.error("RSA解密容器失败，容器类型: {}, 策略: {}", container.getClass().getSimpleName(), strategy.getStrategyName(), e);
            throw CryptoException.generalError("RSA解密容器失败", e, "RSA解密", container);
        }
    }

    /**
     * 检查是否为支持的容器类型
     *
     * @param obj 待检查的对象
     * @return 是否为支持的容器类型
     */
    public boolean isSupportedContainer(Object obj) {
        return !Objects.isNull(getStrategyType(obj));
    }

    /**
     * 获取容器类型名称
     *
     * @param obj 容器对象
     * @return 容器类型名称
     */
    public String getContainerTypeName(Object obj) {
        if (Objects.isNull(obj)) {
            return "null";
        }

        CollectionStrategyType strategyType = getStrategyType(obj);
        if (!Objects.isNull(strategyType)) {
            CollectionCryptoStrategy strategy = strategyFactory.getStrategy(strategyType);
            if (!Objects.isNull(strategy)) {
                return strategy.getStrategyName();
            }
        }

        return obj.getClass().getSimpleName();
    }

    /**
     * 获取容器大小
     *
     * @param container 容器对象
     * @return 容器中元素的数量
     */
    private int getContainerSize(Object container) {
        if (Objects.isNull(container)) {
            return 0;
        }

        if (container.getClass().isArray()) {
            return java.lang.reflect.Array.getLength(container);
        } else if (container instanceof java.util.Collection) {
            return ((java.util.Collection<?>) container).size();
        } else if (container instanceof java.util.Map) {
            return ((java.util.Map<?, ?>) container).size();
        }

        return 0;
    }
}