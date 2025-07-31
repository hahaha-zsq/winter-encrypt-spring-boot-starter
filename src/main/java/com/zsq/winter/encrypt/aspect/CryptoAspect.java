package com.zsq.winter.encrypt.aspect;

import cn.hutool.json.JSONUtil;
import com.zsq.winter.encrypt.annotation.FieldDecrypt;
import com.zsq.winter.encrypt.annotation.FieldEncrypt;
import com.zsq.winter.encrypt.entity.CryptoProperties;
import com.zsq.winter.encrypt.enums.CryptoType;
import com.zsq.winter.encrypt.exception.CryptoException;
import com.zsq.winter.encrypt.service.ContainerCryptoService;
import com.zsq.winter.encrypt.service.CryptoService;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;

/**
 * 加密解密切面类
 * 使用AOP技术，在方法执行前后自动进行加密解密处理
 * 支持对方法参数和返回值中的字段进行加密解密
 * 支持对List、Set、Map、Queue、Array等各种集合类型中的字段进行加密解密处理
 * 
 * 加密类型处理策略：
 * - DES/AES：使用容器策略进行加解密
 * - RSA：使用单独容器的加解密逻辑
 */
@Aspect
@Slf4j
public class CryptoAspect {

    /**
     * 加密配置属性，包含密钥等信息
     */
    private final CryptoProperties cryptoProperties;

    /**
     * 加解密服务，提供加密解密功能
     */
    private final CryptoService cryptoService;

    /**
     * 容器加密解密服务
     */
    private final ContainerCryptoService containerCryptoService;

    /**
     * 构造函数，通过依赖注入方式获取加密配置和加密服务
     *
     * @param cryptoProperties       加密配置属性，包含密钥等信息
     * @param cryptoService          加解密服务，提供加密解密功能
     * @param containerCryptoService 容器加密解密服务
     */
    public CryptoAspect(CryptoProperties cryptoProperties, CryptoService cryptoService, ContainerCryptoService containerCryptoService) {
        this.cryptoProperties = cryptoProperties;
        this.cryptoService = cryptoService;
        this.containerCryptoService = containerCryptoService;
    }

    /**
     * 环绕通知方法，处理带有{@link com.zsq.winter.encrypt.annotation.Encrypt}注解的方法。
     *
     * <p>该方法在目标方法执行后，对返回值中带有{@link com.zsq.winter.encrypt.annotation.FieldEncrypt}注解的字段进行加密处理。
     * 加密过程：
     * <ol>
     *   <li>执行目标方法获取返回值</li>
     *   <li>通过反射获取返回值对象的所有字段</li>
     *   <li>检查字段是否带有{@link com.zsq.winter.encrypt.annotation.FieldEncrypt}注解</li>
     *   <li>对带有注解的字段，获取字段值并转换为JSON字符串</li>
     *   <li>根据注解中的加密参数和配置属性进行加密</li>
     *   <li>将加密后的值设置回字段</li>
     *   <li>支持对List、Set、Map、Queue、Array等各种集合类型中的字段进行加密处理</li>
     * </ol>
     * </p>
     *
     * @param joinPoint 切入点，包含目标方法的相关信息
     * @return 处理后的返回值（字段已加密）
     * @throws Throwable 执行过程中可能抛出的异常
     * @see com.zsq.winter.encrypt.annotation.Encrypt
     * @see com.zsq.winter.encrypt.annotation.FieldEncrypt
     */
    @Around("@annotation(com.zsq.winter.encrypt.annotation.Encrypt)")
    public Object encrypt(ProceedingJoinPoint joinPoint) throws Throwable {
        // 获取目标方法的参数
        Object[] args = joinPoint.getArgs();
        Object result;
        // 执行目标方法并获取结果
        result = joinPoint.proceed(args);
        // 获取返回结果的类型
        Class<?> resultClass = result.getClass();
        // 遍历结果对象的所有字段，检查是否有@FieldEncrypt注解
        for (Field field : resultClass.getDeclaredFields()) {
            // 对于有@FieldEncrypt注解的字段，进行加密处理
            if (field.isAnnotationPresent(FieldEncrypt.class)) {
                // 设置字段可访问（处理私有字段）
                field.setAccessible(true);
                // 获取字段当前值
                Object value = field.get(result);
                
                // 检查字段值是否为null（允许空字符串）
                if (Objects.isNull(value)) {
                    log.error("加密失败：字段 {} 的值不能为null，值: {}", field.getName(), null);
                    throw CryptoException.emptyData("加密", null);
                }
                
                // 获取字段上的@FieldEncrypt注解
                FieldEncrypt annotation = field.getAnnotation(FieldEncrypt.class);
                assert annotation != null;
                
                // 根据加密类型选择不同的处理策略
                if (isSymmetricCrypto(annotation.cryptoType())) {
                    // DES/AES对称加密：使用容器策略
                    processSymmetricEncryption(field, result, value, annotation);
                } else if (CryptoType.RSA.equals(annotation.cryptoType())) {
                    // RSA非对称加密：使用单独逻辑
                    processRsaEncryption(field, result, value, annotation);
                } else {
                    log.warn("不支持的加密类型: {}", annotation.cryptoType());
                }
            }
        }
        // 返回处理后的结果
        return result;
    }

    /**
     * 环绕通知，拦截标注了@Decrypt注解的方法
     * 在方法执行前，对方法参数中标注了@FieldDecrypt注解的字段进行解密处理
     * 解密完成后，再执行原方法并返回结果
     * 支持对List、Set、Map、Queue、Array等各种集合类型中的字段进行解密处理
     *
     * @param joinPoint 连接点，包含被拦截方法的信息和参数
     * @return 原方法执行的结果
     * @throws Throwable 执行过程中可能抛出的异常
     */
    @Around("@annotation(com.zsq.winter.encrypt.annotation.Decrypt)")
    public Object decrypt(ProceedingJoinPoint joinPoint) throws Throwable {
        // 获取的是方法调用时的实际参数值，不是参数名
        Object[] args = joinPoint.getArgs();
        // 遍历所有参数，处理需要解密的字段
        for (Object arg : args) {
            if (!Objects.isNull(arg)) {
                // 获取参数的类型
                Class<?> argClass = arg.getClass();
                // 遍历参数对象的所有字段
                for (Field field : argClass.getDeclaredFields()) {
                    // 检查字段是否标注了@FieldDecrypt注解
                    if (field.isAnnotationPresent(FieldDecrypt.class)) {
                        // 设置字段可访问，以便获取和设置私有字段的值
                        field.setAccessible(true);
                        // 获取字段的值
                        Object value = field.get(arg);

                        // 检查字段值是否为null（允许空字符串）
                        if (Objects.isNull(value)) {
                            log.error("解密失败：字段 {} 的值不能为null，值: {}", field.getName(), null);
                            throw CryptoException.emptyData("解密", null);
                        }

                        // 获取字段上的@FieldDecrypt注解
                        FieldDecrypt annotation = field.getAnnotation(FieldDecrypt.class);
                        assert annotation != null;
                        
                        // 根据解密类型选择不同的处理策略
                        if (isSymmetricCrypto(annotation.cryptoType())) {
                            // DES/AES对称解密：使用容器策略
                            processSymmetricDecryption(field, arg, value, annotation);
                        } else if (annotation.cryptoType() == CryptoType.RSA) {
                            // RSA非对称解密：使用单独逻辑
                            processRsaDecryption(field, arg, value, annotation);
                        } else {
                            log.warn("不支持的解密类型: {}", annotation.cryptoType());
                        }
                    }
                }
            }
        }
        // 执行原方法并返回结果
        return joinPoint.proceed(args);
    }

    /**
     * 判断是否为对称加密类型（DES/AES）
     *
     * @param cryptoType 加密类型
     * @return 是否为对称加密
     */
    private boolean isSymmetricCrypto(CryptoType cryptoType) {
        return cryptoType == CryptoType.AES || cryptoType == CryptoType.DES;
    }

    /**
     * 处理对称加密（DES/AES）- 使用容器策略
     *
     * @param field      字段对象
     * @param result     结果对象
     * @param value      字段值
     * @param annotation 加密注解
     * @throws Exception 加密异常
     */
    private void processSymmetricEncryption(Field field, Object result, Object value, FieldEncrypt annotation) throws Exception {
        // 处理集合类型的字段（List、Set、Map、Queue、Array等）
        if (containerCryptoService.isSupportedContainer(value)) {
            logCollectionField("对称加密", field, value);
            
            // AOP层容器元素类型检查
            validateContainerElementsAreString(value, field.getName(), "对称加密");
            
            try {
                String encryptKey = cryptoProperties.getEncryptKey(annotation.cryptoType());
                String iv = cryptoProperties.getIv(annotation.cryptoType());

                Object encryptedCollection = containerCryptoService.encryptContainer(
                        value,
                        cryptoService,
                        annotation,
                        encryptKey,
                        iv
                );
                // 将加密后的值设置回字段
                field.set(result, encryptedCollection);
            } catch (CryptoException e) {
                log.error("对称加密失败，字段: {}, 错误类型: {}, 错误: {}",
                    field.getName(), e.getErrorType(), e.getMessage());
                throw e;
            }
        } else if (value instanceof String) {
            // 处理普通字符串字段
            String stringValue = (String) value;
            String encryptedValue = cryptoService.encrypt(
                    annotation.mode(),
                    annotation.padding(),
                    stringValue,
                    cryptoProperties.getEncryptKey(annotation.cryptoType()),
                    cryptoProperties.getIv(annotation.cryptoType()),
                    annotation.cryptoType()
            );
            // 将加密后的值设置回字段
            field.set(result, encryptedValue);
        } else {
            // 不支持的数据类型
            String dataType = value != null ? value.getClass().getSimpleName() : "null";
            log.error("加密失败：字段 {} 的数据类型不支持，当前类型: {}, 只支持字符串类型", field.getName(), dataType);
            throw CryptoException.unsupportedDataType("加密", dataType, value);
        }
    }

    /**
     * 处理RSA加密 - 使用单独逻辑
     *
     * @param field      字段对象
     * @param result     结果对象
     * @param value      字段值
     * @param annotation 加密注解
     * @throws Exception 加密异常
     */
    private void processRsaEncryption(Field field, Object result, Object value, FieldEncrypt annotation) throws Exception {
        // 处理集合类型的字段
        if (containerCryptoService.isSupportedContainer(value)) {
            logCollectionField("RSA加密", field, value);
            
            // AOP层容器元素类型检查
            validateContainerElementsAreString(value, field.getName(), "RSA加密");
            
            try {
                String privateKey = cryptoProperties.getEncryptKey(annotation.cryptoType());
                String publicKey = cryptoProperties.getDecryptKey(annotation.cryptoType());
                Object encryptedCollection = containerCryptoService.encryptRsaContainer(
                        value,
                        cryptoService,
                        annotation,
                        privateKey,
                        publicKey
                );
                field.set(result, encryptedCollection);
            } catch (CryptoException e) {
                log.error("RSA加密失败，字段: {}, 错误类型: {}, 错误: {}",
                    field.getName(), e.getErrorType(), e.getMessage());
                throw e;
            }
        } else if (value instanceof String) {
            // 处理普通字符串字段
            String stringValue = (String) value;
            String encryptedValue = cryptoService.encryptRsa(
                    stringValue,
                    cryptoProperties.getEncryptKey(annotation.cryptoType()),
                    cryptoProperties.getDecryptKey(annotation.cryptoType())
            );
            field.set(result, encryptedValue);
        } else {
            // 不支持的数据类型
            String dataType = value != null ? value.getClass().getSimpleName() : "null";
            log.error("RSA加密失败：字段 {} 的数据类型不支持，当前类型: {}, 只支持字符串类型", field.getName(), dataType);
            throw CryptoException.unsupportedDataType("RSA加密", dataType, value);
        }
    }

    /**
     * 处理对称解密（DES/AES）- 使用容器策略
     *
     * @param field      字段对象
     * @param arg        参数对象
     * @param value      字段值
     * @param annotation 解密注解
     * @throws Exception 解密异常
     */
    private void processSymmetricDecryption(Field field, Object arg, Object value, FieldDecrypt annotation) throws Exception {
        // 处理集合类型的字段
        if (containerCryptoService.isSupportedContainer(value)) {
            logCollectionField("对称解密", field, value);
            
            // AOP层容器元素类型检查
            validateContainerElementsAreString(value, field.getName(), "对称解密");
            
            try {
                String decryptKey = cryptoProperties.getDecryptKey(annotation.cryptoType());
                String iv = cryptoProperties.getIv(annotation.cryptoType());
                
                Object decryptedCollection = containerCryptoService.decryptContainer(
                        value,
                        cryptoService,
                        annotation,
                        decryptKey,
                        iv
                );
                field.set(arg, decryptedCollection);
            } catch (CryptoException e) {
                log.error("对称解密失败，字段: {}, 错误类型: {}, 错误: {}",
                        field.getName(), e.getErrorType(), e.getMessage());
                throw e;
            }
        } else if (value instanceof String) {
            // 处理普通字符串字段
            String encryptedValue = (String) value;
            try {
                String decryptedValue = cryptoService.decrypt(
                        annotation.mode(),
                        annotation.padding(),
                        encryptedValue,
                        cryptoProperties.getDecryptKey(annotation.cryptoType()),
                        cryptoProperties.getIv(annotation.cryptoType()),
                        annotation.cryptoType()
                );
                field.set(arg, decryptedValue);
            } catch (Exception e) {
                log.error("对称解密字段失败，字段: {}, 错误: {}", field.getName(), e.getMessage());
                throw new RuntimeException("对称解密字段失败", e);
            }
        } else {
            // 不支持的数据类型
            String dataType = value != null ? value.getClass().getSimpleName() : "null";
            log.error("对称解密失败：字段 {} 的数据类型不支持，当前类型: {}, 只支持字符串类型", field.getName(), dataType);
            throw CryptoException.unsupportedDataType("对称解密", dataType, value);
        }
    }

    /**
     * 处理RSA解密 - 使用单独逻辑
     *
     * @param field      字段对象
     * @param arg        参数对象
     * @param value      字段值
     * @param annotation 解密注解
     * @throws Exception 解密异常
     */
    private void processRsaDecryption(Field field, Object arg, Object value, FieldDecrypt annotation) throws Exception {
        // 处理集合类型的字段
        if (containerCryptoService.isSupportedContainer(value)) {
            logCollectionField("RSA解密", field, value);
            
            // AOP层容器元素类型检查
            validateContainerElementsAreString(value, field.getName(), "RSA解密");
            
            try {
                String publicKey = cryptoProperties.getDecryptKey(annotation.cryptoType());
                String privateKey = cryptoProperties.getEncryptKey(annotation.cryptoType());
                
                Object decryptedCollection = containerCryptoService.decryptRsaContainer(
                        value,
                        cryptoService,
                        annotation,
                        publicKey,
                        privateKey
                );
                field.set(arg, decryptedCollection);
            } catch (CryptoException e) {
                log.error("RSA解密失败，字段: {}, 错误类型: {}, 错误: {}",
                        field.getName(), e.getErrorType(), e.getMessage());
                throw e;
            }
        } else if (value instanceof String) {
            // 处理普通字符串字段
            String encryptedValue = (String) value;
            try {
                String decryptedValue = cryptoService.decryptRsa(
                        encryptedValue,
                        cryptoProperties.getDecryptKey(annotation.cryptoType()),
                        cryptoProperties.getEncryptKey(annotation.cryptoType())
                );
                field.set(arg, decryptedValue);
            } catch (Exception e) {
                log.error("RSA解密字段失败，字段: {}, 错误: {}", field.getName(), e.getMessage());
                throw new RuntimeException("RSA解密字段失败", e);
            }
        } else {
            // 不支持的数据类型
            String dataType = value != null ? value.getClass().getSimpleName() : "null";
            log.error("RSA解密失败：字段 {} 的数据类型不支持，当前类型: {}, 只支持字符串类型", field.getName(), dataType);
            throw CryptoException.unsupportedDataType("RSA解密", dataType, value);
        }
    }

    /**
     * 检查容器中所有元素是否都是字符串类型
     * 
     * <p>在AOP层检查容器中的所有元素是否都是字符串类型。
     * 如果发现非字符串元素，立即抛出异常。</p>
     *
     * @param container 待检查的容器
     * @param fieldName 字段名称
     * @param operation 操作类型（加密/解密）
     * @throws CryptoException 当发现非字符串元素时抛出
     */
    private void validateContainerElementsAreString(Object container, String fieldName, String operation) {
        if (Objects.isNull(container)) {
            return;
        }
        
        if (container instanceof List) {
            List<?> list = (List<?>) container;
            for (int i = 0; i < list.size(); i++) {
                Object item = list.get(i);
                if (!Objects.isNull(item) && !(item instanceof String)) {
                    String dataType = item.getClass().getSimpleName();
                    log.error("{}失败：字段 {} 的List中第{}个元素不是字符串类型，当前类型: {}, 元素值: {}", 
                        operation, fieldName, i + 1, dataType, item);
                    throw CryptoException.unsupportedDataType(operation, 
                        String.format("字段 %s 的List中第%d个元素类型: %s", fieldName, i + 1, dataType), item);
                }
            }
        } else if (container instanceof Set) {
            Set<?> set = (Set<?>) container;
            int index = 0;
            for (Object item : set) {
                index++;
                if (!Objects.isNull(item) && !(item instanceof String)) {
                    String dataType = item.getClass().getSimpleName();
                    log.error("{}失败：字段 {} 的Set中第{}个元素不是字符串类型，当前类型: {}, 元素值: {}", 
                        operation, fieldName, index, dataType, item);
                    throw CryptoException.unsupportedDataType(operation, 
                        String.format("字段 %s 的Set中第%d个元素类型: %s", fieldName, index, dataType), item);
                }
            }
        } else if (container instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) container;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                Object value = entry.getValue();
                Object key = entry.getKey();
                if (!Objects.isNull(value) && !(value instanceof String)) {
                    String dataType = value.getClass().getSimpleName();
                    log.error("{}失败：字段 {} 的Map中键[{}]对应的值不是字符串类型，当前类型: {}, 值: {}", 
                        operation, fieldName, key, dataType, value);
                    throw CryptoException.unsupportedDataType(operation, 
                        String.format("字段 %s 的Map中键[%s]对应的值类型: %s", fieldName, key, dataType), value);
                }
            }
        } else if (container instanceof Queue) {
            Queue<?> queue = (Queue<?>) container;
            int index = 0;
            for (Object item : queue) {
                index++;
                if (!Objects.isNull(item) && !(item instanceof String)) {
                    String dataType = item.getClass().getSimpleName();
                    log.error("{}失败：字段 {} 的Queue中第{}个元素不是字符串类型，当前类型: {}, 元素值: {}", 
                        operation, fieldName, index, dataType, item);
                    throw CryptoException.unsupportedDataType(operation, 
                        String.format("字段 %s 的Queue中第%d个元素类型: %s", fieldName, index, dataType), item);
                }
            }
        } else if (container.getClass().isArray()) {
            Object[] array = (Object[]) container;
            for (int i = 0; i < array.length; i++) {
                Object item = array[i];
                if (!Objects.isNull(item) && !(item instanceof String)) {
                    String dataType = item.getClass().getSimpleName();
                    log.error("{}失败：字段 {} 的Array中第{}个元素不是字符串类型，当前类型: {}, 元素值: {}", 
                        operation, fieldName, i + 1, dataType, item);
                    throw CryptoException.unsupportedDataType(operation, 
                        String.format("字段 %s 的Array中第%d个元素类型: %s", fieldName, i + 1, dataType), item);
                }
            }
        }
    }

    /**
     * 记录集合类型字段的调试日志
     *
     * @param action 操作类型（加密/解密）
     * @param field  字段对象
     * @param value  字段值
     */
    private void logCollectionField(String action, Field field, Object value) {
        // 记录集合类型字段的调试日志，包含字段名、集合类型和操作类型
        log.debug("检测到集合类型字段: {}, 类型: {}, 操作: {}", field.getName(), containerCryptoService.getContainerTypeName(value), action);
    }
}
