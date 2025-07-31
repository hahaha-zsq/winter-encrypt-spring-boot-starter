package com.zsq.winter.encrypt.strategy;

import cn.hutool.json.JSONUtil;
import com.zsq.winter.encrypt.annotation.FieldDecrypt;
import com.zsq.winter.encrypt.annotation.FieldEncrypt;
import com.zsq.winter.encrypt.enums.CryptoType;
import com.zsq.winter.encrypt.exception.CryptoException;
import com.zsq.winter.encrypt.service.CryptoService;
import lombok.extern.slf4j.Slf4j;

import java.util.Objects;

/**
 * 抽象集合加密解密策略基类
 * 
 * <p>提供通用的加密解密逻辑，子类只需要实现特定的集合类型处理。
 * 该抽象类实现了模板方法模式，定义了集合加密解密的基本流程。</p>
 * 
 * <p>设计说明：</p>
 * <ul>
 *   <li>抽象类实现接口（可以不实现方法，也可以实现一部分方法）</li>
 *   <li>如果抽象类没有实现接口的所有抽象方法，那么它自身必须用 abstract 关键字修饰</li>
 *   <li>具体类继承抽象类（必须实现剩余方法）</li>
 * </ul>
 * 
 * <p>加密解密方法分类：</p>
 * <ul>
 *   <li><strong>对称加密方法</strong>：{@link #encryptItem(Object, CryptoService, FieldEncrypt, String, String)} - 用于AES/DES</li>
 *   <li><strong>对称解密方法</strong>：{@link #decryptItem(Object, CryptoService, FieldDecrypt, String, String)} - 用于AES/DES</li>
 *   <li><strong>RSA加密方法</strong>：{@link #encryptRsaItem(Object, CryptoService, String, String)} - 专门用于RSA</li>
 *   <li><strong>RSA解密方法</strong>：{@link #decryptRsaItem(Object, CryptoService, String, String)} - 专门用于RSA</li>
 * </ul>
 * 
 * <p>子类需要实现的方法：</p>
 * <ul>
 *   <li>{@link #encrypt(Object, CryptoService, FieldEncrypt, String, String)}</li>
 *   <li>{@link #decrypt(Object, CryptoService, FieldDecrypt, String, String)}</li>
 *   <li>{@link #getStrategyName()}</li>
 *   <li>{@link #getStrategyType()}</li>
 * </ul>
 * 
 * @author dadandiaoming
 * @since 1.0.0
 * @see CollectionCryptoStrategy
 */
@Slf4j
public abstract class AbstractCollectionCryptoStrategy implements CollectionCryptoStrategy {

    /**
     * 加密单个元素（对称加密）
     * 
     * <p>将集合中的单个元素转换为JSON字符串后进行对称加密处理。
     * 专门用于AES、DES等对称加密算法。</p>
     *
     * @param item 待加密的元素，不能为null
     * @param cryptoService 加密服务实例
     * @param annotation 加密注解，包含加密参数配置
     * @param encryptKey 加密密钥
     * @param iv 初始化向量
     * @return 加密后的字符串
     * @throws CryptoException 当加密过程中发生错误时抛出
     * @throws IllegalArgumentException 如果item为null
     */
    protected String encryptItem(Object item, CryptoService cryptoService, 
                               FieldEncrypt annotation, String encryptKey, String iv) {
        // 检查数据是否为null（允许空字符串）
        if (Objects.isNull(item)) {
            log.error("加密失败：数据不能为null，数据: {}", item);
            throw CryptoException.emptyData("加密", item);
        }
        
        // 检查是否为字符串类型
        if (!(item instanceof String)) {
            String dataType = item.getClass().getSimpleName();
            log.error("加密失败：数据必须是字符串类型，当前类型: {}, 数据: {}", dataType, item);
            throw CryptoException.unsupportedDataType("加密", dataType, item);
        }
        
        try {
            // 直接使用字符串，不进行JSON转换
            String stringValue = (String) item;
            return encryptSymmetricItem(stringValue, cryptoService, annotation, encryptKey, iv);
        } catch (Exception e) {
            log.error("对称加密集合元素失败: {}", item, e);
            throw CryptoException.containerCryptoError("对称加密集合元素失败", e, "对称加密", item);
        }
    }

    /**
     * RSA加密单个元素
     * 
     * <p>专门处理RSA加密，包含RSA特有的优化和错误处理。
     * 将集合中的单个元素转换为JSON字符串后进行RSA加密处理。</p>
     *
     * @param item 待加密的元素，不能为null
     * @param cryptoService 加密服务实例
     * @param privateKey RSA私钥
     * @param publicKey RSA公钥
     * @return 加密后的字符串
     * @throws CryptoException 当RSA加密过程中发生错误时抛出
     */
    protected String encryptRsaItem(Object item, CryptoService cryptoService, 
                                   String privateKey, String publicKey) {
        // 检查数据是否为null（允许空字符串）
        if (Objects.isNull(item)) {
            log.error("RSA加密失败：数据不能为null，数据: {}", item);
            throw CryptoException.emptyData("RSA加密", item);
        }
        
        // 检查是否为字符串类型
        if (!(item instanceof String)) {
            String dataType = item.getClass().getSimpleName();
            log.error("RSA加密失败：数据必须是字符串类型，当前类型: {}, 数据: {}", dataType, item);
            throw CryptoException.unsupportedDataType("RSA加密", dataType, item);
        }
        
        try {
            // 直接使用字符串，不进行JSON转换
            String stringValue = (String) item;
            
            // RSA加密特有的优化：检查数据长度
            if (stringValue.length() > 117) { // RSA-1024的最大加密长度约为117字节
                log.warn("RSA加密数据长度较长: {} 字符，可能影响性能", stringValue.length());
            }
            
            return cryptoService.encryptRsa(stringValue, privateKey, publicKey);
        } catch (Exception e) {
            log.error("RSA加密集合元素失败: {}", item, e);
            throw CryptoException.containerCryptoError("RSA加密集合元素失败", e, "RSA加密", item);
        }
    }

    /**
     * 对称加密单个元素
     * 
     * <p>处理AES/DES等对称加密。</p>
     *
     * @param jsonStr 待加密的JSON字符串
     * @param cryptoService 加密服务实例
     * @param annotation 加密注解
     * @param encryptKey 加密密钥
     * @param iv 初始化向量
     * @return 加密后的字符串
     * @throws CryptoException 当对称加密过程中发生错误时抛出
     */
    protected String encryptSymmetricItem(String jsonStr, CryptoService cryptoService,
                                         FieldEncrypt annotation, String encryptKey, String iv) {
        try {
            return cryptoService.encrypt(
                annotation.mode(),
                annotation.padding(),
                jsonStr,
                encryptKey,
                iv,
                annotation.cryptoType()
            );
        } catch (Exception e) {
            log.error("对称加密集合元素失败", e);
            throw CryptoException.containerCryptoError("对称加密集合元素失败", e, "对称加密", jsonStr);
        }
    }

    /**
     * 解密单个元素（对称解密）
     * 
     * <p>将集合中的加密字符串解密为原始内容。
     * 专门用于AES、DES等对称解密算法。</p>
     *
     * @param item 待解密的元素，必须是字符串类型且不能为null
     * @param cryptoService 解密服务实例
     * @param annotation 解密注解，包含解密参数配置
     * @param decryptKey 解密密钥
     * @param iv 初始化向量
     * @return 解密后的字符串
     * @throws CryptoException 当解密过程中发生错误时抛出
     * @throws IllegalArgumentException 如果item为null或不是字符串类型
     */
    protected String decryptItem(Object item, CryptoService cryptoService, 
                               FieldDecrypt annotation, String decryptKey, String iv) {
        // 检查数据是否为null（允许空字符串）
        if (Objects.isNull(item)) {
            log.error("解密失败：数据不能为null，数据: {}", item);
            throw CryptoException.emptyData("解密", item);
        }
        
        // 检查是否为字符串类型
        if (!(item instanceof String)) {
            log.error("解密失败：数据必须是字符串类型，当前类型: {}, 数据: {}", 
                item.getClass().getSimpleName(), item);
            throw CryptoException.containerCryptoError(
                String.format("解密数据必须是字符串类型，当前类型: %s", item.getClass().getSimpleName()), 
                null, "解密", item);
        }
        
        try {
            String encryptedValue = (String) item;
            return decryptSymmetricItem(encryptedValue, cryptoService, annotation, decryptKey, iv);
        } catch (Exception e) {
            log.error("对称解密集合元素失败: {}", item, e);
            throw CryptoException.containerCryptoError("对称解密集合元素失败", e, "对称解密", item);
        }
    }

    /**
     * RSA解密单个元素
     * 
     * <p>专门处理RSA解密，包含RSA特有的优化和错误处理。
     * 将集合中的RSA加密字符串解密为原始内容。</p>
     *
     * @param item 待解密的元素，必须是字符串类型且不能为null
     * @param cryptoService 解密服务实例
     * @param publicKey RSA公钥
     * @param privateKey RSA私钥
     * @return 解密后的字符串
     * @throws CryptoException 当RSA解密过程中发生错误时抛出
     */
    protected String decryptRsaItem(Object item, CryptoService cryptoService,
                                   String publicKey, String privateKey) {
        // 检查数据是否为null（允许空字符串）
        if (Objects.isNull(item)) {
            log.error("RSA解密失败：数据不能为null，数据: {}", item);
            throw CryptoException.emptyData("RSA解密", item);
        }
        
        // 检查是否为字符串类型
        if (!(item instanceof String)) {
            log.error("RSA解密失败：数据必须是字符串类型，当前类型: {}, 数据: {}", 
                item.getClass().getSimpleName(), item);
            throw CryptoException.containerCryptoError(
                String.format("RSA解密数据必须是字符串类型，当前类型: %s", item.getClass().getSimpleName()), 
                null, "RSA解密", item);
        }
        
        try {
            String encryptedValue = (String) item;
            
            // RSA解密特有的优化：检查加密数据格式
            if (encryptedValue.trim().isEmpty()) {
                throw CryptoException.emptyData("RSA解密", encryptedValue);
            }
            
            // 检查是否为Base64格式（RSA加密结果通常是Base64格式）
            if (!isValidBase64(encryptedValue)) {
                log.warn("RSA解密数据可能不是有效的Base64格式: {}", encryptedValue.substring(0, Math.min(50, encryptedValue.length())));
            }
            
            return cryptoService.decryptRsa(encryptedValue, publicKey, privateKey);
        } catch (Exception e) {
            log.error("RSA解密集合元素失败: {}", item, e);
            throw CryptoException.containerCryptoError("RSA解密集合元素失败", e, "RSA解密", item);
        }
    }

    /**
     * 对称解密单个元素
     * 
     * <p>处理AES/DES等对称解密。</p>
     *
     * @param encryptedValue 待解密的字符串
     * @param cryptoService 解密服务实例
     * @param annotation 解密注解
     * @param decryptKey 解密密钥
     * @param iv 初始化向量
     * @return 解密后的字符串
     * @throws CryptoException 当对称解密过程中发生错误时抛出
     */
    protected String decryptSymmetricItem(String encryptedValue, CryptoService cryptoService,
                                         FieldDecrypt annotation, String decryptKey, String iv) {
        try {
            return cryptoService.decrypt(
                annotation.mode(),
                annotation.padding(),
                encryptedValue,
                decryptKey,
                iv,
                annotation.cryptoType()
            );
        } catch (Exception e) {
            log.error("对称解密集合元素失败", e);
            throw CryptoException.containerCryptoError("对称解密集合元素失败", e, "对称解密", encryptedValue);
        }
    }

    /**
     * 检查字符串是否为有效的Base64格式
     * 
     * <p>用于RSA解密前的数据格式验证。</p>
     *
     * @param str 待检查的字符串
     * @return 如果是有效的Base64格式返回true，否则返回false
     */
    private boolean isValidBase64(String str) {
        if (str == null || str.trim().isEmpty()) {
            return false;
        }
        
        try {
            // 尝试解码Base64，如果成功则认为是有效格式
            java.util.Base64.getDecoder().decode(str);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }



    /**
     * 记录处理日志
     * 
     * <p>记录集合加密解密操作的调试日志，包含操作类型、策略名称、集合对象和类型信息。</p>
     *
     * @param collection 集合对象
     * @param operation 操作类型（加密/解密）
     */
    protected void logOperation(Object collection, String operation) {
        log.debug("{} {}集合: {}, 类型: {}", 
            operation, getStrategyName(), collection, collection.getClass().getSimpleName());
    }

    /**
     * 检查集合是否为null
     * 
     * <p>通用的null检查方法，避免子类重复编写相同的检查逻辑。</p>
     *
     * @param collection 待检查的集合
     * @return 如果集合为null返回true，否则返回false
     */
    protected boolean isNullCollection(Object collection) {
        return Objects.isNull(collection);
    }

    /**
     * 默认RSA加密实现
     * 
     * <p>子类可以重写此方法提供特定的RSA加密实现。</p>
     *
     * @param collection 待加密的集合
     * @param cryptoService 加密服务
     * @param annotation 加密注解
     * @param privateKey RSA私钥
     * @param publicKey RSA公钥
     * @return 加密后的集合
     */
    @Override
    public Object encryptRsa(Object collection, CryptoService cryptoService,
                            FieldEncrypt annotation, String privateKey, String publicKey) {
        // 默认实现：抛出异常，要求子类实现
        throw new UnsupportedOperationException("RSA加密方法需要子类实现");
    }

    /**
     * 默认RSA解密实现
     * 
     * <p>子类可以重写此方法提供特定的RSA解密实现。</p>
     *
     * @param collection 待解密的集合
     * @param cryptoService 解密服务
     * @param annotation 解密注解
     * @param publicKey RSA公钥
     * @param privateKey RSA私钥
     * @return 解密后的集合
     */
    @Override
    public Object decryptRsa(Object collection, CryptoService cryptoService,
                            FieldDecrypt annotation, String publicKey, String privateKey) {
        // 默认实现：抛出异常，要求子类实现
        throw new UnsupportedOperationException("RSA解密方法需要子类实现");
    }
} 