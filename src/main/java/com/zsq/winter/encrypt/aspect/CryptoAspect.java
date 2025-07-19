package com.zsq.winter.encrypt.aspect;

import cn.hutool.json.JSONUtil;
import com.zsq.winter.encrypt.annotation.FieldDecrypt;
import com.zsq.winter.encrypt.annotation.FieldEncrypt;
import com.zsq.winter.encrypt.entity.CryptoProperties;
import com.zsq.winter.encrypt.service.CryptoService;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.util.ObjectUtils;

import java.lang.reflect.Field;

/**
 * 加密解密切面类
 * 
 * 该切面类负责处理带有@Encrypt注解的方法，对方法返回值中带有@FieldEncrypt注解的字段进行加密处理。
 * 通过Spring AOP机制，在目标方法执行后动态地应用加密操作，实现了业务逻辑与加密逻辑的解耦。
 */
@Aspect
@Slf4j
public class CryptoAspect {
    /**
     * 加密配置属性
     * 包含加密所需的密钥、向量等配置信息
     */
    private final CryptoProperties cryptoProperties;
    
    /**
     * 加密服务
     * 提供实际的加密和解密功能实现
     */
    private final CryptoService cryptoService;

    /**
     * 构造函数，通过依赖注入方式获取加密配置和加密服务
     *
     * @param cryptoProperties 加密配置属性，包含密钥等信息
     * @param cryptoService    加密服务，提供加密解密功能
     */
    public CryptoAspect(CryptoProperties cryptoProperties, CryptoService cryptoService) {
        this.cryptoProperties = cryptoProperties;
        this.cryptoService = cryptoService;
    }

    /**
     * 环绕通知方法，处理带有@Encrypt注解的方法
     * 
     * 该方法在目标方法执行后，对返回值中带有@FieldEncrypt注解的字段进行加密处理。
     * 加密过程：
     * 1. 执行目标方法获取返回值
     * 2. 通过反射获取返回值对象的所有字段
     * 3. 检查字段是否带有@FieldEncrypt注解
     * 4. 对带有注解的字段，获取字段值并转换为JSON字符串
     * 5. 根据注解中的加密参数和配置属性进行加密
     * 6. 将加密后的值设置回字段
     *
     * @param joinPoint 切入点，包含目标方法的相关信息
     * @return 处理后的返回值（字段已加密）
     * @throws Throwable 执行过程中可能抛出的异常
     */
    @Around("@annotation(com.zsq.winter.encrypt.annotation.Encrypt)")
    public Object encryptDecrypt(ProceedingJoinPoint joinPoint) throws Throwable {
        // 获取目标方法的参数
        Object[] args = joinPoint.getArgs();
        Object result = null;
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
                // 将字段值转换为JSON字符串
                String jsonStr = JSONUtil.toJsonStr(value);
                // 获取字段上的@FieldEncrypt注解
                FieldEncrypt annotation = field.getAnnotation(FieldEncrypt.class);
                // 调用加密服务进行加密，使用注解中指定的模式、填充方式和加密类型
                String encryptedValue = cryptoService.encrypt(
                    annotation.mode(),       // 加密模式
                    annotation.padding(),    // 填充方式
                    jsonStr,                 // 待加密的JSON字符串
                    cryptoProperties.getEncryptKey(),  // 加密密钥
                    cryptoProperties.getIv(),          // 初始化向量
                    annotation.cryptoType()  // 加密类型
                );
                // 将加密后的值设置回字段
                field.set(result, encryptedValue);
            }
        }
        // 返回处理后的结果
        return result;
    }


    /**
     * 环绕通知，拦截标注了@Decrypt注解的方法
     * 在方法执行前，对方法参数中标注了@FieldDecrypt注解的字段进行解密处理
     * 解密完成后，再执行原方法并返回结果
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
        for (int i = 0; i < args.length; i++) {
            Object arg = args[i];
            if (!ObjectUtils.isEmpty(arg)) {
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
                        // 如果字段值是字符串类型，则进行解密处理
                        if (!ObjectUtils.isEmpty(value) && value instanceof String) {
                            String encryptedValue = (String) value;
                            // 获取字段上的@FieldDecrypt注解
                            FieldDecrypt annotation = field.getAnnotation(FieldDecrypt.class);
                            // 调用解密服务进行解密
                            String decryptedValue = cryptoService.decrypt(
                                    annotation.mode(),      // 解密模式，如ECB、CBC等
                                    annotation.padding(),   // 填充方式，如PKCS5Padding等
                                    encryptedValue,         // 待解密的内容
                                    cryptoProperties.getDecryptKey(),  // 解密密钥
                                    cryptoProperties.getIv(),          // 偏移量
                                    annotation.cryptoType()            // 解密算法类型，如AES、DES等
                            );
                            // 将解密后的JSON字符串解析为对象，并设置回字段
                            field.set(arg, decryptedValue);
                        }
                    }
                }
                // 更新处理后的参数
                args[i] = arg;
            }
        }

        // 执行原方法并返回结果
        return joinPoint.proceed(args);
    }
}
