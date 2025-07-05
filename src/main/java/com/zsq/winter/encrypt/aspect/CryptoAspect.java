package com.zsq.winter.encrypt.aspect;

import cn.hutool.json.JSONUtil;
import com.zsq.winter.encrypt.annotation.FieldEncrypt;
import com.zsq.winter.encrypt.entity.CryptoProperties;
import com.zsq.winter.encrypt.service.CryptoService;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;

import java.lang.reflect.Field;

@Aspect
@Slf4j
/**
 * CryptoAspect类是一个切面类，用于处理加密和解密逻辑它利用Spring的AOP框架，
 * 在方法执行前后动态地应用加密和解密操作
 */
public class CryptoAspect {
    // CryptoProperties用于存储加密相关的配置属性
    private final CryptoProperties cryptoProperties;
    // CryptoService提供了加密和解密的服务
    private final CryptoService cryptoService;

    /**
     * 构造函数注入CryptoProperties和CryptoService
     *
     * @param cryptoProperties 加密配置属性
     * @param cryptoService    加密服务
     */
    public CryptoAspect(CryptoProperties cryptoProperties, CryptoService cryptoService) {
        this.cryptoProperties = cryptoProperties;
        this.cryptoService = cryptoService;
    }

    /**
     * 环绕通知，用于处理带有@Encrypt注解的方法它在方法执行前后
     * 对方法的参数和返回值进行加密和解密
     *
     * @param joinPoint 切入点，提供了关于目标方法的信息
     * @return 执行后的结果
     * @throws Throwable 目标方法执行过程中可能抛出的异常
     */
    @Around("@annotation(com.zsq.winter.encrypt.annotation.Encrypt)")
    public Object encryptDecrypt(ProceedingJoinPoint joinPoint) throws Throwable {
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
                field.setAccessible(true);
                Object value = field.get(result);
                String jsonStr = JSONUtil.toJsonStr(value);
                FieldEncrypt annotation = field.getAnnotation(FieldEncrypt.class);
                // 调用CryptoService的encrypt方法进行加密
                String encryptedValue = cryptoService.encrypt(annotation.mode(),annotation.padding(),jsonStr, cryptoProperties.getEncryptKey(),cryptoProperties.getIv(), annotation.cryptoType());
                field.set(result, encryptedValue);
            }
        }
        return result;
    }
}
