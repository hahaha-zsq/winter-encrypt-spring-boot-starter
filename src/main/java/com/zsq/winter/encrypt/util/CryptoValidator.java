package com.zsq.winter.encrypt.util;

import com.zsq.winter.encrypt.enums.CryptoType;
import com.zsq.winter.encrypt.exception.CryptoException;

/**
 * 加密参数验证工具类
 * 
 * <p>用于验证不同加密算法的密钥和初始化向量长度是否符合要求。</p>
 * 
 * <p>支持的算法及要求：</p>
 * <ul>
 *   <li><strong>AES</strong>：密钥长度128位(16字节)、192位(24字节)、256位(32字节)，IV长度128位(16字节)</li>
 *   <li><strong>DES</strong>：密钥长度64位(8字节)，IV长度64位(8字节)</li>
 *   <li><strong>RSA</strong>：密钥长度1024位、2048位、4096位等（PEM格式），不需要IV</li>
 * </ul>
 * 
 * @author dadandiaoming
 * @since 1.0.0
 */
public class CryptoValidator {

    // ==================== 密钥相关常量 ====================
    
    /**
     * AES算法支持的密钥长度（字节）
     */
    public static final int[] AES_KEY_LENGTHS = {16, 24, 32};
    
    /**
     * DES算法要求的密钥长度（字节）
     */
    public static final int DES_KEY_LENGTH = 8;

    // ==================== IV相关常量 ====================
    
    /**
     * AES算法要求的IV长度（字节）
     */
    public static final int AES_IV_LENGTH = 16;
    
    /**
     * DES算法要求的IV长度（字节）
     */
    public static final int DES_IV_LENGTH = 8;

    // ==================== 密钥验证方法 ====================

    /**
     * 验证密钥长度是否符合算法要求
     *
     * @param key 密钥
     * @param cryptoType 加密算法类型
     * @throws CryptoException 如果密钥长度不符合要求
     */
    public static void validateKeyLength(String key, CryptoType cryptoType) {
        if (key == null) {
            throw CryptoException.generalError("密钥不能为null", null, "验证", null);
        }

        switch (cryptoType) {
            case AES:
                validateAesKeyLength(key);
                break;
            case DES:
                validateDesKeyLength(key);
                break;
            case RSA:
                validateRsaKeyFormat(key, null); // RSA只验证私钥格式
                break;
            default:
                validateAesKeyLength(key); // 默认使用AES验证
        }
    }

    /**
     * 验证AES密钥长度
     *
     * @param key AES密钥
     * @throws CryptoException 如果密钥长度不符合AES要求
     */
    public static void validateAesKeyLength(String key) {
        int keyLength = key.getBytes().length;
        boolean isValidLength = false;
        
        for (int validLength : AES_KEY_LENGTHS) {
            if (keyLength == validLength) {
                isValidLength = true;
                break;
            }
        }
        
        if (!isValidLength) {
            throw CryptoException.generalError(
                String.format("AES密钥长度必须为16、24或32字节，当前长度为%d字节", keyLength),
                null, "验证", key
            );
        }
    }

    /**
     * 验证DES密钥长度
     *
     * @param key DES密钥
     * @throws CryptoException 如果密钥长度不符合DES要求
     */
    public static void validateDesKeyLength(String key) {
        int keyLength = key.getBytes().length;
        
        if (keyLength != DES_KEY_LENGTH) {
            throw CryptoException.generalError(
                String.format("DES密钥长度必须为8字节，当前长度为%d字节", keyLength),
                null, "验证", key
            );
        }
    }

    /**
     * 验证RSA密钥格式
     *
     * @param privateKey RSA私钥
     * @param publicKey RSA公钥
     * @throws CryptoException 如果密钥格式不正确
     */
    public static void validateRsaKeyFormat(String privateKey, String publicKey) {
        if (privateKey != null && !privateKey.contains("-----BEGIN PRIVATE KEY-----")) {
            throw CryptoException.invalidKeyFormat(
                "RSA私钥格式不正确，应为PEM格式，包含-----BEGIN PRIVATE KEY-----",
                "验证", privateKey
            );
        }
        
        if (publicKey != null && !publicKey.contains("-----BEGIN PUBLIC KEY-----")) {
            throw CryptoException.invalidKeyFormat(
                "RSA公钥格式不正确，应为PEM格式，包含-----BEGIN PUBLIC KEY-----",
                "验证", publicKey
            );
        }
    }

    /**
     * 获取指定算法要求的密钥长度
     *
     * @param cryptoType 加密算法类型
     * @return 要求的密钥长度数组（字节）
     */
    public static int[] getRequiredKeyLengths(CryptoType cryptoType) {
        switch (cryptoType) {
            case AES:
                return AES_KEY_LENGTHS;
            case DES:
                return new int[]{DES_KEY_LENGTH};
            default:
                return AES_KEY_LENGTHS; // 默认使用AES长度
        }
    }

    /**
     * 检查密钥长度是否有效
     *
     * @param key 密钥
     * @param cryptoType 加密算法类型
     * @return 如果密钥长度有效返回true，否则返回false
     */
    public static boolean isValidKeyLength(String key, CryptoType cryptoType) {
        if (key == null) {
            return false;
        }
        
        int keyLength = key.getBytes().length;
        
        switch (cryptoType) {
            case AES:
                for (int validLength : AES_KEY_LENGTHS) {
                    if (keyLength == validLength) {
                        return true;
                    }
                }
                return false;
            case DES:
                return keyLength == DES_KEY_LENGTH;
            default:
                // 默认使用AES验证
                for (int validLength : AES_KEY_LENGTHS) {
                    if (keyLength == validLength) {
                        return true;
                    }
                }
                return false;
        }
    }

    // ==================== IV验证方法 ====================

    /**
     * 验证IV长度是否符合算法要求
     *
     * @param iv 初始化向量
     * @param cryptoType 加密算法类型
     * @throws CryptoException 如果IV长度不符合要求
     */
    public static void validateIvLength(String iv, CryptoType cryptoType) {
        // RSA不需要IV
        if (cryptoType == CryptoType.RSA) {
            return;
        }
        
        if (iv == null) {
            throw CryptoException.generalError("初始化向量不能为null", null, "验证", null);
        }

        int requiredLength = getRequiredIvLength(cryptoType);
        int actualLength = iv.getBytes().length;

        if (actualLength != requiredLength) {
            throw CryptoException.generalError(
                String.format("%s算法要求IV长度为%d字节，但提供的IV长度为%d字节", 
                    cryptoType.name(), requiredLength, actualLength),
                null, "验证", iv
            );
        }
    }

    /**
     * 获取指定算法要求的IV长度
     *
     * @param cryptoType 加密算法类型
     * @return 要求的IV长度（字节）
     */
    public static int getRequiredIvLength(CryptoType cryptoType) {
        switch (cryptoType) {
            case AES:
                return AES_IV_LENGTH;
            case DES:
                return DES_IV_LENGTH;
            case RSA:
                return 0; // RSA不需要IV
            default:
                return AES_IV_LENGTH; // 默认使用AES长度
        }
    }

    /**
     * 检查IV是否有效
     *
     * @param iv 初始化向量
     * @param cryptoType 加密算法类型
     * @return 如果IV有效返回true，否则返回false
     */
    public static boolean isValidIv(String iv, CryptoType cryptoType) {
        if (iv == null) {
            return false;
        }

        int requiredLength = getRequiredIvLength(cryptoType);
        int actualLength = iv.getBytes().length;

        return actualLength == requiredLength;
    }

    // ==================== 调整方法（保持向后兼容） ====================

    /**
     * 调整密钥长度以适应算法要求
     *
     * @param key 原始密钥
     * @param cryptoType 加密算法类型
     * @return 调整后的密钥
     */
    public static String adjustKeyLength(String key, CryptoType cryptoType) {
        if (key == null) {
            return generateDefaultKey(cryptoType);
        }

        switch (cryptoType) {
            case AES:
                return adjustAesKeyLength(key);
            case DES:
                return adjustDesKeyLength(key);
            default:
                return adjustAesKeyLength(key); // 默认使用AES
        }
    }

    /**
     * 调整IV长度以适应算法要求
     *
     * @param iv 原始IV
     * @param cryptoType 加密算法类型
     * @return 调整后的IV
     */
    public static String adjustIvLength(String iv, CryptoType cryptoType) {
        if (iv == null) {
            return generateDefaultIv(cryptoType);
        }

        int requiredLength = getRequiredIvLength(cryptoType);
        byte[] ivBytes = iv.getBytes();

        if (ivBytes.length == requiredLength) {
            return iv;
        } else if (ivBytes.length > requiredLength) {
            // 截断到指定长度
            return new String(ivBytes, 0, requiredLength);
        } else {
            // 填充到指定长度
            byte[] adjustedBytes = new byte[requiredLength];
            System.arraycopy(ivBytes, 0, adjustedBytes, 0, ivBytes.length);
            // 用0填充剩余部分
            for (int i = ivBytes.length; i < requiredLength; i++) {
                adjustedBytes[i] = 0;
            }
            return new String(adjustedBytes);
        }
    }

    // ==================== 私有调整方法 ====================

    /**
     * 调整AES密钥长度
     *
     * @param key 原始密钥
     * @return 调整后的AES密钥
     */
    private static String adjustAesKeyLength(String key) {
        byte[] keyBytes = key.getBytes();
        
        // 如果长度已经是有效的AES密钥长度，直接返回
        for (int validLength : AES_KEY_LENGTHS) {
            if (keyBytes.length == validLength) {
                return key;
            }
        }
        
        // 如果长度大于32字节，截断到32字节
        if (keyBytes.length > 32) {
            return new String(keyBytes, 0, 32);
        }
        
        // 如果长度小于16字节，填充到16字节
        if (keyBytes.length < 16) {
            byte[] adjustedBytes = new byte[16];
            System.arraycopy(keyBytes, 0, adjustedBytes, 0, keyBytes.length);
            // 用0填充剩余部分
            for (int i = keyBytes.length; i < 16; i++) {
                adjustedBytes[i] = 0;
            }
            return new String(adjustedBytes);
        }
        
        // 如果长度在16-24之间，填充到24字节
        if (keyBytes.length < 24) {
            byte[] adjustedBytes = new byte[24];
            System.arraycopy(keyBytes, 0, adjustedBytes, 0, keyBytes.length);
            // 用0填充剩余部分
            for (int i = keyBytes.length; i < 24; i++) {
                adjustedBytes[i] = 0;
            }
            return new String(adjustedBytes);
        }
        
        // 如果长度在24-32之间，填充到32字节
        byte[] adjustedBytes = new byte[32];
        System.arraycopy(keyBytes, 0, adjustedBytes, 0, keyBytes.length);
        // 用0填充剩余部分
        for (int i = keyBytes.length; i < 32; i++) {
            adjustedBytes[i] = 0;
        }
        return new String(adjustedBytes);
    }

    /**
     * 调整DES密钥长度
     *
     * @param key 原始密钥
     * @return 调整后的DES密钥
     */
    private static String adjustDesKeyLength(String key) {
        byte[] keyBytes = key.getBytes();
        
        if (keyBytes.length == DES_KEY_LENGTH) {
            return key;
        } else if (keyBytes.length > DES_KEY_LENGTH) {
            // 截断到8字节
            return new String(keyBytes, 0, DES_KEY_LENGTH);
        } else {
            // 填充到8字节
            byte[] adjustedBytes = new byte[DES_KEY_LENGTH];
            System.arraycopy(keyBytes, 0, adjustedBytes, 0, keyBytes.length);
            // 用0填充剩余部分
            for (int i = keyBytes.length; i < DES_KEY_LENGTH; i++) {
                adjustedBytes[i] = 0;
            }
            return new String(adjustedBytes);
        }
    }

    // ==================== 生成默认值方法 ====================

    /**
     * 生成默认密钥
     *
     * @param cryptoType 加密算法类型
     * @return 默认密钥
     */
    public static String generateDefaultKey(CryptoType cryptoType) {
        switch (cryptoType) {
            case AES:
                return "1234567890123456"; // 16字节 = 128位
            case DES:
                return "12345678"; // 8字节 = 64位
            default:
                return "1234567890123456"; // 默认使用AES密钥
        }
    }

    /**
     * 生成默认的IV
     *
     * @param cryptoType 加密算法类型
     * @return 默认IV
     */
    public static String generateDefaultIv(CryptoType cryptoType) {
        int length = getRequiredIvLength(cryptoType);
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append("0");
        }
        return sb.toString();
    }
} 