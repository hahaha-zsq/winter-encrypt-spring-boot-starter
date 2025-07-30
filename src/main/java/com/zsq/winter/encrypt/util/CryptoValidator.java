package com.zsq.winter.encrypt.util;

import cn.hutool.crypto.asymmetric.RSA;
import com.zsq.winter.encrypt.enums.CryptoType;
import com.zsq.winter.encrypt.exception.CryptoException;

/**
 * 加密算法参数验证器
 *
 * <p>用于验证不同加密算法的密钥和初始化向量长度是否符合要求。</p>
 * 
 * <p>支持的算法及要求：</p>
 * <ul>
 *   <li><strong>AES</strong>：密钥长度128位(16字节)、192位(24字节)、256位(32字节)，IV长度128位(16字节)</li>
 *   <li><strong>DES</strong>：密钥长度64位(8字节)，IV长度64位(8字节)</li>
 *   <li><strong>RSA</strong>：仅支持Base64格式密钥，不检查密钥长度，不需要IV</li>
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
     * AES算法要求的IV长度（字节）
     */
    public static final int AES_IV_LENGTH = 16;
    
    /**
     * DES算法要求的密钥长度（字节）
     */
    public static final int DES_KEY_LENGTH = 8;
    
    /**
     * DES算法要求的IV长度（字节）
     */
    public static final int DES_IV_LENGTH = 8;

    // ==================== 公共验证方法 ====================

    /**
     * 验证AES密钥长度
     *
     * @param key AES密钥字节数组
     * @throws CryptoException 如果密钥长度不符合要求
     */
    public static void validateAesKeyLength(byte[] key) {
        if (key == null) {
            throw CryptoException.generalError("AES密钥不能为null", null, "验证", null);
        }

        boolean isValidLength = false;
        for (int validLength : AES_KEY_LENGTHS) {
            if (key.length == validLength) {
                isValidLength = true;
                break;
            }
        }

        if (!isValidLength) {
            throw CryptoException.generalError(
                    String.format("AES密钥长度必须为16、24或32字节，当前长度为%d字节", key.length),
                    null, "验证", key
            );
        }
    }

    /**
     * 验证AES初始化向量长度
     *
     * @param iv AES初始化向量字节数组
     * @throws CryptoException 如果IV长度不符合要求
     */
    public static void validateAesIvLength(byte[] iv) {
        if (iv == null) {
            throw CryptoException.generalError("AES初始化向量不能为null", null, "验证", null);
        }

        if (iv.length != AES_IV_LENGTH) {
            throw CryptoException.generalError(
                    String.format("AES初始化向量长度必须为16字节，当前长度为%d字节", iv.length),
                    null, "验证", iv
            );
        }
    }

    /**
     * 验证DES密钥长度
     *
     * @param key DES密钥字节数组
     * @throws CryptoException 如果密钥长度不符合要求
     */
    public static void validateDesKeyLength(byte[] key) {
        if (key == null) {
            throw CryptoException.generalError("DES密钥不能为null", null, "验证", null);
        }

        if (key.length != DES_KEY_LENGTH) {
            throw CryptoException.generalError(
                    String.format("DES密钥长度必须为8字节，当前长度为%d字节", key.length),
                    null, "验证", key
            );
        }
    }

    /**
     * 验证DES初始化向量长度
     *
     * @param iv DES初始化向量字节数组
     * @throws CryptoException 如果IV长度不符合要求
     */
    public static void validateDesIvLength(byte[] iv) {
        if (iv == null) {
            throw CryptoException.generalError("DES初始化向量不能为null", null, "验证", null);
        }

        if (iv.length != DES_IV_LENGTH) {
            throw CryptoException.generalError(
                    String.format("DES初始化向量长度必须为8字节，当前长度为%d字节", iv.length),
                    null, "验证", iv
            );
        }
    }

    /**
     * 验证RSA密钥格式
     * 
     * <p>仅支持Base64格式的RSA密钥</p>
     *
     * @param privateKey RSA私钥（Base64格式）
     * @param publicKey RSA公钥（Base64格式）
     * @throws CryptoException 如果密钥格式不正确
     */
    public static void validateRsaKeyFormat(String privateKey, String publicKey) {
        // 验证私钥
        if (privateKey != null) {
            validateSingleRsaKey(privateKey, true);
        }
        
        // 验证公钥
        if (publicKey != null) {
            validateSingleRsaKey(publicKey, false);
        }
    }

    /**
     * 验证单个RSA密钥格式
     * 
     * @param key RSA密钥字符串（Base64格式）
     * @param isPrivateKey 是否为私钥
     * @throws CryptoException 如果密钥格式不正确
     */
    private static void validateSingleRsaKey(String key, boolean isPrivateKey) {
        String keyType = isPrivateKey ? "私钥" : "公钥";
        
        // 基本检查
        if (key.trim().isEmpty()) {
            throw CryptoException.invalidKeyFormat(
                "RSA" + keyType + "不能为空",
                "验证", key
            );
        }
        
        // 检查密钥格式：仅支持Base64格式
        if (!isBase64Format(key)) {
            throw CryptoException.invalidKeyFormat(
                "RSA" + keyType + "格式不正确。仅支持Base64格式（纯Base64编码字符串）",
                "验证", key
            );
        }
    }
    
    /**
     * 检查是否为Base64格式
     */
    private static boolean isBase64Format(String key) {
        // 移除可能的空白字符
        String cleanKey = key.replaceAll("\\s", "");
        
        // Base64字符集检查
        return cleanKey.matches("^[A-Za-z0-9+/]*={0,2}$") && cleanKey.length() > 0;
    }
    
    /**
     * 清理密钥字符串用于验证
     */
    private static String cleanKeyForValidation(String key) {
        return key.replaceAll("\\s", "");  // 移除所有空白字符
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

        // RSA密钥格式验证单独处理
        if (cryptoType == CryptoType.RSA) {
            // RSA密钥验证使用专门的方法
            return;
        }

        int keyLength = key.getBytes().length;
        
        switch (cryptoType) {
            case AES:
                boolean isValidAes = false;
                for (int validLength : AES_KEY_LENGTHS) {
                    if (keyLength == validLength) {
                        isValidAes = true;
                        break;
                    }
                }
                if (!isValidAes) {
                    throw CryptoException.generalError(
                        String.format("AES密钥长度必须为16、24或32字节，当前长度为%d字节", keyLength),
                        null, "验证", key
                    );
                }
                break;
            case DES:
                if (keyLength != DES_KEY_LENGTH) {
                    throw CryptoException.generalError(
                        String.format("DES密钥长度必须为8字节，当前长度为%d字节", keyLength),
                        null, "验证", key
                    );
                }
                break;
            default:
                // 默认使用AES验证
                boolean isValidDefault = false;
                for (int validLength : AES_KEY_LENGTHS) {
                    if (keyLength == validLength) {
                        isValidDefault = true;
                        break;
                    }
                }
                if (!isValidDefault) {
                    throw CryptoException.generalError(
                        String.format("密钥长度必须为16、24或32字节，当前长度为%d字节", keyLength),
                        null, "验证", key
                    );
                }
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