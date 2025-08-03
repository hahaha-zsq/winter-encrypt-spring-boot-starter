package com.zsq.winter.encrypt.enums;

import lombok.Getter;

/**
 * 集合加密解密策略类型枚举
 */
@Getter
public enum CollectionStrategyType {
    LIST(1, "List集合"),
    SET(2, "Set集合"),
    MAP(3, "Map集合"),
    ARRAY(4, "数组");

    private final int code;
    private final String desc;

    CollectionStrategyType(int code, String desc) {
        this.code = code;
        this.desc = desc;
    }

    public static CollectionStrategyType getByCode(int code) {
        for (CollectionStrategyType type : values()) {
            if (type.code == code) {
                return type;
            }
        }
        return null;
    }
} 