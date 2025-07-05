#!/bin/bash

# 读取用户输入的版本号
read -p "请输入发布的版本号（如0.0.2）: " VERSION

if [ -z "$VERSION" ]; then
    echo "版本号不能为空，发布终止。"
    exit 1
fi

# 更新版本号
echo "更新pom.xml中的版本号为$VERSION..."
sed -i '' "s/<version>.*<\/version>/<version>$VERSION<\/version>/" pom.xml

# 提交更改
echo "提交更改..."
git add pom.xml
git commit -m "发布版本 $VERSION"

# 推送到远程仓库
echo "推送到远程仓库..."
git push origin main

# 创建标签
echo "创建标签v$VERSION..."
git tag v$VERSION

# 推送标签
echo "推送标签..."
git push origin v$VERSION

echo "发布流程已启动，请查看GitHub Actions运行状态。"
echo "GitHub Actions将自动构建并发布到Maven中央仓库。" 