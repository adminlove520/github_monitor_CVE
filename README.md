# github-monitor

> 实时监控 GitHub 上新增的 CVE、自定义关键词、安全工具更新、大佬仓库监控，并多渠道推送通知。

当前版本：**V1.1.0**
版本更新时间：2026-01-05


## 实时监控github上新增的cve、自定义关键词、安全工具更新、大佬仓库监控，并多渠道推送通知

每日定时检测github是否有新的cve漏洞提交、安全工具更新记录、关键词监控和大佬仓库更新，若有则通过配置的渠道通知用户

## 功能特性

- ✅ CVE漏洞监控
- ✅ 自定义关键词监控
- ✅ 安全工具更新监控
- ✅ 大佬仓库监控
- ✅ 多渠道推送（钉钉、飞书、Telegram）
- ✅ 日报生成功能
- ✅ 百度翻译集成（替代有道翻译）
- ✅ 翻译缓存机制
- ✅ 访问频率控制
- ✅ 黑名单配置
- ✅ GitHub Actions 支持

## 技术栈

- Python 3.x
- Requests
- SQLite3
- GitHub API
- 百度翻译 API

## 配置说明

### 配置文件（config.yaml）

- `github_token`: GitHub API Token
- `push_channel`: 推送渠道配置（钉钉、飞书、Telegram）
- `translate`: 翻译功能配置
- `black_user`: 黑名单用户配置

### 百度翻译配置

已集成百度翻译API，替换了原有的有道翻译
- APP ID: ${{ secrets.BAIDU_APP_ID }}
- 密钥: ${{ secrets.BAIDU_SECRET_KEY }}

## 注意事项

- 如非必须，请勿使用翻译功能
- 提交代码不可包含敏感信息，否则会导致 GitHub Token 失效
- 翻译功能已优化，添加了缓存和访问频率控制，避免API调用限制
- 支持代理配置，可根据网络环境调整
- 支持 GitHub Actions 部署，无需本地运行

## 部署方式

### 本地部署

```bash
# 安装依赖
pip install -r requirements.txt

# 运行脚本
python github_cve_monitor.py
```

### GitHub Actions 部署 (免费)

1. Fork 本仓库
2. 添加 Secrets：
   - `GITHUB_TOKEN`: GitHub API Token
   - `DINGDING_WEBHOOK`: 钉钉机器人 Webhook
   - `DINGDING_SECRETKEY`: 钉钉机器人密钥
   - `FEISHU_WEBHOOK`: 飞书机器人 Webhook
   - `TG_BOT_TOKEN`: Telegram Bot Token
   - `TG_GROUP_ID`: Telegram 群组 ID
   - `DISCARD_WEBHOOK`: Discard 推送 Webhook
   - `DISCARD_SWITCH`: Discard 推送开关
   - `DISCARD_SEND_DAILY_REPORT`: Discard 日报推送开关
   - `DISCARD_SEND_NORMAL_MSG`: Discard 普通消息推送开关
   - `BAIDU_APP_ID`: 百度翻译 APP ID
   - `BAIDU_SECRET_KEY`: 百度翻译密钥
3. 启用 GitHub Actions

### Docker / Zeabur 部署 (推荐)

代码推送到 `main` 分支会自动构建镜像到 GHCR。

1. **部署**：在 Zeabur 或 Docker 环境中使用镜像 `ghcr.io/${{ github.repository_owner }}/github_monitor:latest`。
2. **环境变量**：参考 GitHub Actions 部署中的 Secrets。
3. **数据持久化 (Zeabur)**：
   - 挂载路径: `/app/data.db`。挂载此文件以确保数据库在重启后不会丢失。

## 日报功能

- 每日自动生成监控日报
- 包含CVE、关键词、工具更新等信息
- 格式优化，便于构建知识库
- 存储在 `archive` 目录下

## 许可证

MIT License

## 更新日志

### v1.0.0 (2024-11-09)
- 仓库创建
- 实现基础功能：CVE漏洞监控、自定义关键词监控、安全工具更新监控、大佬仓库监控
- 支持多渠道推送（钉钉、飞书、Telegram）
- 集成GitHub Actions

### v1.1.0 (2025-12-26)
- 新增Discard推送支持
- 优化日报生成功能
- 实现按日期建立文件夹保存日报
- 日报列表显示统计信息（总更新数、CVE数、关键字监控数、红队工具更新数）
- 优化index.html界面设计
- 修复当日多次更新日报时重复条目的问题
- 完善GitHub Actions环境变量配置

### v1.2.0 (2025-12-26)
- 优化日报模板UI设计
- 实现渐变背景和动画效果
- 增强响应式设计
- 优化卡片布局和视觉层次

# CreateBy 东方隐侠·Anonymous

