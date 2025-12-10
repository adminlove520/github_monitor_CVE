# github-monitor

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

### GitHub Actions 部署

1. Fork 本仓库
2. 添加 Secrets：
   - `GITHUB_TOKEN`: GitHub API Token
   - `DINGDING_WEBHOOK`: 钉钉机器人 Webhook
   - `DINGDING_SECRETKEY`: 钉钉机器人密钥
   - `BAIDU_APP_ID`: 百度翻译 APP ID
   - `BAIDU_SECRET_KEY`: 百度翻译密钥
3. 启用 GitHub Actions

## 日报功能

- 每日自动生成监控日报
- 包含CVE、关键词、工具更新等信息
- 格式优化，便于构建知识库
- 存储在 `archive` 目录下

## 许可证

MIT License

# CreateBy 东方隐侠·Anonymous

