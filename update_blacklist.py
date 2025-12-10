#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""
通过GitHub Issue更新黑名单用户的脚本
"""

import yaml
import os
import re

def load_config():
    """加载配置文件"""
    with open('config.yaml', 'r', encoding='utf-8') as f:
        return yaml.load(f, Loader=yaml.FullLoader)

def save_config(config):
    """保存配置文件"""
    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)

def extract_blacklist_users(body):
    """从issue内容中提取黑名单用户"""
    users = []
    # 匹配用户名列表，支持多种格式
    lines = body.split('\n')
    for line in lines:
        # 移除注释和空白行
        line = line.split('#')[0].strip()
        if not line:
            continue
        
        # 匹配逗号分隔的用户名
        if ',' in line:
            users.extend([user.strip() for user in line.split(',') if user.strip()])
        else:
            # 匹配单个用户名
            users.append(line.strip())
    
    # 去重并过滤空字符串
    return list(set([user for user in users if user]))

def update_blacklist():
    """更新黑名单用户"""
    # 获取issue内容
    issue_body = os.environ.get('ISSUE_BODY', '')
    if not issue_body:
        print("No issue body found")
        return
    
    # 提取黑名单用户
    new_users = extract_blacklist_users(issue_body)
    if not new_users:
        print("No new users found in issue body")
        return
    
    # 加载现有配置
    config = load_config()
    all_config = config.get('all_config', {})
    black_user = all_config.get('black_user', [])
    
    # 添加新用户，去重
    original_count = len(black_user)
    for user in new_users:
        if user not in black_user:
            black_user.append(user)
    
    # 保存更新后的配置
    all_config['black_user'] = black_user
    config['all_config'] = all_config
    save_config(config)
    
    print(f"Added {len(black_user) - original_count} new users to blacklist")
    print(f"Total blacklist users: {len(black_user)}")
    print(f"New users: {', '.join(new_users)}")

if __name__ == "__main__":
    update_blacklist()
