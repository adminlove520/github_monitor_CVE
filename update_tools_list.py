#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动处理GitHub Issue中提交的tools_list条目
并更新到tools_list.yaml文件
"""

import os
import re
import yaml
import requests
from github import Github

# 获取GitHub Token，优先使用环境变量
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')

# 仓库信息
REPO_OWNER = os.environ.get('GITHUB_REPOSITORY_OWNER', '')
REPO_NAME = os.environ.get('GITHUB_REPOSITORY', '').split('/')[-1] or ''

# tools_list.yaml文件路径
TOOLS_LIST_PATH = 'tools_list.yaml'

# Issue标签
ISSUE_LABEL = 'add-tools'


def load_tools_list():
    """加载tools_list.yaml文件"""
    try:
        with open(TOOLS_LIST_PATH, 'r', encoding='utf-8') as f:
            return yaml.load(f, Loader=yaml.FullLoader)
    except Exception as e:
        print(f"[错误] 加载tools_list.yaml失败: {e}")
        return {
            'tools_list': [],
            'keyword_list': [],
            'user_list': []
        }


def save_tools_list(tools_data):
    """保存tools_list.yaml文件"""
    try:
        with open(TOOLS_LIST_PATH, 'w', encoding='utf-8') as f:
            yaml.dump(tools_data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        print(f"[成功] 已更新tools_list.yaml")
        return True
    except Exception as e:
        print(f"[错误] 保存tools_list.yaml失败: {e}")
        return False


def is_entry_exists(tools_data, entry_type, entry_value):
    """检查条目是否已存在"""
    # 支持中英文条目类型
    if entry_type in ['GitHub Repository (tools_list)', 'GitHub仓库 (tools_list)']:
        return entry_value in tools_data.get('tools_list', [])
    elif entry_type in ['Keyword (keyword_list)', '监控关键词 (keyword_list)']:
        return entry_value in tools_data.get('keyword_list', [])
    elif entry_type in ['GitHub User (user_list)', 'GitHub用户 (user_list)']:
        return entry_value in tools_data.get('user_list', [])
    return False


def add_entry(tools_data, entry_type, entry_value):
    """添加条目到tools_list.yaml"""
    # 支持中英文条目类型
    if entry_type in ['GitHub Repository (tools_list)', 'GitHub仓库 (tools_list)']:
        tools_data.setdefault('tools_list', []).append(entry_value)
        print(f"[成功] 添加GitHub仓库: {entry_value}")
    elif entry_type in ['Keyword (keyword_list)', '监控关键词 (keyword_list)']:
        tools_data.setdefault('keyword_list', []).append(entry_value)
        print(f"[成功] 添加监控关键词: {entry_value}")
    elif entry_type in ['GitHub User (user_list)', 'GitHub用户 (user_list)']:
        tools_data.setdefault('user_list', []).append(entry_value)
        print(f"[成功] 添加GitHub用户: {entry_value}")
    return tools_data


def process_issues():
    """处理GitHub Issue"""
    if not GITHUB_TOKEN:
        print("[错误] 未设置GITHUB_TOKEN环境变量")
        return False

    if not REPO_OWNER or not REPO_NAME:
        print("[错误] 未设置GITHUB_REPOSITORY环境变量")
        return False

    try:
        # 初始化GitHub API客户端
        g = Github(GITHUB_TOKEN)
        repo = g.get_repo(f"{REPO_OWNER}/{REPO_NAME}")
        
        # 获取带有add-tools标签的open issue
        issues = repo.get_issues(state='open', labels=[ISSUE_LABEL])
        
        for issue in issues:
            print(f"[处理] Issue #{issue.number}: {issue.title}")
            
            # 获取issue的表单数据
            entry_type = None
            entry_value = None
            
            # 解析issue正文，提取表单数据
            body = issue.body
            
            # 解析条目类型
            type_match = re.search(r'条目类型\s*[:：]\s*([^\n]+)', body)
            if type_match:
                entry_type = type_match.group(1).strip()
            
            # 解析条目值
            value_match = re.search(r'条目值\s*[:：]\s*([^\n]+)', body)
            if value_match:
                entry_value = value_match.group(1).strip()
            
            if not entry_type or not entry_value:
                print(f"[错误] 无法解析Issue #{issue.number}的表单数据")
                continue
            
            # 加载当前的tools_list.yaml
            tools_data = load_tools_list()
            
            # 检查条目是否已存在
            if is_entry_exists(tools_data, entry_type, entry_value):
                print(f"[警告] 条目已存在: {entry_value}")
                issue.create_comment(f"条目 '{entry_value}' 已存在于tools_list.yaml中，无需重复添加。")
            else:
                # 添加条目
                tools_data = add_entry(tools_data, entry_type, entry_value)
                if save_tools_list(tools_data):
                    issue.create_comment(f"成功添加条目 '{entry_value}' 到tools_list.yaml中。")
                else:
                    issue.create_comment(f"添加条目 '{entry_value}' 失败，请检查日志。")
                    continue
            
            # 关闭issue
            issue.edit(state='closed')
            print(f"[成功] 已处理并关闭Issue #{issue.number}")
            
        return True
    except Exception as e:
        print(f"[错误] 处理Issue失败: {e}")
        return False


if __name__ == '__main__':
    print("开始处理GitHub Issue中的tools_list条目...")
    process_issues()
    print("处理完成!")
