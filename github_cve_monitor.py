#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : anonymous520

# 每3分钟检测一次github
# 配置优先级: 环境变量 > 配置文件
import json
from collections import OrderedDict
import requests, time, re, os
import dingtalkchatbot.chatbot as cb
import datetime
import hashlib
import yaml
from lxml import etree
import sqlite3

# 配置requests会话，自动使用系统代理
http_session = requests.Session()
http_session.trust_env = True  # 自动使用系统代理
http_session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'application/vnd.github.v3+json'
})

# 全局配置变量
GLOBAL_CONFIG = {
    'github_token': '',
    'translate': False,
    'push_channel': {
        'type': '',
        'webhook': '',
        'secretKey': '',
        'token': '',
        'group_id': ''
    }
}

# 初始化全局配置
def init_config():
    global GLOBAL_CONFIG
    
    # 读取配置文件
    config = {}
    try:
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
            config = config.get('all_config', {})
    except Exception as e:
        print(f"[警告] 读取配置文件失败: {e}")
    
    # 优先使用环境变量，其次使用配置文件
    # GitHub Token 配置
    GLOBAL_CONFIG['github_token'] = os.environ.get('GITHUB_TOKEN', 
                                                config.get('github_token', ''))
    
    # 翻译配置
    translate_enable = os.environ.get('TRANSLATE_ENABLE', '')
    if translate_enable:
        GLOBAL_CONFIG['translate'] = translate_enable == '1'
    else:
        try:
            GLOBAL_CONFIG['translate'] = bool(int(config.get('translate', [{'enable': 0}])[0]['enable']))
        except:
            GLOBAL_CONFIG['translate'] = False
    
    # 推送渠道配置
    # 检测哪个推送渠道被启用
    push_channel = ''
    channel_config = {}
    
    # 优先检测环境变量中的推送渠道
    if os.environ.get('DINGDING_WEBHOOK'):
        push_channel = 'dingding'
    elif os.environ.get('FEISHU_WEBHOOK'):
        push_channel = 'feishu'
    elif os.environ.get('TG_BOT_TOKEN'):
        push_channel = 'tgbot'
    else:
        # 从配置文件检测
        for channel in ['dingding', 'feishu', 'tgbot']:
            channel_config = config.get(channel, [])
            if len(channel_config) > 0:
                try:
                    if int(channel_config[0]['enable']) == 1:
                        push_channel = channel
                        break
                except:
                    continue
    
    GLOBAL_CONFIG['push_channel']['type'] = push_channel
    
    # 根据推送渠道类型加载配置
    if push_channel == 'dingding':
        GLOBAL_CONFIG['push_channel']['webhook'] = os.environ.get('DINGDING_WEBHOOK', 
                                                             channel_config[1]['webhook'] if len(channel_config) > 1 else '')
        GLOBAL_CONFIG['push_channel']['secretKey'] = os.environ.get('DINGDING_SECRETKEY', 
                                                               channel_config[2]['secretKey'] if len(channel_config) > 2 else '')
    elif push_channel == 'feishu':
        GLOBAL_CONFIG['push_channel']['webhook'] = os.environ.get('FEISHU_WEBHOOK', 
                                                            channel_config[1]['webhook'] if len(channel_config) > 1 else '')
    elif push_channel == 'tgbot':
        GLOBAL_CONFIG['push_channel']['token'] = os.environ.get('TG_BOT_TOKEN', 
                                                           channel_config[1]['token'] if len(channel_config) > 1 else '')
        GLOBAL_CONFIG['push_channel']['group_id'] = os.environ.get('TG_GROUP_ID', 
                                                              channel_config[2]['group_id'] if len(channel_config) > 2 else '')

# 读取配置文件 - 兼容旧代码
def load_config():
    init_config()
    
    channel = GLOBAL_CONFIG['push_channel']
    channel_type = channel['type']
    
    if channel_type == 'dingding':
        return 'dingding', GLOBAL_CONFIG['github_token'], channel['webhook'], channel['secretKey'], GLOBAL_CONFIG['translate']
    elif channel_type == 'feishu':
        return 'feishu', GLOBAL_CONFIG['github_token'], channel['webhook'], channel['webhook'], GLOBAL_CONFIG['translate']
    elif channel_type == 'tgbot':
        return 'tgbot', GLOBAL_CONFIG['github_token'], channel['token'], channel['group_id'], GLOBAL_CONFIG['translate']
    else:
        print("[-] 配置文件有误, 未找到启用的推送渠道")
        return '', '', '', '', False

# 全局github_headers，使用GLOBAL_CONFIG
github_headers = {
    'Authorization': "token {}" .format(GLOBAL_CONFIG['github_token'])
}

# 初始化配置
init_config()
# 更新github_headers
github_headers['Authorization'] = "token {}" .format(GLOBAL_CONFIG['github_token'])

# 黑名单用户缓存
BLACK_USER_CACHE = []

# 加载黑名单用户
def load_black_user():
    global BLACK_USER_CACHE
    BLACK_USER_CACHE = []
    try:
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
            BLACK_USER_CACHE = config.get('all_config', {}).get('black_user', [])
        print(f"[+] 成功加载 {len(BLACK_USER_CACHE)} 个黑名单用户")
    except Exception as e:
        print(f"[警告] 加载黑名单用户失败: {e}")
        BLACK_USER_CACHE = []

# 获取黑名单用户
def black_user():
    global BLACK_USER_CACHE
    if not BLACK_USER_CACHE:
        load_black_user()
    return BLACK_USER_CACHE

# 初始化创建数据库
def create_database():
    try:
        conn = sqlite3.connect('data.db')
        cur = conn.cursor()
        
        # 创建CVE监控表
        cur.execute('''CREATE TABLE IF NOT EXISTS cve_monitor
                   (cve_name varchar(255),
                    pushed_at varchar(255),
                    cve_url varchar(255));''')
        print("[+] 成功创建CVE监控表")
        
        # 创建关键字监控表
        cur.execute('''CREATE TABLE IF NOT EXISTS keyword_monitor
                   (keyword_name varchar(255),
                    pushed_at varchar(255),
                    keyword_url varchar(255));''')
        print("[+] 成功创建关键字监控表")
        
        # 创建红队工具监控表
        cur.execute('''CREATE TABLE IF NOT EXISTS redteam_tools_monitor
                   (tools_name varchar(255),
                    pushed_at varchar(255),
                    tag_name varchar(255));''')
        print("[+] 成功创建红队工具监控表")
        
        # 创建大佬仓库监控表
        cur.execute('''CREATE TABLE IF NOT EXISTS user_monitor
                   (repo_name varchar(255));''')
        print("[+] 成功创建大佬仓库监控表")
        
        conn.commit()
        conn.close()
        
        # 发送连接成功消息
        app_name, _, webhook, secretKey, _ = load_config()
        if app_name == "dingding":
            dingding("spaceX", "连接成功~", webhook, secretKey)
        elif app_name == "tgbot":
            tgbot("spaceX", "连接成功~", webhook, secretKey)
            
    except Exception as e:
        print(f"[-] 创建监控表失败！报错：{e}")
        if 'conn' in locals():
            conn.close()
#根据排序获取本年前20条CVE
def getNews():
    today_cve_info_tmp = []
    try:
        # 抓取本年的
        year = datetime.datetime.now().year
        api = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated" .format(year)
        json_str = http_session.get(api, headers=github_headers, timeout=10).json()
        today_date = datetime.date.today()
        n = len(json_str.get('items', []))
        if n > 20:
            n = 20
        for i in range(0, n):
            try:
                cve_url = json_str['items'][i]['html_url']
                if cve_url.split("/")[-2] not in black_user():
                    try:
                        cve_name_tmp = json_str['items'][i]['name'].upper()
                        cve_name = re.findall('(CVE\-\d+\-\d+)', cve_name_tmp)[0].upper()
                        pushed_at_tmp = json_str['items'][i]['created_at']
                        pushed_at = re.findall('\d{4}-\d{2}-\d{2}', pushed_at_tmp)[0]
                        if pushed_at == str(today_date):
                            today_cve_info_tmp.append({"cve_name": cve_name, "cve_url": cve_url, "pushed_at": pushed_at})
                        else:
                            print("[-] 该{}的更新时间为{}, 不属于今天的CVE" .format(cve_name, pushed_at))
                    except Exception as e:
                        pass
            except Exception as e:
                pass
        today_cve_info = OrderedDict()
        for item in today_cve_info_tmp:
            today_cve_info.setdefault(item['cve_name'], {**item, })
        today_cve_info = list(today_cve_info.values())

        return today_cve_info
        # return cve_total_count, cve_description, cve_url, cve_name
        #\d{4}-\d{2}-\d{2}

    except Exception as e:
        print(f"getNews 函数 error: {e}")
        return []

def getKeywordNews(keyword):
    today_keyword_info_tmp = []
    try:
        # 抓取本年的
        api = "https://api.github.com/search/repositories?q={}&sort=updated" .format(keyword)
        json_str = http_session.get(api, headers=github_headers, timeout=10).json()
        today_date = datetime.date.today()
        n = len(json_str['items'])
        if n > 20:
            n = 20
        for i in range(0, n):
            keyword_url = json_str['items'][i]['html_url']
            if keyword_url.split("/")[-2] not in black_user():
                try:
                    keyword_name = json_str['items'][i]['name']
                    # 获取仓库描述
                    description = json_str['items'][i].get('description', '作者未写描述')
                    pushed_at_tmp = json_str['items'][i]['created_at']
                    pushed_at = re.findall('\d{4}-\d{2}-\d{2}', pushed_at_tmp)[0]
                    if pushed_at == str(today_date):
                        today_keyword_info_tmp.append({"keyword_name": keyword_name, "keyword_url": keyword_url, "pushed_at": pushed_at, "description": description})
                        print("[+] keyword: {} ,{}" .format(keyword, keyword_name))
                    else:
                        print("[-] keyword: {} ,该{}的更新时间为{}, 不属于今天" .format(keyword, keyword_name, pushed_at))
                except Exception as e:
                    pass
            else:
                pass
        today_keyword_info = OrderedDict()
        for item in today_keyword_info_tmp:
            today_keyword_info.setdefault(item['keyword_name'], {**item, })
        today_keyword_info = list(today_keyword_info.values())

        return today_keyword_info

    except Exception as e:
        print(e, "github链接不通")
    return today_keyword_info_tmp

#获取到的关键字仓库信息插入到数据库
def keyword_insert_into_sqlite3(data):
    conn = sqlite3.connect('data.db')
    print("keyword_insert_into_sqlite3 函数 打开数据库成功！")
    print(data)
    cur = conn.cursor()
    for i in range(len(data)):
        try:
            keyword_name = data[i]['keyword_name']
            cur.execute("INSERT INTO keyword_monitor (keyword_name,pushed_at,keyword_url) VALUES ('{}', '{}','{}')".format(keyword_name, data[i]['pushed_at'], data[i]['keyword_url']))
            print("keyword_insert_into_sqlite3 函数: {}插入数据成功！".format(keyword_name))
        except Exception as e:
            print("keyword_insert_into_sqlite3 error {}".format(e))
            pass
    conn.commit()
    conn.close()
#查询数据库里是否存在该关键字仓库的方法
def query_keyword_info_database(keyword_name):
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT keyword_name FROM keyword_monitor WHERE keyword_name = '{}';".format(keyword_name)
    cursor = cur.execute(sql_grammar)
    return len(list(cursor))

#获取不存在数据库里的关键字信息
def get_today_keyword_info(today_keyword_info_data):
    today_all_keyword_info = []
    for i in range(len(today_keyword_info_data)):
        try:
            today_keyword_name = today_keyword_info_data[i]['keyword_name']
            today_cve_name = re.findall('(CVE\-\d+\-\d+)', today_keyword_info_data[i]['keyword_name'].upper())
            # 如果仓库名字带有 cve-xxx-xxx, 先查询看看 cve 监控中是否存在, 防止重复推送
            if len(today_cve_name) > 0 and query_cve_info_database(today_cve_name.upper()) == 1: 
                pass
            Verify = query_keyword_info_database(today_keyword_name)
            if Verify == 0:
                print("[+] 数据库里不存在{}".format(today_keyword_name))
                today_all_keyword_info.append(today_keyword_info_data[i])
            else:
                print("[-] 数据库里存在{}".format(today_keyword_name))
        except Exception as e:
            pass
    return today_all_keyword_info


#获取到的CVE信息插入到数据库
def cve_insert_into_sqlite3(data):
    conn = sqlite3.connect('data.db')
    print("cve_insert_into_sqlite3 函数 打开数据库成功！")
    cur = conn.cursor()
    for i in range(len(data)):
        try:
            cve_name = re.findall('(CVE\-\d+\-\d+)', data[i]['cve_name'])[0].upper()
            cur.execute("INSERT INTO cve_monitor (cve_name,pushed_at,cve_url) VALUES ('{}', '{}', '{}')".format(cve_name, data[i]['pushed_at'], data[i]['cve_url']))
            print("cve_insert_into_sqlite3 函数: {}插入数据成功！".format(cve_name))
        except Exception as e:
            pass
    conn.commit()
    conn.close()
#查询数据库里是否存在该CVE的方法
def query_cve_info_database(cve_name):
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT cve_name FROM cve_monitor WHERE cve_name = '{}';".format(cve_name)
    cursor = cur.execute(sql_grammar)
    return len(list(cursor))
#查询数据库里是否存在该tools工具名字的方法
def query_tools_info_database(tools_name):
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT tools_name FROM redteam_tools_monitor WHERE tools_name = '{}';".format(tools_name)
    cursor = cur.execute(sql_grammar)
    return len(list(cursor))
#获取不存在数据库里的CVE信息
def get_today_cve_info(today_cve_info_data):
    today_all_cve_info = []
    # today_cve_info_data = getNews()
    for i in range(len(today_cve_info_data)):
        try:
            today_cve_name = re.findall('(CVE\-\d+\-\d+)', today_cve_info_data[i]['cve_name'])[0].upper()
            if exist_cve(today_cve_name) == 1:
                Verify = query_cve_info_database(today_cve_name.upper())
                if Verify == 0:
                    print("[+] 数据库里不存在{}".format(today_cve_name.upper()))
                    today_all_cve_info.append(today_cve_info_data[i])
                else:
                    print("[-] 数据库里存在{}".format(today_cve_name.upper()))
        except Exception as e:
            pass
    return today_all_cve_info
#获取红队工具信息插入到数据库
def tools_insert_into_sqlite3(data):
    conn = sqlite3.connect('data.db')
    print("tools_insert_into_sqlite3 函数 打开数据库成功！")
    cur = conn.cursor()
    for i in range(len(data)):
        Verify = query_tools_info_database(data[i]['tools_name'])
        if Verify == 0:
            print("[+] 红队工具表数据库里不存在{}".format(data[i]['tools_name']))
            cur.execute("INSERT INTO redteam_tools_monitor (tools_name,pushed_at,tag_name) VALUES ('{}', '{}','{}')".format(data[i]['tools_name'], data[i]['pushed_at'], data[i]['tag_name']))
            print("tools_insert_into_sqlite3 函数: {}插入数据成功！".format(format(data[i]['tools_name'])))
        else:
            print("[-] 红队工具表数据库里存在{}".format(data[i]['tools_name']))
    conn.commit()
    conn.close()
# 工具列表缓存
TOOLS_LIST_CACHE = {
    'tools_list': [],
    'keyword_list': [],
    'user_list': [],
    'last_load_time': 0
}

# 读取本地红队工具链接文件转换成list
def load_tools_list():
    global TOOLS_LIST_CACHE
    current_time = time.time()
    
    # 缓存有效期300秒（5分钟）
    if current_time - TOOLS_LIST_CACHE['last_load_time'] < 300 and TOOLS_LIST_CACHE['tools_list']:
        return TOOLS_LIST_CACHE['tools_list'], TOOLS_LIST_CACHE['keyword_list'], TOOLS_LIST_CACHE['user_list']
    
    try:
        with open('tools_list.yaml', 'r',  encoding='utf-8') as f:
            list_data = yaml.load(f,Loader=yaml.FullLoader)
        
        tools_list = list_data.get('tools_list', [])
        keyword_list = list_data.get('keyword_list', [])
        user_list = list_data.get('user_list', [])
        
        # 从环境变量中读取keywords，如果存在则合并到keyword_list中
        env_keywords = os.environ.get('keywords', '')
        if env_keywords:
            env_keyword_list = [kw.strip() for kw in env_keywords.split(' ') if kw.strip()]
            # 合并关键字列表，去重
            keyword_list = list(set(keyword_list + env_keyword_list))
        
        # 更新缓存
        TOOLS_LIST_CACHE = {
            'tools_list': tools_list,
            'keyword_list': keyword_list,
            'user_list': user_list,
            'last_load_time': current_time
        }
        
        print(f"[+] 成功加载工具列表：{len(tools_list)}个工具，{len(keyword_list)}个关键字，{len(user_list)}个用户")
        return tools_list, keyword_list, user_list
        
    except Exception as e:
        print(f"[警告] 加载工具列表失败: {e}")
        # 返回缓存数据或空列表
        return TOOLS_LIST_CACHE['tools_list'], TOOLS_LIST_CACHE['keyword_list'], TOOLS_LIST_CACHE['user_list']
#获取红队工具的名称，更新时间，版本名称信息
def get_pushed_at_time(tools_list):
    tools_info_list = []
    for url in tools_list:
        try:
            tools_json = http_session.get(url, headers=github_headers, timeout=10).json()
            pushed_at_tmp = tools_json['pushed_at']
            pushed_at = re.findall('\d{4}-\d{2}-\d{2}', pushed_at_tmp)[0] #获取的是API上的时间
            tools_name = tools_json['name']
            api_url = tools_json['url']
            try:
                releases_json = http_session.get(url+"/releases", headers=github_headers, timeout=10).json()
                tag_name = releases_json[0]['tag_name']
            except Exception as e:
                tag_name = "no releases"
            tools_info_list.append({"tools_name":tools_name,"pushed_at":pushed_at,"api_url":api_url,"tag_name":tag_name})
        except Exception as e:
            print(f"get_pushed_at_time 处理 {url} 时出错: {e}")
            pass

    return tools_info_list
#根据红队名名称查询数据库红队工具的更新时间以及版本名称并返回
def tools_query_sqlite3(tools_name):
    result_list = []
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT pushed_at,tag_name FROM redteam_tools_monitor WHERE tools_name = '{}';".format(tools_name)
    cursor = cur.execute(sql_grammar)
    for result in cursor:
        result_list.append({"pushed_at":result[0],"tag_name":result[1]})
    conn.close()
    print("[###########]  tools_query_sqlite3 函数内 result_list 的值 为 - > {}".format(result_list))
    return result_list
#获取更新了的红队工具在数据库里面的时间和版本
def get_tools_update_list(data):
    tools_update_list = []
    for dist in data:
        print("dist 变量 ->{}".format(dist))
        query_result = tools_query_sqlite3(dist['tools_name'])
        if len(query_result) > 0:
            today_tools_pushed_at = query_result[0]['pushed_at']
            # print("[!!] 今日获取时间: ", dist['pushed_at'], "获取数据库时间: ", today_tools_pushed_at, dist['tools_name'])
            if dist['pushed_at'] != today_tools_pushed_at:
                print("今日获取时间: ",dist['pushed_at'],"获取数据库时间: ",today_tools_pushed_at,dist['tools_name'],"update!!!!")
                #返回数据库里面的时间和版本
                tools_update_list.append({"api_url":dist['api_url'],"pushed_at":today_tools_pushed_at,"tag_name":query_result[0]['tag_name']})
            else:
                print("今日获取时间: ",dist['pushed_at'],"获取数据库时间: ",today_tools_pushed_at,dist['tools_name'],"   no update")
    return tools_update_list


# 监控用户是否新增仓库，不是 fork 的
def getUserRepos(user):
    try:
        api = "https://api.github.com/users/{}/repos".format(user)
        json_str = http_session.get(api, headers=github_headers, timeout=10).json()
        today_date = datetime.date.today()

        for i in range(0, len(json_str)):
            created_at = re.findall('\d{4}-\d{2}-\d{2}', json_str[i]['created_at'])[0]
            if json_str[i]['fork'] == False and created_at == str(today_date):
                Verify = user_insert_into_sqlite3(json_str[i]['full_name'])
                print(json_str[i]['full_name'], Verify)
                if Verify == 0:
                    name = json_str[i]['name']
                    try:
                        description = json_str[i]['description']
                    except Exception as e:
                        description = "作者未写描述"
                    download_url = json_str[i]['html_url']
                    text = r'大佬' + r'** ' + user + r' ** ' + r'又分享了一款工具! '
                    body = "工具名称: " + name + " \r\n" + "工具地址: " + download_url + " \r\n" + "工具描述: " + "" + description
                    if load_config()[0] == "dingding":
                        dingding(text, body,load_config()[2],load_config()[3])
                    if load_config()[0] == "tgbot":
                        tgbot(text,body,load_config()[2],load_config()[3])
    except Exception as e:
        print(e, "github链接不通")

#获取用户或者组织信息插入到数据库
def user_insert_into_sqlite3(repo_name):
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT repo_name FROM user_monitor WHERE repo_name = '{}';".format(repo_name)
    Verify = len(list(cur.execute(sql_grammar)))
    if Verify == 0:
        print("[+] 用户仓库表数据库里不存在{}".format(repo_name))
        cur.execute("INSERT INTO user_monitor (repo_name) VALUES ('{}')".format(repo_name))
        print("user_insert_into_sqlite3 函数: {}插入数据成功！".format(repo_name))
    else:
        print("[-] 用户仓库表数据库里存在{}".format(repo_name))
    conn.commit()
    conn.close()
    return Verify

#获取更新信息并发送到对应社交软件
def send_body(url,query_pushed_at,query_tag_name):
    # 考虑到有的工具没有 releases, 则通过 commits 记录获取更新描述
    # 判断是否有 releases 记录
    json_str = http_session.get(url + '/releases', headers=github_headers, timeout=10).json()
    new_pushed_at = re.findall('\d{4}-\d{2}-\d{2}', http_session.get(url, headers=github_headers, timeout=10).json()['pushed_at'])[0]
    if len(json_str) != 0:
        tag_name = json_str[0]['tag_name']
        if query_pushed_at < new_pushed_at :
            print("[*] 数据库里的pushed_at -->", query_pushed_at, ";;;; api的pushed_at -->", new_pushed_at)
            if tag_name != query_tag_name:
                try:
                    update_log = json_str[0]['body']
                except Exception as e:
                    update_log = "作者未写更新内容"
                download_url = json_str[0]['html_url']
                tools_name = url.split('/')[-1]
                text = r'** ' + tools_name + r' ** 工具,版本更新啦!'
                body = "工具名称：" + tools_name + "\r\n" + "工具地址：" + download_url + "\r\n" + "工具更新日志：" + "\r\n" + update_log
                if load_config()[0] == "dingding":
                    dingding(text, body,load_config()[2],load_config()[3])
                if load_config()[0] == "tgbot":
                    tgbot(text,body,load_config()[2],load_config()[3])
                conn = sqlite3.connect('data.db')
                cur = conn.cursor()
                sql_grammar = "UPDATE redteam_tools_monitor SET tag_name = '{}' WHERE tools_name='{}'" .format(tag_name,tools_name)
                sql_grammar1 = "UPDATE redteam_tools_monitor SET pushed_at = '{}' WHERE tools_name='{}'" .format(new_pushed_at, tools_name)
                cur.execute(sql_grammar)
                cur.execute(sql_grammar1)
                conn.commit()
                conn.close()
                print("[+] tools_name -->", tools_name, "pushed_at 已更新，现在pushed_at 为 -->", new_pushed_at,"tag_name 已更新，现在tag_name为 -->",tag_name)
            elif tag_name == query_tag_name:
                commits_url = url + "/commits"
                commits_url_response_json = http_session.get(commits_url).text
                commits_json = json.loads(commits_url_response_json)
                tools_name = url.split('/')[-1]
                download_url = commits_json[0]['html_url']
                try:
                    update_log = commits_json[0]['commit']['message']
                except Exception as e:
                    update_log = "作者未写更新内容，具体点击更新详情地址的URL进行查看"
                text = r'** ' + tools_name + r' ** 工具小更新了一波!'
                body = "工具名称：" + tools_name + "\r\n" + "更新详情地址：" + download_url + "\r\n" + "commit更新日志：" + "\r\n" + update_log
                if load_config()[0] == "dingding":
                    dingding(text, body,load_config()[2],load_config()[3])
                if load_config()[0] == "feishu":
                    feishu(text,body,load_config()[2])
                if load_config()[0] == "tgbot":
                    tgbot(text,body,load_config()[2],load_config()[3])
                conn = sqlite3.connect('data.db')
                cur = conn.cursor()
                sql_grammar = "UPDATE redteam_tools_monitor SET pushed_at = '{}' WHERE tools_name='{}'" .format(new_pushed_at,tools_name)
                cur.execute(sql_grammar)
                conn.commit()
                conn.close()
                print("[+] tools_name -->",tools_name,"pushed_at 已更新，现在pushed_at 为 -->",new_pushed_at)

        # return update_log, download_url, tools_version
    else:
        if query_pushed_at != new_pushed_at:
            print("[*] 数据库里的pushed_at -->", query_pushed_at, ";;;; api的pushed_at -->", new_pushed_at)
            json_str = http_session.get(url + '/commits', headers=github_headers, timeout=10).json()
            update_log = json_str[0]['commit']['message']
            download_url = json_str[0]['html_url']
            tools_name = url.split('/')[-1]
            text = r'** ' + tools_name + r' ** 工具更新啦!'
            body = "工具名称：" + tools_name + "\r\n" + "工具地址：" + download_url + "\r\n" + "commit更新日志：" + "\r\n" + update_log
            if load_config()[0] == "dingding":
                dingding(text, body, load_config()[2], load_config()[3])
            if load_config()[0] == "feishu":
                feishu(text,body,load_config[2])
            if load_config()[0] == "tgbot":
                tgbot(text, body, load_config()[2], load_config()[3])
            conn = sqlite3.connect('data.db')
            cur = conn.cursor()
            sql_grammar = "UPDATE redteam_tools_monitor SET pushed_at = '{}' WHERE tools_name='{}'" .format(new_pushed_at,tools_name)
            cur.execute(sql_grammar)
            conn.commit()
            conn.close()
            print("[+] tools_name -->", tools_name, "pushed_at 已更新，现在pushed_at 为 -->", new_pushed_at)
            # return update_log, download_url
# 创建md5对象
def nmd5(str):
    m = hashlib.md5()
    b = str.encode(encoding='utf-8')
    m.update(b)
    str_md5 = m.hexdigest()
    return str_md5

# Google翻译
def google_translate(word):
    try:
        url = f"https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=zh-CN&dt=t&q={requests.utils.quote(word)}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
        }
        res = http_session.get(url=url, headers=headers, timeout=10)
        result_dict = res.json()
        result = ""
        for item in result_dict[0]:
            if item[0]:
                result += item[0]
        return result
    except Exception as e:
        print(f"Google翻译失败，使用有道翻译: {e}")
        return youdao_translate(word)

# 有道翻译
def youdao_translate(word):
    try:
        # 简化的有道翻译API调用，使用更稳定的接口
        url = f"https://fanyi.youdao.com/translate?&doctype=json&type=AUTO&i={requests.utils.quote(word)}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Referer': 'https://fanyi.youdao.com/',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        }
        res = http_session.get(url=url, headers=headers, timeout=10)
        result_dict = res.json()
        if 'translateResult' in result_dict:
            result = ""
            for json_str in result_dict['translateResult'][0]:
                tgt = json_str['tgt']
                result += tgt
            return result
        return word
    except Exception as e:
        print(f"有道翻译失败: {e}")
        return word

# 主翻译函数，默认使用Google翻译
def translate(word):
    return google_translate(word)

# 钉钉
def dingding(text, msg,webhook,secretKey):
    try:
        ding = cb.DingtalkChatbot(webhook, secret=secretKey)
        ding.send_text(msg='{}\r\n{}'.format(text, msg), is_at_all=False)
    except Exception as e:
        print(f"钉钉推送失败: {e}")
        pass
## 飞书
def feishu(text,msg,webhook):
    try:
        ding = cb.DingtalkChatbot(webhook)
        ding.send_text(msg='{}\r\n{}'.format(text, msg), is_at_all=False)
    except Exception as e:
        print(f"飞书推送失败: {e}")
        pass
# 添加Telegram Bot推送支持
def tgbot(text, msg,token,group_id):
    try:
        import telegram
        bot = telegram.Bot(token='{}'.format(token))# Your Telegram Bot Token
        bot.send_message(chat_id=group_id, text='{}\r\n{}'.format(text, msg))
    except Exception as e:
        print(f"Telegram推送失败: {e}")
        pass

#判断是否存在该CVE
def exist_cve(cve):
    try:
        query_cve_url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve
        response = http_session.get(query_cve_url, timeout=10)
        html = etree.HTML(response.text)
        des = html.xpath('//*[@id="GeneratedTable"]/table//tr[4]/td/text()')[0].strip()
        return 1
    except Exception as e:
        return 0

# 根据cve 名字，获取描述，并翻译
def get_cve_des_zh(cve):
    time.sleep(3)
    try:
        query_cve_url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve
        response = http_session.get(query_cve_url, timeout=10)
        html = etree.HTML(response.text)
        des = html.xpath('//*[@id="GeneratedTable"]/table//tr[4]/td/text()')[0].strip()
        cve_time = html.xpath('//*[@id="GeneratedTable"]/table//tr[11]/td[1]/b/text()')[0].strip()
        if load_config()[-1]:
            return translate(des)
        return des, cve_time
    except Exception as e:
        pass
#发送CVE信息到社交工具
def sendNews(data):
    try:
        text = '有新的CVE送达! \r\n** 请自行分辨是否为红队钓鱼!!! **'
        # 获取 cve 名字 ，根据cve 名字，获取描述，并翻译
        for i in range(len(data)):
            try:
                cve_name = re.findall('(CVE\-\d+\-\d+)', data[i]['cve_name'])[0].upper()
                cve_zh, cve_time = get_cve_des_zh(cve_name)
                body = "CVE编号: " + cve_name + "  --- " + cve_time + " \r\n" + "Github地址: " + str(data[i]['cve_url']) + "\r\n" + "CVE描述: " + "\r\n" + cve_zh
                if load_config()[0] == "dingding":
                    dingding(text, body, load_config()[2], load_config()[3])
                    print("钉钉 发送 CVE 成功")
                if load_config()[0] == "feishu":
                    feishu(text, body, load_config()[2])
                    print("飞书 发送 CVE 成功")
                if load_config()[0] == "tgbot":
                    tgbot(text, body, load_config()[2], load_config()[3])
                    print("tgbot 发送 CVE 成功")
            except IndexError:
                pass
    except Exception as e:
        print("sendNews 函数 error:{}" .format(e))
#发送信息到社交工具
def sendKeywordNews(keyword, data):
    try:
        text = '有新的关键字监控 - {} - 送达! \r\n** 请自行分辨是否为红队钓鱼!!! **' .format(keyword)
        # 获取 cve 名字 ，根据cve 名字，获取描述，并翻译
        for i in range(len(data)):
            try:
                item = data[i]
                keyword_name = item.get('keyword_name', '未知项目')
                keyword_url = item.get('keyword_url', '')
                description = item.get('description', '作者未写描述')
                translated_description = ""
                if load_config()[-1]:
                    translated_description = translate(description)
                
                body = "项目名称: " + str(keyword_name) + "\r\n"
                body += "Github地址: " + str(keyword_url) + "\r\n"
                body += "项目描述: " + str(description) + "\r\n"
                if translated_description and translated_description != description:
                    body += "项目描述-译文: " + str(translated_description) + "\r\n"
                
                if load_config()[0] == "dingding":
                    dingding(text, body, load_config()[2], load_config()[3])
                    print("钉钉 发送 CVE 成功")
                if load_config()[0] == "feishu":
                    feishu(text, body, load_config()[2])
                    print("飞书 发送 CVE 成功")
                if load_config()[0] == "tgbot":
                    tgbot(text, body, load_config()[2], load_config()[3])
                    print("tgbot 发送 CVE 成功")
            except Exception as e:
                print(f"处理关键字监控数据时出错: {e}")
                pass
    except Exception as e:
        print("sendKeywordNews 函数 error:{}" .format(e))

# 生成日报功能
def generate_daily_report(cve_data=None, keyword_data=None, tools_update_data=None):
    import os
    today = datetime.date.today().strftime('%Y-%m-%d')
    archive_dir = 'archive'
    report_path = os.path.join(archive_dir, f'Daily_{today}.md')
    
    # 创建archive目录如果不存在
    if not os.path.exists(archive_dir):
        os.makedirs(archive_dir)
    
    # 读取模板文件
    with open('temple.md', 'r', encoding='utf-8') as f:
        template = f.read()
    
    # 从数据库获取数据
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    
    # 获取当天的CVE信息
    cur.execute("SELECT cve_name, cve_url, pushed_at FROM cve_monitor WHERE pushed_at = ?", (today,))
    db_cve_data = cur.fetchall()
    
    # 获取当天的关键字监控信息
    cur.execute("SELECT keyword_name, keyword_url, pushed_at FROM keyword_monitor WHERE pushed_at = ?", (today,))
    db_keyword_data = cur.fetchall()
    
    # 获取当天的工具更新信息
    cur.execute("SELECT tools_name, pushed_at, tag_name FROM redteam_tools_monitor WHERE pushed_at = ?", (today,))
    db_tools_data = cur.fetchall()
    
    conn.close()
    
    # 合并数据，优先使用传入的数据，否则使用数据库数据
    final_cve_data = cve_data if cve_data else db_cve_data
    final_keyword_data = keyword_data if keyword_data else db_keyword_data
    final_tools_data = tools_update_data if tools_update_data else db_tools_data
    
    # 构建更新关键词
    keywords = []
    tools_list, keyword_list, user_list = load_tools_list()
    keywords.extend(keyword_list)
    if final_cve_data:
        keywords.append('CVE')
    if final_tools_data:
        keywords.append('红队工具')
    keywords = list(set(keywords))
    keywords_str = '、'.join(keywords) if keywords else '无'
    
    # 构建项目信息
    projects = []
    project_details = []
    
    # 添加CVE信息
    if final_cve_data:
        for item in final_cve_data:
            # 处理字典类型数据
            if isinstance(item, dict):
                cve_name = item.get('cve_name', '未知CVE')
                cve_url = item.get('cve_url', '')
                if cve_name and cve_url:
                    projects.append(f'- [{cve_name}]({cve_url})')
                    project_details.append(f"### {cve_name}\n- GitHub地址: {cve_url}\n- 类型: CVE\n")
            # 处理元组类型数据
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                cve_name, cve_url = item[0], item[1]
                projects.append(f'- [{cve_name}]({cve_url})')
                project_details.append(f"### {cve_name}\n- GitHub地址: {cve_url}\n- 类型: CVE\n")
    
    # 添加关键字监控信息
    if final_keyword_data:
        for item in final_keyword_data:
            # 处理字典类型数据
            if isinstance(item, dict):
                keyword_name = item.get('keyword_name', '未知项目')
                keyword_url = item.get('keyword_url', '')
                if keyword_name and keyword_url:
                    projects.append(f'- [{keyword_name}]({keyword_url})')
                    project_details.append(f"### {keyword_name}\n- GitHub地址: {keyword_url}\n- 类型: 关键字监控\n")
            # 处理元组类型数据
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                keyword_name, keyword_url = item[0], item[1]
                projects.append(f'- [{keyword_name}]({keyword_url})')
                project_details.append(f"### {keyword_name}\n- GitHub地址: {keyword_url}\n- 类型: 关键字监控\n")
    
    # 添加工具更新信息
    if final_tools_data:
        for item in final_tools_data:
            # 处理字典类型数据
            if isinstance(item, dict):
                tools_name = item.get('tools_name', '未知工具')
                if tools_name:
                    projects.append(f'- [{tools_name}](https://github.com/search?q={tools_name})')
                    project_details.append(f"### {tools_name}\n- 类型: 红队工具更新\n")
            # 处理元组类型数据
            elif isinstance(item, (list, tuple)) and len(item) >= 1:
                tools_name = item[0]
                projects.append(f'- [{tools_name}](https://github.com/search?q={tools_name})')
                project_details.append(f"### {tools_name}\n- 类型: 红队工具更新\n")
    
    projects_str = '\n'.join(projects) if projects else '无'
    project_details_str = '\n'.join(project_details) if project_details else '无更新内容'
    
    # 填充模板
    report_content = template.replace('当日情报_YYYY-MM-DD', f'当日情报_{today}')
    
    # 处理不同操作系统的换行符
    report_content = report_content.replace('## 【更新关键词】\r\n', f'## 【更新关键词】\r\n{keywords_str}\r\n')
    report_content = report_content.replace('## 【更新关键词】\n', f'## 【更新关键词】\n{keywords_str}\n')
    
    report_content = report_content.replace('## 【项目名称】\r\n', f'## 【项目名称】\r\n{projects_str}\r\n')
    report_content = report_content.replace('## 【项目名称】\n', f'## 【项目名称】\n{projects_str}\n')
    
    report_content = report_content.replace('## 【项目描述】\r\n', f'## 【项目描述】\r\n{project_details_str}\r\n')
    report_content = report_content.replace('## 【项目描述】\n', f'## 【项目描述】\n{project_details_str}\n')
    
    report_content = report_content.replace('## 【Github地址】\r\n- [仓库名称](仓库地址)', f'## 【Github地址】\r\n{projects_str}')
    report_content = report_content.replace('## 【Github地址】\n- [仓库名称](仓库地址)', f'## 【Github地址】\n{projects_str}')
    
    # 保存报告
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    print(f"日报已生成: {report_path}")
    return report_path

#main函数
if __name__ == '__main__':
    print("cve 、github 工具 和 大佬仓库 监控中 ...")
    #初始化部分
    create_database()

    while True:
        tools_list, keyword_list, user_list = load_tools_list()
        tools_data = get_pushed_at_time(tools_list)
        tools_insert_into_sqlite3(tools_data)   # 获取文件中的工具列表，并从 github 获取相关信息，存储下来

        print("\r\n\t\t  用户仓库监控 \t\t\r\n")
        for user in user_list:
            getUserRepos(user)
        #CVE部分
        print("\r\n\t\t  CVE 监控 \t\t\r\n")
        cve_data = getNews()
        today_cve_data = []
        if len(cve_data) > 0 :
            today_cve_data = get_today_cve_info(cve_data)
            sendNews(today_cve_data)
            cve_insert_into_sqlite3(today_cve_data)

        print("\r\n\t\t  关键字监控 \t\t\r\n")
        # 关键字监控 , 最好不要太多关键字，防止 github 次要速率限制  https://docs.github.com/en/rest/overview/resources-in-the-rest-api#secondary-rate-limits=
        all_today_keyword_data = []
        for keyword in keyword_list:
             time.sleep(3)  # 每个关键字停 1s ，防止关键字过多导致速率限制
             keyword_data = getKeywordNews(keyword)

             if len(keyword_data) > 0:
                today_keyword_data = get_today_keyword_info(keyword_data)
                if len(today_keyword_data) > 0:
                    sendKeywordNews(keyword, today_keyword_data)
                    keyword_insert_into_sqlite3(today_keyword_data)
                    all_today_keyword_data.extend(today_keyword_data)
        
        # 红队工具监控
        print("\r\n\t\t  红队工具监控 \t\t\r\n")
        tools_list_new, keyword_list, user_list = load_tools_list()
        data2 = get_pushed_at_time(tools_list_new)      # 再次从文件中获取工具列表，并从 github 获取相关信息,
        data3 = get_tools_update_list(data2)        # 与 3 分钟前数据进行对比，如果在三分钟内有新增工具清单或者工具有更新则通知一下用户
        for i in range(len(data3)):
            try:
                send_body(data3[i]['api_url'],data3[i]['pushed_at'],data3[i]['tag_name'])
            except Exception as e:
                print("main函数 try循环 遇到错误-->{}" .format(e))
        
        # 生成日报，传入运行结果数据
        generate_daily_report(today_cve_data, all_today_keyword_data, data3)

        print("\r\n\t\t  等待下一次监控... \t\t\r\n")
        time.sleep(5*60)
