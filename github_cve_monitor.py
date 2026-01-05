#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : anonymous520
__version__ = "V1.1.1"

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
import pytz
import logging
import logging.handlers

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('github_monitor.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('github_monitor')
logger.info('程序启动')

# 配置requests会话，添加重试机制和SSL优化
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning

# 禁用不安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

http_session = requests.Session()

# 配置重试策略，包括SSL错误重试
retry_strategy = Retry(
    total=3,  # 总重试次数
    status_forcelist=[429, 500, 502, 503, 504],  # 触发重试的HTTP状态码
    allowed_methods=["HEAD", "GET", "OPTIONS"],  # 允许重试的HTTP方法
    backoff_factor=1,  # 重试间隔因子
    raise_on_status=False
)

# 应用重试策略
adapter = HTTPAdapter(max_retries=retry_strategy)
http_session.mount("https://", adapter)
http_session.mount("http://", adapter)

# SSL配置优化
http_session.verify = False  # 禁用SSL证书验证（解决证书问题导致的SSL:997错误）
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
        'group_id': '',
        'send_daily_report': 0,
        'send_normal_msg': 1
    },
    'workflow': {
        'night_sleep_switch': 'ON',
        'daily_report_switch': 'ON',
        'push_switch': 'ON'
    }
}

# 消息队列配置
MESSAGE_QUEUE_CONFIG = {
    'max_queue_size': 1000,  # 队列最大容量
    'max_per_minute': 20,     # 每分钟最多发送20条消息
    'batch_size': 5           # 批量发送大小
}

# 消息队列和相关变量
message_queue = []           # 消息队列
last_send_time = 0           # 上次发送时间
message_count = 0            # 分钟内发送消息计数
message_cache = set()        # 已发送消息缓存，用于去重

# 消息队列类
class MessageQueue:
    """轻量级消息队列，处理钉钉推送限制"""
    
    def __init__(self):
        self.queue = []
        self.last_send = 0
        self.send_count = 0
        self.cache = set()
        
    def add_message(self, message, priority=1):
        """添加消息到队列，带优先级"""
        # 生成消息唯一标识
        msg_id = hashlib.md5(str(message).encode()).hexdigest()
        
        # 检查是否已发送过
        if msg_id in self.cache:
            return False
        
        # 添加到队列，按优先级排序
        self.queue.append({
            'content': message,
            'priority': priority,
            'timestamp': time.time(),
            'id': msg_id
        })
        
        # 按优先级降序排序
        self.queue.sort(key=lambda x: x['priority'], reverse=True)
        
        # 限制队列大小
        if len(self.queue) > MESSAGE_QUEUE_CONFIG['max_queue_size']:
            self.queue = self.queue[:MESSAGE_QUEUE_CONFIG['max_queue_size']]
        
        return True
    
    def send_messages(self):
        """发送队列中的消息，处理速率限制"""
        # 检查推送开关
        if GLOBAL_CONFIG['workflow']['push_switch'] != 'ON':
            print("[+] 推送功能已关闭")
            # 清空队列，避免消息积压
            self.queue = []
            return 0
            
        global last_send_time, message_count
        
        current_time = time.time()
        sent_count = 0
        
        # 检查是否可以发送新消息（每分钟20条）
        if current_time - last_send_time > 60:
            # 重置计数和时间
            last_send_time = current_time
            message_count = 0
        
        # 计算可以发送的消息数量
        can_send = min(
            MESSAGE_QUEUE_CONFIG['max_per_minute'] - message_count,
            MESSAGE_QUEUE_CONFIG['batch_size'],
            len(self.queue)
        )
        
        if can_send <= 0:
            return 0
        
        # 发送消息
        for i in range(can_send):
            if not self.queue:
                break
                
            message = self.queue.pop(0)
            
            try:
                # 调用实际发送函数
                self._send_message(message['content'])
                # 添加到已发送缓存
                self.cache.add(message['id'])
                sent_count += 1
                message_count += 1
                
                # 避免发送过快
                time.sleep(0.5)
            except Exception as e:
                print(f"[-] 发送消息失败: {e}")
                # 可以选择重新入队或丢弃
        
        return sent_count
    
    def _send_message(self, message):
        """实际发送消息的函数，根据配置调用不同渠道"""
        app_name, _, webhook, secretKey, _ = load_config()
        
        try:
            from dingtalkchatbot.chatbot import DingtalkChatbot
            
            if app_name == "dingding":
                # 直接调用DingtalkChatbot，避免递归调用
                ding = DingtalkChatbot(webhook, secret=secretKey)
                ding.send_text(msg=message, is_at_all=False)
                update_push_count()
                logger.info("[+] 钉钉消息发送成功")
            elif app_name == "feishu":
                # 直接发送飞书消息，避免递归调用
                import requests
                headers = {"Content-Type": "application/json"}
                data = {
                    "msg_type": "text",
                    "content": {
                        "text": message
                    }
                }
                response = requests.post(webhook, json=data, headers=headers, timeout=10)
                if response.status_code == 200:
                    update_push_count()
                    logger.info("[+] 飞书消息发送成功")
            elif app_name == "tgbot":
                # 直接发送Telegram消息，避免递归调用
                import telegram
                bot = telegram.Bot(token=webhook)
                bot.send_message(chat_id=secretKey, text=message, timeout=10)
                update_push_count()
                logger.info("[+] Telegram消息发送成功")
        except Exception as e:
            logger.error(f"[-] 发送消息失败: {e}")

# 初始化消息队列实例
msg_queue = MessageQueue()

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
        GLOBAL_CONFIG['translate'] = translate_enable.upper() == 'ON' or translate_enable == '1'
    else:
        try:
            translate_config = config.get('translate', [{'enable': 'OFF'}])[0]['enable']
            GLOBAL_CONFIG['translate'] = translate_config.upper() == 'ON' if isinstance(translate_config, str) else bool(int(translate_config))
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
    elif os.environ.get('DISCARD_WEBHOOK'):
        push_channel = 'discard'
    else:
        # 从配置文件检测
        for channel in ['dingding', 'feishu', 'tgbot', 'discard']:
            channel_config = config.get(channel, [])
            if len(channel_config) > 0:
                try:
                    enable_value = channel_config[0]['enable']
                    if isinstance(enable_value, str):
                        if enable_value.upper() == 'ON':
                            push_channel = channel
                            break
                    else:
                        if int(enable_value) == 1:
                            push_channel = channel
                            break
                except:
                    continue
    
    
    
    # 确保channel_config被正确设置为当前push_channel的配置
    if push_channel and push_channel != '' and (not channel_config or len(channel_config) == 0):
        channel_config = config.get(push_channel, [])
    
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
    elif push_channel == 'discard':
        GLOBAL_CONFIG['push_channel']['webhook'] = os.environ.get('DISCARD_WEBHOOK', 
                                                            channel_config[1]['webhook'] if len(channel_config) > 1 else '')
        
        # 安全处理环境变量转换，防止'***'等无效值
        try:
            send_daily_report = os.environ.get('DISCARD_SEND_DAILY_REPORT', '')
            if send_daily_report and send_daily_report != '***':
                # 只支持 ON/OFF 格式
                GLOBAL_CONFIG['push_channel']['send_daily_report'] = 1 if send_daily_report.upper() == 'ON' else 0
            else:
                # 从配置文件读取，支持 ON/OFF 和数字格式
                config_value = channel_config[2]['send_daily_report'] if len(channel_config) > 2 else 0
                if isinstance(config_value, str):
                    GLOBAL_CONFIG['push_channel']['send_daily_report'] = 1 if config_value.upper() == 'ON' else 0
                else:
                    GLOBAL_CONFIG['push_channel']['send_daily_report'] = config_value
        except Exception as e:
            GLOBAL_CONFIG['push_channel']['send_daily_report'] = 0
        
        try:
            send_normal_msg = os.environ.get('DISCARD_SEND_NORMAL_MSG', '')
            if send_normal_msg and send_normal_msg != '***':
                # 只支持 ON/OFF 格式
                GLOBAL_CONFIG['push_channel']['send_normal_msg'] = 1 if send_normal_msg.upper() == 'ON' else 0
            else:
                # 从配置文件读取，支持 ON/OFF 和数字格式
                config_value = channel_config[3]['send_normal_msg'] if len(channel_config) > 3 else 1
                if isinstance(config_value, str):
                    GLOBAL_CONFIG['push_channel']['send_normal_msg'] = 1 if config_value.upper() == 'ON' else 0
                else:
                    GLOBAL_CONFIG['push_channel']['send_normal_msg'] = config_value
        except Exception as e:
            GLOBAL_CONFIG['push_channel']['send_normal_msg'] = 1
        
        # 处理 DISCARD_SWITCH 环境变量（可选，用于控制推送开关）
        try:
            discard_switch = os.environ.get('DISCARD_SWITCH', '')
            if discard_switch and discard_switch != '***':
                # DISCARD_SWITCH 是 ON/OFF 格式，用于控制是否启用推送
                GLOBAL_CONFIG['workflow']['push_switch'] = discard_switch
        except Exception as e:
            # 如果处理失败，保留原来的 push_switch 配置
            pass
    
    # 加载 workflow dispatch 输入配置
    GLOBAL_CONFIG['workflow']['night_sleep_switch'] = os.environ.get('NIGHT_SLEEP_SWITCH', 'ON')
    GLOBAL_CONFIG['workflow']['daily_report_switch'] = os.environ.get('DAILY_REPORT_SWITCH', 'ON')
    GLOBAL_CONFIG['workflow']['push_switch'] = os.environ.get('PUSH_SWITCH', 'ON')

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
    elif channel_type == 'discard':
        return 'discard', GLOBAL_CONFIG['github_token'], channel['webhook'], channel['webhook'], GLOBAL_CONFIG['translate']
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
        logger.info(f"成功加载 {len(BLACK_USER_CACHE)} 个黑名单用户")
        logger.info(f"已启用黑名单配置，共 {len(BLACK_USER_CACHE)} 个用户")
    except Exception as e:
        logger.warning(f"加载黑名单用户失败: {e}")
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
        logger.info("成功创建CVE监控表")
        
        # 创建关键字监控表
        cur.execute('''CREATE TABLE IF NOT EXISTS keyword_monitor
                   (keyword_name varchar(255),
                    pushed_at varchar(255),
                    keyword_url varchar(255));''')
        logger.info("成功创建关键字监控表")
        
        # 创建红队工具监控表
        cur.execute('''CREATE TABLE IF NOT EXISTS redteam_tools_monitor
                   (tools_name varchar(255),
                    pushed_at varchar(255),
                    tag_name varchar(255));''')
        logger.info("成功创建红队工具监控表")
        
        # 创建大佬仓库监控表
        cur.execute('''CREATE TABLE IF NOT EXISTS user_monitor
                   (repo_name varchar(255));''')
        logger.info("成功创建大佬仓库监控表")
        
        # 创建推送计数表
        cur.execute('''CREATE TABLE IF NOT EXISTS push_count
                   (date TEXT PRIMARY KEY,
                    count INTEGER);''')
        logger.info("成功创建推送计数表")
        
        # 创建消息缓存表
        cur.execute('''CREATE TABLE IF NOT EXISTS message_cache
                   (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_type varchar(50),
                    message_content TEXT,
                    message_data TEXT,
                    create_time datetime,
                    status varchar(20));''')
        logger.info("成功创建消息缓存表")
        
        conn.commit()
        conn.close()
        
        # 发送连接成功消息
        app_name, _, webhook, secretKey, _ = load_config()
        if app_name == "dingding":
            dingding("spaceX", "连接成功~", webhook, secretKey)
        elif app_name == "tgbot":
            tgbot("spaceX", "连接成功~", webhook, secretKey)
            
    except Exception as e:
        logger.error(f"创建监控表失败！报错：{e}")
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
                        cve_name = re.findall(r'(CVE\-\d+\-\d+)', cve_name_tmp)[0].upper()
                        
                        # 同时检查创建时间和更新时间
                        created_at = re.findall(r'\d{4}-\d{2}-\d{2}', json_str['items'][i]['created_at'])[0]
                        pushed_at = re.findall(r'\d{4}-\d{2}-\d{2}', json_str['items'][i]['pushed_at'])[0]
                        
                        # 如果创建时间或更新时间是今天，都视为今天的CVE
                        if created_at == str(today_date) or pushed_at == str(today_date):
                            today_cve_info_tmp.append({"cve_name": cve_name, "cve_url": cve_url, "pushed_at": pushed_at})
                            logger.info("[+] 该{}的创建时间为{}，更新时间为{}，属于今天的CVE" .format(cve_name, created_at, pushed_at))
                        else:
                            logger.info("[-] 该{}的创建时间为{}，更新时间为{}, 不属于今天的CVE" .format(cve_name, created_at, pushed_at))
                    except Exception as e:
                        logger.debug(f"处理CVE项目失败: {e}")
            except Exception as e:
                logger.debug(f"遍历CVE项目列表失败: {e}")
        today_cve_info = OrderedDict()
        for item in today_cve_info_tmp:
            today_cve_info.setdefault(item['cve_name'], {**item, })
        today_cve_info = list(today_cve_info.values())

        logger.info(f"成功获取 {len(today_cve_info)} 条今日CVE信息")
        return today_cve_info
        # return cve_total_count, cve_description, cve_url, cve_name
        #\d{4}-\d{2}-\d{2}

    except Exception as e:
        logger.error(f"getNews 函数 error: {e}")
        return []

def getKeywordNews(keyword):
    today_keyword_info_tmp = []
    try:
        # 特殊关键词处理
        special_keywords = ['poc', 'exp', 'cve']
        is_special = keyword.lower() in special_keywords or 'cve-' in keyword.lower()
        
        if is_special:
            # 使用专门的特殊关键词搜索函数
            today_keyword_info_tmp = get_special_keyword_news(keyword)
        else:
            # 获取搜索配置
            search_config = get_github_search_config()
            
            # 普通关键词搜索，按配置排序
            api = "https://api.github.com/search/repositories?q={}&sort={}&order={}&per_page={}" .format(
                keyword, search_config['sort'], search_config['order'], search_config['per_page'])
            json_str = http_session.get(api, headers=github_headers, timeout=10).json()
            today_date = datetime.date.today()
            
            for repo in json_str.get('items', []):
                try:
                    if repo['html_url'].split("/")[-2] not in black_user():
                        pushed_at = re.findall(r'\d{4}-\d{2}-\d{2}', repo['pushed_at'])[0]
                        if pushed_at == str(today_date):
                            # 使用关键词检测函数判断相关性
                            if is_keyword_relevant(repo, keyword):
                                today_keyword_info_tmp.append({
                                    "keyword_name": repo['name'], 
                                    "keyword_url": repo['html_url'], 
                                    "pushed_at": pushed_at, 
                                    "description": repo.get('description', '作者未写描述'),
                                    "stargazers_count": repo.get('stargazers_count', 0)
                                })
                                logger.info("keyword: {} ,{} ({} stars)" .format(keyword, repo['name'], repo.get('stargazers_count', 0)))
                except Exception as e:
                    logger.error(f"处理项目 {repo.get('name', '未知')} 时出错: {e}")
                    continue
        
        # 去重处理
        today_keyword_info = OrderedDict()
        for item in today_keyword_info_tmp:
            today_keyword_info.setdefault(item['keyword_name'], {**item, })
        today_keyword_info = list(today_keyword_info.values())
        
        logger.info(f"成功获取 {len(today_keyword_info)} 条关键词 '{keyword}' ")
        return today_keyword_info

    except Exception as e:
        logger.error(f"getKeywordNews 函数 error: {e}")
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
            today_cve_name = re.findall(r'(CVE\-\d+\-\d+)', today_keyword_info_data[i]['keyword_name'].upper())
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
            cve_name = re.findall(r'(CVE\-\d+\-\d+)', data[i]['cve_name'])[0].upper()
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
            today_cve_item = today_cve_info_data[i]
            today_cve_name = re.findall(r'(CVE\-\d+\-\d+)', today_cve_item['cve_name'])[0].upper()
            
            # 检查CVE是否存在于数据库中，避免重复推送
            Verify = query_cve_info_database(today_cve_name.upper())
            if Verify == 0:
                # 检查CVE是否在mitre.org上存在
                cve_exists = exist_cve(today_cve_name)
                
                # 如果CVE存在于mitre.org或创建/更新时间是今天，都推送
                if cve_exists == 1 or today_cve_item['pushed_at'] == str(datetime.date.today()):
                    print("[+] 数据库里不存在{}，mitre.org状态: {}，属于今天的CVE" .format(today_cve_name.upper(), "存在" if cve_exists == 1 else "不存在"))
                    today_all_cve_info.append(today_cve_item)
                else:
                    print("[-] 数据库里不存在{}，但mitre.org上也不存在，且不是今天更新，跳过" .format(today_cve_name.upper()))
            else:
                print("[-] 数据库里存在{}".format(today_cve_name.upper()))
        except Exception as e:
            print(f"[-] 处理CVE {today_cve_item.get('cve_name', '未知')} 时出错: {e}")
            pass
    
    logger.info(f"get_today_cve_info 返回 {len(today_all_cve_info)} 条CVE信息")
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
        
        # 从环境变量中读取keywords，如果存在则直接使用环境变量中的关键词，不合并
        env_keywords = os.environ.get('keywords', '')
        if env_keywords:
            keyword_list = [kw.strip() for kw in env_keywords.split(' ') if kw.strip()]
            # 去重
            keyword_list = list(set(keyword_list))
        
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
            # 将 GitHub 仓库 URL 转换为 API URL
            import re
            github_url_match = re.match(r'https://github.com/([^/]+)/([^/]+)', url)
            if github_url_match:
                owner, repo = github_url_match.groups()
                api_url = f"https://api.github.com/repos/{owner}/{repo}"
            elif url.startswith("https://api.github.com/repos/"):
                api_url = url
            else:
                print(f"[警告] 无效的 GitHub URL: {url}")
                continue
            
            tools_json = http_session.get(api_url, headers=github_headers, timeout=10).json()
            
            # 检查关键字段是否存在
            if 'pushed_at' in tools_json and 'name' in tools_json:
                pushed_at_tmp = tools_json['pushed_at']
                pushed_at = re.findall(r'\d{4}-\d{2}-\d{2}', pushed_at_tmp)[0] if pushed_at_tmp else datetime.date.today().strftime('%Y-%m-%d')
                tools_name = tools_json['name']
                html_url = tools_json.get('html_url', '')
                
                try:
                    releases_url = f"{api_url}/releases"
                    releases_json = http_session.get(releases_url, headers=github_headers, timeout=10).json()
                    tag_name = releases_json[0]['tag_name'] if releases_json and len(releases_json) > 0 else "no releases"
                except Exception as e:
                    tag_name = "no releases"
                
                tools_info_list.append({"tools_name":tools_name,"pushed_at":pushed_at,"api_url":html_url,"tag_name":tag_name})
            else:
                print(f"[警告] API返回数据缺少关键字段: {api_url}")
                print(f"[调试] API返回: {str(tools_json)[:100]}...")
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
            created_at = re.findall(r'\d{4}-\d{2}-\d{2}', json_str[i]['created_at'])[0]
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
                    if load_config()[0] == "discard":
                        tools_name = json_str[i]['name']
                        if discard(text, body, load_config()[2], GLOBAL_CONFIG['push_channel']['send_normal_msg']):
                            logger.info(f"discard 发送用户仓库 {tools_name} 成功")
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
    new_pushed_at = re.findall(r'\d{4}-\d{2}-\d{2}', http_session.get(url, headers=github_headers, timeout=10).json()['pushed_at'])[0]
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
                if load_config()[0] == "discard":
                    if discard(text, body, load_config()[2], GLOBAL_CONFIG['push_channel']['send_normal_msg']):
                        logger.info(f"discard 发送工具更新 {tools_name} 成功")
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
                feishu(text,body,load_config()[2])
            if load_config()[0] == "tgbot":
                tgbot(text, body, load_config()[2], load_config()[3])
            if load_config()[0] == "discard":
                if discard(text, body, load_config()[2], GLOBAL_CONFIG['push_channel']['send_normal_msg']):
                    logger.info(f"discard 发送工具更新 {tools_name} 成功")
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
        # 缩短超时时间，避免长时间挂起
        res = http_session.get(url=url, headers=headers, timeout=3)
        res.raise_for_status()
        result_dict = res.json()
        result = ""
        # 增强JSON解析的健壮性
        if isinstance(result_dict, list) and len(result_dict) > 0:
            for item in result_dict[0]:
                if isinstance(item, list) and len(item) > 0 and item[0]:
                    result += item[0]
        return result.strip() or word
    except Exception as e:
        print(f"Google翻译失败，使用百度翻译: {e}")
        return baidu_translate(word)

# 翻译结果缓存，避免重复翻译相同内容
TRANSLATION_CACHE = {}
# 上次API调用时间，用于控制访问频率
LAST_TRANSLATE_TIME = 0
# API调用最小间隔（毫秒）
MIN_TRANSLATE_INTERVAL = 1000

# 百度翻译实现
def baidu_translate(word):
    global LAST_TRANSLATE_TIME
    
    # 检查缓存，避免重复翻译
    if word in TRANSLATION_CACHE:
        return TRANSLATION_CACHE[word]
    
    try:
        import random
        import hashlib
        import time
        import yaml
        import os
        
        # 控制访问频率，避免54003错误
        current_time = time.time() * 1000  # 转换为毫秒
        if current_time - LAST_TRANSLATE_TIME < MIN_TRANSLATE_INTERVAL:
            sleep_time = (MIN_TRANSLATE_INTERVAL - (current_time - LAST_TRANSLATE_TIME)) / 1000
            time.sleep(sleep_time)
        
        # 从环境变量或配置文件读取百度翻译配置
        baidu_app_id = os.environ.get('BAIDU_APP_ID', '')
        baidu_secret_key = os.environ.get('BAIDU_SECRET_KEY', '')
        
        if not baidu_app_id or not baidu_secret_key:
            # 从配置文件读取
            try:
                with open('config.yaml', 'r', encoding='utf-8') as f:
                    config = yaml.load(f, Loader=yaml.FullLoader)
                    baidu_config = config.get('all_config', {}).get('baidu_translate', [{}])[0]
                    baidu_app_id = baidu_config.get('app_id', '')
                    baidu_secret_key = baidu_config.get('secret_key', '')
            except Exception as e:
                print(f"[警告] 读取百度翻译配置失败: {e}")
                return word
        
        # 检查配置是否完整
        if not baidu_app_id or not baidu_secret_key:
            print("[警告] 百度翻译配置不完整，无法进行翻译")
            return word
        
        # 百度翻译API URL
        url = 'https://fanyi-api.baidu.com/api/trans/vip/translate'
        
        # 构建请求参数
        salt = str(random.randint(32768, 65536))
        sign_str = baidu_app_id + word + salt + baidu_secret_key
        sign = hashlib.md5(sign_str.encode('utf-8')).hexdigest()
        
        params = {
            'q': word,
            'from': 'auto',
            'to': 'zh',
            'appid': baidu_app_id,
            'salt': salt,
            'sign': sign
        }
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        # 发送请求
        res = http_session.get(url=url, params=params, headers=headers, timeout=3)
        LAST_TRANSLATE_TIME = time.time() * 1000  # 更新上次调用时间
        res.raise_for_status()
        result_dict = res.json()
        
        # 处理API响应
        if 'trans_result' in result_dict:
            result = ""
            for item in result_dict['trans_result']:
                if 'dst' in item:
                    result += item['dst']
            translated_result = result.strip() or word
            # 缓存翻译结果
            TRANSLATION_CACHE[word] = translated_result
            return translated_result
        elif 'error_code' in result_dict:
            error_code = result_dict['error_code']
            error_msg = result_dict.get('error_msg', '未知错误')
            print(f"百度翻译API错误: {error_code} - {error_msg}")
            if error_code == '54003':
                print("[提示] 访问频率受限，请稍后再试")
                # 对于54003错误，增加等待时间
                time.sleep(2)
            return word
        else:
            return word
    except Exception as e:
        print(f"百度翻译失败: {e}")
        return word

# 夜间模式配置
default_night_time_config = {
    'start_hour': 0,    # 夜间开始时间（小时）
    'end_hour': 7       # 夜间结束时间（小时）
}

# 检查是否为夜间时间（北京时间）
def is_night_time():
    """检查当前是否为夜间时间（北京时间）"""
    import datetime
    import pytz
    
    try:
        # 首先检查夜间休眠开关是否开启
        night_sleep_switch = GLOBAL_CONFIG['workflow']['night_sleep_switch']
        if night_sleep_switch != 'ON':
            return False
        
        # 获取当前北京时间
        beijing_tz = pytz.timezone('Asia/Shanghai')
        now = datetime.datetime.now(beijing_tz)
        current_hour = now.hour
        
        # 检查是否在夜间时间范围内
        return default_night_time_config['start_hour'] <= current_hour < default_night_time_config['end_hour']
    except Exception as e:
        print(f"[-] 检查夜间时间失败: {e}")
        # 发生错误时，默认返回False，不影响程序运行
        return False

# 主函数中添加夜间模式检查
def main():
    """主函数，添加夜间模式检查"""
    # 检查是否为夜间时间
    if is_night_time():
        print("[+] 当前为夜间时间（北京时间0-7点），程序休眠中...")
        # 休眠直到早上7点
        import time
        beijing_tz = pytz.timezone('Asia/Shanghai')
        now = datetime.datetime.now(beijing_tz)
        # 计算到早上7点的秒数
        tomorrow = now.replace(hour=7, minute=0, second=0, microsecond=0)
        if now.hour >= 7:
            tomorrow += datetime.timedelta(days=1)
        sleep_seconds = (tomorrow - now).total_seconds()
        time.sleep(sleep_seconds)
        print("[+] 夜间时间结束，程序继续运行...")

# 推送限制配置
PUSH_LIMITS = {
    'daily': 500,      # 每日推送限制
    'monthly': 5000,   # 每月推送限制
    'alert_threshold': 0.8  # 接近限制的提醒阈值（80%）
}

# 初始化推送计数表
def init_push_count_table():
    """初始化推送计数表"""
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    
    try:
        # 创建推送计数表
        cur.execute('''CREATE TABLE IF NOT EXISTS push_count 
                      (date TEXT PRIMARY KEY, count INTEGER)''')
        conn.commit()
        print("[+] 推送计数表初始化成功")
    except Exception as e:
        print(f"[-] 初始化推送计数表失败: {e}")
    finally:
        conn.close()

# 获取当日推送计数
def get_today_push_count():
    import datetime
    
    today = datetime.date.today().strftime('%Y-%m-%d')
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    
    try:
        cur.execute("SELECT count FROM push_count WHERE date = ?", (today,))
        result = cur.fetchone()
        return result[0] if result else 0
    except Exception as e:
        print(f"[-] 获取当日推送计数失败: {e}")
        return 0
    finally:
        conn.close()

# 获取本月推送计数
def get_monthly_push_count():
    """获取本月推送总数"""
    import datetime
    
    today = datetime.date.today()
    month_start = today.replace(day=1).strftime('%Y-%m-%d')
    
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    
    try:
        cur.execute("SELECT SUM(count) FROM push_count WHERE date >= ?", (month_start,))
        result = cur.fetchone()
        return result[0] if result else 0
    except Exception as e:
        print(f"[-] 获取本月推送计数失败: {e}")
        return 0
    finally:
        conn.close()

# 更新当日推送计数
def update_push_count():
    import datetime
    
    today = datetime.date.today().strftime('%Y-%m-%d')
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    
    try:
        # 检查是否已有今日记录
        cur.execute("SELECT count FROM push_count WHERE date = ?", (today,))
        result = cur.fetchone()
        
        if result:
            # 更新现有记录
            new_count = result[0] + 1
            cur.execute("UPDATE push_count SET count = ? WHERE date = ?", (new_count, today))
        else:
            # 插入新记录
            cur.execute("INSERT INTO push_count (date, count) VALUES (?, 1)", (today,))
        
        conn.commit()
        
        # 检查是否需要发送提醒
        check_push_limit_alert()
        
        return True
    except Exception as e:
        print(f"[-] 更新推送计数失败: {e}")
        return False
    finally:
        conn.close()

# 检查推送限制并发送提醒
def check_push_limit_alert():
    """检查是否接近推送限制，发送提醒"""
    try:
        daily_count = get_today_push_count()
        monthly_count = get_monthly_push_count()
        
        # 计算接近程度
        daily_ratio = daily_count / PUSH_LIMITS['daily']
        monthly_ratio = monthly_count / PUSH_LIMITS['monthly']
        
        # 检查是否需要发送提醒
        alert_needed = False
        alert_message = ""
        
        if daily_ratio >= PUSH_LIMITS['alert_threshold']:
            alert_message += f"⚠️  当日推送已使用 {daily_count}/{PUSH_LIMITS['daily']} 条 ({int(daily_ratio*100)}%)\n"
            alert_needed = True
        
        if monthly_ratio >= PUSH_LIMITS['alert_threshold']:
            alert_message += f"⚠️  本月推送已使用 {monthly_count}/{PUSH_LIMITS['monthly']} 条 ({int(monthly_ratio*100)}%)\n"
            alert_needed = True
        
        if alert_needed:
            # 发送提醒消息
            app_name, _, webhook, secretKey, _ = load_config()
            if app_name == "dingding":
                dingding("推送限制提醒", alert_message, webhook, secretKey)
            elif app_name == "feishu":
                feishu("推送限制提醒", alert_message, webhook)
            elif app_name == "tgbot":
                tgbot("推送限制提醒", alert_message, webhook, secretKey)
            
            logger.info(f"已发送推送限制提醒: {alert_message.strip()}")
    except Exception as e:
        logger.error(f"检查推送限制失败: {e}")

# 检查是否超过推送限制
def is_push_limit_reached():
    """检查是否超过每日推送限制"""
    daily_count = get_today_push_count()
    return daily_count >= PUSH_LIMITS['daily']

# 缓存消息到数据库
def cache_message(message_type, message_content, message_data):
    import datetime
    
    create_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    
    try:
        cur.execute(
            "INSERT INTO message_cache (message_type, message_content, message_data, create_time, status) VALUES (?, ?, ?, ?, ?)",
            (message_type, message_content, message_data, create_time, 'pending')
        )
        conn.commit()
        conn.close()
        print(f"[+] 消息已缓存到数据库: {message_type}")
        return True
    except Exception as e:
        conn.close()
        print(f"[-] 缓存消息失败: {e}")
        return False

# 发送缓存的消息
def send_cached_messages():
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    
    try:
        # 获取所有待发送的消息
        cur.execute("SELECT id, message_type, message_content, message_data FROM message_cache WHERE status = 'pending' ORDER BY id LIMIT 500")
        cached_messages = cur.fetchall()
        
        if not cached_messages:
            conn.close()
            return 0
        
        sent_count = 0
        for msg in cached_messages:
            msg_id, msg_type, msg_content, msg_data = msg
            
            # 检查是否超过推送限制
            if is_push_limit_reached():
                break
            
            # 发送消息（这里需要根据message_type和message_content调用对应的发送函数）
            # 由于消息内容已经序列化，需要根据实际情况反序列化后发送
            print(f"[+] 发送缓存消息: {msg_type}")
            
            # 更新消息状态
            cur.execute("UPDATE message_cache SET status = 'sent' WHERE id = ?", (msg_id,))
            update_push_count()
            sent_count += 1
        
        conn.commit()
        conn.close()
        return sent_count
    except Exception as e:
        conn.close()
        print(f"[-] 发送缓存消息失败: {e}")
        return 0

# 主翻译函数，默认使用Google翻译
def translate(word):
    # 先检查是否已经是中文，避免不必要的翻译
    if re.search('[一-龥]', word):
        return word
    
    # 尝试Google翻译
    try:
        return google_translate(word)
    except Exception as e:
        print(f"Google翻译失败，使用百度翻译: {e}")
        # 尝试百度翻译
        try:
            return baidu_translate(word)
        except Exception as e2:
            print(f"百度翻译也失败: {e2}")
            # 两次翻译都失败，返回原词
            return word

# 钉钉
def dingding(text, msg,webhook,secretKey):
    try:
        # 构建完整消息
        full_message = '{}\r\n{}'.format(text, msg)
        
        # 添加到消息队列，设置优先级
        priority = 2 if 'CVE' in text.upper() or '漏洞' in text else 1
        msg_queue.add_message(full_message, priority)
        
        # 尝试发送队列中的消息
        msg_queue.send_messages()
        
        print("[+] 消息已加入队列，等待发送")
    except Exception as e:
        print(f"钉钉推送失败: {e}")
        pass
## 飞书
def feishu(text,msg,webhook):
    try:
        # 构建完整消息
        full_message = '{}\r\n{}'.format(text, msg)
        
        # 添加到消息队列
        priority = 2 if 'CVE' in text.upper() or '漏洞' in text else 1
        msg_queue.add_message(full_message, priority)
        
        # 尝试发送队列中的消息
        msg_queue.send_messages()
        
        print("[+] 消息已加入队列，等待发送")
    except Exception as e:
        print(f"飞书推送失败: {e}")
        pass
# 添加Telegram Bot推送支持
def tgbot(text, msg,token,group_id):
    try:
        # 构建完整消息
        full_message = '{}\r\n{}'.format(text, msg)
        
        # 添加到消息队列
        priority = 2 if 'CVE' in text.upper() or '漏洞' in text else 1
        msg_queue.add_message(full_message, priority)
        
        # 尝试发送队列中的消息
        msg_queue.send_messages()
        
        print("[+] 消息已加入队列，等待发送")
    except Exception as e:
        print(f"Telegram推送失败: {e}")
        pass

# 添加Discard推送支持
def discard(text, msg, webhook, send_normal_msg=1, is_daily_report=False, html_file=None, markdown_content=None):
    try:
        # 检查推送开关
        if GLOBAL_CONFIG['workflow']['push_switch'] != 'ON':
            print("[+] 推送功能已关闭")
            return False
            
        if send_normal_msg == 0 and not is_daily_report:
            return False
        
        headers = {
            "Content-Type": "application/json;charset=utf-8"
        }
        
        if is_daily_report and html_file:
            # 推送日报
            current_date = time.strftime('%Y-%m-%d', time.localtime())
            push_content = f"📅 **{text}**\n📊 {msg}\n\n"
            
            if markdown_content:
                # 提取markdown内容中的文章列表
                lines = markdown_content.split('\n')
                category = ""
                category_items = []
                
                for line in lines:
                    if line.strip().startswith('Power By') or line.strip().startswith('---'):
                        continue
                    
                    if line.startswith('## '):
                        # 处理新分类
                        if category and category_items:
                            # 添加之前的分类
                            push_content += f"\n🔖 **{category}**\n"
                            push_content += '\n'.join(category_items)
                            push_content += '\n'
                        # 重置分类和内容
                        category = line[3:].strip()  # 移除 ## 前缀
                        category_items = []
                    elif line.startswith('- [') and category:  # 处理列表项
                        # 优化链接格式
                        item_text = line.strip()
                        category_items.append(item_text)
                
                # 添加最后一个分类
                if category and category_items:
                    push_content += f"\n🔖 **{category}**\n"
                    push_content += '\n'.join(category_items)
                    push_content += '\n'
            
            # 添加底部信息
            # 构建GitHub Pages的完整日报链接
            current_date = time.strftime('%Y-%m-%d', time.localtime())
            github_pages_url = f"https://adminlove520.github.io/github_monitor/archive/{current_date}/Daily_{current_date}.html"
            push_content += f"\n🌐 [查看完整日报]({github_pages_url})\n"
            push_content += f"🔗 [隐侠安全客栈](https://www.dfyxsec.com/)"
            
            data = {
                "content": push_content
            }
        else:
            # 推送普通消息
            data = {
                "content": f"**{text}**\n{msg}"
            }
        
        response = http_session.post(webhook, json=data, headers=headers, timeout=10)
        if response.status_code in [200, 204]:
            print(f"Discard推送成功: {text}")
            update_push_count()
            return True
        else:
            print(f"Discard推送失败: HTTP状态码 - {response.status_code}")
            print(f"响应内容: {response.text}")
            return False
    except Exception as e:
        print(f"Discard推送失败: {e}")
        return False

# 判断是否存在该CVE
def exist_cve(cve):
    try:
        # 首先尝试新版MITRE API检查CVE是否存在
        query_cve_url = "https://cveawg.mitre.org/api/cve/" + cve
        response = http_session.get(query_cve_url, timeout=10)
        # 如果HTTP状态码是200，说明CVE存在
        if response.status_code == 200:
            return 1
    except Exception as e:
        logger.error(f"使用API检查CVE {cve} 存在性失败: {e}")
    
    # 如果API失败，尝试使用旧版HTML页面检查
    try:
        query_cve_url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve
        response = http_session.get(query_cve_url, timeout=10)
        # 检查页面是否包含CVE信息，而不是404页面
        if response.status_code == 200:
            # 简单检查页面内容，看是否包含CVE信息
            if cve in response.text and "CVE" in response.text:
                return 1
    except Exception as e:
        logger.error(f"使用HTML页面检查CVE {cve} 存在性失败: {e}")
    
    # 如果所有方法都失败，返回0（不存在）
    return 0

# 关键词检测函数，判断项目是否与关键词相关
def is_keyword_relevant(repo, keyword):
    """检查项目是否与关键词相关"""
    # 检查项目名称
    if keyword.lower() in repo.get('name', '').lower():
        return True
    # 检查项目描述
    if repo.get('description') and keyword.lower() in repo['description'].lower():
        return True
    # 检查内容长度
    if len(repo.get('description', '')) < 20:
        return True
    return False

# 获取GitHub搜索配置
def get_github_search_config():
    """读取GitHub搜索配置"""
    try:
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
            github_search_config = config.get('all_config', {}).get('github_search', {})
        
        # 设置默认值
        return {
            'star_threshold': github_search_config.get('star_threshold', 100),
            'per_page': github_search_config.get('per_page', 20),
            'sort': github_search_config.get('sort', 'stars'),
            'order': github_search_config.get('order', 'desc')
        }
    except Exception as e:
        print(f"[-] 读取GitHub搜索配置失败: {e}")
        # 返回默认配置
        return {
            'star_threshold': 100,
            'per_page': 20,
            'sort': 'stars',
            'order': 'desc'
        }

# 特殊关键词新闻获取函数
def get_special_keyword_news(keyword):
    """使用CVE-Poc_All_in_One的搜索逻辑获取特殊关键词新闻"""
    today_special_news = []
    try:
        # 获取搜索配置
        search_config = get_github_search_config()
        
        # 特殊关键词使用高级搜索，按star数降序
        api = f"https://api.github.com/search/repositories?q={keyword}&sort={search_config['sort']}&order={search_config['order']}&per_page={search_config['per_page']}"
        json_str = http_session.get(api, headers=github_headers, timeout=10).json()
        today_date = datetime.date.today()
        
        for repo in json_str.get('items', []):
            try:
                # 检查star数是否达到阈值
                if repo.get('stargazers_count', 0) < search_config['star_threshold']:
                    continue
                    
                if repo['html_url'].split("/")[-2] not in black_user():
                    pushed_at = re.findall(r'\d{4}-\d{2}-\d{2}', repo['pushed_at'])[0]
                    if pushed_at == str(today_date):
                        today_special_news.append({
                            "keyword_name": repo['name'],
                            "keyword_url": repo['html_url'],
                            "pushed_at": pushed_at,
                            "description": repo.get('description', '作者未写描述'),
                            "stargazers_count": repo.get('stargazers_count', 0)
                        })
                        print(f"[+] special keyword: {keyword}, {repo['name']} ({repo.get('stargazers_count', 0)} stars)")
            except Exception as e:
                print(f"[-] 处理特殊关键词项目 {repo.get('name', '未知')} 时出错: {e}")
                continue
    except Exception as e:
        print(f"get_special_keyword_news 函数 error: {e}")
    
    return today_special_news

#根据cve 名字，获取描述，并翻译
def get_cve_des_zh(cve, github_url=None):
    """获取CVE描述并翻译，如果CVE API失败则尝试从GitHub README获取"""
    try:
        # 首先尝试从CVE API获取信息
        query_cve_url = "https://cveawg.mitre.org/api/cve/" + cve
        response = http_session.get(query_cve_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # 从JSON数据中提取描述
            try:
                # 优先从containers.cna.descriptions中获取描述
                descriptions = data.get('containers', {}).get('cna', {}).get('descriptions', [])
                if descriptions:
                    # 寻找英文描述，支持en和en-US
                    des = next((desc.get('value', '') for desc in descriptions if desc.get('lang', '').startswith('en')), '')
                else:
                    # 尝试其他可能的描述字段
                    des = data.get('descriptions', [{}])[0].get('value', '')
                
                # 提取发布时间
                cve_time = data.get('cveMetadata', {}).get('datePublished', '') or data.get('published', '')
                if cve_time:
                    # 格式化时间，使用dateutil模块兼容所有Python版本
                    import datetime
                    try:
                        # 尝试使用dateutil.parser.isoparse，兼容所有Python版本
                        from dateutil.parser import isoparse
                        cve_time = isoparse(cve_time).strftime('%Y-%m-%d %H:%M:%S')
                    except Exception as e:
                        logger.error(f"解析CVE {cve} 时间失败: {e}")
                        cve_time = "未知时间"
                else:
                    cve_time = "未知时间"
                
                # 确保描述不为空
                des = des.strip() if des.strip() else "无法获取CVE描述"
            except Exception as e_json:
                logger.error(f"解析CVE {cve} JSON数据失败: {e_json}")
                des = "无法获取CVE描述"
                cve_time = "未知时间"
        else:
            logger.error(f"获取CVE {cve} 信息失败，HTTP状态码: {response.status_code}")
            des = "无法获取CVE描述"
            cve_time = "未知时间"
        
        # 如果从CVE API获取到了有效信息，直接返回
        if des != "无法获取CVE描述" and cve_time != "未知时间":
            # 翻译描述（如果启用）
            if load_config()[-1]:
                translated_des = translate(des)
                return translated_des, cve_time
            return des, cve_time
        
        # 如果CVE API获取失败，尝试从GitHub获取信息
        if github_url:
            logger.info(f"尝试从GitHub URL获取CVE {cve} 信息: {github_url}")
            try:
                # 从GitHub URL提取owner和repo
                import re
                match = re.match(r'https://github.com/([^/]+)/([^/]+)', github_url)
                if match:
                    owner, repo = match.groups()
                    
                    # 先获取仓库基本信息，包含描述和推送时间
                    repo_url = f"https://api.github.com/repos/{owner}/{repo}"
                    repo_response = http_session.get(repo_url, headers=github_headers, timeout=10)
                    if repo_response.status_code == 200:
                        repo_data = repo_response.json()
                        
                        # 使用仓库描述作为CVE描述
                        repo_des = repo_data.get('description', '')
                        # 如果描述为空，使用仓库名称作为备选
                        if not repo_des.strip():
                            repo_des = f"{owner}/{repo}"
                        
                        # 获取仓库推送时间
                        pushed_at = repo_data.get('pushed_at', '')
                        repo_time = "未知时间"
                        if pushed_at:
                            import datetime
                            try:
                                # 尝试使用dateutil.parser.isoparse，兼容所有Python版本
                                from dateutil.parser import isoparse
                                repo_time = isoparse(pushed_at).strftime('%Y-%m-%d %H:%M:%S')
                            except Exception as e:
                                logger.error(f"解析GitHub仓库推送时间失败: {e}")
                                repo_time = "未知时间"
                        
                        # 然后尝试获取README，优先使用README内容
                        readme_url = f"https://api.github.com/repos/{owner}/{repo}/readme"
                        readme_response = http_session.get(readme_url, headers=github_headers, timeout=10)
                        
                        if readme_response.status_code == 200:
                            readme_data = readme_response.json()
                            import base64
                            # 解码README内容
                            readme_content = base64.b64decode(readme_data['content']).decode('utf-8')
                            
                            # 使用README的所有内容作为描述
                            readme_des = readme_content.strip()
                            if readme_des:
                                des = readme_des
                                cve_time = repo_time
                                logger.info(f"从GitHub README成功获取CVE {cve} 信息")
                            else:
                                # 如果README为空，使用仓库描述
                                des = repo_des
                                cve_time = repo_time
                                logger.info(f"从GitHub仓库信息成功获取CVE {cve} 信息")
                        else:
                            # 如果README获取失败，使用仓库描述
                            des = repo_des
                            cve_time = repo_time
                            logger.info(f"从GitHub仓库信息成功获取CVE {cve} 信息")
                    else:
                        logger.error(f"获取GitHub仓库信息失败: {repo_response.status_code}")
            except Exception as e_github:
                logger.error(f"从GitHub获取CVE {cve} 信息失败: {e_github}")
        
        # 翻译描述（如果启用）
        if load_config()[-1]:
            translated_des = translate(des)
            return translated_des, cve_time
        return des, cve_time
    except Exception as e:
        logger.error(f"获取CVE {cve} 描述失败: {e}")
        
        # 如果CVE API失败且提供了GitHub URL，尝试从GitHub获取
        if github_url:
            try:
                logger.info(f"尝试从GitHub URL获取CVE {cve} 信息: {github_url}")
                import re
                match = re.match(r'https://github.com/([^/]+)/([^/]+)', github_url)
                if match:
                    owner, repo = match.groups()
                    # 获取仓库的基本信息（包含推送时间）
                    repo_url = f"https://api.github.com/repos/{owner}/{repo}"
                    repo_response = http_session.get(repo_url, headers=github_headers, timeout=10)
                    if repo_response.status_code == 200:
                        repo_data = repo_response.json()
                        # 使用仓库描述作为CVE描述
                        des = repo_data.get('description', '')
                        # 如果描述为空，使用仓库名称作为备选
                        if not des.strip():
                            des = f"{owner}/{repo}"
                        # 获取仓库推送时间
                        pushed_at = repo_data.get('pushed_at', '')
                        if pushed_at:
                            import datetime
                            try:
                                # 尝试使用dateutil.parser.isoparse，兼容所有Python版本
                                from dateutil.parser import isoparse
                                cve_time = isoparse(pushed_at).strftime('%Y-%m-%d %H:%M:%S')
                            except Exception as e:
                                logger.error(f"解析GitHub仓库推送时间失败: {e}")
                                cve_time = "未知时间"
                        else:
                            cve_time = "未知时间"
                        
                        logger.info(f"从GitHub成功获取CVE {cve} 信息")
                        # 翻译描述（如果启用）
                        if load_config()[-1]:
                            translated_des = translate(des)
                            return translated_des, cve_time
                        return des, cve_time
                    else:
                        # 如果获取仓库信息失败，直接使用owner/repo作为描述
                        des = f"{owner}/{repo}"
                        cve_time = "未知时间"
                        logger.info(f"从GitHub获取CVE {cve} 信息失败，使用owner/repo作为描述")
                        # 翻译描述（如果启用）
                        if load_config()[-1]:
                            translated_des = translate(des)
                            return translated_des, cve_time
                        return des, cve_time
            except Exception as e_github:
                logger.error(f"从GitHub获取CVE {cve} 信息失败: {e_github}")
        
        # 如果所有尝试都失败，尝试从GitHub URL提取owner/repo作为最后的备选
        if github_url:
            try:
                import re
                match = re.match(r'https://github.com/([^/]+)/([^/]+)', github_url)
                if match:
                    owner, repo = match.groups()
                    des = f"{owner}/{repo}"
                    cve_time = "未知时间"
                    logger.info(f"所有尝试失败，使用owner/repo作为CVE {cve} 的描述")
                    # 翻译描述（如果启用）
                    if load_config()[-1]:
                        translated_des = translate(des)
                        return translated_des, cve_time
                    return des, cve_time
            except Exception as e_final:
                logger.error(f"从GitHub URL提取owner/repo失败: {e_final}")
        
        # 如果真的所有尝试都失败，返回默认值
        return "无法获取CVE描述", "未知时间"

#发送CVE信息到社交工具
def sendNews(data):
    """发送CVE信息到配置的推送渠道"""
    try:
        text = '有新的CVE送达! \r\n** 请自行分辨是否为红队钓鱼!!! **'
        logger.info(f"开始发送 {len(data)} 条CVE信息")
        
        # 获取 cve 名字 ，根据cve 名字，获取描述，并翻译
        for i in range(len(data)):
            try:
                cve_item = data[i]
                cve_name = re.findall(r'(CVE\-\d+\-\d+)', cve_item['cve_name'])[0].upper()
                
                # 获取CVE描述，传递GitHub URL作为备选
                cve_zh, cve_time = get_cve_des_zh(cve_name, cve_item['cve_url'])
                
                # 构建推送内容
                body = "CVE编号: " + cve_name + " \r\n"
                body += "发布时间: " + cve_time + " \r\n"
                body += "Github地址: " + str(cve_item['cve_url']) + "\r\n"
                body += "CVE描述: " + "\r\n" + cve_zh
                
                # 发送到配置的渠道
                app_name = load_config()[0]
                if app_name == "dingding":
                    dingding(text, body, load_config()[2], load_config()[3])
                    logger.info(f"钉钉 发送 CVE {cve_name} 成功")
                elif app_name == "feishu":
                    feishu(text, body, load_config()[2])
                    logger.info(f"飞书 发送 CVE {cve_name} 成功")
                elif app_name == "tgbot":
                    tgbot(text, body, load_config()[2], load_config()[3])
                    logger.info(f"tgbot 发送 CVE {cve_name} 成功")
                elif app_name == "discard":
                    if discard(text, body, load_config()[2], GLOBAL_CONFIG['push_channel']['send_normal_msg']):
                        logger.info(f"discard 发送 CVE {cve_name} 成功")
            except IndexError as e:
                logger.error(f"处理CVE数据时索引错误: {e}")
            except Exception as e:
                logger.error(f"发送CVE {cve_name} 失败: {e}")
    except Exception as e:
        logger.error(f"sendNews 函数 error: {e}")
#发送信息到社交工具
def sendKeywordNews(keyword, data):
    """发送关键字监控信息到配置的推送渠道"""
    try:
        text = '有新的关键字监控 - {} - 送达! \r\n** 请自行分辨是否为红队钓鱼!!! **' .format(keyword)
        logger.info(f"开始发送关键字 {keyword} 的 {len(data)} 条监控信息")
        
        # 遍历关键字监控数据
        for i in range(len(data)):
            try:
                item = data[i]
                keyword_name = item.get('keyword_name', '未知项目')
                keyword_url = item.get('keyword_url', '')
                description = item.get('description', '作者未写描述')
                translated_description = ""
                
                # 翻译描述（如果启用）
                if load_config()[-1]:
                    translated_description = translate(description)
                
                # 构建推送内容
                body = "项目名称: " + str(keyword_name) + "\r\n"
                body += "Github地址: " + str(keyword_url) + "\r\n"
                body += "项目描述: " + str(description) + "\r\n"
                if translated_description and translated_description != description:
                    body += "项目描述-译文: " + str(translated_description) + "\r\n"
                
                # 发送到配置的渠道
                app_name = load_config()[0]
                if app_name == "dingding":
                    dingding(text, body, load_config()[2], load_config()[3])
                    logger.info(f"钉钉 发送关键字 {keyword} 的项目 {keyword_name} 成功")
                elif app_name == "feishu":
                    feishu(text, body, load_config()[2])
                    logger.info(f"飞书 发送关键字 {keyword} 的项目 {keyword_name} 成功")
                elif app_name == "tgbot":
                    tgbot(text, body, load_config()[2], load_config()[3])
                    logger.info(f"tgbot 发送关键字 {keyword} 的项目 {keyword_name} 成功")
                elif app_name == "discard":
                    if discard(text, body, load_config()[2], GLOBAL_CONFIG['push_channel']['send_normal_msg']):
                        logger.info(f"discard 发送关键字 {keyword} 的项目 {keyword_name} 成功")
            except Exception as e:
                logger.error(f"处理关键字 {keyword} 的监控数据时出错: {e}")
                pass
    except Exception as e:
        logger.error(f"sendKeywordNews 函数 error: {e}")

# 生成日报功能
def generate_daily_report(cve_data=None, keyword_data=None, tools_update_data=None):
    import os
    today = datetime.date.today().strftime('%Y-%m-%d')
    archive_dir = 'archive'
    # 按照日期建立文件夹
    daily_dir = os.path.join(archive_dir, today)
    report_path = os.path.join(daily_dir, f'Daily_{today}.md')
    
    # 创建archive目录和每日子目录如果不存在
    if not os.path.exists(archive_dir):
        os.makedirs(archive_dir)
    if not os.path.exists(daily_dir):
        os.makedirs(daily_dir)
    
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
    
    # 去重处理 - 确保当日日报只包含唯一数据
    # CVE去重
    unique_cve = []
    cve_seen = set()
    if final_cve_data:
        for item in final_cve_data:
            # 生成唯一标识
            if isinstance(item, dict):
                key = f"{item.get('cve_name', '')}_{item.get('cve_url', '')}"
            else:
                key = f"{item[0]}_{item[1]}"
            
            if key not in cve_seen:
                cve_seen.add(key)
                unique_cve.append(item)
    final_cve_data = unique_cve
    
    # 关键字监控去重
    unique_keyword = []
    keyword_seen = set()
    if final_keyword_data:
        for item in final_keyword_data:
            # 生成唯一标识
            if isinstance(item, dict):
                key = f"{item.get('keyword_name', '')}_{item.get('keyword_url', '')}"
            else:
                key = f"{item[0]}_{item[1]}"
            
            if key not in keyword_seen:
                keyword_seen.add(key)
                unique_keyword.append(item)
    final_keyword_data = unique_keyword
    
    # 红队工具去重
    unique_tools = []
    tools_seen = set()
    if final_tools_data:
        for item in final_tools_data:
            # 生成唯一标识
            if isinstance(item, dict):
                key = f"{item.get('tools_name', '')}"
            else:
                key = f"{item[0]}"
            
            if key not in tools_seen:
                tools_seen.add(key)
                unique_tools.append(item)
    final_tools_data = unique_tools
    
    # 构建更新关键词
    keywords = []
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
    
    # 统计数量
    cve_count = len(final_cve_data)
    keyword_count = len(final_keyword_data)
    tools_count = len(final_tools_data)
    total_count = cve_count + keyword_count + tools_count
    
    # 构建更新关键词
    keywords = []
    if final_cve_data:
        keywords.append('CVE')
    if final_tools_data:
        keywords.append('红队工具')
    keywords = list(set(keywords))
    keywords_formatted = '\n'.join([f'- {kw}' for kw in keywords]) if keywords else '- 无'
    
    # 构建CVE列表和详情
    cve_list = []
    cve_details = []
    if final_cve_data:
        for item in final_cve_data:
            # 处理字典类型数据
            if isinstance(item, dict):
                cve_name = item.get('cve_name', '未知CVE')
                cve_url = item.get('cve_url', '')
                pushed_at = item.get('pushed_at', today)
            # 处理元组类型数据
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                cve_name, cve_url = item[0], item[1]
                pushed_at = item[2] if len(item) >= 3 else today
            else:
                continue
            
            if cve_name and cve_url:
                cve_list.append(f'- [{cve_name}]({cve_url})')
                cve_details.append(f"### {cve_name}\n- GitHub地址: {cve_url}\n- 推送时间: {pushed_at}\n- 类型: CVE\n")
    cve_list_str = '\n'.join(cve_list) if cve_list else '无CVE更新'
    cve_details_str = '\n'.join(cve_details) if cve_details else '无CVE详情'
    
    # 构建关键字监控列表和详情
    keyword_list_items = []
    keyword_details = []
    if final_keyword_data:
        for item in final_keyword_data:
            # 处理字典类型数据
            if isinstance(item, dict):
                keyword_name = item.get('keyword_name', '未知项目')
                keyword_url = item.get('keyword_url', '')
                pushed_at = item.get('pushed_at', today)
            # 处理元组类型数据
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                keyword_name, keyword_url = item[0], item[1]
                pushed_at = item[2] if len(item) >= 3 else today
            else:
                continue
            
            if keyword_name and keyword_url:
                keyword_list_items.append(f'- [{keyword_name}]({keyword_url})')
                keyword_details.append(f"### {keyword_name}\n- GitHub地址: {keyword_url}\n- 推送时间: {pushed_at}\n- 类型: 关键字监控\n")
    keyword_list_str = '\n'.join(keyword_list_items) if keyword_list_items else '无关键字监控更新'
    keyword_details_str = '\n'.join(keyword_details) if keyword_details else '无关键字监控详情'
    
    # 构建红队工具列表和详情
    tools_list_items = []
    tools_details = []
    if final_tools_data:
        for item in final_tools_data:
            # 处理字典类型数据
            if isinstance(item, dict):
                tools_name = item.get('tools_name', '未知工具')
                api_url = item.get('api_url', '')
                tag_name = item.get('tag_name', 'no releases')
                pushed_at = item.get('pushed_at', today)
            # 处理元组类型数据
            elif isinstance(item, (list, tuple)) and len(item) >= 1:
                tools_name = item[0]
                pushed_at = item[1] if len(item) >= 2 else today
                tag_name = item[2] if len(item) >= 3 else 'no releases'
                api_url = f"https://github.com/search?q={tools_name}"
            else:
                continue
            
            if tools_name:
                tools_list_items.append(f'- [{tools_name}]({api_url})')
                tools_details.append(f"### {tools_name}\n- GitHub地址: {api_url}\n- 推送时间: {pushed_at}\n- 版本: {tag_name}\n- 类型: 红队工具\n")
    tools_list_str = '\n'.join(tools_list_items) if tools_list_items else '无红队工具更新'
    tools_details_str = '\n'.join(tools_details) if tools_details else '无红队工具详情'
    
    # 构建知识库标签
    tags = ['GitHub监控', 'CVE', '红队工具', '安全资讯']
    tags.extend(keywords)
    tags = list(set(tags))
    tags_formatted = '\n'.join([f'- {tag}' for tag in tags]) if tags else '- GitHub监控'
    
    # 填充模板
    report_content = template
    report_content = report_content.replace('当日情报_YYYY-MM-DD', f'当日情报_{today}')
    report_content = report_content.replace('{total_count}', str(total_count))
    report_content = report_content.replace('{cve_count}', str(cve_count))
    report_content = report_content.replace('{keyword_count}', str(keyword_count))
    report_content = report_content.replace('{tools_count}', str(tools_count))
    report_content = report_content.replace('{keywords}', keywords_formatted)
    report_content = report_content.replace('{cve_list}', cve_list_str)
    report_content = report_content.replace('{keyword_list}', keyword_list_str)
    report_content = report_content.replace('{tools_list}', tools_list_str)
    report_content = report_content.replace('{cve_details}', cve_details_str)
    report_content = report_content.replace('{keyword_details}', keyword_details_str)
    report_content = report_content.replace('{tools_details}', tools_details_str)
    report_content = report_content.replace('{tags}', tags_formatted)
    
    # 保存报告
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    # 创建GitHub Issue
    create_github_issue(today, report_content)
    
    # 生成HTML日报
    html_report_path = os.path.join(daily_dir, f'Daily_{today}.html')
    generate_html_report(today, report_content, html_report_path)
    
    # 更新index.html
    update_index_html(archive_dir)
    
    # 推送日报到discard
    app_name = load_config()[0]
    if app_name == "discard" and GLOBAL_CONFIG['push_channel']['send_daily_report'] == 1:
        text = f"GitHub监控日报·{today}"
        msg = f"共收集到 {total_count} 条更新，其中CVE {cve_count} 条，关键字监控 {keyword_count} 条，红队工具 {tools_count} 条"
        discard(text, msg, load_config()[2], is_daily_report=True, html_file=html_report_path, markdown_content=report_content)
    
    print(f"日报已生成: {report_path}")
    print(f"HTML日报已生成: {html_report_path}")
    return report_path

# 生成HTML日报
def generate_html_report(date, markdown_content, output_path):
    """将Markdown格式的日报转换为HTML格式"""
    import markdown
    from jinja2 import Template
    
    # 定义HTML模板
    html_template = """
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{ title }}</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }
            
            header {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                color: #333;
                padding: 30px;
                border-radius: 16px;
                text-align: center;
                margin-bottom: 30px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                animation: fadeInDown 0.6s ease-out;
            }
            
            h1 {
                margin: 0;
                font-size: 2.5rem;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 10px;
            }
            
            h2 {
                color: #667eea;
                border-bottom: 2px solid #667eea;
                padding-bottom: 10px;
                margin-top: 30px;
                margin-bottom: 20px;
                font-size: 1.8rem;
            }
            
            h3 {
                color: #333;
                margin-top: 20px;
                margin-bottom: 15px;
                font-size: 1.4rem;
            }
            
            ul {
                list-style-type: none;
                padding: 0;
            }
            
            li {
                margin-bottom: 15px;
                padding: 15px;
                background-color: white;
                border-radius: 12px;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
                transition: transform 0.3s ease, box-shadow 0.3s ease;
            }
            
            li:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
            }
            
            a {
                color: #667eea;
                text-decoration: none;
                font-weight: 500;
                transition: color 0.3s ease;
            }
            
            a:hover {
                color: #764ba2;
                text-decoration: underline;
            }
            
            .stats {
                display: flex;
                justify-content: space-around;
                margin: 30px 0;
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                padding: 30px;
                border-radius: 16px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                animation: fadeInUp 0.6s ease-out 0.2s both;
            }
            
            .stat-item {
                text-align: center;
                flex: 1;
                padding: 0 20px;
            }
            
            .stat-item:not(:last-child) {
                border-right: 1px solid #e0e0e0;
            }
            
            .stat-number {
                font-size: 2.8rem;
                font-weight: bold;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 5px;
            }
            
            .stat-label {
                color: #666;
                font-size: 1.1rem;
                font-weight: 500;
            }
            
            .details {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                padding: 30px;
                border-radius: 16px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                margin-bottom: 30px;
                animation: fadeInUp 0.6s ease-out 0.4s both;
            }
            
            footer {
                text-align: center;
                margin-top: 50px;
                color: white;
                font-size: 1rem;
                background: rgba(0, 0, 0, 0.1);
                padding: 20px;
                border-radius: 12px;
                animation: fadeIn 0.6s ease-out 0.6s both;
            }
            
            /* 动画效果 */
            @keyframes fadeInDown {
                from {
                    opacity: 0;
                    transform: translateY(-30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            @keyframes fadeIn {
                from {
                    opacity: 0;
                }
                to {
                    opacity: 1;
                }
            }
            
            /* 响应式设计 */
            @media (max-width: 768px) {
                body {
                    padding: 10px;
                }
                
                h1 {
                    font-size: 2rem;
                }
                
                h2 {
                    font-size: 1.5rem;
                }
                
                h3 {
                    font-size: 1.2rem;
                }
                
                .stats {
                    flex-direction: column;
                    gap: 20px;
                    padding: 20px;
                }
                
                .stat-item:not(:last-child) {
                    border-right: none;
                    border-bottom: 1px solid #e0e0e0;
                    padding-bottom: 20px;
                }
                
                .details {
                    padding: 20px;
                }
                
                header {
                    padding: 20px;
                }
            }
            
            /* 卡片悬停效果 */
            .card {
                transition: all 0.3s ease;
            }
            
            .card:hover {
                transform: translateY(-5px);
                box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15);
            }
            
            /* 生成时间样式 */
            .generate-time {
                color: #666;
                font-size: 1rem;
                font-weight: 500;
            }
        </style>
    </head>
    <body>
        <header>
            <h1>{{ title }}</h1>
            <p class="generate-time">生成时间: {{ generate_time }}</p>
        </header>
        
        <div class="stats card">
            <div class="stat-item">
                <div class="stat-number">{{ total_count }}</div>
                <div class="stat-label">总更新数</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{{ cve_count }}</div>
                <div class="stat-label">CVE数</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{{ keyword_count }}</div>
                <div class="stat-label">关键字监控数</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{{ tools_count }}</div>
                <div class="stat-label">红队工具数</div>
            </div>
        </div>
        
        <div class="details card">
            {{ content | safe }}
        </div>
        
        <footer>
            <p style="text-align: center; margin: 0;">Power By 东方隐侠安全团队·Anonymous@ <a href="https://www.dfyxsec.com/" style="color: white; text-decoration: underline;">隐侠安全客栈</a></p>
        </footer>
    </body>
    </html>
    """
    
    try:
        # 解析Markdown内容，提取统计数据
        total_count = 0
        cve_count = 0
        keyword_count = 0
        tools_count = 0
        
        # 从Markdown中提取统计数据
        import re
        total_match = re.search(r'总更新数量：(\d+)', markdown_content)
        if total_match:
            total_count = total_match.group(1)
        
        cve_match = re.search(r'CVE数量：(\d+)', markdown_content)
        if cve_match:
            cve_count = cve_match.group(1)
        
        keyword_match = re.search(r'关键字监控数量：(\d+)', markdown_content)
        if keyword_match:
            keyword_count = keyword_match.group(1)
        
        tools_match = re.search(r'红队工具更新数量：(\d+)', markdown_content)
        if tools_match:
            tools_count = tools_match.group(1)
        
        # 将Markdown转换为HTML
        html_content = markdown.markdown(markdown_content)
        
        # 渲染HTML模板
        template = Template(html_template)
        html_output = template.render(
            title=f"GitHub监控日报 {date}",
            generate_time=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            total_count=total_count,
            cve_count=cve_count,
            keyword_count=keyword_count,
            tools_count=tools_count,
            content=html_content
        )
        
        # 保存HTML文件
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_output)
        
        print(f"HTML日报已生成: {output_path}")
    except Exception as e:
        print(f"生成HTML日报失败: {e}")

# 更新index.html

def update_index_html(archive_dir):
    """更新Github监控页"""
    from jinja2 import Template
    
    # 定义index.html模板
    index_template = """
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>GitHub监控日报</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }
            
            header {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                color: #333;
                padding: 30px;
                border-radius: 16px;
                text-align: center;
                margin-bottom: 30px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                animation: fadeInDown 0.6s ease-out;
            }
            
            h1 {
                margin: 0;
                font-size: 2.5rem;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 10px;
            }
            
            h2 {
                color: #667eea;
                margin-bottom: 20px;
                font-size: 1.8rem;
            }
            
            main {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                padding: 30px;
                border-radius: 16px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                animation: fadeInUp 0.6s ease-out 0.2s both;
            }
            
            .report-list {
                list-style: none;
                padding: 0;
            }
            
            .report-item {
                background-color: white;
                padding: 20px;
                margin-bottom: 15px;
                border-radius: 12px;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
                transition: transform 0.3s ease, box-shadow 0.3s ease;
                animation: fadeInUp 0.6s ease-out 0.3s both;
            }
            
            .report-item:hover {
                transform: translateY(-5px);
                box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
            }
            
            .report-link {
                color: #667eea;
                text-decoration: none;
                font-size: 1.3rem;
                font-weight: bold;
                transition: color 0.3s ease;
            }
            
            .report-link:hover {
                color: #764ba2;
                text-decoration: underline;
            }
            
            .report-info {
                color: #666;
                font-size: 1rem;
                margin-top: 5px;
            }
            
            footer {
                text-align: center;
                margin-top: 50px;
                color: white;
                font-size: 1rem;
                background: rgba(0, 0, 0, 0.1);
                padding: 20px;
                border-radius: 12px;
                animation: fadeIn 0.6s ease-out 0.6s both;
            }
            
            /* 动画效果 */
            @keyframes fadeInDown {
                from {
                    opacity: 0;
                    transform: translateY(-30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            @keyframes fadeIn {
                from {
                    opacity: 0;
                }
                to {
                    opacity: 1;
                }
            }
            
            /* 响应式设计 */
            @media (max-width: 768px) {
                body {
                    padding: 10px;
                }
                
                h1 {
                    font-size: 2rem;
                }
                
                h2 {
                    font-size: 1.5rem;
                }
                
                main {
                    padding: 20px;
                }
                
                .report-item {
                    padding: 15px;
                }
                
                .report-link {
                    font-size: 1.1rem;
                }
                
                header {
                    padding: 20px;
                }
            }
        </style>
    </head>
    <body>
        <header>
            <h1>GitHub监控日报</h1>
            <div>每日Github监控汇总</div>
        </header>
        
        <main>
            <h2>Github监控</h2>
            <ul class="report-list">
                {% for report in reports %}
                <li class="report-item">
                    <a href="archive/{{ report.date }}/{{ report.path }}" class="report-link" target="_blank">{{ report.date }}</a>
                    <div class="report-info">总更新数: {{ report.total_count }} | CVE数: {{ report.cve_count }} | 关键字监控数: {{ report.keyword_count }} | 红队工具更新数: {{ report.tools_count }}</div>
                </li>
                {% endfor %}
            </ul>
        </main>
        
        <footer>
            <p style="text-align: center; margin: 0;">Power By 东方隐侠安全团 队·Anonymous@ <a href="https://www.dfyxsec.com/" style="color: white; text-decoration: underline;">隐侠安全客栈</a></p>
        </footer>
    </body>
    </html>
    """
    
    try:
        # 获取所有已生成的日报
        import os
        import re
        reports = []
        report_dict = {}  # 使用字典确保每个日期只有一个条目
        
        if os.path.exists(archive_dir):
            # 遍历archive目录下的所有子目录
            for root, dirs, files in os.walk(archive_dir):
                # 遍历所有HTML文件
                for filename in files:
                    if filename.endswith('.html') and filename.startswith('Daily_'):
                        date = filename[6:-5]  # 提取日期部分
                        file_path = os.path.join(root, filename)
                        
                        # 读取HTML文件，提取统计信息
                        total_count = 0
                        cve_count = 0
                        keyword_count = 0
                        tools_count = 0
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                # 从HTML中提取统计数据
                                total_match = re.search(r'总更新数量.*?(\d+)', content)
                                if total_match:
                                    total_count = total_match.group(1)
                                
                                cve_match = re.search(r'CVE数量.*?(\d+)', content)
                                if cve_match:
                                    cve_count = cve_match.group(1)
                                
                                keyword_match = re.search(r'关键字监控数量.*?(\d+)', content)
                                if keyword_match:
                                    keyword_count = keyword_match.group(1)
                                
                                tools_match = re.search(r'红队工具更新数量.*?(\d+)', content)
                                if tools_match:
                                    tools_count = tools_match.group(1)
                        except Exception as e:
                            print(f"读取日报文件 {file_path} 失败: {e}")
                        
                        # 将日报信息添加到字典中，相同日期会覆盖旧条目
                        report_dict[date] = {
                            'date': date,
                            'path': filename,
                            'total_count': total_count,
                            'cve_count': cve_count,
                            'keyword_count': keyword_count,
                            'tools_count': tools_count
                        }
            
            # 将字典转换为列表
            reports = list(report_dict.values())
            # 按日期降序排序
            reports.sort(key=lambda x: x['date'], reverse=True)
        
        # 渲染index.html
        template = Template(index_template)
        html_content = template.render(reports=reports)
        
        # 写入index.html文件到根目录
        index_path = os.path.join(os.path.dirname(archive_dir), 'index.html')
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"index.html已更新: {index_path}")
    except Exception as e:
        print(f"更新index.html失败: {e}")

# 创建GitHub Issue
def create_github_issue(title, body):
    import os
    import requests
    
    # 获取GitHub Token，优先使用环境变量，其次使用全局配置
    github_token = os.environ.get('GITHUB_TOKEN')
    
    # 如果环境变量中没有，尝试使用全局配置中的token
    if not github_token:
        global GLOBAL_CONFIG
        github_token = GLOBAL_CONFIG['github_token']
        
    if not github_token:
        print("[+] No GITHUB_TOKEN found, skipping GitHub issue creation")
        return
    
    # 获取仓库信息
    repo_full_name = os.environ.get('GITHUB_REPOSITORY')
    if not repo_full_name:
        print("[+] No GITHUB_REPOSITORY found, skipping GitHub issue creation")
        return
    
    # 定义issue标题
    issue_title = f'当日情报_{title}'
    
    # 请求头
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'GitHub-Monitor-Script'
    }
    
    # GitHub API URL
    repo_url = f"https://api.github.com/repos/{repo_full_name}"
    
    try:
        # 1. 检查是否已存在当日的日报issue
        search_url = f"{repo_url}/issues"
        search_params = {
            'state': 'all',
            'title': issue_title,
            'labels': '日报,自动生成',
            'per_page': 1
        }
        
        # 发送搜索请求
        response = requests.get(search_url, params=search_params, headers=headers, timeout=10)
        response.raise_for_status()
        existing_issues = response.json()
        
        if existing_issues and len(existing_issues) > 0:
            # 2. 如果已存在，更新issue内容
            existing_issue = existing_issues[0]
            issue_url = f"{repo_url}/issues/{existing_issue['number']}"
            update_data = {
                'body': body
            }
            response = requests.patch(issue_url, json=update_data, headers=headers, timeout=10)
            response.raise_for_status()
            updated_issue = response.json()
            print(f"[+] Updated existing GitHub issue: {updated_issue['html_url']}")
        else:
            # 3. 如果不存在，创建新issue
            create_url = f"{repo_url}/issues"
            create_data = {
                'title': issue_title,
                'body': body,
                'labels': ['日报', '自动生成']
            }
            response = requests.post(create_url, json=create_data, headers=headers, timeout=10)
            response.raise_for_status()
            new_issue = response.json()
            print(f"[+] Created new GitHub issue: {new_issue['html_url']}")
    except requests.exceptions.HTTPError as e:
        print(f"[-] HTTP error with GitHub issue: {e.response.status_code} - {e.response.text}")
    except Exception as e:
        print(f"[-] Failed to process GitHub issue: {e}")

#main函数
if __name__ == '__main__':
    print("cve 、github 工具 和 大佬仓库 监控中 ...")
    #初始化部分
    create_database()
    # 主动加载黑名单配置，确保日志显示
    load_black_user()
    
    # 输出配置信息
    print("\n=== GitHub 监控配置 ===")
    print("配置加载成功！")
    print(f"推送渠道类型: {GLOBAL_CONFIG['push_channel']['type']}")
    print(f"推送开关: {GLOBAL_CONFIG['workflow']['push_switch']}")
    print(f"日报开关: {GLOBAL_CONFIG['workflow']['daily_report_switch']}")
    print(f"夜间休眠开关: {GLOBAL_CONFIG['workflow']['night_sleep_switch']}")
    print(f"翻译功能: {GLOBAL_CONFIG['translate']}")
    
    # 检查是否在GitHub Actions环境中运行
    is_github_actions = os.environ.get('GITHUB_ACTIONS') == 'true'
    
    # 发送缓存的消息（如果有）
    if not is_github_actions:
        sent_count = send_cached_messages()
        if sent_count > 0:
            print(f"[+] 已发送 {sent_count} 条缓存消息")
    
    # 如果在GitHub Actions中，只执行一次
    if is_github_actions:
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
        if GLOBAL_CONFIG['workflow']['daily_report_switch'] == 'ON':
            generate_daily_report(today_cve_data, all_today_keyword_data, data3)
        else:
            print("[+] 日报生成已关闭")

        print("\r\n\t\t  监控完成！ \t\t\r\n")
    else:
        # 本地运行时，循环执行
        while True:
            # 夜间休眠检查
            if is_night_time():
                import datetime
                beijing_tz = pytz.timezone('Asia/Shanghai')
                now = datetime.datetime.now(beijing_tz)
                next_morning = now.replace(hour=7, minute=0, second=0, microsecond=0)
                sleep_seconds = (next_morning - now).total_seconds()
                print(f"[+] 当前为夜间时间 {now.strftime('%H:%M:%S')}，程序将休眠至早上7点，预计休眠 {sleep_seconds/3600:.1f} 小时")
                time.sleep(sleep_seconds)
            
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
            if GLOBAL_CONFIG['workflow']['daily_report_switch'] == 'ON':
                generate_daily_report(today_cve_data, all_today_keyword_data, data3)
            else:
                print("[+] 日报生成已关闭")

            print("\r\n\t\t  等待下一次监控... \t\t\r\n")
            time.sleep(5*60)
