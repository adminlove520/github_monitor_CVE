#!/bin/bash
# GitHub CVE监控脚本部署启动脚本
# 功能：启动Python监控脚本，日志按日期分割存储在当前目录log文件夹

# ===================== 配置项 =====================
# Python脚本名称（可根据实际修改）
PYTHON_SCRIPT="github_cve_monitor.py"
# 日志根目录（当前目录下的log文件夹）
LOG_DIR="./log"

# 缓存目录（当前目录下的cache文件夹）
CACHE_DIR="./cache"
# Python解释器路径（可根据实际修改，如/usr/bin/python3）
PYTHON_CMD="python3"
# 进程PID存储文件
PID_FILE="${LOG_DIR}/github_cve_monitor.pid"
# ===================== 函数定义 =====================

# 检查脚本依赖
check_deps() {
    # 检查Python是否存在
    if ! command -v ${PYTHON_CMD} &> /dev/null; then
        echo "错误：未找到${PYTHON_CMD}，请先安装Python3或修改脚本中的PYTHON_CMD配置"
        exit 1
    fi

    # 检查目标Python脚本是否存在
    if [ ! -f "${PYTHON_SCRIPT}" ]; then
        echo "错误：未找到Python脚本${PYTHON_SCRIPT}，请确认脚本路径是否正确"
        exit 1
    fi

    # 创建日志目录和缓存目录（不存在则创建）
    if [ ! -d "${LOG_DIR}" ]; then
        mkdir -p "${LOG_DIR}"
        echo "信息：日志目录${LOG_DIR}已创建"
    fi
    
    # 创建缓存目录
    if [ ! -d "${CACHE_DIR}" ]; then
        mkdir -p "${CACHE_DIR}"
        echo "信息：缓存目录${CACHE_DIR}已创建"
    fi
}

# 停止已有进程
stop_process() {
    if [ -f "${PID_FILE}" ]; then
        OLD_PID=$(cat "${PID_FILE}")
        # 检查进程是否存在
        if ps -p ${OLD_PID} &> /dev/null; then
            echo "信息：正在停止已有进程（PID: ${OLD_PID}）"
            kill ${OLD_PID}
            # 等待进程退出
            sleep 2
            # 强制杀死未退出的进程
            if ps -p ${OLD_PID} &> /dev/null; then
                kill -9 ${OLD_PID}
                echo "信息：强制终止进程（PID: ${OLD_PID}）"
            fi
        fi
        rm -f "${PID_FILE}"
    fi
}

# 启动进程
start_process() {
    # 按日期生成日志文件名（格式：YYYY-MM-DD-github_cve_monitor.log）
    LOG_FILE="${LOG_DIR}/$(date +%Y-%m-%d)-github_cve_monitor.log"
    # 错误日志重定向到同日期的error.log
    ERROR_LOG_FILE="${LOG_DIR}/$(date +%Y-%m-%d)-github_cve_monitor-error.log"

    echo "信息：启动Python脚本，日志文件：${LOG_FILE}"
    # nohup启动，标准输出和标准错误分别重定向到按日期命名的日志文件
    nohup ${PYTHON_CMD} ${PYTHON_SCRIPT} >> ${LOG_FILE} 2>> ${ERROR_LOG_FILE} &
    # 保存进程PID
    echo $! > ${PID_FILE}
    echo "信息：脚本启动成功，PID: $(cat ${PID_FILE})"
}

# 查看运行状态
check_status() {
    if [ -f "${PID_FILE}" ]; then
        CURRENT_PID=$(cat "${PID_FILE}")
        if ps -p ${CURRENT_PID} &> /dev/null; then
            echo "状态：脚本正在运行（PID: ${CURRENT_PID}）"
            echo "日志目录：${LOG_DIR}"
            echo "最新日志：${LOG_DIR}/$(date +%Y-%m-%d)-github_cve_monitor.log"
        else
            echo "状态：脚本已退出（PID文件存在但进程不存在）"
            rm -f ${PID_FILE}
        fi
    else
        echo "状态：脚本未运行"
    fi
}

# ===================== 主逻辑 =====================
case "$1" in
    start)
        check_deps
        stop_process  # 先停止已有进程
        start_process
        ;;
    stop)
        stop_process
        echo "信息：脚本已停止"
        ;;
    restart)
        check_deps
        stop_process
        sleep 1
        start_process
        ;;
    status)
        check_status
        ;;
    *)
        echo "使用方法：$0 {start|stop|restart|status}"
        echo "示例："
        echo "  启动脚本：$0 start"
        echo "  停止脚本：$0 stop"
        echo "  重启脚本：$0 restart"
        echo "  查看状态：$0 status"
        exit 1
        ;;
esac

exit 0
