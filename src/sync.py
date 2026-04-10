# -*- encoding: utf-8 -*-
"""
Go 漏洞数据库同步脚本
每周从 https://vuln.go.dev 检查并更新本地漏洞数据库
"""
import os
import json
import shutil
import zipfile
import tempfile
import logging
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# 远程漏洞数据库地址
REMOTE_DB_INDEX_URL = "https://vuln.go.dev/index/db.json"
REMOTE_VULNDB_ZIP_URL = "https://vuln.go.dev/vulndb.zip"

# 本地路径
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL_VULNDB_DIR = os.path.join(BASE_DIR, "vulndb")
LOCAL_DB_INDEX_FILE = os.path.join(LOCAL_VULNDB_DIR, "index", "db.json")

# 请求超时时间（秒）
REQUEST_TIMEOUT = 60
# 下载超时时间（秒）
DOWNLOAD_TIMEOUT = 600

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


def get_local_modified_time() -> str:
    """
    获取本地漏洞数据库的最后修改时间
    :return: ISO 8601 格式的时间字符串，如果本地文件不存在则返回空字符串
    """
    if not os.path.exists(LOCAL_DB_INDEX_FILE):
        logger.info("本地索引文件不存在: %s", LOCAL_DB_INDEX_FILE)
        return ""
    try:
        with open(LOCAL_DB_INDEX_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("modified", "")
    except (json.JSONDecodeError, IOError) as e:
        logger.warning("读取本地索引文件失败: %s", e)
        return ""


def get_remote_modified_time() -> str:
    """
    从远程获取漏洞数据库的最后修改时间
    :return: ISO 8601 格式的时间字符串
    :raises: Exception 当请求失败时
    """
    logger.info("正在获取远程索引: %s", REMOTE_DB_INDEX_URL)
    req = Request(REMOTE_DB_INDEX_URL, headers={"User-Agent": "tca-govulncheck-plugin/1.0"})
    try:
        with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        remote_modified = data.get("modified", "")
        logger.info("远程数据库最后修改时间: %s", remote_modified)
        return remote_modified
    except (HTTPError, URLError) as e:
        raise Exception(f"获取远程索引失败: {e}") from e


def parse_iso_time(time_str: str) -> datetime:
    """
    解析 ISO 8601 时间字符串为 datetime 对象
    :param time_str: ISO 8601 格式的时间字符串
    :return: datetime 对象（UTC）
    """
    # 兼容多种 ISO 8601 格式
    time_str = time_str.replace("Z", "+00:00")
    return datetime.fromisoformat(time_str)


def need_update(local_modified: str, remote_modified: str) -> bool:
    """
    判断是否需要更新漏洞数据库
    :param local_modified: 本地修改时间
    :param remote_modified: 远程修改时间
    :return: 是否需要更新
    """
    if not local_modified:
        logger.info("本地无索引记录，需要更新")
        return True
    if not remote_modified:
        logger.warning("远程索引无修改时间，跳过更新")
        return False
    try:
        local_time = parse_iso_time(local_modified)
        remote_time = parse_iso_time(remote_modified)
        if remote_time > local_time:
            logger.info("远程数据库有更新 (本地: %s, 远程: %s)", local_modified, remote_modified)
            return True
        else:
            logger.info("本地数据库已是最新 (本地: %s, 远程: %s)", local_modified, remote_modified)
            return False
    except (ValueError, TypeError) as e:
        logger.warning("时间解析失败: %s，将执行更新", e)
        return True


def download_and_extract_vulndb(remote_modified: str):
    """
    下载远程漏洞数据库 zip 并解压到本地 vulndb 目录
    :param remote_modified: 远程修改时间，用于更新本地索引
    """
    tmp_dir = tempfile.mkdtemp(prefix="govulndb_")
    zip_path = os.path.join(tmp_dir, "vulndb.zip")
    extract_dir = os.path.join(tmp_dir, "vulndb_extracted")

    try:
        # 1. 下载 zip 文件
        logger.info("正在下载漏洞数据库: %s", REMOTE_VULNDB_ZIP_URL)
        req = Request(REMOTE_VULNDB_ZIP_URL, headers={"User-Agent": "tca-govulncheck-plugin/1.0"})
        with urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
            with open(zip_path, "wb") as f:
                while True:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    f.write(chunk)
        zip_size = os.path.getsize(zip_path)
        logger.info("下载完成，文件大小: %.2f MB", zip_size / (1024 * 1024))

        # 2. 解压 zip 文件
        logger.info("正在解压漏洞数据库...")
        os.makedirs(extract_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_dir)
        logger.info("解压完成")

        # 3. 查找解压后的 vulndb 根目录
        #    zip 内可能直接是文件，也可能有一层目录包裹
        extracted_vulndb = _find_vulndb_root(extract_dir)

        # 4. 备份并替换本地 vulndb 目录
        backup_dir = LOCAL_VULNDB_DIR + ".bak"
        if os.path.exists(backup_dir):
            shutil.rmtree(backup_dir)
        if os.path.exists(LOCAL_VULNDB_DIR):
            logger.info("备份旧数据库到: %s", backup_dir)
            shutil.move(LOCAL_VULNDB_DIR, backup_dir)

        logger.info("更新本地漏洞数据库...")
        shutil.copytree(extracted_vulndb, LOCAL_VULNDB_DIR)

        # 5. 确保 index 目录和 db.json 存在，并写入最新的 modified 时间
        index_dir = os.path.join(LOCAL_VULNDB_DIR, "index")
        os.makedirs(index_dir, exist_ok=True)
        db_index_path = os.path.join(index_dir, "db.json")
        # 如果解压后已有 db.json，读取并保留；否则写入远程的 modified 时间
        if os.path.exists(db_index_path):
            logger.info("解压后已包含 index/db.json")
        else:
            with open(db_index_path, "w", encoding="utf-8") as f:
                json.dump({"modified": remote_modified}, f)
            logger.info("已写入索引文件: %s", db_index_path)

        # 6. 清理备份
        if os.path.exists(backup_dir):
            shutil.rmtree(backup_dir)
            logger.info("已清理备份目录")

        logger.info("漏洞数据库更新成功！")

    except Exception as e:
        # 更新失败时尝试恢复备份
        backup_dir = LOCAL_VULNDB_DIR + ".bak"
        if os.path.exists(backup_dir):
            if os.path.exists(LOCAL_VULNDB_DIR):
                shutil.rmtree(LOCAL_VULNDB_DIR)
            shutil.move(backup_dir, LOCAL_VULNDB_DIR)
            logger.info("更新失败，已恢复备份")
        raise Exception(f"下载或解压漏洞数据库失败: {e}") from e
    finally:
        # 清理临时目录
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)


def _find_vulndb_root(extract_dir: str) -> str:
    """
    在解压目录中查找 vulndb 的根目录
    zip 解压后可能直接包含 ID/ 等目录，也可能有一层包裹目录
    :param extract_dir: 解压目录
    :return: vulndb 根目录路径
    """
    # 检查解压目录下是否直接包含 ID 目录（vulndb 的标志性子目录）
    if os.path.isdir(os.path.join(extract_dir, "ID")):
        return extract_dir

    # 检查是否有一层包裹目录
    entries = os.listdir(extract_dir)
    if len(entries) == 1:
        candidate = os.path.join(extract_dir, entries[0])
        if os.path.isdir(candidate):
            if os.path.isdir(os.path.join(candidate, "ID")):
                return candidate
            # 可能还有一层
            sub_entries = os.listdir(candidate)
            if len(sub_entries) == 1:
                sub_candidate = os.path.join(candidate, sub_entries[0])
                if os.path.isdir(sub_candidate) and os.path.isdir(os.path.join(sub_candidate, "ID")):
                    return sub_candidate

    # 如果找不到 ID 目录，直接返回解压目录
    logger.warning("未在解压目录中找到标准的 vulndb 结构（ID/ 目录），将直接使用解压目录")
    return extract_dir


def sync_vulndb():
    """
    同步漏洞数据库的主函数
    检查远程是否有更新，如果有则下载并更新本地数据库
    """
    logger.info("=" * 50)
    logger.info("开始检查 Go 漏洞数据库更新...")
    logger.info("本地数据库路径: %s", LOCAL_VULNDB_DIR)

    try:
        # 获取本地和远程的修改时间
        local_modified = get_local_modified_time()
        remote_modified = get_remote_modified_time()

        # 判断是否需要更新
        if need_update(local_modified, remote_modified):
            download_and_extract_vulndb(remote_modified)
        else:
            logger.info("无需更新")

    except Exception as e:
        logger.error("同步漏洞数据库失败: %s", e)
        raise

    logger.info("检查完成")
    logger.info("=" * 50)


if __name__ == "__main__":
    sync_vulndb()
