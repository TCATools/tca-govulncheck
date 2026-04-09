# -*- encoding: utf-8 -*-
'''
Tca Govulncheck Plugin
'''
import os
import re
import json
import platform
import subprocess

PWD = os.getcwd()
WOORK_DIR = os.environ.get("RESULT_DIR")
SOURCE_DIR = os.environ.get("SOURCE_DIR")

VULN_RE = re.compile(r'Vulnerability #(\d+):')

def decode_str(text) -> str:
    try:
        return text.decode(encoding='UTF-8')
    except UnicodeDecodeError:
        return text.decode(encoding="gbk", errors="surrogateescape")

def get_task_params():
    """
    获取需要任务参数
    :return:
    """
    task_request_file = os.environ["TASK_REQUEST"]
    with open(task_request_file, "r") as rf:
        task_request = json.load(rf)
    task_params = task_request["task_params"]
    return task_params

class Govulncheck():

    def __init__(self, params):
        self.params = params
        self.tool = self._get_tool()

    def _get_tool(self) -> str:
        system = platform.system()
        if system == "Linux":
            if platform.machine() == "aarch64":
                return os.path.join(PWD, "bin", "linux", "arm64", "govulncheck")
            else:
                return os.path.join(PWD, "bin", "linux", "amd64", "govulncheck")
        elif system == "Darwin":
            return os.path.join(PWD, "bin", "darwin", "amd64", "govulncheck")
        elif system == "Windows":
            return os.path.join(PWD, "bin", "windows", "amd64", "govulncheck.exe")
        else:
            raise Exception("未支持的系统平台或者无法识别的系统平台")


    def __vuln_handle(self, section, cwd, end):
        issues = []
        stat = 0
        flag = False
        for line in section.splitlines():
            math = VULN_RE.match(line)
            if math:
                rule_name = line.split(":")[1].strip()
                print("find Vulnerability : ", rule_name)
                stat = math.end()
                continue
            if line.find("Example traces found:") != -1:
                flag = True
                continue
            if flag and stat != 0:
                try:
                    infos = line.split(":")
                    issue_file = infos[1].strip()
                    issue_file = os.path.join(cwd, issue_file)
                    issue_line = infos[2].strip()
                    issue_col = infos[3].strip()
                    issue_msg = infos[4].strip()
                    issue_msg = issue_msg + '\n' + section[stat:end]
                    issues.append({"path": issue_file, "rule": "GO-Vulnerability", "msg": issue_msg, "line": issue_line, "column": issue_col})
                except:
                    print("unmatched output : ", line)
        return issues

    def __get_scan_path(self) -> list:
        relpos = len(SOURCE_DIR) + 1
        mods = []
        for dirpath, _, _ in os.walk(SOURCE_DIR):
            if os.path.exists(os.path.join(dirpath, "go.mod")):
                mods.append(dirpath)
        if not mods:
            # 没有发现gomod 的情况下默认使用根目录检查
            return [SOURCE_DIR]
        re_path_include = self.params["path_filters"].get("re_inclusion", [])
        re_path_exclude = self.params["path_filters"].get("re_exclusion", ["vendors/.*", ".*/vendors/.*"])
        re_inc = "|".join(re_path_include)
        re_exp = "|".join(re_path_exclude)
        re_inc_compile = re.compile(re_inc) if re_inc else None
        re_exp_compile = re.compile(re_exp)
        mod_dirs = []
        for mod in mods:
            rel_mod = mod[relpos:] + os.path.sep + "go.mod"
            if re_exp_compile.fullmatch(rel_mod):
                continue
            if re_inc_compile:
                if re_inc_compile.fullmatch(rel_mod):
                    mod_dirs.append(mod)
            else:
                mod_dirs.append(mod)
        return mod_dirs


    def analyze(self) -> list:
        print("当前使用的工具：" + self.tool)
        issues = []
        issues_file = os.path.join(WOORK_DIR, "govulncheck-result.txt")
        db_path = os.path.join(PWD, "vulndb")
        scan_cmd = [self.tool, "-db", f"file://{db_path}"]
        mod_dirs = self.__get_scan_path()
        print("go mod dirs: " + " ".join(mod_dirs))
        scan_path = self.params.get("scan_path", "/")
        scan_go_pattern = ["./..."]
        # 设置了扫描目录
        if scan_path != "/":
            # 根据 scan_path 下是否存在 go.mod 来决定是include目录还是子模块
            if os.path.exists(os.path.join(SOURCE_DIR, scan_path, "go.mod")):
                mod_dirs = [os.path.join(SOURCE_DIR, scan_path)]
            else:
                scan_go_pattern = [scan_path + "/..."]
        scan_cmd.extend(scan_go_pattern)
        for cwd in mod_dirs:
            print("govunlncheck 将会分析目录 : ", cwd)
            with open(issues_file, "w") as fw:
                sp = subprocess.Popen(scan_cmd, cwd=cwd, stdout=fw, stderr=subprocess.PIPE)
                _, stderr = sp.communicate(timeout=int(os.environ.get("TCA_TASK_TIMEOUT", "6000")))
            if stderr:
                stderr_str = decode_str(stderr)
                print(stderr_str)
            try:
                # 分析异常时可能生成空文件导致读取异常
                with open(issues_file, "r") as fr:
                    datas = fr.read()
                # 无问题时datas为None
                if not datas:
                    print("datas is None")
                    continue
                for section in datas.split("\n\n"):
                    if section.find("Example traces found:") != -1:
                        issues.extend(self.__vuln_handle(section, cwd, section.find("Example traces found:")))
                    elif VULN_RE.match(section):
                        i_file = os.path.join(cwd, "go.mod")
                        rule_msg = section.splitlines()[0]
                        i_rule = rule_msg.split(":")[1].strip()
                        stat = VULN_RE.match(rule_msg).end()
                        issues.append({"path": i_file, "rule": "GO-Vulnerability", "msg": section[stat:], "line": 0})
                    else:
                        for line in section.splitlines():
                            print(line)
            except Exception as err:
                print(f"解析结果异常: {err}")
        return issues


if __name__ == "__main__":
    params = get_task_params()
    tool = Govulncheck(params)
    result_file = os.path.join(WOORK_DIR, "result.json")
    issues = tool.analyze()
    with open(result_file, "w") as fw:
        json.dump(issues, fw, indent=2)
