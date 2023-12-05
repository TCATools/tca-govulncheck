# -*- encoding: utf8 -*-
import json
import os
import re
import subprocess
import tempfile
import platform


VULN_RE = re.compile(r'Vulnerability #(\d+):')

pwd = os.getcwd()
source_dir = os.getenv("SOURCE_DIR")
# export
system = platform.system()
tool_bin = ""
if system == "Linux":
    tool_bin = pwd + r'/tool/linux/govulncheck'
elif system == "Darwin":
    too_bin = pwd + r'/tool/mac/govulncheck'
else:
    raise "未支持的平台或者无法识别的平台"


def get_task_params():
    """
    获取需要任务参数
    """
    task_request_file = os.environ.get("TASK_REQUEST")
    with open(task_request_file, 'r') as fr:
        task_request = json.load(fr)
    task_params = task_request["task_params"]
    return task_params

class Invocation(object):
    def __init__(self, params):
        self.params = params

    def scan_path(self):
        mod_path = []
        for dirpath, dirs, filenames in os.walk(source_dir):
            for i in dirs:
                if os.path.exists(os.path.join(dirpath, i, "go.mod")):
                    mod_path.append(os.path.join(dirpath, i))
        if not mod_path:
            # 没有发现gomod 的情况下默认使用根目录检查
            mod_path = [source_dir]
        path_include = self.params["path_filters"].get("inclusion", [])
        if path_include:
            include_mod_path = path_include.copy()
            for index, path in enumerate(include_mod_path):
                include_mod_path[index] = os.path.join(source_dir, path.replace("/*", ""))
            if set(include_mod_path).intersection(set(mod_path)):
                mod_path = list(set(include_mod_path).intersection(set(mod_path)))
        return mod_path

    def set_go(self):
        if system == "Linux":
            path = os.environ['PATH']
            os.environ['GOROOT'] = pwd + r'/tool/linux/go-1.21.0'
            if os.getenv("GOPATH"):
                print("GOPATH : ", os.getenv("GOPATH"))
            else:
                os.environ['GOPATH'] = pwd + r'/tool/linux/gopath'
                print("GOPATH : ", os.getenv("GOPATH"))
            os.environ['GOBIN'] = pwd + r'/tool/linux/gopath/bin'
            os.environ['PATH'] = pwd + r'/tool/linux/go-1.21.0/bin:' + pwd + r'/tool/linux/gopath/bin:' + path
            print("GOPROXY : ", os.getenv("GOPROXY"))
            print("GOROOT : ", os.getenv("GOROOT"))
            print("GOBIN : ", os.getenv("GOBIN"))
            print("PATH : ", os.getenv("PATH"))
            

    def check(self):
        """
        检查工具在当前机器环境下是否可用
        """
        model = os.environ.get("GOVULNCHECK_MODEL", "auto")
        if model.lower() == "auto":
            check_go = ['go', 'version']
            go_outfile = tempfile.TemporaryFile()
            try:
                go_process = subprocess.Popen(check_go,
                                              stdout=go_outfile,
                                              stderr=subprocess.STDOUT,
                                              shell=False)
                go_process.wait()
                go_outfile.seek(0)
                go_output = go_outfile.read().decode("utf-8")
                go_line = go_output.splitlines()[0]
                print(go_line)
                pattern = r"go(\d+\.\d+)"
                match = re.search(pattern, go_line)
                if match:
                    version = match.group(1)
                    if float(version) < 1.21:
                        self.set_go()
                else:
                    self.set_go()
            except:
                self.set_go()
        elif model.lower() == "off":
            self.set_go()
        check_cmd_args = ["govulncheck", "-version"]
        check_outfile = tempfile.TemporaryFile()
        check_process = subprocess.Popen(check_cmd_args,
                                         stdout=check_outfile,
                                         stderr=subprocess.STDOUT,
                                         shell=False)
        check_process.wait()
        check_outfile.seek(0)
        check_output = check_outfile.read().decode("utf-8")
        for check_line in check_output.splitlines():
            print(check_line)

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


    def run(self):
        pos = len(source_dir) + 1
        issues = []
        incr_scan = self.params["incr_scan"]
        diff_env = os.environ.get("DIFF_FILES", None)
        scan_cmd = "govulncheck ./..."
        print("scan_cmd : ", scan_cmd)
        scan_path = self.scan_path()
        for cwd in scan_path:
            print("govunlncheck 将会分析目录 : ", cwd)
            outfile = tempfile.TemporaryFile()
            process = subprocess.Popen(scan_cmd, cwd=cwd, stdout=outfile, stderr=subprocess.STDOUT, shell=True)
            process.wait()
            outfile.seek(0)
            try:
                output = outfile.read().decode("utf-8")
                outfile.close()
                for section in output.split("\n\n"):
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
            except UnicodeEncodeError:
                print("UnicodeEncodeError")
        with open("result.json", "w") as fp:
            json.dump(issues, fp, indent=2)


if __name__ == '__main__':
    print("--- start tool ---")
    params = get_task_params()
    tool = Invocation(params)
    print("--- check tool ---")
    tool.check()
    print("--- run tool ---")
    tool.run()
    print("--- end tool ---")