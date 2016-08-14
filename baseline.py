#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Linux基线扫描
# 基于 centos6.7完成
# author:End1ng

import paramiko
import logging
import re
import sys
from time import strftime

# 日志类
class classlog(object):
    """log class"""
    def __init__(self,logfilename="log.txt",level="INFO"):
        level = level if level in ['CRITICAL','ERROR','WARNING','INFO','DEBUG','NOTSET'] else 'INFO'
        self.logger = logging.getLogger("classlog")
        self.logger.setLevel(logging.DEBUG)
        Fileformatter = logging.Formatter("%(asctime)s - %(filename)s - %(levelname)-8s:%(message)s",
        datefmt='%Y-%m-%d %I:%M:%S %p')
        Streamformatter = logging.Formatter("%(asctime)s %(filename)s %(levelname)s:%(message)s",
        datefmt='%Y-%m-%d %I:%M:%S')# ,filename='example.log')

        Filelog = logging.FileHandler(logfilename)
        Filelog.setFormatter(Fileformatter)
        Filelog.setLevel(logging.DEBUG)

        Streamlog = logging.StreamHandler()
        Streamlog.setFormatter(Streamformatter)
        Streamlog.setLevel(level)

        self.logger.addHandler(Filelog)
        self.logger.addHandler(Streamlog)

    def debug(self,msg):
        self.logger.debug(msg)

    def info(self,msg):
        self.logger.info(msg)

    def warn(self,msg):
        self.logger.warn(msg)

    def error(self,msg):
        self.logger.error(msg)

    def critical(self,msg):
        self.logger.critical(msg)

# 扫描类 一台主机一个对象
class Base_Line(object):
    """docstring for Base_Line"""

    def __init__(self, ip, username, password, port=22, timeout=1):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh.connect(ip,port,username,password,timeout=timeout)
            LOG.info(u"登陆成功 " + username + "@" + ip)
        except:
            LOG.info(u"登陆失败 " + username + "@" + ip)
            return
        # 获取主机信息
        LOG.info("   version   " + self.run_command("cat /etc/issue.*")[0].strip())
        LOG.info("   hostname  " + self.run_command("uname -n")[0].strip())
        LOG.info("   osname    " + self.run_command("uname -s")[0].strip())
        LOG.info("   osversion " + self.run_command("uname -r")[0].strip())
        print

        # 开始检查
        self.run()

    def __del__(self):
        self.ssh.close()

    # 执行命令函数
    def run_command(self, command):
        stdin, stdout, stderr = self.ssh.exec_command(command)
        resrow = stdout.readlines()
        if resrow:
            return resrow
        return False

    # 获取配置
    def get_config(self, path, text):
        command = "cat " + path + " | grep \"" + text + "\""
        stdin, stdout, stderr = self.ssh.exec_command(command)
        resrow = stdout.readlines()
        if resrow:
            return resrow[0].strip()
        return False

    # 检查配置
    def check_config(self, doc, currow, path, text):
        resrow = self.get_config(path, text)
        if resrow:
            if resrow == currow:
                LOG.info(u"合格配置 " + doc + " " + currow)
            else:
                resrow = resrow.replace("/", "\/")
                LOG.info(u"发现配置 " + doc + " " + resrow.replace("\/", "/"))
                # sed -i "/PASS_WARN_AGE    7/c PASS_WARN_AGE  15" /etc/login.defs
                self.ssh.exec_command("sed -i \"/" + resrow + "/c " + currow + "\" " + path)
                LOG.info(u"修改配置 " + doc + " " + currow)
        else:
            LOG.info(u"检查配置 " + doc + u" 无")
            self.ssh.exec_command("echo \"" + currow + "\" >> " + path)
            LOG.info(u"增加配置 " + doc + " " + currow)
        print

    # 检查文件权限
    def check_perm(self, path, perm):
        resrow = self.run_command("stat -c%a " + path)[0].strip()
        if int(resrow) == perm:
            LOG.info(u"合格配置 文件权限 " + path + " " + resrow)
        else:
            LOG.info(u"错误配置 文件权限 " + path + " " + resrow)
            if self.run_command("chomd " + str(perm) + " " + path):
                LOG.info(u"修改配置 文件权限 " + path + " " + str(perm))
            else:
                LOG.info(u"修改失败 文件权限 " + path + " " + str(perm))
        print

    # 文件重命名
    def mv_file(self, doc, text):
        resrow = self.run_command("ls " + text)
        if resrow:
            resrow = resrow[0].strip()
            currow = resrow + strftime('.%Y-%m-%d-%H-%M-%S.bak')
            LOG.info(u"错误配置 " + doc + resrow)
            self.ssh.exec_command("mv " + resrow + " " + currow)
            LOG.info(u"修改配置 " + doc + currow)
        else:
            LOG.info(u"合格配置 " + doc + u"无")
        print

    # 添加只允许追加 权限
    def addperm_a(self, path):
        resrow = self.run_command("lsattr " + path + " | awk '{print $1}' | grep a")
        if resrow:
            LOG.info(u"合格配置 只允许追加 " + path)
        else:
            LOG.info(u"错误配置 只允许追加 " + path + u"无")
            self.run_command("chattr +a " + path)
            LOG.info(u"修改配置 只允许追加 " + path)
        print

    # 添加不允许修改权限
    def addperm_i(self, path):
        resrow = self.run_command("lsattr " + path + " | awk '{print $1}' | grep i")
        if resrow:
            LOG.info(u"合格配置 不允许修改 " + path)
        else:
            LOG.info(u"错误配置 不允许修改 " + path + u"无")
            self.run_command("chattr +i " + path)
            LOG.info(u"修改配置 不允许修改 " + path)
        print

    def run(self):
        doc   = u"密码设置限制"
        currow = "password    requisite     pam_cracklib.so try_first_pass retry=3 type= dcredit=-1 ocredit=-1 lcredit=-1 ucredit=-1 minlen=8"
        path   = "/etc/pam.d/system-auth"
        text = "pam_cracklib.so"
        self.check_config(doc, currow, path, text)

        doc   = u"输入错误锁定"
        currow = "auth required pam_tally.so onerr=fail deny=3 unlock_time=300"
        path   = "/etc/pam.d/system-auth"
        text = "unlock_time"
        self.check_config(doc, currow, path, text)

        doc = u"密码的最大有效期"
        currow = "PASS_MAX_DAYS    90"
        path = "/etc/login.defs"
        text = "^PASS_MAX_DAYS"
        self.check_config(doc, currow, path, text)

        doc = u"密码最小长度"
        currow = "PASS_MIN_LEN   8"
        path = "/etc/login.defs"
        text = "^PASS_MIN_LEN"
        self.check_config(doc, currow, path, text)

        doc = u"通知用户修改密码天数"
        currow = "PASS_WARN_AGE  15"
        path = "/etc/login.defs"
        text = "^PASS_WARN_AGE"
        self.check_config(doc, currow, path, text)

        doc   = u"空密码登陆"
        currow = "PermitEmptyPasswords no"
        path   = "/etc/ssh/sshd_config"
        text = "^PermitEmptyPasswords"
        self.check_config(doc, currow, path, text)

        doc = u"profile umask值"
        currow = "umask=077"
        path = "/etc/profile"
        text = "^umask"
        self.check_config(doc, currow, path, text)

        doc = u"csh.login umask值"
        currow = "umask=077"
        path = "/etc/csh.login"
        text = "^umask"
        self.check_config(doc, currow, path, text)

        doc = u"csh.cshrc umask值"
        currow = "umask=077"
        path = "/etc/csh.cshrc"
        text = "^umask"
        self.check_config(doc, currow, path, text)

        doc = u"bashrc umask值"
        currow = "umask=077"
        path = "/etc/bashrc"
        text = "^umask"
        self.check_config(doc, currow, path, text)

        doc = u"命令历史纪录"
        currow = "HISTSIZE=30"
        path = "/etc/profile"
        text = "^HISTSIZE"
        self.check_config(doc, currow, path, text)

        doc = u"系统空闲等待时间"
        currow = "TMOUT=300"
        path = "/etc/profile"
        text = "^TMOUT"
        self.check_config(doc, currow, path, text)

        doc = u"将/var/tmp 绑定到/tmp"
        currow = "/tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 0"
        path = "/etc/fstab"
        text = "^/tmp /var/tmp"
        self.check_config(doc, currow, path, text)

        doc = u"内核文件的大小的生效值"
        currow = "* soft core 0"
        path = "/etc/security/limits.conf"
        text = "^* soft core"
        self.check_config(doc, currow, path, text)

        doc = u"内核文件的最大值"
        currow = "* hard core 0"
        path = "/etc/security/limits.conf"
        text = "^* hard core"
        self.check_config(doc, currow, path, text)

        doc = u"最大持久设置最大值"
        currow = "* hard rss 5000"
        path = "/etc/security/limits.conf"
        text = "^* hard rss"
        self.check_config(doc, currow, path, text)

        doc = u"进程的最大数目"
        currow = "* hard nproc 20"
        path = "/etc/security/limits.conf"
        text = "^* hard nproc"
        self.check_config(doc, currow, path, text)

        doc = u"限制用户对系统资源的使用生效"
        currow = "session required /lib/security/pam_limits.so"
        path = "/etc/pam.d/login"
        text = "^session required /lib/security/pam_limits.so"
        self.check_config(doc, currow, path, text)

        doc = u"打开syncookie缓解syn flood攻击"
        currow = "net.ipv4.tcp_syncookies = 1"
        path = "/etc/sysctl.conf"
        text = "^net.ipv4.tcp_syncookies = "
        self.check_config(doc, currow, path, text)

        doc   = u"root远程登陆"
        currow = "PermitRootLogin no"
        path   = "/etc/ssh/sshd_config"
        text = "^PermitRootLogin"
        self.check_config(doc, currow, path, text)

        doc = u"允许本地root登陆 "
        path = "/etc/securetty"
        text = "^[vtp]"
        resrow = self.get_config(path, text)
        if resrow:
            while resrow:
                currow = "#" + resrow
                self.check_config(doc, currow, path, text)
                resrow = self.get_config(path, text)
        else:
            LOG.info(u"合格配置 " + doc + u"无")
            print

        doc = u"仅主机的网络参数"
        path = "/etc/sysctl.conf"
        sysctl_conf = [
        "net.ipv4.ip_forward = 0",
        "net.ipv4.conf.all.sendredirects = 0",
        "net.ipv4.conf.default.sendredirects = 0",]
        for x in sysctl_conf:
            currow = x
            text = "^" + x[:-1]
            self.check_config(doc, currow, path, text)

        doc = u"主机与路由器的网络参数"
        path = "/etc/sysctl.conf"
        sysctl_conf = [
        "net.ipv4.conf.all.accept_source_route = 0",
        "net.ipv4.conf.all.accept_redirects = 0",
        "net.ipv4.conf.all.secure_redirects = 0",
        "net.ipv4.conf.all.log_martians = 1",
        "net.ipv4.conf.default.accept_source_route = 0",
        "net.ipv4.conf.default.accept_redirects = 0",
        "net.ipv4.conf.default.secure_redirects = 0",
        "net.ipv4.icmp_echo_ignore_broadcasts = 1",
        "net.ipv4.icmp_ignore_bogus_error_messages = 1",
        "net.ipv4.tcp_syncookies = 1",
        "net.ipv4.conf.all.rp_filter = 1",
        "net.ipv4.conf.default.rp_filter = 1",]
        for x in sysctl_conf:
            currow = x
            text = "^" + x[:-1]
            self.check_config(doc, currow, path, text)

        # alias 别名设置
        doc = u"别名 ls"
        currow = "alias ls='ls -aol'"
        path = "/etc/profile"
        text = "^alias ls='ls -aol'"
        self.check_config(doc, currow, path, text)

        doc = u"别名 mv"
        currow = "alias mv='mv -i'"
        path = "/etc/profile"
        text = "^alias mv='mv -i'"
        self.check_config(doc, currow, path, text)

        doc = u"别名 ls"
        currow = "alias rm='rm -i'"
        path = "/etc/profile"
        text = "^alias rm='rm -i'"
        self.check_config(doc, currow, path, text)
        # 别名生效
        self.run_command("source /etc/profile")

        # 日志配置
        doc = u"对修改日期和时间信息的事件进行记录"
        path = "/etc/audit/audit.rules"
        audit_rules = [
        "-a always,exit -F arch=ARCH -S adjtimex -S settimeofday -S stime -k time-change",
        "-a always,exit -F arch=ARCH -S clock_settime -k time-change",
        "-w /etc/localtime -p wa -k time-change",]
        for x in audit_rules:
            currow = x
            text = "^" + x[:-1]
            self.check_config(doc, currow, path, text)

        doc = u"对修改用户/组信息的事件进行记录"
        path = "/etc/audit/audit.rules"
        audit_rules = [
        "-w /etc/group -p wa -k identity",
        "-w /etc/passwd -p wa -k identity",
        "-w /etc/gshadow -p wa -k identity",
        "-w /etc/shadow -p wa -k identity",
        "-w /etc/security/opasswd -p wa -k identity",]
        for x in audit_rules:
            currow = x
            text = "^" + x[:-1]
            self.check_config(doc, currow, path, text)

        doc = u"对修改系统的网络环境的事件进行记录"
        path = "/etc/audit/audit.rules"
        audit_rules = [
        "-a exit,always -F arch=ARCH -S sethostname -S setdomainname -k system-locale",
        "-w /etc/issue -p wa -k system-locale",
        "-w /etc/issue.net -p wa -k system-locale",
        "-w /etc/hosts -p wa -k system-locale",
        "-w /etc/sysconfig/network -p wa -k system-locale",]
        for x in audit_rules:
            currow = x
            text = "^" + x[:-1]
            self.check_config(doc, currow, path, text)

        doc = u"对修改系统的强制访问控制的事件进行记录"
        path = "/etc/audit/audit.rules"
        currow = "-w /etc/selinux/ -p wa -k MAC-policy"
        text = "^-w /etc/selinux/ -p wa -k MAC-policy"
        self.check_config(doc, currow, path, text)

        doc = u"对试图改变登录和注销的事件进行记录"
        path = "/etc/audit/audit.rules"
        audit_rules = [
        "-w /var/log/faillog -p wa -k logins",
        "-w /var/log/lastlog -p wa -k logins",]
        for x in audit_rules:
            currow = x
            text = "^" + x[:-1]
            self.check_config(doc, currow, path, text)

        doc = u"对试图改变进程和会话启动信息进行记录"
        path = "/etc/audit/audit.rules"
        audit_rules = [
        "-w /var/run/utmp -p wa -k session",
        "-w /var/log/btmp -p wa -k session",
        "-w /var/log/wtmp -p wa -k session",]
        for x in audit_rules:
            currow = x
            text = "^" + x[:-1]
            self.check_config(doc, currow, path, text)

        doc = u"确保审计记录系统管理员的操作"
        path = "/etc/audit/audit.rules"
        currow = "-w /etc/sudoers -p wa -k actions"
        text = "^-w /etc/sudoers -p wa -k actions"
        self.check_config(doc, currow, path, text)

        # 文件重命名
        doc = u"issue 系统banner "
        text = "/etc/issue"
        self.mv_file(doc, text)

        doc = u"issue.net 系统banner "
        text = "/etc/issue.net"
        self.mv_file(doc, text)

        doc = u"rhost 无密码访问 "
        text = "\.rhost"
        self.mv_file(doc, text)

        doc = u"netrc ftp自动登陆 "
        text = "\.netrc"
        self.mv_file(doc, text)

        doc = u"forward 邮件发送到本地用户 "
        text = "\.forward"
        self.mv_file(doc, text)

        # 文件权限设置
        path = "/etc/passwd"
        perm = 644
        self.check_perm(path, perm)
        self.addperm_i(path)

        path = "/etc/shadow"
        perm = 0
        self.check_perm(path, perm)
        self.addperm_i(path)

        path = "/etc/group"
        perm = 644
        self.check_perm(path, perm)
        self.addperm_i(path)

        path = "/etc/gshadow"
        perm = 0
        self.check_perm(path, perm)
        self.addperm_i(path)

        path = "/var/log/messages"
        self.addperm_a(path)

        # 非统一格式
        doc = u"环境变量 "
        resrow = self.run_command("echo $PATH")[0].strip()
        if re.search("tmp", resrow):
            LOG.info(u"错误配置 " + doc + resrow)
        else:
            LOG.info(u"合格配置 " + doc + resrow)
        print

        doc = u"uid为0用户 "
        userdict = []
        resrow = self.run_command("cat /etc/passwd | grep -v nologin")
        for row in resrow:
            temp = row.split(":")
            if temp[2] == "0":
                userdict.append(temp[0])
        if userdict.__len__() == 1 and userdict[0] == "root":
            LOG.info(u"合格配置 " + doc + u"root")
        else:
            for x in userdict:
                if x != "root":
                    LOG.info(u"错误配置 " + doc + x)
        print

        doc = u"存在空密码用户 "
        userdict = {}
        resrow = self.run_command("join -t ':' /etc/shadow /etc/passwd | grep -v nologin")
        for row in resrow:
            temp = row.split(":")
            userdict[temp[0]] = temp[1]
        if "" in userdict.values():
            for x in userdict:
                if userdict[x] == "":
                    LOG.info(u"错误配置 " + doc + x)
        else:
            LOG.info(u"合格配置 " + doc + u"无")
        print

if len(sys.argv) == 1:
    print u"./baseline ipfile.txt"
    sys.exit()

ipfile = sys.argv[1]

with open(ipfile) as file:
    data = file.readlines()

LOG = classlog("log.txt")

for i in data:
    # Base_Line(ip,username,password,port=22)
    hostlist = i.split()
    Base_Line(hostlist[0], hostlist[1], hostlist[2])#