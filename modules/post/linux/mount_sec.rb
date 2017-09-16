##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Linux Mount Encrypted LUKS Partition',
      'Description'   => %q{
        This module will mount an encrypted LUKS partition. It is very
        usefull when using Kali-Pi's or other "drop devices" that are
        set up to automatically connect back with a Meterpreter shell.
        This module will not check your password for bash safety! Visit
        the reference below for a description of bad password chars. 
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
          [ 'URL', 'https://github.com/sn0wfa11/Kali-Pi/blob/master/secure_storage.md' ]
        ]
    ))

    register_options(
      [
        OptInt.new('DELAY',          [ true, "Delay on the execute command. (In seconds)", 0]),
        OptString.new('PARTITION',   [ true, "The encrypted partitiont to be mounted.", "/dev/mmcblk0p3"]),
        OptString.new('MOUNT_POINT', [ true, "The folder to mount the partition.", "/root/secstorage"]),
        OptString.new('PASSWORD',    [ true, "The password to unlock the LUKS partition."]),
        OptString.new('MAP_LOC',     [ true, "The location in /dev/mapper/ to map the unlocked volume.", "sec_store"])
      ], self.class)
  end

  def run
    partition = datastore['PARTITION']
    mount_point = datastore['MOUNT_POINT']
    password = datastore['PASSWORD']
    map_loc = datastore['MAP_LOC']

    if execute("mount | grep #{mount_point}") != ""
      print_error("Mount point #{mount_point} already in use!")
      return
    end

    if client.fs.file.exist?("/dev/mapper/#{map_loc}")
      print_error("Map location /dev/mapper/#{map_loc} already in use!")
      return
    end

    print_status("Attempting to unlock encrypted volume #{partition}")
    output = execute("echo -n \"#{password}\" | cryptsetup luksOpen #{partition} #{map_loc} -")
    if output != ""
      fail_with(Failure::NoAccess, "#{output}")
    end

    print_status("Mounting unlocked volume at #{mount_point}")
    execute("mkdir -p #{mount_point}")
    execute("mount /dev/mapper/#{map_loc} #{mount_point}")

    print_good("Finished. Data can be accessed at #{mount_point}")
  end

  ###########################################
  # Managment Functions
  ###########################################

  def execute(cmd)
    vprint_status("Execute: #{cmd}")
    output = cmd_exec(cmd)
    sleep(datastore['DELAY']) if datastore['DELAY']
    vprint_line("#{output}")
    return output
  end
end
