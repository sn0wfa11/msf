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
        OptString.new('PARTITION',   [ true, "The encrypted partitiont to be mounted.", "/dev/mmcblk0p3"]),
        OptString.new('MOUNT_POINT', [ true, "The folder to mount the partition.", "/root/secstorage"]),
        OptString.new('PASSWORD',    [ true, "The password to unlock the LUKS partition."]),
        OptString.new('MAP_LOC',     [ true, "The location in /dev/mapper/ to map the unlocked volume.", "sec_store"])
      ], self.class)
  end

  def run
    partition = datastore['PARTITION']
    mount_point = datastore['MOUNT_POINT']
    map_loc = datastore['MAP_LOC']

    if execute("mount | grep #{mount_point}") != ""
      print_error("Mount point #{mount_point} already in use!")
      return
    end

    if unlock_volume(partition, map_loc, datastore['PASSWORD'])
      print_good("Unlocked #{partition} and mapped to /dev/mapper/#{map_loc}")
    else
      print_error("Unable to unlock #{partition}!")
      return
    end

    mount(mount_point, map_loc)
  end

  ###########################################
  # Managment Functions
  ###########################################

  def execute(cmd)
    vprint_status("Execute: #{cmd}")
    output = cmd_exec(cmd)
    vprint_line("#{output}")
    return output
  end

  def unlock_volume(partition, map_loc, password)
    if client.fs.file.exist?("/dev/mapper/#{map_loc}")
      print_status("Looks like volume is already unlocked at /dev/mapper/#{map_loc}")
      return true
    else
      print_status("Attempting to unlock encrypted volume #{partition}")
      cmd = "echo -n \"#{password}\" | cryptsetup luksOpen #{partition} #{map_loc} -"
      vprint_status("Execute: #{cmd}")
      output = cmd_exec(cmd)
      sleep(2)
      if output != ""
        print_error("#{output}")
        return false
      end
      print_status("Waiting for volume to become available for mounting.")
      for x in 0..29
        if client.fs.file.exist?("/dev/mapper/#{map_loc}")
          return true
        end
        sleep 1
      end
      return false
    end
  end

  def mount(mount_point, map_loc)
    print_status("Mounting unlocked volume at #{mount_point}")
    execute("mkdir -p #{mount_point}")
    execute("mount /dev/mapper/#{map_loc} #{mount_point}")

    if execute("mount | grep #{mount_point}") != ""
      print_good("Finished. Data can be accessed at #{mount_point}")
    else
      print_error("Something went wrong mounting the volume.")
    end
  end
end
