require 'net/ssh'
require 'net/sftp'
require 'tempfile'

class MiqSshUtil
  # The exit status of the ssh command.
  attr_reader :status

  # The name of the host provided to the constructor.
  attr_reader :host

  # Create and return a MiqSshUtil object. A host, user and
  # password must be specified.
  #
  # The +options+ param may contain options that are passed directly
  # to the Net::SSH constructor. By default the :non_interactive option is
  # set to true (meaning it will fail instead of prompting for a password),
  # and the :verbose level is set to :warn.
  #
  # The following local options are also supported:
  #
  # :passwordless_sudo - If set to true, then it is assumed that the sudo
  # command does not require a password, and 'sudo' will automatically be
  # prepended to your command. For sudo that requires a password, set
  # the :su_user and :su_password options instead.
  #
  # :remember_host - Setting this to true will cause a HostKeyMismatch
  # error to be rescued and retried once after recording the host and
  # key in the known hosts file. By default this is false.
  #
  # :su_user - If set, ssh commands for that object will be executed via sudo.
  # Do not use if :passwordless_sudo is set to true.
  #
  # :su_password - When used in conjunction with :su_user, the password sent
  # to the command prompt when asked for as the result of using the su command.
  # Do not use if :passwordless_sudo is set to true.
  #
  def initialize(host, user, password, options = {})
    @host     = host
    @user     = user
    @password = password
    @status   = 0
    @shell    = nil
    @options  = {
      :password        => @password,
      :remember_host   => false,
      :verbose         => :warn,
      :non_interactive => true,
    }.merge(options)

    # Seems like in 2.9.2, there needs to be blank :keys, when we are passing private key as string
    @options[:keys] = [] if options[:key_data]

    # Pull the 'remember_host' key out of the hash because the SSH initializer will complain
    @remember_host     = @options.delete(:remember_host)
    @su_user           = @options.delete(:su_user)
    @su_password       = @options.delete(:su_password)
    @passwordless_sudo = @options.delete(:passwordless_sudo)

    # Obsolete, delete if passed in
    @options.delete(:authentication_prompt_delay)

    # don't use the ssh-agent
    @options[:use_agent] = false

    # Set logging to use our default handle if it exists and one was not passed in
    unless @options.key?(:logger)
      #        @options[:logger] = $log if $log
    end
  end # def initialize

  # Download the contents of the remote +from+ file to the local +to+ file. Some
  # messages will be written to the global ManageIQ log in debug mode.
  #
  def get_file(from, to)
    run_session do |ssh|
      $log&.debug("MiqSshUtil::get_file - Copying file #{@host}:#{from} to #{to}.")
      data = ssh.sftp.download!(from, to)
      $log&.debug("MiqSshUtil::get_file - Copying of #{@host}:#{from} to #{to}, complete.")
      return data
    end
  end

  # Upload the contents of local file +to+ to remote location +path+. You may
  # use the specified +content+ instead of the content of the local file.
  #
  # At least one of the +content+ or +path+ parameters must be specified or
  # an error is raised.
  #
  def put_file(to, content = nil, path = nil)
    raise "Need to provide either content or path" if content.nil? && path.nil?
    run_session do |ssh|
      content ||= IO.binread(path)
      $log&.debug("MiqSshUtil::put_file - Copying file to #{@host}:#{to}.")
      ssh.sftp.file.open(to, 'wb') { |f| f.write(content) }
      $log&.debug("MiqSshUtil::get_file - Copying of file to #{@host}:#{to}, complete.")
    end
  end

  # Execute the remote +cmd+ via ssh. This is automatically handled via
  # channels on the ssh session so that various states can be checked,
  # stored and logged independently and asynchronously.
  #
  # If the :passwordless_sudo option was set to true in the constructor
  # then the +cmd+ will automatically be prepended with "sudo".
  #
  # If specified, the data collection will stop the first time a +doneStr+
  # argument is encountered at the end of a line. In practice you would
  # typically specify a newline character.
  #
  # If present, the +stdin+ argument will be sent to the underlying
  # command as input for those commands that expect it, e.g. tee.
  #
  def exec(cmd, doneStr = nil, stdin = nil)
    errBuf = ""
    outBuf = ""
    status = nil
    signal = nil

    # If passwordless sudo is true, we will just prepend every command by sudo
    cmd  = 'sudo ' + cmd if @passwordless_sudo

    run_session do |ssh|
      ssh.open_channel do |channel|
        channel.on_data do |_channel, data|
          $log.debug "MiqSshUtil::exec - STDOUT: #{data}" if $log
          outBuf << data
          data.each_line { |l| return outBuf if doneStr == l.chomp } unless doneStr.nil?
        end

        channel.on_extended_data do |_channel, _type, data|
          $log.debug "MiqSshUtil::exec - STDERR: #{data}" if $log
          errBuf << data
        end

        channel.on_request('exit-status') do |_channel, data|
          status = data.read_long
          $log.debug "MiqSshUtil::exec - STATUS: #{status}" if $log
        end

        channel.on_request('exit-signal') do |_channel, data|
          signal = data.read_string
          $log.debug "MiqSshUtil::exec - SIGNAL: #{signal}" if $log
        end

        channel.on_eof do |_channel|
          $log.debug "MiqSshUtil::exec - EOF RECEIVED" if $log
        end

        channel.on_close do |_channel|
          $log.debug "MiqSshUtil::exec - Command: #{cmd}, exit status: #{status}" if $log
          unless signal.nil? || status.zero?
            raise "MiqSshUtil::exec - Command #{cmd}, exited with signal #{signal}" unless signal.nil?
            raise "MiqSshUtil::exec - Command #{cmd}, exited with status #{status}" if errBuf.empty?
            raise "MiqSshUtil::exec - Command #{cmd} failed: #{errBuf}, status: #{status}"
          end
          return outBuf
        end

        $log.debug "MiqSshUtil::exec - Command: #{cmd} started." if $log
        channel.exec(cmd) do |chan, success|
          raise "MiqSshUtil::exec - Could not execute command #{cmd}" unless success
          if stdin.present?
            chan.send_data(stdin)
            chan.eof!
          end
        end
      end
      ssh.loop
    end
  end # def exec

  # Execute the remote +cmd+ via ssh. This is nearly identical to the exec
  # method, and is used only if the :su_user and :su_password options are
  # set in the constructor.
  #
  # The difference between this method and the exec method are primarily in
  # the underlying handling of the sudo user and sudo password parameters, i.e
  # creating a PTY session and dealing with prompts. From the perspective of
  # an end user they are essentially identical.
  #
  def suexec(cmd_str, doneStr = nil, stdin = nil)
    errBuf = ""
    outBuf = ""
    prompt = ""
    cmdRX  = ""
    status = nil
    signal = nil
    state  = :initial

    run_session do |ssh|
      temp_cmd_file(cmd_str) do |cmd|
        ssh.open_channel do |channel|
          # now we request a "pty" (i.e. interactive) session so we can send data back and forth if needed.
          # it WILL NOT WORK without this, and it has to be done before any call to exec.
          channel.request_pty(:chars_wide => 256) do |_channel, success|
            raise "Could not obtain pty (i.e. an interactive ssh session)" unless success
          end

          channel.on_data do |channel, data|
            $log.debug "MiqSshUtil::suexec - state: [#{state.inspect}] STDOUT: [#{data.hex_dump.chomp}]" if $log
            if state == :prompt
              # Detect the common prompts
              # someuser@somehost ... $  rootuser@somehost ... #  [someuser@somehost ...] $  [rootuser@somehost ...] #
              prompt = data if data =~ /^\[*[\w\-\.]+@[\w\-\.]+.+\]*[\#\$]\s*$/
              outBuf << data
              unless doneStr.nil?
                data.each_line { |l| return outBuf if doneStr == l.chomp }
              end

              if outBuf[-prompt.length, prompt.length] == prompt
                return outBuf[0..(outBuf.length - prompt.length)]
              end
            end

            if state == :command_sent
              cmdRX << data
              state = :prompt if cmdRX == "#{cmd}\r\n"
            end

            if (state == :password_sent)
              prompt << data.lstrip
              if data.strip =~ /\#/
                $log.debug "MiqSshUtil::suexec - Superuser Prompt detected: sending command #{cmd}" if $log
                channel.send_data("#{cmd}\n")
                state = :command_sent
              end
            end

            if (state == :initial)
              prompt << data.lstrip
              if data.strip =~ /[Pp]assword:/
                prompt = ""
                $log.debug "MiqSshUtil::suexec - Password Prompt detected: sending su password" if $log
                channel.send_data("#{@su_password}\n")
                state = :password_sent
              end
            end
          end

          channel.on_extended_data do |_channel, _type, data|
            $log.debug "MiqSshUtil::suexec - STDERR: #{data}" if $log
            errBuf << data
          end

          channel.on_request('exit-status') do |_channel, data|
            status = data.read_long
            $log.debug "MiqSshUtil::suexec - STATUS: #{status}" if $log
          end

          channel.on_request('exit-signal') do |_channel, data|
            signal = data.read_string
            $log.debug "MiqSshUtil::suexec - SIGNAL: #{signal}" if $log
          end

          channel.on_eof do |_channel|
            $log.debug "MiqSshUtil::suexec - EOF RECEIVED" if $log
          end

          channel.on_close do |_channel|
            errBuf << prompt if [:initial, :password_sent].include?(state)
            $log.debug "MiqSshUtil::suexec - Command: #{cmd}, exit status: #{status}" if $log
            raise "MiqSshUtil::suexec - Command #{cmd}, exited with signal #{signal}" unless signal.nil?
            unless status.zero?
              raise "MiqSshUtil::suexec - Command #{cmd}, exited with status #{status}" if errBuf.empty?
              raise "MiqSshUtil::suexec - Command #{cmd} failed: #{errBuf}, status: #{status}"
            end
            return outBuf
          end

          $log.debug "MiqSshUtil::suexec - Command: [#{cmd_str}] started." if $log
          su_command = @su_user == 'root' ? "su -l\n" : "su -l #{@su_user}\n"
          channel.exec(su_command) do |chan, success|
            raise "MiqSshUtil::suexec - Could not execute command #{cmd}" unless success
            if stdin.present?
              chan.send_data(stdin)
              chan.eof!
            end
          end
        end
      end
      ssh.loop
    end
  end # suexec

  # Creates a local temporary file under /var/tmp with +cmd+ as its contents.
  # The tempfile name is the name of the command with "miq-" prepended and ".sh"
  # appended to the end.
  #
  # The end result is a string meant to be run via the suexec method. For example:
  #
  # "chmod 700 /var/tmp/miq-foo.sh; /var/tmp/miq-foo.sh; rm -f /var/tmp/miq-foo.sh
  #
  def temp_cmd_file(cmd)
    temp_remote_script = Tempfile.new(["miq-", ".sh"], "/var/tmp")
    temp_file          = temp_remote_script.path
    begin
      temp_remote_script.write(cmd)
      temp_remote_script.close
      remote_cmd = "chmod 700 #{temp_file}; #{temp_file}; rm -f #{temp_file}"
      yield(remote_cmd)
    ensure
      temp_remote_script.close!
    end
  end

  # Shortcut method that creates and yields an MiqSshUtil object, with the +host+,
  # +remote_user+ and +remote_password+ options passed in as the first three
  # params to the constructor, while the +su_user+ and +su_password+ parameters
  # automatically set the corresponding :su_user and :su_password options. The
  # remaining options are passed normally.
  #
  # This method is functionally identical to the following code, except that it
  # yields itself (and nil) and re-raises certain Net::SSH exceptions as
  # ManageIQ exceptions.
  #
  #   MiqSshUtil.new(host, remote_user, remote_password, {:su_user => su_user, :su_password => su_password})
  #
  def self.shell_with_su(host, remote_user, remote_password, su_user, su_password, options = {})
    options[:su_user], options[:su_password] = su_user, su_password
    ssu = MiqSshUtil.new(host, remote_user, remote_password, options)
    yield(ssu, nil)
  rescue Net::SSH::AuthenticationFailed
    raise MiqException::MiqInvalidCredentialsError
  rescue Net::SSH::HostKeyMismatch
    raise MiqException::MiqSshUtilHostKeyMismatch
  end

  # Executes the provided +cmd+ using the exec or suexec method, depending on
  # whether or not the :su_user option is set. The +doneStr+ and +stdin+
  # arguments are passed along to the appropriate method as well.
  #
  # In the case of suexec, escape characters are automatically removed from
  # the final output.
  #
  #--
  # The _shell argument appears to be an artifact that has been retained
  # over time for reasons that aren't immediately apparent.
  #
  def shell_exec(cmd, doneStr = nil, _shell = nil, stdin = nil)
    return exec(cmd, doneStr, stdin) if @su_user.nil?
    ret = suexec(cmd, doneStr, stdin)
    # Remove escape character from the end of the line
    ret.sub!(/\e$/, '')
    ret
  end

  # Copies the remote +file_path+ to a local temporary file, and then
  # yields or returns a filehandle to the local temporary file.
  #--
  # Presumably this method was meant for use with the SCVMM provider
  # given the hardcoded name of the temporary file.
  #
  def fileOpen(file_path, perm = 'r')
    if block_given?
      Tempfile.open('miqscvmm') do |tf|
        tf.close
        get_file(file_path, tf.path)
        File.open(tf.path, perm) { |f| yield(f) }
      end
    else
      tf = Tempfile.open('miqscvmm')
      tf.close
      get_file(file_path, tf.path)
      f = File.open(tf.path, perm)
      return f
    end
  end

  # Returns whether or not the remote +filename+ exists.
  #
  def fileExists?(filename)
    shell_exec("test -f #{filename}") rescue return false
    true
  end

  # This method creates and yields an ssh object. If the :remember_host option
  # was set to true, it will record this host and key in the known hosts file
  # and retry once.
  #
  def run_session
    first_try = true

    begin
      Net::SSH.start(@host, @user, @options) do |ssh|
        yield(ssh)
      end
    rescue Net::SSH::HostKeyMismatch => e
      if @remember_host == true && first_try
        # Save fingerprint and try again
        first_try = false
        e.remember_host!
        retry
      else
        # Re-raise error
        raise e
      end
    end
  end
end
