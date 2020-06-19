# encoding: US-ASCII

require 'sys-uname'
require 'sys/proctable'
require 'util/runcmd'
require 'util/miq-system'

class MiqProcess
  # Collect and return a list of PID's for all processes that match
  # +process_name+ or +process_name.exe+.
  #
  def self.get_active_process_by_name(process_name)
    procs = Sys::ProcTable.ps(:smaps => false, :cgroup => false)
    procs.select { |process| [process_name, "#{process_name}.exe"].include?(process.name) }.map(&:pid)
  end

  # Collect and return a list of process information for Linux.
  #
  def self.linux_process_stat(pid = Process.pid)
    Sys::ProcTable.ps(:pid => pid, :smaps => false, :cgroup => false)
  end

  def self.processInfo(pid = Process.pid)
    result = Sys::ProcTable.ps(:pid => pid, :smaps => true, :cgroup => false).to_h

    if Sys::Platform::IMPL == :linux
      result[:memory_usage]          = result[:rss] * 4096
      result[:memory_size]           = result[:vsize]
      percent_memory                 = (1.0 * result[:memory_usage]) / MiqSystem.total_memory
      result[:percent_memory]        = percent_memory.round(2)
      result[:cpu_time]              = result[:stime] + x[:utime]
      cpu_status                     = MiqSystem.status[:cpu]
      cpu_total                      = (0..3).inject(0) { |sum, x| sum + cpu_status[x].to_i }
      cpu_total                     /= MiqSystem.num_cpus
      percent_cpu                    = (1.0 * result[:cpu_time]) / cpu_total
      result[:percent_cpu]           = percent_cpu.round(2)
      result[:proportional_set_size] = results[:smaps].pss
      result[:unique_set_size]       = results[:smaps].uss
    end

    result
  end

  # Return the command line string for the given +pid+. If the pid has already
  # exited, or there is some sort of permissions issue that causes it to be set
  # to nil, then return an empty string instead.
  #
  def self.command_line(pid)
    # Already exited pids, or permission errors cause ps or ps.cmdline to be nil,
    # so the best we can do is return an empty string.
    Sys::ProcTable.ps(:pid => pid).try(:cmdline) || ""
  end

  def self.is_worker?(pid)
    command_line = self.command_line(pid)
    command_line.include?(MiqWorker::PROCESS_TITLE_PREFIX)
  end

  def self.process_list_all(wmi = nil)
    pl = {}
    return process_list_wmi(wmi) unless wmi.nil?

    case Sys::Platform::IMPL
    when :mswin, :mingw
      pl = process_list_wmi(wmi)
    when :linux
      pl = process_list_linux("ps -e -o pid,rss,vsize,%mem,%cpu,time,priority,ucomm --no-headers")
    when :macosx
      pl = process_list_linux("ps -e -o pid,rss,vsize,%mem,%cpu,time,pri,ucomm", true)
    end
    pl
  end

  def self.process_list_wmi(wmi = nil, pid = nil)
    require 'util/win32/miq-wmi'
    pl = {}
    wmi = WMIHelper.connectServer if wmi.nil?
    os_data = wmi.get_instance('select TotalVisibleMemorySize from Win32_OperatingSystem')
    proc_query = 'select PageFileUsage,Name,Handle,WorkingSetSize,Priority,UserModeTime,KernelModeTime from Win32_Process'
    proc_query += " where Handle = '#{pid}'" unless pid.nil?
    proc_data = wmi.run_query(proc_query)

    # Calculate the CPU % from a 2 second sampling of the raw perf counters.
    perf_query = 'Select IDProcess,PercentProcessorTime,Timestamp_Sys100NS from Win32_PerfRawData_PerfProc_Process'
    perf_query += " where IDProcess = '#{pid}'" unless pid.nil?
    fh = {}; perf = {}
    wmi.run_query(perf_query).each { |p| fh[p.IDProcess] = {:ppt => p.PercentProcessorTime.to_i, :ts => p.Timestamp_Sys100NS.to_i} }
    sleep(2)
    wmi.run_query(perf_query).each do |p|
      m1 = fh[p.IDProcess]
      if m1
        n = p.PercentProcessorTime.to_i - m1[:ppt]
        d = p.Timestamp_Sys100NS.to_i - m1[:ts]
        perf[p.IDProcess.to_i] = 100 * n / d
      end
    end

    proc_data.each { |p| next if p.Handle.to_i <= 4; pl[p.Handle.to_i] = parse_process_data(:wmi, p, perf, os_data) }
    pl
  end

  def self.process_list_linux(cmd_str, skip_header = false)
    pl, i = {}, 0
    rc = MiqUtil.runcmd(cmd_str)
    rc.each_line do |ps_str|
      i += 1
      next if i == 1 && skip_header == true
      pinfo = ps_str.strip.split(' ')
      nh = parse_process_data(:linux, pinfo, perf = nil, os = nil)
      pl[nh[:pid]] = nh
      pl
    end
    pl
  end

  def self.parse_process_data(data_type, pinfo, perf = nil, os = nil)
    nh = {}
    if data_type == :wmi
      nh[:pid]            = pinfo.Handle.to_i
      nh[:name]           = pinfo.Name
      nh[:memory_size]    = pinfo.WorkingSetSize.to_i
      nh[:memory_usage]   = nh[:memory_size] - pinfo.PageFileUsage.to_i * 1024
      # Keep the percent format to 2 decimal places
      nh[:percent_memory] = sprintf("%.2f", pinfo.WorkingSetSize.to_f / (os.TotalVisibleMemorySize.to_i * 1024) * 100)
      nh[:cpu_time]       = (pinfo.UserModeTime.to_i + pinfo.KernelModeTime.to_i) / 10000000    # in seconds
      nh[:priority]       = pinfo.Priority.to_i
      nh[:percent_cpu]    = perf[nh[:pid]]
    else
      nh[:pid]            = pinfo[0].to_i
      nh[:memory_usage]   = pinfo[1].to_i * 1024   # Memory in RAM
      nh[:memory_size]    = pinfo[2].to_i * 1024   # Memory in RAM and swap
      nh[:percent_memory] = pinfo[3]
      nh[:percent_cpu]    = pinfo[4]
      nh[:cpu_time]       = str_time_to_sec(pinfo[5])
      nh[:priority]       = pinfo[6]
      nh[:name]           = pinfo[7..-1].join(' ')
    end
    nh
  end

  def self.str_time_to_sec(time_str)
    # Convert format 00:00:00 to seconds
    t = time_str.split(':')
    (t[0].to_i * 3600) + (t[1].to_i * 60) + t[2].to_i
  end
end
