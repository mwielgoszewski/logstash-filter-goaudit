# encoding: utf-8
require "logstash/filters/base"
require "logstash/json"
require "logstash/namespace"
require "logstash/timestamp"

require_relative 'goaudit_constants'

class LogStash::Filters::GoAudit < LogStash::Filters::Base

  include GoAudit::Constants

  config_name "goaudit"

  # The configuration for the GoAudit filter:
  # [source,ruby]
  #     source => source_field
  #
  # For example, if you have GoAudit JSON data in the `message` field:
  # [source,ruby]
  #     filter {
  #       goaudit {
  #         source => "message"
  #       }
  #     }
  #
  # The above would parse the json from the `message` field
  config :source, :validate => :string, :required => true

  # Define the target field for placing the parsed data. If this setting is
  # omitted, the JSON data will be stored at the root (top level) of the event.
  #
  # For example, if you want the data to be put in the `doc` field:
  # [source,ruby]
  #     filter {
  #       goaudit {
  #         target => "doc"
  #       }
  #     }
  #
  # JSON in the value of the `source` field will be expanded into a
  # data structure in the `target` field.
  #
   # NOTE: if the `target` field already exists, it will be overwritten!
  config :target, :validate => :string

  # Append values to the `tags` field when there has been no
  # successful match
  config :tag_on_failure, :validate => :array, :default => ["_jsonparsefailure"]

  # Allow to skip filter on invalid json (allows to handle json and non-json data without warnings)
  config :skip_on_invalid_json, :validate => :boolean, :default => false

  def register
    # Nothing to do here
  end

  def filter(event)
    @logger.debug? && @logger.debug("Running go-audit filter", :event => event)

    source = event.get(@source)

    begin
      parsed = LogStash::Json.load(source)

      result = {
        "@timestamp" => Time.at(parsed["timestamp"].to_f),
        "data" => {
          "sequence" => parsed["sequence"],
          "unknown" => []
        },
        "error" => nil
      }

      uid_map = parsed["uid_map"] || {}
      messages = parsed["messages"] || []

      # gather types
      groups = messages.group_by{ |h| h["type"]}.each{|_, v| v.map!{|h| h["data"].strip}}

      groups.each do |type, msgs|
        case type
        when TYPES[:config_change]
        when TYPES[:syscall]
          parse_syscall(msgs, result, uid_map)

        when TYPES[:execve]
          parse_execve(msgs, result)

        when TYPES[:path]
          parse_path(msgs, result, uid_map)

        when TYPES[:cwd]
          parse_cwd(msgs, result)

        when TYPES[:sockaddr]
          parse_sockaddr(msgs, result)

        when TYPES[:proctitle]
          parse_proctitle(msgs, result)

        else
          result["data"]["unknown"].push(msgs)
          result["error"] = "unknown kauditd type #{type}"
        end
      end

      build_message(result)
    rescue => e
      unless @skip_on_invalid_json
        @tag_on_failure.each{|tag| event.tag(tag)}
        @logger.warn("Error parsing json", :source => @source, :raw => source, :exception => e)
      end
      return
    end

    if @target
      event.set(@target, result)
    else
      unless result.is_a?(Hash)
        @tag_on_failure.each{|tag| event.tag(tag)}
        @logger.warn("Parsed JSON object/hash requires a target configuration option", :source => @source, :raw => source)
        return
      end

      # TODO: (colin) the timestamp initialization should be DRY'ed but exposing the similar code
      # in the Event#init_timestamp method. See https://github.com/elastic/logstash/issues/4293

      # a) since the parsed hash will be set in the event root, first extract any @timestamp field to properly initialized it
      parsed_timestamp = result.delete(LogStash::Event::TIMESTAMP)
      begin
        timestamp = parsed_timestamp ? LogStash::Timestamp.coerce(parsed_timestamp) : nil
      rescue LogStash::TimestampParserError => e
        timestamp = nil
      end

      # b) then set all parsed fields in the event
      result.each{|k, v| event.set(k, v)}

      # c) finally re-inject proper @timestamp
      if parsed_timestamp
        if timestamp
          event.timestamp = timestamp
        else
          event.timestamp = LogStash::Timestamp.new
          @logger.warn("Unrecognized #{LogStash::Event::TIMESTAMP} value, setting current time to #{LogStash::Event::TIMESTAMP}, original in #{LogStash::Event::TIMESTAMP_FAILURE_FIELD} field", :value => parsed_timestamp.inspect)
          event.tag(LogStash::Event::TIMESTAMP_FAILURE_TAG)
          event.set(LogStash::Event::TIMESTAMP_FAILURE_FIELD, parsed_timestamp.to_s)
        end
      end
    end

    filter_matched(event)

    @logger.debug? && @logger.debug("Event after go-audit filter", :event => event)
  end

  def parse_syscall(msgs, result, uid_map)
    msg = msgs.join(" ")
    result["data"]["syscall"] = data = split_fields(msg)

    map_arch(data)

    map_uid("uid", data, uid_map)
    map_uid("auid", data, uid_map)
    map_uid("euid", data, uid_map)
    map_uid("fsuid", data, uid_map)
    map_uid("suid", data, uid_map)

    data["key"] = convert_value(data["key"], true)

    # remap some values
    data["id"] = data.delete("syscall")
    data["session_id"] = data.delete("ses")

    if SYSCALLS.key?(data["arch"]["name"])
      if SYSCALLS[data["arch"]["name"]].key?(data["id"])
        data["name"] = SYSCALLS[data["arch"]["name"]][data["id"]]
      end
    end

    data["command"] = convert_value(data.delete("comm") || "", true)
    data["executable"] = convert_value(data.delete("exe") || "", true)
  end

  def parse_execve(msgs, result)
    msg = msgs.join(" ")
    result["data"]["execve"] = execve = split_fields(msg)

    return unless execve.key?("argc")

    argc = execve.delete("argc").to_i

    command = []

    (0..argc).map { |i| "a#{i}" } .each do |find_arg|
      smash_args(find_arg, execve)

      if !execve.key?(find_arg)
        next
      end

      argv = convert_value(execve.delete(find_arg), true)
      command.push(argv)
    end

    execve["command"] = command.join(" ").strip
  end

  def parse_path(msgs, result, uid_map)
    result["data"]["paths"] = paths = []
    msgs.each do | msg |
      entries = split_fields(msg)
      map_uid("ouid", entries, uid_map)
      entries["name"] = convert_value(entries.fetch("name", ""), true)

      i = entries.delete("item").to_i
      paths[i] = entries
    end
  end

  def parse_cwd(msgs, result)
    msg = msgs.join(" ")
    data = split_fields(msg)
    result["data"]["cwd"] = convert_value(data.fetch("cwd", ""), true)
  end

  def parse_sockaddr(msgs, result)
    msg = msgs.join(" ")
    data = split_fields(msg)
    result["data"]["socket_address"] = parse_addr(data["saddr"])
  end

  def parse_proctitle(msgs, result)
    msg = msgs.join(" ")
    data = split_fields(msg)
    result["data"]["proctitle"] = convert_value(data.fetch("proctitle", ""), true)
  end

  def parse_addr(addr)
    return {"unknown" => addr} if addr.length < 2

    family = addr[0, 2].hex + (256 * addr[2, 2].hex)

    return {"unknown" => addr} if !ADDRESS_FAMILES.key?(family)

    details = {
      "family" => ADDRESS_FAMILES[family]
    }

    case family
    when 1
      parse_addr_local(addr, details)
    when 2
      parse_addr_inet(addr, details)
    when 10
      parse_addr_inet6(addr, details)
    else
      details["unknown"] = addr[4..-1]
    end

    return details
  end

  def parse_addr_local(addr, details)
    if addr.length < 5
      detail["unknown"] = addr[2..-1]
      return
    end

    pos = addr.index("00", 4) - 4
    if pos < 0
      pos = addr.length - 4
    end

    details["path"] = convert_value(addr[4, pos], true)

    if addr.length > pos + 5
      details["unknown"] = addr[pos + 4..-1]
    end
  end

  def parse_addr_inet(addr, details)
    if addr.length < 16
      detail["unknown"] = addr[2..-1]
      return
    end

    details["port"] = (addr[4, 2].hex * 256) + addr[6, 2].hex
    details["ip"] = addr[8, 8].scan(/.{2}/).map{ |x| x.hex }.join(".")

    if addr.length > 16
      details["unknown"] = addr[16..-1]
    end
  end

  def parse_addr_inet6(addr, details)
    if addr.length < 56
      detail["unknown"] = addr[2..-1]
      return
    end

    details["port"] = (addr[4, 2].hex * 256) + addr[6, 2].hex
    details["flow_info"] = addr[8, 8]
    details["ip"] = addr[16, 32].scan(/.{4}/).map{ |x| x.downcase }.join(":")
    details["scope_id"] = addr[48, 8]

    if addr.length > 56
      details["unknown"] = addr[56..-1]
    end
  end

  def smash_args(arg, data)
    return unless data.key?("#{arg}_len")
    arg_len = data.delete("#{arg}_len").to_i
    val = []

    i = 0
    while true
      sub_arg = "#{arg}[#{i}]"
      if !data.key?(sub_arg)
        break
      end
      val.push(data.delete(sub_arg))
      i += 1
    end

    data[arg] = val.join
  end

  def map_arch(data)
    return unless data.key?("arch")

    t_arch = data.delete("arch").hex

    data["arch"] = arch = {
      "bits" => nil,
      "endianness" => nil,
      "name" => nil,
    }

    if !(t_arch & ARCH["64bit"])
      arch["bits"] = 32
    else
      t_arch ^= ARCH["64bit"]
      arch["bits"] = 64
    end

    if !(t_arch & ARCH["little_endian"])
      arch["endianness"] = "big"
    else
      t_arch ^= ARCH["little_endian"]
      arch["endianness"] = "little"
    end

    if !(t_arch & ARCH["convention_mips64_n32"]).zero?
      t_arch ^= ARCH["convention_mips64_n32"]
    end

    if MACHINES.key?(t_arch)
      arch["name"] = MACHINES[t_arch]
    else
      @logger.error("Unrecognized #{t_arch} architecture")
    end
  end

  def map_uid(find_uid, data, uid_map)
    if data.key?(find_uid) 
      uid = data.fetch(find_uid)

      # Overflow uint32 is `null`
      if uid == "4294967295"
        data[find_uid] = nil
        return
      end

      data[find_uid] = {
        "name" => uid_map.fetch(uid, "UNKNOWN_USER"),
        "id" => uid
      }
    end
  end

  def split_fields(str)
    # to_h on Array is only availble in Ruby 2.1+
    Hash[*str.split.map{|el| el.split('=', 2) }.flatten]
  end

  def convert_value(str, parse_hex)
    if str.start_with?('"')
      return str[1..-2]
    elsif parse_hex && !str[/\H+/]
      return [str].pack("H*").strip.gsub(/[^[:print:]]/, " ")
    elsif str == "(null)"
      return ""
    else
      str
    end
  end

  def find_path_type(paths, type)
    return paths.find { |p| p["nametype"] == type } unless paths.nil?
  end

  def get_path_name(path)
    return "unknown path" unless !path.nil?
    return path["name"] || "inode: %s" % path.inode
  end

  def build_message(result)
    data = result["data"]
    message = []

    if data.key?("syscall")
      if data["syscall"].key?("auid") && data["syscall"]["auid"] && data["syscall"]["auid"]["id"] != data["syscall"]["uid"]["id"]
        message.push(data["syscall"]["auid"]["name"], "as")
      end

      # who did it?
      if data["syscall"].key?("uid") && data["syscall"]["uid"]
        message.push(data["syscall"]["uid"]["name"])
      end

      # succeeded or failed?
      if data["syscall"].key?("success")
        if data["syscall"]["success"] == "yes"
          message.push("succeeded to")
        else
          message.push("failed to")
        end
      end

      # to do what?
      message.push(data["syscall"]["name"])

      include_cmd = false

      if data.key?("execve") && data["execve"].key?("command")
        i = data["execve"]["command"].index(" ") || data["execve"]["command"].length
        path = data["execve"]["command"][0, i]
        message.push("`%s`" % data["execve"]["command"][0,25])

      elsif data["syscall"].key?("name")
        case data["syscall"]["name"]
        when "rename"
          deleted = get_path_name(find_path_type(data["paths"], "DELETE"))
          created = get_path_name(find_path_type(data["paths"], "CREATE"))
          message.push("`#{deleted}` to `#{created}`")

        when "bind", "connect", "sendto"
          message.push("to")
          include_cmd = true
          if data.key?("socket_address")
            if data["socket_address"].key?("ip") && data["socket_address"].key?("port")
              message.push("`%s:%s`" % [data["socket_address"]["ip"], data["socket_address"]["port"]])
            elsif data["socket_address"].key?("path")
              message.push("`%s`" % data["socket_address"]["path"])
            else
              message.push("`unknown address")
            end
          else
            message.push("`unknown address")
          end

        else
          if (created = find_path_type(data["paths"], "CREATE"))
            path = get_path_name(created)
            message.push("and create")
          elsif (normal = find_path_type(data["paths"], "NORMAL"))
            path = get_path_name(normal)
          else
            path = "unknown path"
          end
          message.push("`#{path}`")
        end
      end

      if data["syscall"].key?("executable") && data["syscall"]["executable"] != path
        message.push("via", "`%s`" % data["syscall"]["executable"])
      end

      if include_cmd && data["syscall"].key?("command")
        message.push("as", "`%s`" % data["syscall"]["command"])
      end

    end
    data["message"] = message.join(" ").strip
  end

end
