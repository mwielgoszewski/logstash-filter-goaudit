# encoding: utf-8
require 'spec_helper'
require "logstash/filters/goaudit"
require 'json'


describe LogStash::Filters::GoAudit do

  describe "Should parse a single event" do
    config <<-CONFIG
      filter {
        goaudit {
          source => "message"
        }
      }
    CONFIG

    data = JSON.generate({
      "sequence": 1226433,
      "timestamp": "1459447820.317",
      "messages": [
        {
          "type": 1305,
          "data": "audit_pid=14842 old=14842 auid=1000 ses=37 res=1"
        }
      ],
      "uid_map": {
        "1000": "ubuntu"
      }
    })

    sample("message" => data) do
      insist { subject.get("@timestamp") }.is_a?(LogStash::Timestamp) 
      insist { LogStash::Json.dump(subject.get("@timestamp")) } == "\"2016-03-31T18:10:20.316Z\""
      insist { subject.get("data")["sequence"] } == 1226433
    end

  end

  describe "Should parse a syscall event" do
    config <<-CONFIG
      filter {
        goaudit {
          source => "message"
        }
      }
    CONFIG

    data = JSON.generate({
      "sequence": 1226679,
      "timestamp": "1459449216.329",
      "messages": [
        {
          "type": 1300,
          "data": "arch=c000003e syscall=59 success=yes exit=0 a0=7f7242278f28 a1=7f7242278e60 a2=7f7242278e78 a3=7f7241707a10 items=2 ppid=15125 pid=15126 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=37 comm=\"curl\" exe=\"/usr/bin/curl\" key=(null)"
        }
      ],
      "uid_map": {
        "0": "root",
        "1000": "ubuntu"
      }
    })

    sample("message" => data) do
      insist { subject.get("data").include?("timestamp") }
      insist { LogStash::Json.dump(subject.get("@timestamp")) } == "\"2016-03-31T18:33:36.328Z\""
      insist { subject.get("data") }.include?("syscall")
      insist { subject.get("data")["syscall"]["name"] } == "execve"
      insist { subject.get("data")["syscall"]["success"] } == "yes"
      insist { subject.get("data")["syscall"]["exit"] } == "0"
      insist { subject.get("data")["syscall"]["arch"] } == {"bits" => 64, "endianness" => "little", "name" => "x86_64"}
      insist { subject.get("data")["syscall"]["id"] } == "59"
      insist { subject.get("data")["syscall"]["a0"] } == "7f7242278f28"
      insist { subject.get("data")["syscall"]["a1"] } == "7f7242278e60"
      insist { subject.get("data")["syscall"]["a2"] } == "7f7242278e78"
      insist { subject.get("data")["syscall"]["a3"] } == "7f7241707a10"
      insist { subject.get("data")["syscall"]["items"] } == "2"
      insist { subject.get("data")["syscall"]["ppid"] } == "15125"
      insist { subject.get("data")["syscall"]["pid"] } == "15126"
      insist { subject.get("data")["syscall"]["auid"] } == {"name" => "ubuntu", "id" => "1000"}
      insist { subject.get("data")["syscall"]["uid"] } == {"name" => "ubuntu", "id" => "1000"}
      insist { subject.get("data")["syscall"]["gid"] } == "1000"
      insist { subject.get("data")["syscall"]["euid"] } == {"name" => "ubuntu", "id" => "1000"}
      insist { subject.get("data")["syscall"]["suid"] } == {"name" => "ubuntu", "id" => "1000"}
      insist { subject.get("data")["syscall"]["fsuid"] } == {"name" => "ubuntu", "id" => "1000"}
      insist { subject.get("data")["syscall"]["sgid"] } == "1000"
      insist { subject.get("data")["syscall"]["egid"] } == "1000"
      insist { subject.get("data")["syscall"]["fsgid"] } == "1000"
      insist { subject.get("data")["syscall"]["tty"] } == "pts0"
      insist { subject.get("data")["syscall"]["session_id"] } == "37"
      insist { subject.get("data")["syscall"]["command"] } == "curl"
      insist { subject.get("data")["syscall"]["executable"] } == "/usr/bin/curl"
      insist { subject.get("data")["syscall"]["key"] } == ""
      insist { subject.get("data")["message"] } == "ubuntu succeeded to execve `unknown path` via `/usr/bin/curl`"
      insist { subject.get("data")["sequence"] } == 1226679
      insist { subject.get("data")["unknown"] } == []
    end

  end

  describe "Should parse a complex execve event" do
    config <<-CONFIG
      filter {
        goaudit {
          source => "message"
        }
      }
    CONFIG

    data = JSON.generate({
      "sequence": 1226679,
      "timestamp": "1459449216.329",
      "messages": [
        {
          "type": 1309,
          "data": "argc=2 a0=\"curl\""
        },
        {
          "type": 1309,
          "data": " a1_len=52082 a1[0]=68"
        },
        {
          "type": 1309,
          "data": " a1[1]=68"
        },
        {
          "type": 1309,
          "data": " a1[2]=68"
        },
        {
          "type": 1309,
          "data": " a1[3]=68"
        },
        {
          "type": 1309,
          "data": " a1[4]=68"
        },
        {
          "type": 1309,
          "data": " a1[5]=68"
        },
        {
          "type": 1309,
          "data": " a1[6]=68"
        }
      ],
      "uid_map": {
        "0": "root",
        "1000": "ubuntu"
      }
    })

    sample("message" => data) do
      insist { subject.get("@timestamp") }.is_a?(LogStash::Timestamp) 
      insist { LogStash::Json.dump(subject.get("@timestamp")) } == "\"2016-03-31T18:33:36.328Z\""
      insist { subject.get("data") }.include?("execve")
      insist { subject.get("data")["execve"]["command"] } == "curl hhhhhhh"
      insist { subject.get("data")["sequence"] } == 1226679
      insist { subject.get("data")["unknown"] } == []
      insist { subject.get("data")["message"] } == ""
    end

  end

  describe "Should parse paths" do
    config <<-CONFIG
      filter {
        goaudit {
          source => "message"
        }
      }
    CONFIG

    data = JSON.generate({
      "sequence": 1226679,
      "timestamp": "1459449216.329",
      "messages": [
        {
          "type": 1302,
          "data": "item=0 name=\"/usr/bin/curl\" inode=638 dev=ca:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL"
        },
        {
          "type": 1302,
          "data": "item=1 name=\"/lib64/ld-linux-x86-64.so.2\" inode=396037 dev=ca:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL"
        }
      ],
      "uid_map": {
        "0": "root",
        "1000": "ubuntu"
      }
    })

    sample("message" => data) do
      insist { subject.get("@timestamp") }.is_a?(LogStash::Timestamp) 
      insist { LogStash::Json.dump(subject.get("@timestamp")) } == "\"2016-03-31T18:33:36.328Z\""
      insist { subject.get("data") }.include?("paths")
      insist { subject.get("data")["paths"][0] } == {"dev"=>"ca:01", "inode"=>"638", "mode"=>"0100755", "name"=>"/usr/bin/curl", "nametype"=>"NORMAL", "ogid"=>"0", "ouid"=>{"id"=>"0", "name"=>"root"}, "rdev"=>"00:00"}
      insist { subject.get("data")["paths"][1] } == {"dev"=>"ca:01", "inode"=>"396037", "mode"=>"0100755", "name"=>"/lib64/ld-linux-x86-64.so.2", "nametype"=>"NORMAL", "ogid"=>"0", "ouid"=>{"id"=>"0", "name"=>"root"}, "rdev"=>"00:00"}
      insist { subject.get("data")["sequence"] } == 1226679
      insist { subject.get("data")["unknown"] } == []
    end
  end

  describe "Should parse cwd" do
    config <<-CONFIG
      filter {
        goaudit {
          source => "message"
        }
      }
    CONFIG

    data = JSON.generate({
      "sequence": 1226679,
      "timestamp": "1459449216.329",
      "messages": [
        {
          "type": 1307,
          "data": " cwd=2F686F6D652F7562756E74752F74657374207769746820737061636573"
        }
      ],
      "uid_map": {
        "0": "root",
        "1000": "ubuntu"
      }
    })

    sample("message" => data) do
      insist { subject.get("@timestamp") }.is_a?(LogStash::Timestamp) 
      insist { LogStash::Json.dump(subject.get("@timestamp")) } == "\"2016-03-31T18:33:36.328Z\""
      insist { subject.get("data") }.include?("cwd")
      insist { subject.get("data")["cwd"] } == "/home/ubuntu/test with spaces"
      insist { subject.get("data")["sequence"] } == 1226679
      insist { subject.get("data")["unknown"] } == []
    end
  end

  describe "Normal execve test" do 
    config <<-CONFIG
      filter {
        goaudit {
          source => "message"
        }
      }
    CONFIG

    data = JSON.generate({
      "sequence": 1226679,
      "timestamp": "1459449216.329",
      "messages": [
        {
          "type": 1307,
          "data": " cwd=2F686F6D652F7562756E74752F74657374207769746820737061636573"
        },
        {
          "type": 1302,
          "data": "item=0 name=\"/usr/bin/curl\" inode=638 dev=ca:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL"
        },
        {
          "type": 1302,
          "data": "item=1 name=\"/lib64/ld-linux-x86-64.so.2\" inode=396037 dev=ca:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL"
        },
        {
          "type": 1309,
          "data": "argc=2 a0=\"curl\""
        },
        {
          "type": 1309,
          "data": " a1_len=52082 a1[0]=68"
        },
        {
          "type": 1309,
          "data": " a1[1]=68"
        },
        {
          "type": 1309,
          "data": " a1[2]=68"
        },
        {
          "type": 1309,
          "data": " a1[3]=68"
        },
        {
          "type": 1309,
          "data": " a1[4]=68"
        },
        {
          "type": 1309,
          "data": " a1[5]=68"
        },
        {
          "type": 1309,
          "data": " a1[6]=68"
        },
        {
          "type": 1300,
          "data": "arch=c000003e syscall=59 success=yes exit=0 a0=7f7242278f28 a1=7f7242278e60 a2=7f7242278e78 a3=7f7241707a10 items=2 ppid=15125 pid=15126 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=37 comm=\"curl\" exe=\"/usr/bin/curl\" key=(null)"
        }
      ],
      "uid_map": {
        "0": "root",
        "1000": "ubuntu"
      }
    })

    sample("message" => data) do
      insist { subject.get("@timestamp") }.is_a?(LogStash::Timestamp) 
      insist { LogStash::Json.dump(subject.get("@timestamp")) } == "\"2016-03-31T18:33:36.328Z\""
      insist { subject.get("data") }.include?("syscall")
      insist { subject.get("data") }.include?("execve")
      insist { subject.get("data") }.include?("paths")
      insist { subject.get("data") }.include?("cwd")
      insist { subject.get("data")["syscall"]["name"] } == "execve"
      insist { subject.get("data")["syscall"]["success"] } == "yes"
      insist { subject.get("data")["syscall"]["exit"] } == "0"
      insist { subject.get("data")["syscall"]["arch"] } == {"bits" => 64, "endianness" => "little", "name" => "x86_64"}
      insist { subject.get("data")["syscall"]["id"] } == "59"
      insist { subject.get("data")["syscall"]["a0"] } == "7f7242278f28"
      insist { subject.get("data")["syscall"]["a1"] } == "7f7242278e60"
      insist { subject.get("data")["syscall"]["a2"] } == "7f7242278e78"
      insist { subject.get("data")["syscall"]["a3"] } == "7f7241707a10"
      insist { subject.get("data")["syscall"]["items"] } == "2"
      insist { subject.get("data")["syscall"]["ppid"] } == "15125"
      insist { subject.get("data")["syscall"]["pid"] } == "15126"
      insist { subject.get("data")["syscall"]["auid"] } == {"name" => "ubuntu", "id" => "1000"}
      insist { subject.get("data")["syscall"]["uid"] } == {"name" => "ubuntu", "id" => "1000"}
      insist { subject.get("data")["syscall"]["gid"] } == "1000"
      insist { subject.get("data")["syscall"]["euid"] } == {"name" => "ubuntu", "id" => "1000"}
      insist { subject.get("data")["syscall"]["suid"] } == {"name" => "ubuntu", "id" => "1000"}
      insist { subject.get("data")["syscall"]["fsuid"] } == {"name" => "ubuntu", "id" => "1000"}
      insist { subject.get("data")["syscall"]["sgid"] } == "1000"
      insist { subject.get("data")["syscall"]["egid"] } == "1000"
      insist { subject.get("data")["syscall"]["fsgid"] } == "1000"
      insist { subject.get("data")["syscall"]["tty"] } == "pts0"
      insist { subject.get("data")["syscall"]["session_id"] } == "37"
      insist { subject.get("data")["syscall"]["command"] } == "curl"
      insist { subject.get("data")["syscall"]["executable"] } == "/usr/bin/curl"
      insist { subject.get("data")["syscall"]["key"] } == ""

      insist { subject.get("data")["paths"][0] } == {"dev"=>"ca:01", "inode"=>"638", "mode"=>"0100755", "name"=>"/usr/bin/curl", "nametype"=>"NORMAL", "ogid"=>"0", "ouid"=>{"id"=>"0", "name"=>"root"}, "rdev"=>"00:00"}
      insist { subject.get("data")["paths"][1] } == {"dev"=>"ca:01", "inode"=>"396037", "mode"=>"0100755", "name"=>"/lib64/ld-linux-x86-64.so.2", "nametype"=>"NORMAL", "ogid"=>"0", "ouid"=>{"id"=>"0", "name"=>"root"}, "rdev"=>"00:00"}
      insist { subject.get("data")["cwd"] } == "/home/ubuntu/test with spaces"

      insist { subject.get("data")["message"] } == "ubuntu succeeded to execve `curl hhhhhhh` via `/usr/bin/curl`"
      insist { subject.get("data")["sequence"] } == 1226679
      insist { subject.get("data")["unknown"] } == []
    end
  end

  describe "Should handle = in values properly" do
    config <<-CONFIG
      filter {
        goaudit {
          source => "message"
        }
      }
    CONFIG

    data = JSON.generate({
      "sequence": 10453717,
      "timestamp": "1462897538.564",
      "messages": [
        {
          "type": 1309,
          "data": "argc=1 a0=\"stuff=things\""
        }
      ]
    })

    sample("message" => data) do
      insist { subject.get("data")["execve"]["command"] } == "stuff=things"
    end

    data = JSON.generate({
      "sequence": 10453717,
      "timestamp": "1462897538.564",
      "messages": [
        {
          "type": 1309,
          "data": "argc=1 a0=\"stuff=\""
        }
      ]
    })

    sample("message" => data) do
      insist { subject.get("data")["execve"]["command"] } == "stuff="
    end

  end

  describe "Should parse a sockaddr" do 
    config <<-CONFIG
      filter {
        goaudit {
          source => "message"
        }
      }
    CONFIG

    data = JSON.generate({
      "sequence": 10453717,
      "timestamp": "1462897538.564",
      "messages": [
        {
          "type": 1306,
          "data": "saddr=0200270F000000000000000000000000"
        }
      ]
    })

    sample("message" => data) do
      insist { subject.get("data") }.include?("socket_address")
      insist { subject.get("data")["socket_address"]["family"] } == "inet"
      insist { subject.get("data")["socket_address"]["port"] } == 9999
      insist { subject.get("data")["socket_address"]["ip"] } == "0.0.0.0"
      insist { subject.get("data")["socket_address"]["unknown"] } == "0000000000000000"
    end

    data = JSON.generate({
      "sequence": 10453717,
      "timestamp": "1462897538.564",
      "messages": [
        {
          "type": 1306,
          "data": "saddr=0A00270F0000000000000000000000000000000000000001000000000000"
        }
      ]
    })

    sample("message" => data) do
      insist { subject.get("data") }.include?("socket_address")
      insist { subject.get("data")["socket_address"]["family"] } == "inet6"
      insist { subject.get("data")["socket_address"]["port"] } == 9999
      insist { subject.get("data")["socket_address"]["ip"] } == "0000:0000:0000:0000:0000:0000:0000:0001"
      insist { subject.get("data")["socket_address"]["unknown"] } == "0000"
      insist { subject.get("data")["socket_address"]["scope_id"] } == "00000000"
      insist { subject.get("data")["socket_address"]["flow_info"] } == "00000000"
    end

    data = JSON.generate({
      "sequence": 10453717,
      "timestamp": "1462897538.564",
      "messages": [
        {
          "type": 1306,
          "data": "saddr=01002F686F6D652F6E6174652F736F636B65740010"
        }
      ]
    })

    sample("message" => data) do
      insist { subject.get("data") }.include?("socket_address")
      insist { subject.get("data")["socket_address"]["family"] } == "local"
      insist { subject.get("data")["socket_address"]["path"] } == "/home/nate/socket"
      insist { subject.get("data")["socket_address"]["unknown"] } == "0010"
    end
  end

  describe "Should parse a proctitle" do
    config <<-CONFIG
      filter {
        goaudit {
          source => "message"
        }
      }
    CONFIG

    data = JSON.generate({
      "sequence": 1188,
      "timestamp": "1473790050.668",
      "messages": [
        {
          "type": 1327,
          "data": "proctitle=6E63002D6C0039393939"
        }
      ]
    })

    sample("message" => data) do
      insist { subject.get("data") }.include?("proctitle")
      insist { subject.get("data")["proctitle"] } == "nc -l 9999"
    end
  end

end
