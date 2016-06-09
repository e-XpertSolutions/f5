#! /bin/bash  

	echo "when RULE_INIT {"
	echo -e "\t set static::json 1"
	echo "}"
	
	echo "when CLIENT_ACCEPTED {"
	echo -e "\t set counter 0"
	echo -e "\t set event_type \"CLIENT_ACCEPTED\""
	echo -e "	set sessionid \"[IP::client_addr][TCP::client_port][IP::local_addr][TCP::local_port][expr { int(100000000 * rand()) }]\""
	echo -e "\t binary scan [md5 \$sessionid] H* md5_string trash"
	echo -e "\t set md5_string [string range \$md5_string 12 20]"
	echo -e "\t set start_time [clock clicks -milliseconds]"
	echo -e "\t log local0. \"virtual=[virtual], id=\$md5_string, time=0, event_order=\$counter, event_type=\$event_type\""
	echo -e "\t if { \$static::json } {"
	echo "	set json_log \"\\{ \\\"\$md5_string\\\": \\[\\{\\\"virtual\\\":\\\"[virtual]\\\", \\\"id\\\":\\\"\$md5_string\\\", \\\"time\\\":\\\"0\\\", \\\"event_order\\\":\\\"\$counter\\\", \\\"event_type\\\":\\\"\$event_type\\\"\\},\""
	echo -e "\t }"
	echo "}"
	
	echo "when CLIENT_CLOSED {"
	echo -e "\t set counter [expr { \$counter+1 }]"
	echo -e "\t set event_type \"CLIENT_CLOSED\""
	echo -e "\t set curtime [expr { [clock clicks -milliseconds] - \$start_time }]"
	echo -e "\t log local0. \"virtual=[virtual], id=\$md5_string, time=\$curtime, event_order=\$counter, event_type=\$event_type\""
	echo -e "\t if { \$static::json } {"
	echo "	append json_log \"\\{\\\"virtual\\\":\\\"[virtual]\\\", \\\"id\\\":\\\"\$md5_string\\\", \\\"time\\\":\\\"\$curtime\\\", \\\"event_order\\\":\\\"\$counter\\\", \\\"event_type\\\":\\\"\$event_type\\\"\\}\\]\\}\""
	echo -e "\t log local0. \"\$json_log\""
	echo -e "\t }"
	echo "}"

while read line  
do   
	echo "when $line {"
	echo -e "\t set counter [expr { \$counter+1 }]"
	echo -e "\t set event_type \"$line\""
	echo -e "\t set curtime [expr { [clock clicks -milliseconds] - \$start_time }]"
	echo -e "\t log local0. \"virtual=[virtual], id=\$md5_string, time=\$curtime, event_order=\$counter, event_type=\$event_type\""
	echo -e "\t if { \$static::json } {"
	echo "		append json_log \"\\{\\\"virtual\\\":\\\"[virtual]\\\", \\\"id\\\":\\\"\$md5_string\\\", \\\"time\\\":\\\"\$curtime\\\", \\\"event_order\\\":\\\"\$counter\\\", \\\"event_type\\\":\\\"\$event_type\\\"\},\""
	echo -e "\t }"
	echo "}"
done < event_list.tcl